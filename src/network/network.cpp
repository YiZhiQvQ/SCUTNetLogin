#define _WIN32_WINNT 0x0601

#include "network/network.h"
#include "core/byte_utils.h"
#include "core/constants.h"
#include <winsock2.h>
#include <windows.h>
// 顺序要求：netioapi.h（由 iphlpapi.h 末尾包含）的主体声明在 #ifdef _WS2IPDEF_ 内，
// 而 winsock2.h 只带 ws2def.h —— 缺 ws2ipdef.h 会让 NotifyIpInterfaceChange /
// MIB_IPFORWARD_TABLE2 等全部"未声明的标识符"
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <ifdef.h>
#include <QProcess>
#include <QRegularExpression>
#include <QNetworkInterface>
#include <QSet>
#include <QElapsedTimer>
#include <QMetaObject>
#include <QtEndian>
#include <vector>
#include <algorithm>
#include <QDebug>
#include <QThread>
#include <pcap.h>

namespace Network {

// ============================================================================
// 共享 Win32 适配器枚举 — findInterface / findAdapterGuidByMac / listInterfaces 共用
// ============================================================================

struct RawWin32Adapter {
    QString guid;           // AdapterName, e.g. "{XXXXXXXX-...}"
    QString description;    // Description (驱动描述，如 "Realtek PCIe GbE Family Controller")
    // FriendlyName：用户在"网络连接"里看到的名称（如"以太网""WLAN 2"），**这才是
    // netsh 接受的 name=**。description 在 netsh 里通常认不出，不要混用。
    QString friendlyName;
    DWORD   ifIndex = 0;    // IPv4 接口索引（netsh 也接受十进制索引）
    // 接口 LUID：GUID/LUID名/ifIndex 之间的换算都以它为中转（netioapi 提供全套转换）
    IF_LUID luid{};
    // ConvertInterfaceLuidToAlias 的结果，等于"友好名"（如"以太网"、"WLAN 2"）
    QString luidAlias;
    // ConvertInterfaceLuidToName 的结果，形如 "ethernet_32774" / "wlan_32769"。
    // **Qt 6 的 QNetworkInterface::name() 在 Windows 上返回的正是这个**（不是 GUID，
    // 也不是友好名——初学者最容易在这两个 API 之间搞混）。
    // 它同样是 netsh 合法的目标名（实测 name=ethernet_32774 可正常读写配置）。
    QString luidName;
    BYTE    mac[8]{};       // PhysicalAddress (max 8, typically 6)
    ULONG   macLen = 0;
    DWORD   ifType = 0;
    // 当前生效的 IPv4 地址 / 网关 / DNS —— 自愈清理靠它判断"这块网卡上是不是挂着
    // 我们（或旧版本）留下的校园配置"，绝不碰与校园配置无关的用户自定义设置。
    QStringList ipv4;
    QStringList gateways;
    QStringList dns;
    // IP_ADAPTER_ADDRESSES::OperStatus 为 IF_OPER_STATUS（iphlpapi <ifdef.h> 枚举，
    // 与 NET_IF_OPER_STATUS 是不同 typedef，不可混用）
    IF_OPER_STATUS operStatus = IfOperStatusUnknown;   // 链路状态（有线插入检测）
};

// 虚拟/干扰适配器排除关键词（有线链路检测；USB 手机共享、虚拟机、蓝牙等不算
// "物理有线网口"，避免 auto 模式被 USB 共享网卡误导为"网线已插入"）。
// VPN/隧道虚拟网卡（Radmin、WireGuard、Tailscale、ZeroTier、OpenVPN 等）在
// Windows 下常以 ifType=Ethernet(6) + oper=Up 出现、即使未连任何 VPN——若不排除，
// 会被误判为"物理有线已接入"，导致 auto 模式恒选有线（实测 Radmin VPN 触发的
// "一直默认连有线" 问题）。
// 全小写：与 isVirtualAdapter 里 toLower() 后的描述做大小写敏感匹配，
// 避免对同一描述做 20 次大小写不敏感子串扫描（该函数在链路检测热路径上）
static const QStringList& virtualAdapterKeys()
{
    static const QStringList keys = {
        QStringLiteral("virtual"), QStringLiteral("vmware"), QStringLiteral("virtualbox"),
        QStringLiteral("hyper-v"), QStringLiteral("tap-windows"),
        QStringLiteral("bluetooth"), QStringLiteral("loopback"), QStringLiteral("remote ndis"),
        QStringLiteral("ndis"), QStringLiteral("teredo"), QStringLiteral("tun"), QStringLiteral("tap"),
        QStringLiteral("npf"),
        QStringLiteral("radmin"), QStringLiteral("vpn"), QStringLiteral("wireguard"),
        QStringLiteral("tailscale"), QStringLiteral("zerotier"), QStringLiteral("openvpn")
    };
    return keys;
}

static bool isVirtualAdapter(const QString& description)
{
    const QString lower = description.toLower();
    for (const QString& key : virtualAdapterKeys()) {
        if (lower.contains(key))
            return true;
    }
    return false;
}

static std::vector<RawWin32Adapter> enumerateWin32Adapters()
{
    std::vector<RawWin32Adapter> result;
    ULONG bufLen = 0;
    // 必须带 GAA_FLAG_INCLUDE_GATEWAYS：默认（flags=0）时
    // PIP_ADAPTER_ADDRESSES::FirstGatewayAddress **恒为 NULL**，网关列表永远是空的，
    // 于是"静态 IP 校验"会把已经设好的网关读成 [] 并误判失败
    // （日志：网关实际为[] 期望[10.40.16.254]，而同一时刻路由表里明明有该默认路由）。
    const ULONG flags = GAA_FLAG_INCLUDE_GATEWAYS;
    // 首次调用只为取所需缓冲区大小：正常返回 ERROR_BUFFER_OVERFLOW 并写入 bufLen；
    // 无任何适配器时返回 NO_ERROR（合法，不是错误）。
    // 失败必须留下痕迹——返回空表会让 ethernetLinkUp() 判为"无线缆"，auto 模式下
    // 静默改走无线，是极难自查的"为什么一直选无线"。
    const ULONG rcSize = GetAdaptersAddresses(AF_INET, flags, nullptr, nullptr, &bufLen);
    if (rcSize == NO_ERROR)
        return result;                       // 本机确实没有适配器
    if (rcSize != ERROR_BUFFER_OVERFLOW || bufLen == 0) {
        qWarning().noquote() << "GetAdaptersAddresses 取缓冲区大小失败, rc=" << rcSize
                             << "（将按'无有线网卡'处理）";
        return result;
    }

    std::vector<BYTE> buf(bufLen);
    PIP_ADAPTER_ADDRESSES adapters =
        reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data());
    const ULONG rc = GetAdaptersAddresses(AF_INET, flags, nullptr, adapters, &bufLen);
    if (rc != NO_ERROR) {
        qWarning().noquote() << "GetAdaptersAddresses 枚举失败, rc=" << rc
                             << "（将按'无有线网卡'处理）";
        return result;
    }
    for (PIP_ADAPTER_ADDRESSES a = adapters; a; a = a->Next) {
        RawWin32Adapter ra;
        ra.guid         = QString::fromLatin1(a->AdapterName);
        ra.description  = QString::fromWCharArray(a->Description);
        ra.friendlyName = a->FriendlyName ? QString::fromWCharArray(a->FriendlyName) : QString();
        ra.ifIndex      = a->IfIndex;
        ra.luid         = a->Luid;
        ra.ifType       = a->IfType;
        {
            wchar_t aliasBuf[NDIS_IF_MAX_STRING_SIZE + 1] = {};
            if (ConvertInterfaceLuidToAlias(&a->Luid, aliasBuf,
                                            NDIS_IF_MAX_STRING_SIZE + 1) == NO_ERROR)
                ra.luidAlias = QString::fromWCharArray(aliasBuf);

            wchar_t nameBuf[NDIS_IF_MAX_STRING_SIZE + 1] = {};
            if (ConvertInterfaceLuidToNameW(&a->Luid, nameBuf,
                                            NDIS_IF_MAX_STRING_SIZE + 1) == NO_ERROR)
                ra.luidName = QString::fromWCharArray(nameBuf);
        }
        ra.operStatus  = a->OperStatus;
        ra.macLen      = a->PhysicalAddressLength;
        if (ra.macLen > 0 && ra.macLen <= sizeof(ra.mac))
            memcpy(ra.mac, a->PhysicalAddress, ra.macLen);

        for (PIP_ADAPTER_UNICAST_ADDRESS u = a->FirstUnicastAddress; u; u = u->Next) {
            if (u->Address.lpSockaddr && u->Address.lpSockaddr->sa_family == AF_INET) {
                const auto* sin = reinterpret_cast<const sockaddr_in*>(u->Address.lpSockaddr);
                char ipBuf[INET_ADDRSTRLEN] = {};
                inet_ntop(AF_INET, &sin->sin_addr, ipBuf, sizeof(ipBuf));
                ra.ipv4 << QString::fromLatin1(ipBuf);
            }
        }
        for (PIP_ADAPTER_GATEWAY_ADDRESS g = a->FirstGatewayAddress; g; g = g->Next) {
            if (g->Address.lpSockaddr && g->Address.lpSockaddr->sa_family == AF_INET) {
                const auto* sin = reinterpret_cast<const sockaddr_in*>(g->Address.lpSockaddr);
                char gwBuf[INET_ADDRSTRLEN] = {};
                inet_ntop(AF_INET, &sin->sin_addr, gwBuf, sizeof(gwBuf));
                ra.gateways << QString::fromLatin1(gwBuf);
            }
        }
        for (PIP_ADAPTER_DNS_SERVER_ADDRESS d = a->FirstDnsServerAddress; d; d = d->Next) {
            if (d->Address.lpSockaddr && d->Address.lpSockaddr->sa_family == AF_INET) {
                const auto* sin = reinterpret_cast<const sockaddr_in*>(d->Address.lpSockaddr);
                char dnsBuf[INET_ADDRSTRLEN] = {};
                inet_ntop(AF_INET, &sin->sin_addr, dnsBuf, sizeof(dnsBuf));
                ra.dns << QString::fromLatin1(dnsBuf);
            }
        }
        result.push_back(ra);
    }
    return result;
}

QString systemExecutable(const QString& name)
{
    // 全路径调用系统命令：本程序以管理员权限运行，按名调用会被 PATH 中的同名程序
    // 劫持（netcfg/netsh 这类工具历来是持久化的常见目标）。失败时退回按名调用，
    // 至少不改变原有行为。
    wchar_t dir[MAX_PATH] = {};
    const UINT n = GetSystemDirectoryW(dir, MAX_PATH);
    if (n == 0 || n >= MAX_PATH)
        return name;
    return QString::fromWCharArray(dir, static_cast<int>(n)) + QLatin1Char('\\') + name;
}

// ============================================================================
// findInterface — 将 pcap 设备名 / 描述映射到 Windows QNetworkInterface
// ============================================================================

// 由 LUID 得到 QNetworkInterface。
// Qt 6 的 interfaceFromName 接受 "ethernet_32774" 这类 LUID 名和十进制 ifIndex，
// 但**不接受 {GUID}**（实测 interfaceFromName("{...}") 返回 invalid）。
// 所以统一先拿到 LUID 名再查。
static QNetworkInterface interfaceFromLuid(const IF_LUID& luid)
{
    wchar_t nameBuf[NDIS_IF_MAX_STRING_SIZE + 1] = {};
    if (ConvertInterfaceLuidToNameW(&luid, nameBuf, NDIS_IF_MAX_STRING_SIZE + 1) == NO_ERROR) {
        QNetworkInterface iface = QNetworkInterface::interfaceFromName(QString::fromWCharArray(nameBuf));
        if (iface.isValid())
            return iface;
    }
    // 兜底：用 ifIndex
    NET_IFINDEX idx = 0;
    if (ConvertInterfaceLuidToIndex(&luid, &idx) == NO_ERROR) {
        QNetworkInterface iface = QNetworkInterface::interfaceFromIndex(static_cast<int>(idx));
        if (iface.isValid())
            return iface;
    }
    return QNetworkInterface();
}

QNetworkInterface findInterface(const QString& pcapName,
                                const QString& pcapDescription)
{
    // 先把 pcap 设备名里的 GUID 取出来（\Device\NPF_{GUID}）。
    // **注意 Qt 6 的 QNetworkInterface::name() 返回的不是 GUID**，而是
    // ConvertInterfaceLuidToName 的结果，形如 "ethernet_32774" / "wireless_32769"。
    // 旧实现拿 iface.name() 与 "{GUID}" 比较，永远不相等 → 有线认证输入映射失败
    // （日志里的"未能把 pcap 网卡名 ... 映射到系统网卡"就是这么来的）。
    // 因此统一改为：GUID → LUID → Qt 接口（经 ConvertInterfaceGuidToLuid）。
    QString ifGuid;
    static const QRegularExpression guidRe(R"(\\Device\\NPF_\{([A-Fa-f0-9\-]+)\})");
    const auto match = guidRe.match(pcapName);
    if (match.hasMatch())
        ifGuid = QStringLiteral("{") + match.captured(1) + QStringLiteral("}");

    // Strategy 1: GUID / LUID / ifIndex 三种形式都交给 Win32 枚举统一解析，
    // 再换算成 Qt 接口（Qt 的 interfaceFromName 只认 LUID 名与 ifIndex，不认 GUID）。
    const auto adapters = enumerateWin32Adapters();
    for (const auto& ra : adapters) {
        const bool hit = (!ifGuid.isEmpty() && ra.guid.compare(ifGuid, Qt::CaseInsensitive) == 0)
                         || (!ra.luidName.isEmpty()
                             && ra.luidName.compare(pcapName, Qt::CaseInsensitive) == 0)
                         || ra.description.compare(pcapName, Qt::CaseInsensitive) == 0;
        if (!hit)
            continue;
        QNetworkInterface iface = interfaceFromLuid(ra.luid);
        if (iface.isValid())
            return iface;
    }

    // Strategy 2: match by description (pcap 描述 -> Qt humanReadableName)
    if (!pcapDescription.isEmpty()) {
        for (const QNetworkInterface& iface : QNetworkInterface::allInterfaces()) {
            if (iface.humanReadableName().compare(pcapDescription, Qt::CaseInsensitive) == 0)
                return iface;
        }
    }

    return QNetworkInterface();
}

// ============================================================================
// adapterInfo — 一次查询返回 guid + displayName
// ============================================================================

AdapterInfo adapterInfo(const QString& pcapName, const QString& pcapDescription)
{
    QNetworkInterface iface = findInterface(pcapName, pcapDescription);
    if (iface.isValid())
        return { iface.name(), iface.humanReadableName() };
    return {};
}

// ============================================================================
// adapterNameByMac — 通过 MAC 地址查找适配器名（用于 netsh）
// ============================================================================

// 把任何形式的网卡标识归一成"netsh 能接受的目标"。
//
// 实测（Windows 11 / netsh ipv4）各形式的可用性：
//   · name={GUID}                      → **失败** exit 1（"文件名、目录名或卷标语法不正确"）
//   · name=以太网（友好名）             → 成功
//   · name=7（ifIndex 十进制）          → 成功
//   · name=ethernet_32774（LUID 别名）  → 成功
//
// 两个历史坑（都实际发生过）：
//   ① 旧版把 iface.name() 直接交给 netsh。Qt 5 下它是 {GUID} → 全部 netsh 失败，
//      静态 IP/校园 DNS/默认路由长期残留，离开校园网后无法上网。
//   ② 只认 GUID/友好名/描述时，Qt 6 的 iface.name() 变成 LUID 别名
//      （"ethernet_32774"）→ 解析不出 → 被当成"无效目标"拒绝 → 静态 IP 完全设不上。
//      因此 LUID 别名必须与友好名同等对待。
static QString toNetshName(const QString& anyForm)
{
    if (anyForm.trimmed().isEmpty())
        return QString();

    // 已经是十进制索引：直接用
    bool allDigits = true;
    for (const QChar c : anyForm) {
        if (!c.isDigit()) { allDigits = false; break; }
    }
    if (allDigits)
        return anyForm;

    const auto adapters = enumerateWin32Adapters();

    // 依次按 GUID / LUID 别名 / 友好名 / 驱动描述匹配；命中后统一返回友好名
    // （最可读，且在"网络适配器"属性里能看到），取不到再退回 ifIndex。
    for (const auto& ra : adapters) {
        const bool hit = ra.guid.compare(anyForm, Qt::CaseInsensitive) == 0
                         || (!ra.luidName.isEmpty()
                             && ra.luidName.compare(anyForm, Qt::CaseInsensitive) == 0)
                         || (!ra.luidAlias.isEmpty()
                             && ra.luidAlias.compare(anyForm, Qt::CaseInsensitive) == 0)
                         || (!ra.friendlyName.isEmpty()
                             && ra.friendlyName.compare(anyForm, Qt::CaseInsensitive) == 0)
                         || ra.description.compare(anyForm, Qt::CaseInsensitive) == 0
                         || QString::number(ra.ifIndex) == anyForm;
        if (!hit)
            continue;
        if (!ra.friendlyName.isEmpty())
            return ra.friendlyName;
        if (!ra.luidAlias.isEmpty())
            return ra.luidAlias;
        return QString::number(ra.ifIndex);
    }

    // 认不出：原样返回。调用方仍会过 isUselessNetshTarget，并用 netsh 回读结果判定，
    // 不会因为"这里没认出来"而误伤（历史回归正是把"没认出"当成"无效"造成的）。
    return anyForm;
}

static QString findAdapterGuidByMac(const QString& normalizedMac)
{
    // Try Qt first
    for (const QNetworkInterface& iface : QNetworkInterface::allInterfaces()) {
        if (ByteUtils::normalizeMac(iface.hardwareAddress()) == normalizedMac)
            return iface.name();
    }

    // Win32 fallback (uses shared enumeration)。
    // 历史坑：这里曾用 interfaceFromName(ra.guid)，但 Qt 6 不接受 {GUID}（返回
    // invalid），于是永远退化成返回 GUID —— 而 GUID 又不能直接喂给 netsh。
    // 现在直接用 LUID 名（"ethernet_32774"），netsh 与 Qt 都认。
    for (const auto& ra : enumerateWin32Adapters()) {
        if (ra.macLen != 6)
            continue;
        const QByteArray macBytes(reinterpret_cast<const char*>(ra.mac), 6);
        if (QString::fromLatin1(macBytes.toHex().toUpper()) == normalizedMac) {
            if (!ra.luidName.isEmpty())
                return toNetshName(ra.luidName);
            return ra.guid;
        }
    }

    return QString();
}

QString adapterNameByMac(const QString& mac)
{
    if (mac.isEmpty())
        return QString();

    QString normalized = ByteUtils::normalizeMac(mac);
    if (normalized.isEmpty())
        return QString();

    // 必须转成 netsh 认识的目标名（友好名 / ifIndex），不能把 {GUID} 直接交出去
    return toNetshName(findAdapterGuidByMac(normalized));
}

QString netshAdapterName(const QString& anyForm)
{
    if (anyForm.isEmpty())
        return QString();

    // pcap 设备名 \Device\NPF_{GUID} 先取出 GUID
    static const QRegularExpression npfRe(R"(\\Device\\NPF_\{([A-Fa-f0-9\-]+)\})",
                                          QRegularExpression::CaseInsensitiveOption);
    const auto m = npfRe.match(anyForm);
    if (m.hasMatch())
        return toNetshName(QStringLiteral("{") + m.captured(1) + QStringLiteral("}"));

    return toNetshName(anyForm);
}

bool isUselessNetshTarget(const QString& anyForm)
{
    if (anyForm.trimmed().isEmpty())
        return true;

    const auto adapters = enumerateWin32Adapters();
    const QString resolved = netshAdapterName(anyForm);

    for (const auto& ra : adapters) {
        // 与 toNetshName 使用同一套"命中"判据，否则会出现
        // "toNetshName 认出来了、这里还认得空 → 误判为无效目标"的互相矛盾
        // （这正是 LUID 别名回归的成因）。
        const bool hit = ra.guid.compare(anyForm, Qt::CaseInsensitive) == 0
                         || (!ra.luidName.isEmpty()
                             && ra.luidName.compare(anyForm, Qt::CaseInsensitive) == 0)
                         || (!ra.luidAlias.isEmpty()
                             && ra.luidAlias.compare(anyForm, Qt::CaseInsensitive) == 0)
                         || (!ra.friendlyName.isEmpty()
                             && (ra.friendlyName.compare(resolved, Qt::CaseInsensitive) == 0
                                 || ra.friendlyName.compare(anyForm, Qt::CaseInsensitive) == 0))
                         || ra.description.compare(anyForm, Qt::CaseInsensitive) == 0
                         || QString::number(ra.ifIndex) == anyForm;
        if (!hit)
            continue;
        // 环回接口：写上网关/DNS 会在路由表里生成 0.0.0.0/0 → 校园网关（metric 1），
        // 且 DNS 也会被系统合并使用，离开校园网后依然解析到错误服务器。
        if (ra.ifType == IF_TYPE_SOFTWARE_LOOPBACK)
            return true;
        const QString lower = ra.description.toLower();
        // WAN Miniport 家族：Kernel Debug / Network Monitor / IPv6 / IP / PPPOE ...
        // 这些接口没有真实链路，给它配 IP 毫无意义且会污染路由与 DNS。
        if (lower.contains(QStringLiteral("wan miniport"))
            || lower.contains(QStringLiteral("kernel debug"))
            || lower.contains(QStringLiteral("teredo"))
            || lower.contains(QStringLiteral("6to4"))
            || lower.contains(QStringLiteral("isatap")))
            return true;
        return false;
    }
    // 解析不到具体接口：**不再直接判死**。历史上这里返回 true，导致 LUID 别名
    // （Qt 6 的 QNetworkInterface::name()）被拒绝、静态 IP 完全设不上。
    // 现在放行，由 setStaticIp/setDhcp 用 netsh 回读结果做最终裁决——
    // netsh 对不存在的接口本来就会报错，不会误写。
    return false;
}

// netsh 退出码非 0 但实际已达目标的情形（幂等调用必然命中）。
// 实测中文 Windows 的原文是「DHCP 已在此接口上启用。」——注意不是"已启用"；
// 只匹配英文 "already" 会漏掉，从而把正常状态误报成失败。
static bool isBenignNetshMessage(const QString& text)
{
    return text.contains(QStringLiteral("already"), Qt::CaseInsensitive)
           || text.contains(QStringLiteral("DHCP is already"))
           || text.contains(QStringLiteral("已在此接口"))
           || text.contains(QStringLiteral("已启用"));
}

// 执行 netsh 并把"已在目标状态"视为成功
static bool runNetshTolerant(const QStringList& args, QString* errorMsg)
{
    QString detail;
    if (runNetsh(args, &detail))
        return true;
    if (isBenignNetshMessage(detail))
        return true;
    if (errorMsg)
        *errorMsg = detail;
    return false;
}

bool purgeStaleCampusIpConfig(const QString& campusGateway, const QStringList& campusDns,
                              const QString& keepAdapter, QStringList* report)
{
    auto note = [report](const QString& s) {
        if (report)
            *report << s;
        qWarning().noquote() << "[自愈]" << s;
    };

    bool clean = true;
    const auto adapters = enumerateWin32Adapters();
    const QString keepName = keepAdapter.isEmpty() ? QString() : netshAdapterName(keepAdapter);

    // 统一用"已在目标状态也算成功"的封装：中文 Windows 返回
    // 「DHCP 已在此接口上启用。」且退出码为 1，若按失败处理会把正常状态
    // 误报成"清理失败"，并在 UI 上闪一条红色错误（曾经真的这么报过）。
    auto setDhcpOn = [&](const QString& name, const QString& tag) {
        QString err;
        const QStringList addrArgs = { QStringLiteral("interface"), QStringLiteral("ipv4"),
                                       QStringLiteral("set"), QStringLiteral("address"),
                                       QStringLiteral("name=%1").arg(name),
                                       QStringLiteral("source=dhcp") };
        if (!runNetshTolerant(addrArgs, &err)) {
            clean = false;
            note(QStringLiteral("%1 地址恢复 DHCP 失败(%2): %3").arg(tag, name, err));
        }
        QString dnsErr;
        const QStringList dnsArgs = { QStringLiteral("interface"), QStringLiteral("ipv4"),
                                      QStringLiteral("set"), QStringLiteral("dnsservers"),
                                      QStringLiteral("name=%1").arg(name),
                                      QStringLiteral("source=dhcp") };
        if (!runNetshTolerant(dnsArgs, &dnsErr)) {
            note(QStringLiteral("%1 DNS 恢复 DHCP 未成功(%2): %3").arg(tag, name, dnsErr));
        }
    };

    // 判定"这块网卡的当前配置里有没有校园网痕迹"：
    //   · 网关命中 campusGateway；或
    //   · DNS 命中 campusDns 中的任意一个；或
    //   · 地址落在校园静态 IP 所属网段（调用方通过 keepAdapter 之外的 IP 无法判断，
    //     因此退化为"有网关且有 DNS"——校园静态 IP 必然同时带这两项）。
    // 只清有痕迹的接口，绝不动用户自己的其它网络配置（如热点、公司网络）。
    auto hasCampusTrace = [&](const RawWin32Adapter& ra) {
        if (!campusGateway.isEmpty()
            && std::any_of(ra.gateways.begin(), ra.gateways.end(),
                           [&](const QString& g) { return g == campusGateway; }))
            return true;
        for (const QString& d : ra.dns) {
            if (campusDns.contains(d))
                return true;
        }
        // 网关 + DNS 同时存在但没有可用判据（campusDns 为空）时不动，避免误伤
        return false;
    };

    for (const auto& ra : adapters) {
        const QString name = ra.friendlyName.isEmpty() ? QString::number(ra.ifIndex)
                                                       : ra.friendlyName;

        if (ra.ifType == IF_TYPE_SOFTWARE_LOOPBACK) {
            // 环回上的网关是破坏性最大的一项：它会生成 metric=1 的默认路由，
            // 优先级高于手机热点，把全部流量送进黑洞。环回接口本就不该有任何网关/
            // DNS，因此无条件清理（这不是"用户的配置"）。
            if (!ra.gateways.isEmpty() || !ra.dns.isEmpty()) {
                setDhcpOn(name, QStringLiteral("环回接口"));
                note(QStringLiteral("环回接口存在网关%1/DNS%2，已清除")
                         .arg(ra.gateways.join(QLatin1Char('+')),
                              ra.dns.join(QLatin1Char('+'))));
            }
            // 环回上的持久默认路由必须显式删除，否则重启后依旧生效
            QString routeErr;
            const QStringList routeArgs = { QStringLiteral("interface"), QStringLiteral("ipv4"),
                                            QStringLiteral("delete"), QStringLiteral("route"),
                                            QStringLiteral("prefix=0.0.0.0/0"),
                                            QStringLiteral("interface=%1").arg(name),
                                            QStringLiteral("store=persistent") };
            if (runNetsh(routeArgs, &routeErr))
                note(QStringLiteral("已删除环回接口上的持久默认路由"));
            continue;
        }

        // 明确保留的接口（通常是当前在用的有线网卡）不动
        if (!keepName.isEmpty()
            && (ra.friendlyName.compare(keepName, Qt::CaseInsensitive) == 0
                || ra.guid.compare(keepAdapter, Qt::CaseInsensitive) == 0)) {
            continue;
        }

        // WAN Miniport / Teredo / 内核调试口等：绝不该带任何 IP 配置，
        // 出现过就说明历史路径写错了目标（本次故障的根源之一），一律清掉。
        if (isUselessNetshTarget(ra.guid)) {
            if (!ra.ipv4.isEmpty() || !ra.gateways.isEmpty() || !ra.dns.isEmpty()) {
                setDhcpOn(name, QStringLiteral("无效接口"));
                note(QStringLiteral("已清理无效接口残留: %1 [%2]").arg(name, ra.description));
            }
            continue;
        }

        // 其它真实网卡：只有确实挂着校园配置才动手（关键——否则会清掉用户自己的设置）
        if (hasCampusTrace(ra)) {
            setDhcpOn(name, QStringLiteral("校园配置残留"));
            note(QStringLiteral("已清除校园配置残留: %1 网关[%2] DNS[%3]")
                     .arg(name, ra.gateways.join(QLatin1Char('+')),
                          ra.dns.join(QLatin1Char('+'))));
        }
    }

    return clean;
}
QString dumpIpConfigSnapshot()
{
    QStringList out;

    // ① IPv4 默认路由（含持久路由）—— 残留的校园网关会在这里原形毕露
    PMIB_IPFORWARD_TABLE2 fwd = nullptr;
    if (GetIpForwardTable2(AF_INET, &fwd) == NO_ERROR && fwd) {
        for (ULONG i = 0; i < fwd->NumEntries; ++i) {
            const MIB_IPFORWARD_ROW2& row = fwd->Table[i];
            if (row.DestinationPrefix.PrefixLength != 0)
                continue;
            if (row.DestinationPrefix.Prefix.si_family != AF_INET)
                continue;
            const auto* nh = reinterpret_cast<const sockaddr_in*>(&row.NextHop);
            if (!nh || nh->sin_addr.S_un.S_addr == 0)
                continue;
            char nhBuf[INET_ADDRSTRLEN] = {};
            inet_ntop(AF_INET, &nh->sin_addr, nhBuf, sizeof(nhBuf));
            out << QStringLiteral("[路由] 默认路由 网关=%1 接口LUID=%2 度量=%3")
                       .arg(QString::fromLatin1(nhBuf))
                       .arg(static_cast<qulonglong>(row.InterfaceLuid.Value))
                       .arg(row.Metric);
        }
        FreeMibTable(fwd);
    } else {
        out << QStringLiteral("[路由] GetIpForwardTable2 失败，无法枚举默认路由");
    }

    // ② 每块网卡的 IPv4 地址与 DNS —— 静态残留 / 校园 DNS 挂在错误接口上一眼可见
    ULONG bufLen = 0;
    // 与 enumerateWin32Adapters 保持一致带上 GAA_FLAG_INCLUDE_GATEWAYS：虽然本段只用
    // 地址与 DNS，但 flags 不一致会让"同一份数据、两个快照不同"在排错时产生歧义。
    const ULONG gaaFlags = GAA_FLAG_INCLUDE_GATEWAYS;
    if (GetAdaptersAddresses(AF_INET, gaaFlags, nullptr, nullptr, &bufLen) == ERROR_BUFFER_OVERFLOW
        && bufLen > 0) {
        std::vector<BYTE> buf(bufLen);
        auto* adapters = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data());
        if (GetAdaptersAddresses(AF_INET, gaaFlags, nullptr, adapters, &bufLen) == NO_ERROR) {
            for (auto* a = adapters; a; a = a->Next) {
                const QString name = a->FriendlyName ? QString::fromWCharArray(a->FriendlyName)
                                                     : QStringLiteral("(无)");
                QStringList ips;
                for (auto* u = a->FirstUnicastAddress; u; u = u->Next) {
                    if (u->Address.lpSockaddr
                        && u->Address.lpSockaddr->sa_family == AF_INET) {
                        const auto* sin = reinterpret_cast<const sockaddr_in*>(
                            u->Address.lpSockaddr);
                        char ipb[INET_ADDRSTRLEN] = {};
                        inet_ntop(AF_INET, &sin->sin_addr, ipb, sizeof(ipb));
                        ips << QString::fromLatin1(ipb);
                    }
                }
                QStringList dns;
                for (auto* d = a->FirstDnsServerAddress; d; d = d->Next) {
                    if (d->Address.lpSockaddr
                        && d->Address.lpSockaddr->sa_family == AF_INET) {
                        const auto* sin = reinterpret_cast<const sockaddr_in*>(
                            d->Address.lpSockaddr);
                        char dnsb[INET_ADDRSTRLEN] = {};
                        inet_ntop(AF_INET, &sin->sin_addr, dnsb, sizeof(dnsb));
                        dns << QString::fromLatin1(dnsb);
                    }
                }
                out << QStringLiteral("[网卡] %1 (idx=%2) IP=[%3] DNS=[%4]")
                           .arg(name)
                           .arg(a->IfIndex)
                           .arg(ips.join(QLatin1Char(',')))
                           .arg(dns.join(QLatin1Char(',')));
            }
        }
    }

    return out.join(QLatin1Char('\n'));
}

// ============================================================================
// listInterfaces — 枚举可用 Npcap 网卡
// ============================================================================

QList<InterfaceEntry> listInterfaces()
{
    // 构建 Wi-Fi GUID 集合（Win32 IfType，精确可靠）
    const auto win32Adapters = enumerateWin32Adapters();
    QSet<QString> wifiGuids;
    for (const auto& ra : win32Adapters) {
        if (ra.ifType == IF_TYPE_IEEE80211)
            wifiGuids.insert(ra.guid.toUpper());
    }

    QList<InterfaceEntry> result;
    QList<InterfaceEntry> wireless;
    static const QRegularExpression guidRe(R"(\\Device\\NPF_\{([A-Fa-f0-9\-]+)\})");

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) != -1) {
        static const QStringList wifiKeys = {"Wireless", "Wi-Fi", "WiFi", "802.11", "WLAN", "无线"};
        for (pcap_if_t* dev = alldevs; dev != nullptr; dev = dev->next) {
            if (dev->flags & PCAP_IF_LOOPBACK)
                continue;
            const QString desc = dev->description ? QString::fromLocal8Bit(dev->description) : QString();
            const QString name = QString::fromUtf8(dev->name);
            if (desc.contains(QStringLiteral("Loopback"), Qt::CaseInsensitive)
                || name.contains(QStringLiteral("Loopback"), Qt::CaseInsensitive))
                continue;

            // 优先通过 Win32 IfType 检测 Wi-Fi，回退到字符串匹配
            bool isWireless = false;
            auto match = guidRe.match(name);
            if (match.hasMatch()) {
                const QString guid = QStringLiteral("{") + match.captured(1) + QStringLiteral("}");
                isWireless = wifiGuids.contains(guid.toUpper());
            }
            if (!isWireless) {
                for (const QString& key : wifiKeys) {
                    if (desc.contains(key, Qt::CaseInsensitive)
                        || name.contains(key, Qt::CaseInsensitive)) {
                        isWireless = true;
                        break;
                    }
                }
            }

            const QString displayName = desc.isEmpty() ? name : desc;
            if (isWireless)
                wireless.append({displayName, name, true});
            else
                result.append({displayName, name, false});
        }
        pcap_freealldevs(alldevs);
    } else {
        // 枚举失败（如 Npcap 未安装）：记录原因，返回空列表由 UI 提示
        qWarning().noquote() << "pcap_findalldevs failed:" << errbuf;
    }

    // Wi-Fi 网卡排到列表末尾，加前缀区分
    for (const auto& w : wireless)
        result.append({QStringLiteral("[Wi-Fi] ") + w.displayName, w.pcapName, true});

    return result;
}

// ============================================================================
// netsh 命令执行
// ============================================================================

// 控制台程序输出编码容错：先按 UTF-8 解，出现替换字符再退回系统本地代码页
// （中文 Windows 为 GBK/936）。netsh / route / schtasks 在不同版本下不一致，
// 硬编码任何一种都会在某些机器上解成乱码——而乱码会直接破坏"按文本判定状态"的逻辑。
static QString decodeConsoleText(const QByteArray& raw)
{
    if (raw.isEmpty())
        return QString();

    const QString asUtf8 = QString::fromUtf8(raw);
    if (!asUtf8.contains(QChar::ReplacementCharacter))
        return asUtf8;

    const QString asLocal = QString::fromLocal8Bit(raw);
    // 本地代码页解码结果里若仍有替换字符，取两者中"更干净"的一个
    if (asLocal.contains(QChar::ReplacementCharacter))
        return asUtf8;
    return asLocal;
}

bool runNetsh(const QStringList& args, QString* errorMsg)
{
    QProcess proc;
    proc.setCreateProcessArgumentsModifier([](QProcess::CreateProcessArguments* cpa) {
        cpa->flags |= CREATE_NO_WINDOW;
    });
    proc.start(systemExecutable(QStringLiteral("netsh.exe")), args);
    if (!proc.waitForStarted(NETSH_TIMEOUT)) {
        if (errorMsg)
            *errorMsg = QStringLiteral("netsh 无法启动: %1").arg(args.join(QLatin1Char(' ')));
        return false;
    }
    if (!proc.waitForFinished(NETSH_TIMEOUT)) {
        // 显式终止挂起的 netsh（QProcess 析构也会杀，但显式 kill 保证
        // 错误信息可读且不依赖析构时序）
        proc.kill();
        proc.waitForFinished(2000);
        if (errorMsg) {
            *errorMsg = QString("netsh 命令超时 (%1 秒): %2")
                            .arg(NETSH_TIMEOUT / 1000)
                            .arg(args.join(' '));
        }
        return false;
    }

    // netsh 把大部分错误写到 **stdout**（而非 stderr），原先只读 stderr 会让
    // "文件名、目录名或卷标语法不正确" 这类关键提示变成空字符串。
    // 编码也必须容错：本机实测 netsh 的本地化文本是 **UTF-8**，而按 GBK 解会把
    // "已在此接口上启用 DHCP" 解成乱码，进而让上面的幂等判定失配、
    // 把正常情况误报成"清理失败"。
    const QString outText = decodeConsoleText(proc.readAllStandardOutput()).trimmed();
    const QString errText = decodeConsoleText(proc.readAllStandardError()).trimmed();

    if (proc.exitCode() != 0) {
        if (errorMsg) {
            QString detail = errText.isEmpty() ? outText : errText;
            *errorMsg = QString("netsh 失败 (exit=%1): %2\n%3")
                            .arg(proc.exitCode())
                            .arg(args.join(' '), detail);
        }
        return false;
    }

    // 退出码 0 也未必真的生效（历史坑：name= 为空时 netsh 静默成功）。这里只负责把
    // 输出透传给调用方做二次校验，判定逻辑放在 setStaticIp/setDhcp 里。
    if (errorMsg && !outText.isEmpty())
        *errorMsg = outText;
    return true;
}

// 逐字段核对网卡当前 IPv4 配置：静态 IP 必须地址/掩码/网关都对上；DHCP 必须
// DHCP 已启用且没有残留的静态网关与 DNS。
//
// 【为什么不再解析 netsh 文本】
// 原实现读 "netsh interface ipv4 show config" 的本地化文本再逐行取值。这条路有三个
// 结构性缺陷，且已经实际造成误判（日志：地址读出空串被判失败，但同一毫秒的 Win32
// 快照里该网卡明明已是 10.40.16.57）：
//   ① 文本标签随系统语言变化（"IP Address" / "IP 地址" / 其他语言版本）；
//   ② 无地址时 netsh 直接不输出该行，与"读取失败"无法区分；
//   ③ netsh set 返回后配置是否已提交到协议栈取决于时序，文本层可能滞后。
// 因此改为直接查 Win32 结构化数据（GetAdaptersAddresses），与语言无关、无文本滞后，
// 并带退避重试等待地址/DNS/网关状态稳定。
// 该 LUID 对应的接口上，是否存在"默认路由 → gw"。
// 网关生效的最终判据：只要路由表里有这条 0.0.0.0/0，网关就一定在工作。
// 单纯依赖适配器的 FirstGatewayAddress 不够稳（它受 GAA flags 与过渡态影响）。
static bool hasDefaultRouteVia(const IF_LUID& luid, const QString& gw)
{
    if (gw.isEmpty())
        return false;
    PMIB_IPFORWARD_TABLE2 fwd = nullptr;
    if (GetIpForwardTable2(AF_INET, &fwd) != NO_ERROR || !fwd)
        return false;

    bool found = false;
    for (ULONG i = 0; i < fwd->NumEntries && !found; ++i) {
        const MIB_IPFORWARD_ROW2& row = fwd->Table[i];
        if (row.DestinationPrefix.PrefixLength != 0)
            continue;                                   // 只看默认路由
        if (row.DestinationPrefix.Prefix.si_family != AF_INET)
            continue;
        if (row.InterfaceLuid.Value != luid.Value)
            continue;
        const auto* nh = reinterpret_cast<const sockaddr_in*>(&row.NextHop);
        if (!nh)
            continue;
        char ipb[INET_ADDRSTRLEN] = {};
        inet_ntop(AF_INET, &nh->sin_addr, ipb, sizeof(ipb));
        if (QString::fromLatin1(ipb) == gw)
            found = true;
    }
    FreeMibTable(fwd);
    return found;
}

static bool verifyIpv4ConfigImpl(const QString& netshName, bool expectStatic,
                             const QString& ip, const QString& mask,
                             const QString& gw, const QString& dns1,
                             QString* detail)
{
    // mask 参数保留但不再参与校验：GetAdaptersAddresses 给的是前缀长度而不是点分掩码，
    // 换算出来只是同义反复（掩码错则地址/前缀必然对不上，已由地址项覆盖）。
    Q_UNUSED(mask);

    // 目标网卡 -> LUID（GUID/LUID 名/友好名/ifIndex 都能换算）
    const auto adapters = enumerateWin32Adapters();
    const RawWin32Adapter* target = nullptr;
    for (const auto& ra : adapters) {
        if (ra.friendlyName.compare(netshName, Qt::CaseInsensitive) == 0
            || ra.luidName.compare(netshName, Qt::CaseInsensitive) == 0
            || ra.guid.compare(netshName, Qt::CaseInsensitive) == 0) {
            target = &ra;
            break;
        }
    }
    if (!target) {
        if (detail)
            *detail = QStringLiteral("回读失败: 找不到网卡[%1]").arg(netshName);
        return false;
    }

    // 退避重试：netsh 返回后配置仍在提交中，等 DHCP/地址状态稳定（最多约 1.5 秒）
    QStringList bad;
    for (int attempt = 0; attempt < 10; ++attempt) {
        if (attempt > 0)
            QThread::msleep(150);

        // 每轮重新枚举（配置在变，不能用缓存）
        const auto snapshotNow = enumerateWin32Adapters();
        const RawWin32Adapter* cur = nullptr;
        for (const auto& ra : snapshotNow) {
            if (ra.ifIndex == target->ifIndex) { cur = &ra; break; }
        }
        if (!cur) {
            bad = { QStringLiteral("网卡消失") };
            continue;
        }

        bad.clear();
        if (expectStatic) {
            if (!ip.isEmpty() && !cur->ipv4.contains(ip)) {
                bad << QStringLiteral("地址实际为[%1] 期望[%2]")
                           .arg(cur->ipv4.join(QLatin1Char(',')), ip);
            }
            if (!gw.isEmpty()) {
                // 网关有两个可信来源，任一命中即算生效：
                //   ① 适配器自身的 FirstGatewayAddress（需 GAA_FLAG_INCLUDE_GATEWAYS）；
                //   ② 路由表里该接口上指向该网关的默认路由。
                // ②是最终判据——只要默认路由在，网关就是生效的。实测出现过适配器
                // 网关为空、但路由表明确有该默认路由的情况（见 .hang.log 快照）。
                const bool gwOnAdapter = cur->gateways.contains(gw);
                if (!gwOnAdapter && !hasDefaultRouteVia(cur->luid, gw)) {
                    bad << QStringLiteral("网关实际为[%1] 期望[%2]")
                               .arg(cur->gateways.join(QLatin1Char(',')), gw);
                }
            }
            if (!dns1.isEmpty() && !cur->dns.contains(dns1)) {
                bad << QStringLiteral("DNS 实际为[%1] 期望含[%2]")
                           .arg(cur->dns.join(QLatin1Char(',')), dns1);
            }
        } else {
            // 期望 DHCP：校园网关/DNS 不能残留
            const bool gwStillThere = cur->gateways.contains(gw)
                                      || (!gw.isEmpty() && hasDefaultRouteVia(cur->luid, gw));
            if (!gw.isEmpty() && gwStillThere)
                bad << QStringLiteral("仍残留网关[%1]").arg(gw);
            if (!dns1.isEmpty() && cur->dns.contains(dns1))
                bad << QStringLiteral("仍残留 DNS[%1]").arg(dns1);
        }

        if (bad.isEmpty())
            return true;   // 已满足期望：不必再等
    }

    if (!bad.isEmpty() && detail)
        *detail = QStringLiteral("%1回读不符: %2")
                      .arg(expectStatic ? QStringLiteral("静态IP ") : QStringLiteral("DHCP "))
                      .arg(bad.join(QStringLiteral("; ")));
    return bad.isEmpty();
}

// 读取网卡驱动注册表里的省电相关键，判断是否存在与 Npcap 冲突的风险。
//
// 背景（实测故障）：Realtek PCIe GbE 的 "Power Saving Mode" 与 "Green Ethernet"
// 开启时，网卡会在链路空闲时进入低功耗、关断部分收发通路。Npcap 是内核级过滤驱动，
// 其 pcap_activate 在这种情况下会**永久阻塞在内核态**，导致：
//   · EAP 线程无法返回，整个连接流程停摆；
//   · 进程无法被终止 —— TerminateProcess 返回 ERROR_ACCESS_DENIED，
//     任务管理器"结束任务"无任何反应，最终只能重启系统。
// 因此这里主动检测并提示用户，把"事后无从下手"变成"事前可规避"。
QString nicPowerSavingWarning(const QString& anyAdapterForm)
{
    // 必须用 netshAdapterName() 而不是 toNetshName()：调用方传进来的常是 pcap
    // 设备名（\Device\NPF_{GUID}），toNetshName 不解析这个前缀，会原样返回，
    // 于是下面的 GUID 匹配永远失败、检测恒为"未检出风险"。
    const QString canonical = netshAdapterName(anyAdapterForm);
    if (canonical.isEmpty())
        return QString();

    const auto adapters = enumerateWin32Adapters();
    QString guid;
    for (const auto& ra : adapters) {
        if (ra.friendlyName.compare(canonical, Qt::CaseInsensitive) == 0
            || ra.luidName.compare(canonical, Qt::CaseInsensitive) == 0) {
            guid = ra.guid;
            break;
        }
    }
    if (guid.isEmpty())
        return QString();

    HKEY classKey = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Control\\Class\\"
                      L"{4d36e972-e325-11ce-bfc1-08002be10318}",
                      0, KEY_READ, &classKey) != ERROR_SUCCESS) {
        return QString();
    }

    QStringList risky;
    for (DWORD i = 0;; ++i) {
        wchar_t subName[64] = {};
        DWORD nameLen = 63;
        if (RegEnumKeyExW(classKey, i, subName, &nameLen, nullptr, nullptr, nullptr, nullptr)
            != ERROR_SUCCESS) {
            break;
        }
        HKEY instKey = nullptr;
        if (RegOpenKeyExW(classKey, subName, 0, KEY_READ, &instKey) != ERROR_SUCCESS)
            continue;

        wchar_t instId[128] = {};
        DWORD idSize = sizeof(instId);
        DWORD type = 0;
        // 花括号方向必须归一：GetAdaptersAddresses 的 AdapterName **不带**花括号
        // （34A9BD27-...），而注册表 NetCfgInstanceId **带**花括号（{34A9BD27-...}）。
        // 直接比字符串永不相等 —— 这正是检测恒为"未检出风险"的原因。
        auto stripBraces = [](QString s) {
            s = s.trimmed();
            if (s.startsWith(QLatin1Char('{')) && s.endsWith(QLatin1Char('}')))
                s = s.mid(1, s.size() - 2);
            return s;
        };
        const bool isTarget =
            RegQueryValueExW(instKey, L"NetCfgInstanceId", nullptr, &type,
                             reinterpret_cast<LPBYTE>(instId), &idSize) == ERROR_SUCCESS
            && stripBraces(guid).compare(stripBraces(QString::fromWCharArray(instId)),
                                          Qt::CaseInsensitive) == 0;

        if (isTarget) {
            struct Check { const wchar_t* key; const char* label; };
            static const Check checks[] = {
                { L"PowerSavingMode",     "Power Saving Mode" },
                { L"EnableGreenEthernet", "Green Ethernet" },
                { L"*EEE",                "Energy Efficient Ethernet" },
                { L"AdvancedEEE",         "Advanced EEE" },
                { L"PowerDownPll",        "Power Down PLL" },
            };
            for (const auto& c : checks) {
                // 注意：Realtek 驱动把这些开关存成 **REG_SZ（字符串 "1"/"0"）**，
                // 而不是 REG_DWORD（实测 GetValueKind = String）。原实现只认
                // REG_DWORD，导致检测恒为空 —— 明明开着省电却报"未检出风险"。
                // 这里两种类型都接受，按文本比较 "1"。
                DWORD type2 = 0;
                BYTE buf[64] = {};
                DWORD size = sizeof(buf);
                if (RegQueryValueExW(instKey, c.key, nullptr, &type2, buf, &size) != ERROR_SUCCESS)
                    continue;

                bool enabled = false;
                if (type2 == REG_DWORD && size >= sizeof(DWORD)) {
                    DWORD v = 0;
                    memcpy(&v, buf, sizeof(v));
                    enabled = (v == 1);
                } else {
                    const QString sv = QString::fromWCharArray(
                        reinterpret_cast<const wchar_t*>(buf)).trimmed();
                    enabled = (sv == QLatin1String("1")
                               || sv.compare(QLatin1String("true"), Qt::CaseInsensitive) == 0
                               || sv.compare(QLatin1String("enabled"), Qt::CaseInsensitive) == 0);
                }
                if (enabled)
                    risky << QString::fromLatin1(c.label);
            }
            RegCloseKey(instKey);
            break;
        }
        RegCloseKey(instKey);
    }
    RegCloseKey(classKey);

    if (risky.isEmpty())
        return QString();

    return QStringLiteral("网卡 [%1] 开启了 %2 —— 这类省电特性会与 Npcap 的内核驱动冲突，"
                          "可能让打开网卡的操作永久阻塞（此时程序无法被结束，只能重启系统）。"
                          "建议在「设备管理器 → 网络适配器 → 属性 → 高级」中把这些项设为 Disabled。")
        .arg(canonical, risky.join(QStringLiteral(" / ")));
}

bool verifyIpv4ConfigPublic(const QString& anyAdapterForm, bool expectStatic,
                            const QString& ip, const QString& mask,
                            const QString& gw, const QString& dns1,
                            QString* detail)
{
    // 入参可能是 {GUID} / pcap 名 / LUID 名 / 友好名：统一解析成 netsh 侧名字后校验
    return verifyIpv4ConfigImpl(netshAdapterName(anyAdapterForm), expectStatic,
                                ip, mask, gw, dns1, detail);
}

// 两个入口都必须先把标识转成 netsh 认识的名称：传进来的可能是 {GUID}
// （adapterNameByMac 的历史返回值）或 pcap 设备名。
bool setStaticIp(const QString& winName, const QString& ip, const QString& mask,
                 const QString& gw, const QString& dns1, const QString& dns2,
                 QString* errorMsg)
{
    const QString target = netshAdapterName(winName);
    // 目标为空或指向环回/WAN Miniport：绝不能写。写错会把网关/DNS 挂到假接口上，
    // 在路由表里留下持久默认路由，离开校园网后依然上不了网。
    if (target.isEmpty() || isUselessNetshTarget(winName)) {
        if (errorMsg) {
            *errorMsg = QStringLiteral("拒绝向无效目标[%1]写入静态IP（解析结果[%2]）")
                            .arg(winName, target);
        }
        return false;
    }

    QStringList errors;
    bool ok = true;
    QString err;
    if (!runNetshTolerant({"interface", "ip", "set", "address", target, "static", ip, mask, gw}, &err)) {
        qWarning().noquote() << err;
        errors << err;
        ok = false;
    }
    if (!runNetshTolerant({"interface", "ip", "set", "dns", target, "static", dns1}, &err)) {
        qWarning().noquote() << err;
        errors << err;
        ok = false;
    }
    if (!dns2.isEmpty()) {
        if (!runNetshTolerant({"interface", "ip", "add", "dns", target, dns2}, &err)) {
            qWarning().noquote() << err;
            errors << err;
            ok = false;   // 备用 DNS 失败同样是"配置未完整生效"，不能对外报成功
        }
    }
    if (ok) {
        QString detail;
        if (!verifyIpv4ConfigImpl(target, /*expectStatic=*/true, ip, mask, gw, dns1, &detail)) {
            errors << detail;
            ok = false;
        }
    }
    if (!ok && errorMsg)
        *errorMsg = errors.join('\n');
    return ok;
}

bool setDhcp(const QString& winName, QString* errorMsg)
{
    const QString target = netshAdapterName(winName);
    if (target.isEmpty() || isUselessNetshTarget(winName)) {
        if (errorMsg) {
            *errorMsg = QStringLiteral("拒绝向无效目标[%1]恢复 DHCP（解析结果[%2]）")
                            .arg(winName, target);
        }
        return false;
    }

    QStringList errors;
    bool ok = true;
    QString err;
    if (!runNetshTolerant({"interface", "ip", "set", "address", target, "dhcp"}, &err)) {
        qWarning().noquote() << err;
        errors << err;
        ok = false;
    }
    if (!runNetshTolerant({"interface", "ip", "set", "dns", target, "dhcp"}, &err)) {
        qWarning().noquote() << err;
        errors << err;
        ok = false;
    }
    if (ok) {
        QString detail;
        if (!verifyIpv4ConfigImpl(target, /*expectStatic=*/false, QString(), QString(),
                              QString(), QString(), &detail)) {
            errors << detail;
            ok = false;
        }
    }
    if (!ok && errorMsg)
        *errorMsg = errors.join('\n');
    return ok;
}

// ============================================================================
// 链路状态
// ============================================================================

// ============================================================================
// LinkMonitor — 接口变更通知（替代 2 秒链路轮询）
// ============================================================================

// 适配器枚举的进程内短缓存（见下面 LinkMonitor 的注释：调用方每 2 秒一次的链路
// 检测会反复枚举适配器，而每次含 2 次 GetAdaptersAddresses + 逐适配器 QString 构造）
constexpr qint64 kAdapterCacheMs = 1500;

static void CALLBACK ipInterfaceChangeCallback(PVOID context, PMIB_IPINTERFACE_ROW /*row*/,
                                               MIB_NOTIFICATION_TYPE /*type*/)
{
    // 系统线程：只允许线程安全的投递，绝不能直接触碰 Qt 对象状态
    QMetaObject::invokeMethod(static_cast<LinkMonitor*>(context), "onSystemLinkChange",
                              Qt::QueuedConnection);
}

LinkMonitor::LinkMonitor(QObject* parent)
    : QObject(parent) {}

LinkMonitor::~LinkMonitor()
{
    if (m_handle) {
        // 会等待在途回调返回（回调只投递事件后立即返回，不会死锁）
        CancelMibChangeNotify2(static_cast<HANDLE>(m_handle));
        m_handle = nullptr;
    }
}

bool LinkMonitor::start()
{
    if (m_handle)
        return true;
    HANDLE h = nullptr;
    // AF_UNSPEC + 不请求初始通知：调用方自行取一次基线，避免注册瞬间的伪变更
    const DWORD rc = NotifyIpInterfaceChange(AF_UNSPEC, ipInterfaceChangeCallback,
                                             this, FALSE, &h);
    if (rc != NO_ERROR)
        return false;
    m_handle = h;
    return true;
}

void LinkMonitor::onSystemLinkChange()
{
    emit linkChanged();
}

// ============================================================================
// 链路状态
// ============================================================================

// 适配器枚举（带 1.5s 进程内缓存）：GUI 线程的链路检测会以 2 秒节奏反复调用它，
// 单次成本 = 2 次 GetAdaptersAddresses + 逐适配器 QString 构造 + 20 关键字扫描；
// 缓存后绝大多数调用只是一次 vector 读取。链路插拔的检测延迟相对原轮询不劣化
// （通知驱动为主，轮询只是兜底）。thread_local：GUI 线程/网络线程/线程池各自缓存，
// 互不干扰也无需加锁。
// 注：用户手动"刷新网卡"与调试诊断（dumpAdapters）走未缓存的 enumerateWin32Adapters()。
static const std::vector<RawWin32Adapter>& enumerateWin32AdaptersCached()
{
    struct Cache {
        std::vector<RawWin32Adapter> adapters;
        QElapsedTimer                stamp;
        bool                         valid = false;
    };
    static thread_local Cache cache;
    if (!cache.valid || cache.stamp.elapsed() > kAdapterCacheMs) {
        cache.adapters = enumerateWin32Adapters();
        cache.stamp.start();
        cache.valid    = true;
    }
    return cache.adapters;
}

QStringList connectedEthernetGuids()
{
    QStringList result;
    for (const auto& ra : enumerateWin32AdaptersCached()) {
        // 仅物理 Ethernet（ipifcons.h: IF_TYPE_ETHERNET_CSMACD=6），排除 802.11 与虚拟网卡
        if (ra.ifType != IF_TYPE_ETHERNET_CSMACD && ra.ifType != IF_TYPE_ETHERNET_3MBIT)
            continue;
        if (isVirtualAdapter(ra.description))
            continue;
        if (ra.operStatus != IfOperStatusUp)
            continue;
        result << ra.guid;
    }
    return result;
}

bool ethernetLinkUp()
{
    return !connectedEthernetGuids().isEmpty();
}

QString dumpAdapters()
{
    auto typeName = [](DWORD t) -> const char* {
        switch (t) {
        case IF_TYPE_ETHERNET_CSMACD:    return "Ethernet(6)";
        case IF_TYPE_ETHERNET_3MBIT:     return "Ethernet3MBit(7)";
        case IF_TYPE_IEEE80211:          return "Wireless(71)";
        case IF_TYPE_SOFTWARE_LOOPBACK:  return "Loopback(24)";
        case IF_TYPE_PPP:                return "PPP(23)";
        case IF_TYPE_TUNNEL:             return "Tunnel(131)";
        default:                         return "Other";
        }
    };
    auto operName = [](IF_OPER_STATUS s) -> const char* {
        switch (s) {
        case IfOperStatusUp:             return "Up";
        case IfOperStatusDown:           return "Down";
        case IfOperStatusTesting:        return "Testing";
        case IfOperStatusUnknown:        return "Unknown";
        case IfOperStatusDormant:        return "Dormant";
        case IfOperStatusNotPresent:     return "NotPresent";
        case IfOperStatusLowerLayerDown: return "LowerLayerDown";
        default:                         return "?";
        }
    };
    auto isEth = [](DWORD t) {
        return t == IF_TYPE_ETHERNET_CSMACD || t == IF_TYPE_ETHERNET_3MBIT;
    };

    const auto adapters = enumerateWin32Adapters();
    int counted = 0;
    QStringList out;
    for (const auto& ra : adapters) {
        const bool eth  = isEth(ra.ifType);
        const bool virt = isVirtualAdapter(ra.description);
        const bool up   = (ra.operStatus == IfOperStatusUp);
        const bool countHere = eth && !virt && up;
        if (countHere)
            ++counted;

        QByteArray macBytes;
        if (ra.macLen >= 6)
            macBytes = QByteArray(reinterpret_cast<const char*>(ra.mac), 6);

        QString cls;
        if (eth && !virt && up)
            cls = QStringLiteral("[有线·计入]");
        else if (eth && virt)
            cls = QStringLiteral("[有线·未计入·虚拟]");
        else if (eth)
            cls = QStringLiteral("[有线·未计入·状态:%1]").arg(QLatin1String(operName(ra.operStatus)));
        else if (ra.ifType == IF_TYPE_IEEE80211)
            cls = QStringLiteral("[无线]");
        else
            cls = QStringLiteral("[其他]");

        const QString mac = macBytes.isEmpty()
                                ? QStringLiteral("(无)")
                                : QString::fromLatin1(macBytes.toHex().toUpper());
        out << QStringLiteral("%1  %2  guid=%3  ifType=%4  oper=%5  MAC=%6")
               .arg(cls, ra.description, ra.guid,
                    QLatin1String(typeName(ra.ifType)),
                    QLatin1String(operName(ra.operStatus)),
                    mac);
    }
    out << QStringLiteral("适配器总计 %1 个；ethernetLinkUp() = %2（计入 %3 个）")
           .arg(adapters.size())
           .arg(counted > 0 ? QStringLiteral("true") : QStringLiteral("false"))
           .arg(counted);
    return out.join('\n');
}
} // namespace Network
