#define _WIN32_WINNT 0x0601

// ============================================================================
// network_adapter.cpp — 适配器枚举与标识解析
//
// 从原 network.cpp 拆出（该文件曾达 1147 行、混合 4 类职责）。本 TU 负责：
//   · GetAdaptersAddresses 快照（RawWin32Adapter）
//   · 各种网卡标识（GUID / LUID 名 / LUID 别名 / 友好名 / 描述 / ifIndex）的解析
//   · 虚拟适配器判定、MAC 反查
//   · LUID → QNetworkInterface 换算
//   · 网卡省电特性检测（与 Npcap 冲突的已知触发条件）
//
// 命名约定：本文件内的辅助函数一律 static，仅 network.h 声明的接口对外可见。
// ============================================================================

#include "network/network.h"
#include "network/network_internal.h"
#include "core/byte_utils.h"
#include "core/constants.h"
#include <winsock2.h>
#include <ws2tcpip.h>   // inet_ntop（仅 ws2ipdef.h 不够）
#include <windows.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <ifdef.h>
#include <QRegularExpression>
#include <QNetworkInterface>
#include <QSet>
#include <QDebug>
#include <vector>

namespace Network {

using Internal::RawWin32Adapter;   // 定义见 network_internal.h

namespace Internal {

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

bool isVirtualAdapter(const QString& description)
{
    const QString lower = description.toLower();
    for (const QString& key : virtualAdapterKeys()) {
        if (lower.contains(key))
            return true;
    }
    return false;
}

std::vector<RawWin32Adapter> enumerateWin32Adapters()
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


// 由 LUID 得到 QNetworkInterface。
// Qt 6 的 interfaceFromName 接受 "ethernet_32774" 这类 LUID 名和十进制 ifIndex，
// 但**不接受 {GUID}**（实测 interfaceFromName("{...}") 返回 invalid）。
// 所以统一先拿到 LUID 名再查，失败再退 ifIndex。
QNetworkInterface interfaceFromLuid(const IF_LUID& luid)
{
    wchar_t nameBuf[NDIS_IF_MAX_STRING_SIZE + 1] = {};
    if (ConvertInterfaceLuidToNameW(&luid, nameBuf, NDIS_IF_MAX_STRING_SIZE + 1) == NO_ERROR) {
        QNetworkInterface iface = QNetworkInterface::interfaceFromName(
            QString::fromWCharArray(nameBuf));
        if (iface.isValid())
            return iface;
    }
    NET_IFINDEX idx = 0;
    if (ConvertInterfaceLuidToIndex(&luid, &idx) == NO_ERROR) {
        QNetworkInterface iface = QNetworkInterface::interfaceFromIndex(static_cast<int>(idx));
        if (iface.isValid())
            return iface;
    }
    return QNetworkInterface();
}

} // namespace Internal

// systemExecutable 属于公开 API（network.h），必须留在 Network 命名空间而非 Internal
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

    const auto adapters = Internal::enumerateWin32Adapters();

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
    for (const auto& ra : Internal::enumerateWin32Adapters()) {
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

    const auto adapters = Internal::enumerateWin32Adapters();
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

QString nicPowerSavingWarning(const QString& anyAdapterForm)
{
    // 必须用 netshAdapterName() 而不是 toNetshName()：调用方传进来的常是 pcap
    // 设备名（\Device\NPF_{GUID}），toNetshName 不解析这个前缀，会原样返回，
    // 于是下面的 GUID 匹配永远失败、检测恒为"未检出风险"。
    const QString canonical = netshAdapterName(anyAdapterForm);
    if (canonical.isEmpty())
        return QString();

    const auto adapters = Internal::enumerateWin32Adapters();
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


// ============================================================================
// findInterface — 将 pcap 设备名 / 描述映射到 Windows QNetworkInterface
// ============================================================================

QNetworkInterface findInterface(const QString& pcapName,
                                const QString& pcapDescription)
{
    // 先把 pcap 设备名里的 GUID 取出来（\Device\NPF_{GUID}）。
    // **注意 Qt 6 的 QNetworkInterface::name() 返回的不是 GUID**，而是
    // ConvertInterfaceLuidToName 的结果，形如 "ethernet_32774" / "wireless_32769"。
    // 旧实现拿 iface.name() 与 "{GUID}" 比较，永远不相等 → 有线认证输入映射失败
    // （日志里的"未能把 pcap 网卡名 ... 映射到系统网卡"就是这么来的）。
    QString ifGuid;
    // pcap 设备名形如 \Device\NPF_{GUID}，取出其中 GUID
    static const QRegularExpression guidRe(
        QStringLiteral(R"((\\Device\\NPF_\{)([A-Fa-f0-9\-]+)(\}))"),
        QRegularExpression::CaseInsensitiveOption);
    const auto match = guidRe.match(pcapName);
    if (match.hasMatch())
        ifGuid = QStringLiteral("{") + match.captured(2) + QStringLiteral("}");

    // GUID / LUID 名 / 描述 三种形式都交给 Win32 枚举统一解析，再换算成 Qt 接口
    // （Qt 的 interfaceFromName 只认 LUID 名与 ifIndex，不认 GUID）。
    for (const auto& ra : Internal::enumerateWin32Adapters()) {
        const bool hit = (!ifGuid.isEmpty() && ra.guid.compare(ifGuid, Qt::CaseInsensitive) == 0)
                         || (!ra.luidName.isEmpty()
                             && ra.luidName.compare(pcapName, Qt::CaseInsensitive) == 0)
                         || ra.description.compare(pcapName, Qt::CaseInsensitive) == 0;
        if (!hit)
            continue;
        QNetworkInterface iface = Internal::interfaceFromLuid(ra.luid);
        if (iface.isValid())
            return iface;
    }

    // 回退：按描述匹配 Qt 的 humanReadableName
    if (!pcapDescription.isEmpty()) {
        for (const QNetworkInterface& iface : QNetworkInterface::allInterfaces()) {
            if (iface.humanReadableName().compare(pcapDescription, Qt::CaseInsensitive) == 0)
                return iface;
        }
    }

    return QNetworkInterface();
}

// adapterInfo — 一次查询返回 guid + displayName
AdapterInfo adapterInfo(const QString& pcapName, const QString& pcapDescription)
{
    QNetworkInterface iface = findInterface(pcapName, pcapDescription);
    if (iface.isValid())
        return { iface.name(), iface.humanReadableName() };
    return {};
}

} // namespace Network