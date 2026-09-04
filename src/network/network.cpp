#define _WIN32_WINNT 0x0601

#include "network/network.h"
#include "core/byte_utils.h"
#include "core/constants.h"
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <ifdef.h>
#include <QProcess>
#include <QRegularExpression>
#include <QNetworkInterface>
#include <QSet>
#include <QtEndian>
#include <vector>
#include <QDebug>
#include <pcap.h>

namespace Network {

// ============================================================================
// 共享 Win32 适配器枚举 — findInterface / findAdapterGuidByMac / listInterfaces 共用
// ============================================================================

struct RawWin32Adapter {
    QString guid;           // AdapterName, e.g. "{XXXXXXXX-...}"
    QString description;    // Description (friendly name)
    BYTE    mac[8]{};       // PhysicalAddress (max 8, typically 6)
    ULONG   macLen = 0;
    DWORD   ifType = 0;
    // IP_ADAPTER_ADDRESSES::OperStatus 为 IF_OPER_STATUS（iphlpapi <ifdef.h> 枚举，
    // 与 NET_IF_OPER_STATUS 是不同 typedef，不可混用）
    IF_OPER_STATUS operStatus = IfOperStatusUnknown;   // 链路状态（有线插入检测）
};

// 虚拟/干扰适配器排除关键词（有线链路检测；USB 手机共享、虚拟机、蓝牙等不算
// "物理有线网口"，避免 auto 模式被 USB 共享网卡误导为"网线已插入"）
static const QStringList& virtualAdapterKeys()
{
    static const QStringList keys = {
        QStringLiteral("Virtual"), QStringLiteral("VMware"), QStringLiteral("VirtualBox"),
        QStringLiteral("Hyper-V"), QStringLiteral("TAP-Windows"), QStringLiteral("TAP-Windows Adapter"),
        QStringLiteral("Bluetooth"), QStringLiteral("Loopback"), QStringLiteral("Remote NDIS"),
        QStringLiteral("NDIS"), QStringLiteral("Teredo"), QStringLiteral("TUN"), QStringLiteral("TAP"),
        QStringLiteral("NPF")
    };
    return keys;
}

static bool isVirtualAdapter(const QString& description)
{
    for (const QString& key : virtualAdapterKeys()) {
        if (description.contains(key, Qt::CaseInsensitive))
            return true;
    }
    return false;
}

static std::vector<RawWin32Adapter> enumerateWin32Adapters()
{
    std::vector<RawWin32Adapter> result;
    ULONG bufLen = 0;
    GetAdaptersAddresses(AF_INET, 0, nullptr, nullptr, &bufLen);
    std::vector<BYTE> buf(bufLen);
    PIP_ADAPTER_ADDRESSES adapters =
        reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data());
    if (GetAdaptersAddresses(AF_INET, 0, nullptr, adapters, &bufLen) == NO_ERROR) {
        for (PIP_ADAPTER_ADDRESSES a = adapters; a; a = a->Next) {
            RawWin32Adapter ra;
            ra.guid        = QString::fromLatin1(a->AdapterName);
            ra.description = QString::fromWCharArray(a->Description);
            ra.ifType      = a->IfType;
            ra.operStatus  = a->OperStatus;
            ra.macLen      = a->PhysicalAddressLength;
            if (ra.macLen > 0 && ra.macLen <= sizeof(ra.mac))
                memcpy(ra.mac, a->PhysicalAddress, ra.macLen);
            result.push_back(ra);
        }
    }
    return result;
}

// ============================================================================
// findInterface — 将 pcap 设备名 / 描述映射到 Windows QNetworkInterface
// ============================================================================

QNetworkInterface findInterface(const QString& pcapName,
                                const QString& pcapDescription)
{
    // Strategy 1: extract GUID from pcap device name → QNetworkInterface
    static const QRegularExpression guidRe(R"(\\Device\\NPF_\{([A-Fa-f0-9\-]+)\})");
    auto match = guidRe.match(pcapName);
    if (match.hasMatch()) {
        const QString guid = QStringLiteral("{") + match.captured(1) + QStringLiteral("}");
        for (const QNetworkInterface& iface : QNetworkInterface::allInterfaces()) {
            if (iface.name().compare(guid, Qt::CaseInsensitive) == 0)
                return iface;
        }
    }

    // Strategy 2: match by human-readable description (Qt)
    if (!pcapDescription.isEmpty()) {
        for (const QNetworkInterface& iface : QNetworkInterface::allInterfaces()) {
            if (iface.humanReadableName().compare(pcapDescription, Qt::CaseInsensitive) == 0)
                return iface;
        }

        // Strategy 3: match by description via Win32 GetAdaptersAddresses fallback
        for (const auto& ra : enumerateWin32Adapters()) {
            if (ra.description.compare(pcapDescription, Qt::CaseInsensitive) == 0) {
                QNetworkInterface iface = QNetworkInterface::interfaceFromName(ra.guid);
                if (iface.isValid())
                    return iface;
            }
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

static QString findAdapterGuidByMac(const QString& normalizedMac)
{
    // Try Qt first
    for (const QNetworkInterface& iface : QNetworkInterface::allInterfaces()) {
        if (ByteUtils::normalizeMac(iface.hardwareAddress()) == normalizedMac)
            return iface.name();
    }

    // Win32 fallback (uses shared enumeration)
    for (const auto& ra : enumerateWin32Adapters()) {
        if (ra.macLen != 6)
            continue;
        const QByteArray macBytes(reinterpret_cast<const char*>(ra.mac), 6);
        if (QString::fromLatin1(macBytes.toHex().toUpper()) == normalizedMac) {
            QNetworkInterface iface = QNetworkInterface::interfaceFromName(ra.guid);
            return iface.isValid() ? iface.name() : ra.guid;
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

    return findAdapterGuidByMac(normalized);
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

bool runNetsh(const QStringList& args, QString* errorMsg)
{
    QProcess proc;
    proc.setCreateProcessArgumentsModifier([](QProcess::CreateProcessArguments* cpa) {
        cpa->flags |= CREATE_NO_WINDOW;
    });
    proc.start("netsh", args);

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

    if (proc.exitCode() != 0) {
        if (errorMsg) {
            QString err = QString::fromLocal8Bit(proc.readAllStandardError()).trimmed();
            if (err.isEmpty())
                err = QString::fromLocal8Bit(proc.readAllStandardOutput()).trimmed();
            *errorMsg = QString("netsh 失败 (exit=%1): %2\n%3")
                            .arg(proc.exitCode())
                            .arg(args.join(' '), err);
        }
        return false;
    }

    return true;
}

bool setStaticIp(const QString& winName, const QString& ip, const QString& mask,
                 const QString& gw, const QString& dns1, const QString& dns2,
                 QString* errorMsg)
{
    QStringList errors;
    bool ok = true;
    QString err;
    if (!runNetsh({"interface", "ip", "set", "address", winName, "static", ip, mask, gw}, &err)) {
        qWarning().noquote() << err;
        errors << err;
        ok = false;
    }
    if (!runNetsh({"interface", "ip", "set", "dns", winName, "static", dns1}, &err)) {
        qWarning().noquote() << err;
        errors << err;
        ok = false;
    }
    if (!dns2.isEmpty()) {
        if (!runNetsh({"interface", "ip", "add", "dns", winName, dns2}, &err)) {
            qWarning().noquote() << err;
            errors << err;
        }
    }
    if (!ok && errorMsg)
        *errorMsg = errors.join('\n');
    return ok;
}

bool setDhcp(const QString& winName, QString* errorMsg)
{
    QStringList errors;
    bool ok = true;
    QString err;
    if (!runNetsh({"interface", "ip", "set", "address", winName, "dhcp"}, &err)) {
        qWarning().noquote() << err;
        errors << err;
        ok = false;
    }
    if (!runNetsh({"interface", "ip", "set", "dns", winName, "dhcp"}, &err)) {
        qWarning().noquote() << err;
        errors << err;
        ok = false;
    }
    if (!ok && errorMsg)
        *errorMsg = errors.join('\n');
    return ok;
}

// ============================================================================
// 链路状态
// ============================================================================

QStringList connectedEthernetGuids()
{
    QStringList result;
    for (const auto& ra : enumerateWin32Adapters()) {
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
} // namespace Network
