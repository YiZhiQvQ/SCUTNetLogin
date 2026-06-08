#define _WIN32_WINNT 0x0601

#include "network.h"
#include "constants.h"
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <QProcess>
#include <QRegularExpression>
#include <QNetworkInterface>
#include <vector>
#include <QDebug>
#include <pcap.h>

namespace Network {

// ============================================================================
// findInterface — 将 pcap 设备名 / 描述映射到 Windows QNetworkInterface
// ============================================================================

QNetworkInterface findInterface(const QString& pcapName,
                                const QString& pcapDescription)
{
    QRegularExpression re(R"(\\Device\\NPF_\{([A-Fa-f0-9\-]+)\})");
    auto match = re.match(pcapName);

    if (match.hasMatch()) {
        QString guid = "{" + match.captured(1) + "}";
        for (const QNetworkInterface& iface : QNetworkInterface::allInterfaces()) {
            if (iface.name().compare(guid, Qt::CaseInsensitive) == 0)
                return iface;
        }
    }

    if (!pcapDescription.isEmpty()) {
        for (const QNetworkInterface& iface : QNetworkInterface::allInterfaces()) {
            if (iface.humanReadableName().compare(pcapDescription, Qt::CaseInsensitive) == 0)
                return iface;
        }

        ULONG bufLen = 0;
        GetAdaptersAddresses(AF_INET, 0, nullptr, nullptr, &bufLen);
        std::vector<BYTE> buf(bufLen);
        PIP_ADAPTER_ADDRESSES adapters =
            reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data());
        if (GetAdaptersAddresses(AF_INET, 0, nullptr, adapters, &bufLen) == NO_ERROR) {
            for (PIP_ADAPTER_ADDRESSES a = adapters; a; a = a->Next) {
                QString desc = QString::fromWCharArray(a->Description);
                if (desc.compare(pcapDescription, Qt::CaseInsensitive) == 0) {
                    QString guid = QString::fromLatin1(a->AdapterName);
                    QNetworkInterface iface = QNetworkInterface::interfaceFromName(guid);
                    if (iface.isValid())
                        return iface;
                }
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
    for (const QNetworkInterface& iface : QNetworkInterface::allInterfaces()) {
        QString hw = normalizeMac(iface.hardwareAddress());
        if (hw == normalizedMac)
            return iface.name();
    }

    ULONG bufLen = 0;
    GetAdaptersAddresses(AF_INET, 0, nullptr, nullptr, &bufLen);
    std::vector<BYTE> buf(bufLen);
    PIP_ADAPTER_ADDRESSES adapters =
        reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data());
    if (GetAdaptersAddresses(AF_INET, 0, nullptr, adapters, &bufLen) == NO_ERROR) {
        for (PIP_ADAPTER_ADDRESSES a = adapters; a; a = a->Next) {
            if (a->PhysicalAddressLength != 6)
                continue;
            QString hw;
            for (ULONG i = 0; i < a->PhysicalAddressLength; ++i)
                hw += QString("%1").arg(a->PhysicalAddress[i], 2, 16, QLatin1Char('0'));
            if (hw.toUpper() == normalizedMac) {
                QString guid = QString::fromLatin1(a->AdapterName);
                QNetworkInterface iface = QNetworkInterface::interfaceFromName(guid);
                return iface.isValid() ? iface.name() : guid;
            }
        }
    }

    return QString();
}

QString adapterNameByMac(const QString& mac)
{
    if (mac.isEmpty())
        return QString();

    QString normalized = normalizeMac(mac);
    if (normalized.isEmpty())
        return QString();

    return findAdapterGuidByMac(normalized);
}

// ============================================================================
// listInterfaces — 枚举可用 Npcap 网卡
// ============================================================================

QList<InterfaceEntry> listInterfaces()
{
    QList<InterfaceEntry> result;
    QList<InterfaceEntry> wireless;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) != -1) {
        static const QStringList wifiKeys = {"Wireless", "Wi-Fi", "WiFi", "802.11", "WLAN", "无线"};
        for (pcap_if_t* dev = alldevs; dev != nullptr; dev = dev->next) {
            if (dev->flags & PCAP_IF_LOOPBACK)
                continue;
            QString desc = dev->description ? QString::fromLocal8Bit(dev->description) : QString();
            QString name = QString::fromUtf8(dev->name);
            if (desc.contains("Loopback", Qt::CaseInsensitive)
                || name.contains("Loopback", Qt::CaseInsensitive))
                continue;

            bool isWireless = false;
            for (const QString& key : wifiKeys) {
                if (desc.contains(key, Qt::CaseInsensitive)
                    || name.contains(key, Qt::CaseInsensitive)) {
                    isWireless = true;
                    break;
                }
            }

            QString displayName = desc.isEmpty() ? name : desc;
            if (isWireless)
                wireless.append({displayName, name, true});
            else
                result.append({displayName, name, false});
        }
        pcap_freealldevs(alldevs);
    }

    // Wi-Fi 网卡排到列表末尾，加前缀区分
    for (const auto& w : wireless)
        result.append({"[Wi-Fi] " + w.displayName, w.pcapName, true});

    return result;
}

// ============================================================================
// 通用工具函数
// ============================================================================

QString normalizeMac(const QString& mac)
{
    QString hex = mac;
    hex.remove(':');
    hex.remove('-');
    if (hex.size() != 12)
        return QString();
    return hex.toUpper();
}

void ipv4ToBytes(const QHostAddress& addr, uint8_t* out)
{
    quint32 ipv4 = addr.toIPv4Address();
    out[0] = (ipv4 >> 24) & 0xFF;
    out[1] = (ipv4 >> 16) & 0xFF;
    out[2] = (ipv4 >> 8) & 0xFF;
    out[3] = ipv4 & 0xFF;
}

bool isMacZero(const uint8_t* mac)
{
    for (int i = 0; i < 6; ++i)
        if (mac[i]) return false;
    return true;
}

bool isIpZero(const uint8_t* ip)
{
    for (int i = 0; i < 4; ++i)
        if (ip[i]) return false;
    return true;
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

} // namespace Network
