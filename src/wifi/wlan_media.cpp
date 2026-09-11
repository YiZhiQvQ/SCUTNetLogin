#define _WIN32_WINNT 0x0601
// wlanapi.h 版本宏必须在包含前定义（决定 WLAN_CONNECTION_ATTRIBUTES 等结构布局）
#define WLAN_CLIENT_VERSION 2

#include "wifi/wlan_media.h"

#include "core/constants.h"
#include "network/network.h"   // Network::systemExecutable（route 回退路径的全路径调用）
#include <winsock2.h>
#include <windows.h>
// 注意顺序：netioapi.h 的主体声明在 #ifdef _WS2IPDEF_ 内，而 winsock2.h 只带 ws2def.h、
// 不带 ws2ipdef.h（iphlpapi.h 的注释也要求调用方先包含 ws2ipdef.h）——缺它会导致
// MIB_IPFORWARD_TABLE2 / GetIpForwardTable2 全部"未声明的标识符"
#include <ws2ipdef.h>
#include <iphlpapi.h>   // 末尾包含 netioapi.h（GetIpForwardTable2 / FreeMibTable）
#include <ifdef.h>
#include <wlanapi.h>
#include <QByteArray>
#include <QHostAddress>
#include <QProcess>
#include <QRegularExpression>
#include <QString>
#include <vector>

namespace WlanMedia {

// GUID ↔ 字符串（不依赖 ole32 的手写转换；仅 wlanapi 内部使用）
static QString guidToString(const GUID& g)
{
    return QStringLiteral("%1-%2-%3-%4-%5")
        .arg(g.Data1, 8, 16, QLatin1Char('0'))
        .arg(g.Data2, 4, 16, QLatin1Char('0'))
        .arg(g.Data3, 4, 16, QLatin1Char('0'))
        .arg(QByteArray::fromRawData(reinterpret_cast<const char*>(&g.Data4[0]), 2).toHex().toUpper())
        .arg(QByteArray::fromRawData(reinterpret_cast<const char*>(&g.Data4[2]), 6).toHex().toUpper());
}

static QString guidToStringBracketed(const GUID& g)
{
    return QStringLiteral("{") + guidToString(g).toUpper() + QStringLiteral("}");
}

// BSSID: 6 字节 → "AA:BB:CC:DD:EE:FF"
static QString formatBssid(const BYTE* mac, ULONG len)
{
    QString s;
    for (ULONG i = 0; i < len && i < 6; ++i) {
        if (i) s += QLatin1Char(':');
        s += QStringLiteral("%1").arg(mac[i], 2, 16, QLatin1Char('0')).toUpper();
    }
    return s;
}

WlanInfo currentWifiConnection()
{
    WlanInfo info;
    DWORD negotiated = 0;
    HANDLE handle = INVALID_HANDLE_VALUE;
    if (WlanOpenHandle(WLAN_CLIENT_VERSION, nullptr, &negotiated, &handle) != ERROR_SUCCESS)
        return info;

    PWLAN_INTERFACE_INFO_LIST ifList = nullptr;
    if (WlanEnumInterfaces(handle, nullptr, &ifList) == ERROR_SUCCESS) {
        for (DWORD i = 0; i < ifList->dwNumberOfItems; ++i) {
            const WLAN_INTERFACE_INFO& ifInfo = ifList->InterfaceInfo[i];
            if (ifInfo.isState != wlan_interface_state_connected)
                continue;

            DWORD dataSize = 0;
            PWLAN_CONNECTION_ATTRIBUTES attrs = nullptr;
            if (WlanQueryInterface(handle, &ifInfo.InterfaceGuid,
                                   wlan_intf_opcode_current_connection, nullptr,
                                   &dataSize, reinterpret_cast<PVOID*>(&attrs), nullptr) == ERROR_SUCCESS
                && attrs && attrs->isState == wlan_interface_state_connected) {
                info.connected = true;
                info.ifGuid    = guidToStringBracketed(ifInfo.InterfaceGuid);
                // 注意：当前 SDK 的 WLAN_CONNECTION_ATTRIBUTES 不含 dot11Ssid，
                // SSID/BSSID 位于内层 wlanAssociationAttributes（WlanQueryInterface
                // 校验过 isState 为已连接，属性数据必然有效）
                const auto& assocAttrs = attrs->wlanAssociationAttributes;
                // ucSSID 是【原始字节】（UTF-8/ASCII 码点），绝不能按 UCS-2 成对
                // 解释（否则 "scut-student" 会被误读为乱码）
                if (assocAttrs.dot11Ssid.uSSIDLength > 0) {
                    info.ssid = QString::fromUtf8(
                        reinterpret_cast<const char*>(assocAttrs.dot11Ssid.ucSSID),
                        assocAttrs.dot11Ssid.uSSIDLength);
                }
                // DOT11_MAC_ADDRESS = BYTE[6]（SDK 字段名 dot11Bssid）
                info.bssid   = formatBssid(assocAttrs.dot11Bssid, sizeof(assocAttrs.dot11Bssid));
            }
            if (attrs)
                WlanFreeMemory(attrs);

            // 只报告首个已连接的 802.11 接口
            if (info.connected)
                break;
        }
        WlanFreeMemory(ifList);
    }
    WlanCloseHandle(handle, nullptr);
    return info;
}

QHostAddress wifiDefaultGateway()
{
    // 实测（该 Windows 11 环境）：802.11 接口在 GetAdaptersAddresses 中【从不】
    // 返回 FirstGatewayAddress（网关只存在于路由表），因此必须查路由表。
    // 1) 先取本机 Wi-Fi 接口的首个 IPv4 及其 LUID（GetAdaptersAddresses unicast）
    QHostAddress wifiIp;
    IF_LUID wifiLuid{};
    bool haveLuid = false;
    {
        ULONG bufLen = 0;
        GetAdaptersAddresses(AF_INET, 0, nullptr, nullptr, &bufLen);
        std::vector<BYTE> buf(bufLen);
        PIP_ADAPTER_ADDRESSES adapters = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data());
        if (GetAdaptersAddresses(AF_INET, 0, nullptr, adapters, &bufLen) == NO_ERROR) {
            for (PIP_ADAPTER_ADDRESSES a = adapters; a; a = a->Next) {
                if (a->IfType != IF_TYPE_IEEE80211 || a->OperStatus != IfOperStatusUp)
                    continue;
                for (PIP_ADAPTER_UNICAST_ADDRESS u = a->FirstUnicastAddress; u; u = u->Next) {
                    if (u->Address.lpSockaddr && u->Address.lpSockaddr->sa_family == AF_INET) {
                        const auto* sin = reinterpret_cast<const sockaddr_in*>(u->Address.lpSockaddr);
                        wifiIp = QHostAddress(ntohl(sin->sin_addr.S_un.S_addr));
                        break;
                    }
                }
                if (!wifiIp.isNull()) {
                    wifiLuid  = a->Luid;
                    haveLuid  = true;
                    break;
                }
            }
        }
    }
    if (wifiIp.isNull())
        return QHostAddress();

    // 2) 首选 IP Helper 路由表 API：零子进程、零文本解析。
    //    查"目的前缀长度 0（默认路由）+ 出接口 == 本机 Wi-Fi LUID"的表项，取其下一跳。
    //    同一接口可能存在多条默认路由（网络切换后残留），此时取【度量最小】的那条——
    //    与系统实际选路一致；取表内第一条会拿到可能已失效的旧网关。
    if (haveLuid) {
        PMIB_IPFORWARD_TABLE2 table = nullptr;
        if (GetIpForwardTable2(AF_INET, &table) == NO_ERROR && table) {
            QHostAddress gw;
            ULONG bestMetric = 0;
            for (ULONG i = 0; i < table->NumEntries; ++i) {
                const MIB_IPFORWARD_ROW2& row = table->Table[i];
                if (row.DestinationPrefix.PrefixLength != 0)          continue;   // 仅默认路由
                if (row.DestinationPrefix.Prefix.si_family != AF_INET) continue;
                if (memcmp(&row.InterfaceLuid, &wifiLuid, sizeof(NET_LUID)) != 0) continue;
                if (row.NextHop.si_family != AF_INET)                 continue;
                const auto* sin = reinterpret_cast<const sockaddr_in*>(&row.NextHop);
                if (sin->sin_addr.S_un.S_addr == 0)                   continue;
                if (!gw.isNull() && row.Metric >= bestMetric)          continue;   // 已有更优
                gw = QHostAddress(ntohl(sin->sin_addr.S_un.S_addr));
                bestMetric = row.Metric;
            }
            FreeMibTable(table);
            if (!gw.isNull())
                return gw;
        }
    }

    // 3) 回退：route print -4 文本解析（默认路由行首列为 0.0.0.0，按接口 IP 匹配）。
    //    route print 无需管理员权限、输出稳定，作为 IP Helper 不可用时的兜底路径。
    static const QRegularExpression re(QStringLiteral(
        R"(^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(?:on-link|(\S+))\s+(\S+)\s+(\d+)\s*$)"),
        QRegularExpression::CaseInsensitiveOption);
    QProcess proc;
    proc.setCreateProcessArgumentsModifier([](QProcess::CreateProcessArguments* cpa) {
        cpa->flags |= CREATE_NO_WINDOW;
    });
    proc.start(Network::systemExecutable(QStringLiteral("route.exe")),
               { QStringLiteral("print"), QStringLiteral("-4") });
    if (!proc.waitForFinished(NETSH_TIMEOUT))
        return QHostAddress();

    const QString out = QString::fromLocal8Bit(proc.readAllStandardOutput());
    for (const QString& line : out.split(QLatin1Char('\n'))) {
        const QRegularExpressionMatch m = re.match(line.trimmed());
        if (!m.hasMatch())
            continue;
        // 匹配由接口 IP 标识的默认路由行
        const QString ifIp = m.captured(2);
        if (ifIp.compare(wifiIp.toString(), Qt::CaseInsensitive) != 0)
            continue;
        QString gw = m.captured(1);
        if (gw.isEmpty() || gw.compare(QStringLiteral("on-link"), Qt::CaseInsensitive) == 0)
            return QHostAddress();
        const QHostAddress addr(gw);
        if (addr.protocol() == QAbstractSocket::IPv4Protocol)
            return addr;
    }
    return QHostAddress();
}

bool disconnectWifi()
{
    // 物理断开：仅首个已连接接口（逻辑上同一时刻只关注一个 Wi-Fi）。
    // 与门户解绑（mac/unbind）是两件事——解绑注销会话，此函数切断关联。
    HANDLE handle = INVALID_HANDLE_VALUE;
    DWORD negotiated = 0;
    if (WlanOpenHandle(WLAN_CLIENT_VERSION, nullptr, &negotiated, &handle) != ERROR_SUCCESS)
        return false;

    bool ok = false;
    PWLAN_INTERFACE_INFO_LIST ifList = nullptr;
    if (WlanEnumInterfaces(handle, nullptr, &ifList) == ERROR_SUCCESS) {
        for (DWORD i = 0; i < ifList->dwNumberOfItems; ++i) {
            const WLAN_INTERFACE_INFO& ifInfo = ifList->InterfaceInfo[i];
            if (ifInfo.isState != wlan_interface_state_connected)
                continue;
            ok = WlanDisconnect(handle, &ifInfo.InterfaceGuid, nullptr) == ERROR_SUCCESS;
            break;
        }
        WlanFreeMemory(ifList);
    }
    WlanCloseHandle(handle, nullptr);
    return ok;
}

} // namespace WlanMedia
