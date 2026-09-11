#ifndef WLAN_MEDIA_H
#define WLAN_MEDIA_H

#include <QHostAddress>
#include <QString>
#include <cstdint>

// ============================================================================
// 无线媒体层 — wlanapi / iphlpapi 封装（Wi-Fi 接口查询、默认网关）
//
// 2026-09-03 从 network/network.{h,cpp} 分离：这些函数只服务无线模块
// （WebAuthProcess / SessionManager 决策 / MainWindow 状态行），
// 放在通用 Network 里会让 wlanapi 泄漏进通用模块。
//
// 线程说明：均为阻塞调用（Wlan* / GetAdaptersAddresses / route print），
// 由调用方按场景选择线程（主线程决策 / 认证线程取网关）——保持一致即可。
// ============================================================================

namespace WlanMedia {

// 当前 802.11 连接的聚合信息（wlanapi WlanQueryInterface）
struct WlanInfo {
    QString ssid;           // 当前连接 SSID（断开/隐藏网络时为空）
    QString bssid;          // AP BSSID（"AA:BB:.." 形式，可能为空）
    QString ifGuid;         // 连接接口 GUID（"{...}"，供其它查询用）
    bool    connected = false;
};

// 正在连接的 Wi-Fi 接口（wlanapi 直查，快速；失败时回退 netsh 解析）
WlanInfo currentWifiConnection();

// 当前 Wi-Fi 接口的默认网关（未认证网关探测用；无则返回空 IPv4）
QHostAddress wifiDefaultGateway();

// 物理断开当前 Wi-Fi 连接（wlanapi WlanDisconnect）。
// 用途：链路切换（有线网线插入→转有线认证）时彻底脱离无线关联——切换后不再残留
// 任何 Wi-Fi 上行。全部应用内调用仅此一处（无关联接口时返回 false，非错误）。
bool disconnectWifi();

} // namespace WlanMedia

#endif // WLAN_MEDIA_H
