#ifndef NETWORK_H
#define NETWORK_H

#include <QObject>
#include <QString>
#include <QStringList>
#include <QList>
#include <QHostAddress>
#include <QNetworkInterface>
#include <cstdint>

namespace Network {

// ============================================================================
// LinkMonitor — 接口变更通知（IP Helper 的 NotifyIpInterfaceChange）
//
// 用途：替代"每 2 秒枚举一次全部适配器"的链路轮询。网卡上/下线（含网线插入/拔出）
// 时由系统回调，链路变化可即时感知，空载时零开销。
//
// 线程：回调在系统线程触发，只做一次队列投递（QMetaObject::invokeMethod），
// 由本对象所在线程（调用方线程，通常是 GUI 线程）发出 linkChanged()。
//
// 生命周期：注册成功则长期有效（析构时 CancelMibChangeNotify2 会等待在途回调结束，
// 回调本身只投递事件、立即返回，不会造成死锁）。注册失败（老系统/受限环境）由调用方
// 自行退回轮询。
// ============================================================================
class LinkMonitor : public QObject {
    Q_OBJECT

public:
    explicit LinkMonitor(QObject* parent = nullptr);
    ~LinkMonitor() override;

    // 注册通知；false = 本环境不支持，调用方须退回轮询
    bool start();
    bool isActive() const { return m_handle != nullptr; }

signals:
    void linkChanged();   // 任一接口上/下线（可能重复触发，消费方需幂等）

private:
    Q_INVOKABLE void onSystemLinkChange();   // 系统线程投递到本对象线程后执行

    void* m_handle = nullptr;   // HNOTIFY_CHANGE（避免在头文件引入 netioapi.h）
};

// Windows 适配器信息 — GUID + 显示名称的聚合查询结果
struct AdapterInfo {
    QString guid;         // 适配器 GUID，如 "{XXXXXXXX-...}"
    QString displayName;  // 用户友好的显示名称
};

// 网卡列表条目
struct InterfaceEntry {
    QString displayName;  // 显示给用户的名称（Wi-Fi 网卡会加 "[Wi-Fi]" 前缀）
    QString pcapName;     // Npcap 设备名，如 \Device\NPF_{GUID}
    bool isWireless = false;
};

// 将 pcap 设备名映射到 Windows QNetworkInterface（一次查询，遍历 GUID + 描述 + WMI）
QNetworkInterface findInterface(const QString& pcapName, const QString& pcapDescription = QString());

// 将 pcap 设备名映射到 Windows 适配器信息（一次查询返回 guid + displayName）
AdapterInfo adapterInfo(const QString& pcapName, const QString& pcapDescription = QString());

// 通过 MAC 地址查找适配器名（用于 netsh 操作）
QString adapterNameByMac(const QString& mac);

// 枚举所有可用于认证的 Npcap 网卡（自动过滤 loopback / 虚拟机适配器）
QList<InterfaceEntry> listInterfaces();

// 注：MAC 标准化、IPv4 转字节、全零判断等纯函数已移至 core/byte_utils.h

// netsh 命令执行
bool runNetsh(const QStringList& args, QString* errorMsg = nullptr);

// 系统目录（System32）下的可执行文件全路径。以管理员权限运行时必须用它调用
// netsh/route/schtasks 等系统命令，否则会被 PATH 中的同名程序劫持。
// 取系统目录失败时原样返回 name（退回按名调用，不改变原有行为）。
QString systemExecutable(const QString& name);

// 静态 IP / DHCP 配置（返回 true 表示全部成功）
bool setStaticIp(const QString& winName, const QString& ip, const QString& mask,
                 const QString& gw, const QString& dns1, const QString& dns2,
                 QString* errorMsg = nullptr);
bool setDhcp(const QString& winName, QString* errorMsg = nullptr);

// ============================================================================
// 链路状态（auto 模式决策与无线 Portal 模块使用）
// ============================================================================

// 物理有线（非虚拟）且链路 Up 的适配器 GUID 列表
QStringList connectedEthernetGuids();

// 是否存在"物理有线且链路 Up"的网卡（auto 模式有线优先的判据）
// 自动排除 VMware/Hyper-V/TAP/蓝牙/USB NDIS 等虚拟适配器
bool ethernetLinkUp();

// 调试诊断：逐条枚举全部 Win32 适配器（GUID/描述/ifType/oper-status/MAC/是否被
// 过滤为虚拟/是否计入"物理有线链路 Up"），末尾给 ethernetLinkUp() 判定汇总。
// 返回多行文本，供调试输出定位"为什么这台机器一直判定有线"。
QString dumpAdapters();

// 注：wlanapi 相关封装（currentWifiConnection / wifiDefaultGateway）已移至
// wifi/wlan_media.h（仅无线模块使用；无线断开采用门户 mac/unbind 解绑，
// 不做物理断开，故不再需要 WlanDisconnect）

} // namespace Network

#endif // NETWORK_H
