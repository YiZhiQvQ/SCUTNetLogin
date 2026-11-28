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

// 把"任意形式的网卡标识"（GUID / 友好名 / ifIndex 十进制 / pcap 设备名）解析成
// **netsh 真正接受的**目标名。返回空表示无法解析（调用方必须放弃，绝不能拿空串
// 调用 netsh—— 实测 `netsh interface ipv4 set address name= dhcp` 不报错也不返回，
// 会一直挂到超时；而带 GUID 的 name={...} 直接报"文件名、目录名或卷标语法不正确"）。
//
// 实测（Windows 11 / netsh ipv4）：name={GUID} → exit 1 失败；name=以太网 → 成功；
// name=7（ifIndex）→ 成功。因此返回值优先"友好名"，失败回退 ifIndex 十进制串。
QString netshAdapterName(const QString& anyForm);

// 该标识是否指向环回 / WAN Miniport 等"绝不该被写静态 IP 或 DNS"的接口。
// 用于在调用 netsh 前拦截——一旦误写，网关/DNS 会落到 Loopback 上并在路由表里
// 留下 0.0.0.0/0 的持久路由，导致离开校园网（如连手机热点）后仍无法上网。
bool isUselessNetshTarget(const QString& anyForm);

// 清理"校园静态 IP 残留"（自愈）。
//
// 背景（实测故障）：程序在校园网里配过静态 IP + 校园 DNS 后，若恢复 DHCP 的 netsh 调用
// 失败（历史缺陷：把 {GUID} 当网卡名传给 netsh），这些配置就永久留在机器上：
//   · 有线网卡保持 10.40.16.57 / 网关 10.40.16.254 / DNS 202.38.193.33；
//   · 若目标误判到 Loopback，网关/DNS 会挂到环回接口，并在路由表留下
//     "0.0.0.0/0 → 10.40.16.254 via 127.0.0.1 (metric 1)" 的持久默认路由。
// 结果：**离开校园网（连手机热点）后依然解析到校园 DNS、把流量送进已经不存在的网关**，
// 表现为"能连上热点但没法上网"，且重启也不消失（持久路由）。
//
// 本函数把"不该再保留校园配置的接口"恢复成 DHCP，并清掉环回接口上的网关：
//   keepAdapter —— 唯一可以保留校园配置的接口（通常是当前在用的有线网卡），可为空。
// campusGateway / campusDns —— 只有匹配这些值的接口才会被动（避免误改他人配置）。
// report —— 追加逐条动作说明（成功/失败都写，便于落盘）。
// 返回 true 表示没有任何残留（或已全部清理干净）。
bool purgeStaleCampusIpConfig(const QString& campusGateway, const QStringList& campusDns,
                              const QString& keepAdapter, QStringList* report);

// 诊断快照：逐条列出 IPv4 默认路由（含持久路由）与各接口 DNS，多行文本。
// 用于在每次连接/恢复 DHCP 前后落盘，定位"静态 IP / 校园 DNS / 默认路由残留"。
QString dumpIpConfigSnapshot();

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

// 核对网卡当前 IPv4 配置是否满足期望（expectStatic=true 校验静态 IP；
// false 校验已回到 DHCP 且不再挂着给定的网关/DNS）。
// 数据源是 Win32 结构化接口而非 netsh 文本，故与系统语言无关、也无文本滞后问题。
// 内部带退避重试（约 1.5 秒上限），供设置/恢复后确认落盘。
// 检查网卡是否开启了会与 Npcap 冲突的省电特性（Realtek 的 Power Saving Mode /
// Green Ethernet 等）。这些特性会在链路空闲时关断收发，与 Npcap 的内核过滤驱动
// 冲突时会让 pcap_activate 永久阻塞，进而导致进程无法被终止（连 TerminateProcess
// 都返回拒绝访问，只能重启系统）。
// 返回告警文本（空 = 未发现风险）。仅读取 registry，无副作用。
QString nicPowerSavingWarning(const QString& anyAdapterForm);

bool verifyIpv4ConfigPublic(const QString& anyAdapterForm, bool expectStatic,
                            const QString& ip, const QString& mask,
                            const QString& gw, const QString& dns1,
                            QString* detail = nullptr);

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
