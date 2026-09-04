#ifndef NETWORK_H
#define NETWORK_H

#include <QString>
#include <QStringList>
#include <QList>
#include <QHostAddress>
#include <QNetworkInterface>
#include <cstdint>

namespace Network {

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

// 静态 IP / DHCP 配置（返回 true 表示全部成功）
bool setStaticIp(const QString& winName, const QString& ip, const QString& mask,
                 const QString& gw, const QString& dns1, const QString& dns2,
                 QString* errorMsg = nullptr);
bool setDhcp(const QString& winName, QString* errorMsg = nullptr);

} // namespace Network

#endif // NETWORK_H
