#ifndef NETWORK_INTERNAL_H
#define NETWORK_INTERNAL_H

// ============================================================================
// Network 模块内部共享声明（不属于公开 API，勿在模块外包含）
//
// network.cpp 按职责拆分为 4 个 TU 后，适配器枚举结构体与几个纯工具函数需要跨 TU
// 共用。此头只声明"内部实现细节"；对外能力仍由 network.h 统一暴露。
// ============================================================================

#include <QString>
#include <QStringList>
#include <QNetworkInterface>
#include <vector>

#include <winsock2.h>
#include <windows.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <ifdef.h>

namespace Network {
namespace Internal {

// Windows 适配器快照（GetAdaptersAddresses 的裁剪结果）。
// 字段含义见 network.cpp 中的原始注释——这里只保留跨 TU 必需的部分说明。
struct RawWin32Adapter {
    QString guid;           // AdapterName，形如 "34A9BD27-..."（**不带**花括号）
    QString description;    // 驱动描述（如 "Realtek PCIe GbE Family Controller"）
    // 用户在"网络连接"里看到的名称（如"以太网"），**这才是 netsh 接受的 name=**
    QString friendlyName;
    DWORD   ifIndex = 0;    // IPv4 接口索引（netsh 也接受十进制索引）
    IF_LUID luid{};         // GUID / LUID名 / ifIndex 之间的换算中转
    QString luidAlias;      // ConvertInterfaceLuidToAlias 的结果（等于友好名）
    // ConvertInterfaceLuidToName 的结果，形如 "ethernet_32774"。
    // **Qt 6 的 QNetworkInterface::name() 返回的正是这个**（不是 GUID，也不是友好名）。
    QString luidName;
    BYTE    mac[8]{};       // PhysicalAddress（最长 8，通常 6）
    ULONG   macLen = 0;
    DWORD   ifType = 0;
    // 当前生效的 IPv4 地址 / 网关 / DNS
    QStringList ipv4;
    QStringList gateways;
    QStringList dns;
    // IP_ADAPTER_ADDRESSES::OperStatus（IF_OPER_STATUS，与 NET_IF_OPER_STATUS 不可混用）
    IF_OPER_STATUS operStatus = IfOperStatusUnknown;
};

// 枚举全部 IPv4 适配器。**就地枚举、不使用缓存**——配置校验必须拿到最新状态。
// 链路检测热路径请用 network_link.cpp 里带 TTL 的缓存版本。
std::vector<RawWin32Adapter> enumerateWin32Adapters();

// 该描述是否属于虚拟/隧道适配器（有线链路检测时需排除，否则 VPN 会被误判为网线插入）
bool isVirtualAdapter(const QString& description);

// 由 LUID 得到 QNetworkInterface（Qt 的 interfaceFromName 不接受 {GUID}，故需中转）
QNetworkInterface interfaceFromLuid(const IF_LUID& luid);

} // namespace Internal
} // namespace Network

#endif // NETWORK_INTERNAL_H