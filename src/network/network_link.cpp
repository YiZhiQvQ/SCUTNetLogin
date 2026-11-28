#define _WIN32_WINNT 0x0601

// ============================================================================
// network_link.cpp — 链路状态监视
//
// 从原 network.cpp 拆出。本 TU 负责：
//   · LinkMonitor：系统接口变更通知（NotifyIpInterfaceChange），替代 2 秒轮询
//   · 带 TTL 的适配器枚举缓存（链路检测热路径专用）
//   · ethernetLinkUp / connectedEthernetGuids：物理有线链路判定
//   · dumpAdapters：诊断用全量适配器转储
// ============================================================================

#include "network/network.h"
#include "network/network_internal.h"
#include "core/constants.h"
#include <winsock2.h>
#include <windows.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <ifdef.h>
#include <QElapsedTimer>
#include <QMetaObject>
#include <QDebug>
#include <vector>

namespace Network {

using Internal::RawWin32Adapter;

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
// 注：用户手动"刷新网卡"与调试诊断（dumpAdapters）走未缓存的 Internal::enumerateWin32Adapters()。
static const std::vector<RawWin32Adapter>& enumerateWin32AdaptersCached()
{
    struct Cache {
        std::vector<RawWin32Adapter> adapters;
        QElapsedTimer                stamp;
        bool                         valid = false;
    };
    static thread_local Cache cache;
    if (!cache.valid || cache.stamp.elapsed() > kAdapterCacheMs) {
        cache.adapters = Internal::enumerateWin32Adapters();
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
        if (Internal::isVirtualAdapter(ra.description))
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

    const auto adapters = Internal::enumerateWin32Adapters();
    int counted = 0;
    QStringList out;
    for (const auto& ra : adapters) {
        const bool eth  = isEth(ra.ifType);
        const bool virt = Internal::isVirtualAdapter(ra.description);
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