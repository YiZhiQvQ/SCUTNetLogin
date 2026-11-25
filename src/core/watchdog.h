#ifndef WATCHDOG_H
#define WATCHDOG_H

#include <QString>

// ============================================================================
// HangWatch — 主线程活性监视 + 卡死现场取证
//
// 为什么需要：本程序的卡死发生在 **内核态**（pcap_open_live / pcap_next_ex 在网卡被
// 电源管理挂起或驱动异常时永久阻塞），此时 Qt 的定时器、信号、日志定时器全部停摆，
// 界面上什么都不写、日志里最后一行停留在"开始802.1X认证..."，事后完全无法定位。
// 实测：合盖不睡 + 挂着等夜间重试 → 早上点连接 → 进程卡死，结束任务也无效。
//
// 做法：一个**独立 std::thread**，不依赖 Qt 事件循环、也不依赖主线程任何对象，
// 每秒检查一次主线程心跳戳：
//   · 主线程每 2 秒 heartbeat() 一次（SessionManager 定时器驱动）；
//   · 超过阈值（默认 15 秒）没有推进 → 判定主线程卡住，立即把现场写入
//     log/SCUTNetLogin_YYYY-MM-DD.hang.log（独立文件，避免与主日志争用同一句柄）；
//   · 卡住期间每 60 秒追加一次，恢复后记一条"已恢复"。
//
// 现场内容：卡住时长、当前阶段（pcap/netsh/portal 等关键阻塞点，由各工作线程
// 通过 setPhase 更新）、进程全部线程 id、IPv4 默认路由与各网卡 IP/DNS 快照。
//
// 线程安全：全部函数可从任意线程调用；内部用 std::atomic + std::mutex。
// ============================================================================
namespace HangWatch {

// 启动监视线程（幂等）。logDir 为主日志所在目录（exe 同目录的 log/）。
void start(const QString& logDir);

// 停止并 join（进程退出时调用；未 start 过则为空操作）
void stop();

// 主线程心跳：每 TICK 调一次。只有主线程调用，用来证明"事件循环还在转"。
void heartbeat();

// 记录"当前阶段"（关键阻塞点）。各工作线程在自己的阻塞调用前后调用，
// 卡死时能直接看出卡在哪一步（例如 "pcap_open_live: \Device\NPF_{...}"）。
void setPhase(const QString& phase);

// 读取当前阶段（用于心跳日志/诊断输出）
QString phase();

// 注册"网络现场快照"提供者（由 SessionManager 注入 Network::dumpIpConfigSnapshot，
// 避免 watchdog 直接依赖 network 模块）。未注册时报告中该段留空。
void setSnapshotProvider(QString (*fn)());

// 判定当前是否处于"疑似卡死"状态（自上次心跳起超过阈值）
bool stalled();

} // namespace HangWatch

#endif // WATCHDOG_H
