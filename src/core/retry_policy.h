#ifndef RETRY_POLICY_H
#define RETRY_POLICY_H

#include <QDateTime>

// ============================================================================
// RetryPolicy — 重连/重试策略的纯逻辑（无 Qt 事件循环、无 I/O，可单测）
//
// 背景：这些判断原先内联在 SessionManager（931 行的编排类）与 UdpProcess 的
// 状态机里，既无法单测，也容易被多处拷贝后各自漂移。抽成纯函数后：
//   · 时间相关的边界（夜间 0:00-6:01、跨午夜）可穷举验证；
//   · 有线连续失败回退无线的判据只有一处定义；
//   · DrCOM 握手超时的"重发/放弃"阈值只有一处定义。
// 调用方只负责取现场输入（当前时间/失败计数/链路与 SSID 状态）与执行动作。
// ============================================================================

namespace RetryPolicy {

// 夜间窗口（校园网 0:00-6:01 禁止上网）的结束时刻。
// 分钟取 1 而非 0：实测 6:00:00 整点重连仍会被服务端按夜间窗口拒绝
// （"当前时段禁止使用"），等一分钟再试才能一次成功。
constexpr int kNightEndHour   = 6;
constexpr int kNightEndMinute = 1;

// 是否处于夜间窗口（该时段登录会被服务器拒绝，应等待到 6:01 再试）
bool isNightWindow(const QDateTime& now);

// 下一次重试的延迟（ms）：
//   白天 → baseIntervalMs（固定间隔）
//   夜间 → 到"当日 6:01"的毫秒数（避免通宵每 5 分钟重试一次刷屏）
// now 已过 6:01 时退化为 baseIntervalMs。
int nextRetryDelayMs(const QDateTime& now, int baseIntervalMs);

// 有线连续认证失败后是否回退无线（auto 模式）：
//   仅当 处于 auto 模式 + 有线失败次数达到阈值 + 当前 Wi-Fi 已连且命中白名单
// 时回退。切有线时通常已物理断开 Wi-Fi，此时不回退（由调用方提示用户）。
constexpr int kWiredFallbackThreshold = 2;
struct WifiFallbackInput {
    bool autoMode       = false;   // 仅 auto 模式允许自动回退
    int  wiredFailStreak = 0;      // 有线连续失败次数
    bool wifiConnected  = false;   // 当前是否已关联 Wi-Fi
    bool ssidMatched    = false;   // 该 SSID 是否命中白名单
};
bool shouldFallbackToWifi(const WifiFallbackInput& in);

// DrCOM UDP 握手阶段的超时处置：
//   重试次数未用尽 → 重发 MiscAlive（服务器不响应时唯一有意义的动作）
//   已用尽         → 放弃（不再发包，因而看门狗不会被重新武装，日志只出现一次）
enum class UdpTimeoutAction { ResendMiscAlive, GiveUp };
UdpTimeoutAction udpHandshakeOnTimeout(int retryCount, int maxRetries);

} // namespace RetryPolicy

#endif // RETRY_POLICY_H
