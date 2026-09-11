#include "core/retry_policy.h"

#include <QTime>

namespace RetryPolicy {

bool isNightWindow(const QDateTime& now)
{
    return now.time().hour() < kNightEndHour;
}

int nextRetryDelayMs(const QDateTime& now, int baseIntervalMs)
{
    if (!isNightWindow(now))
        return baseIntervalMs;

    // 夜间：等到当日 kNightEndHour:00。now 恰在边界之前（如 05:59:59.9）时结果可能
    // 很小（近 0），由调用方的"到点后重新判定"兜住；这里只保证非负。
    const qint64 ms = now.msecsTo(QDateTime(now.date(), QTime(kNightEndHour, 0)));
    return ms > 0 ? static_cast<int>(ms) : 0;
}

bool shouldFallbackToWifi(const WifiFallbackInput& in)
{
    return in.autoMode
        && in.wiredFailStreak >= kWiredFallbackThreshold
        && in.wifiConnected
        && in.ssidMatched;
}

UdpTimeoutAction udpHandshakeOnTimeout(int retryCount, int maxRetries)
{
    return (retryCount < maxRetries) ? UdpTimeoutAction::ResendMiscAlive
                                     : UdpTimeoutAction::GiveUp;
}

} // namespace RetryPolicy
