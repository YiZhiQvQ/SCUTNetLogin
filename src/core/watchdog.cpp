#include "core/watchdog.h"

#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QTextStream>
#include <QMutex>
#include <QMutexLocker>

#include <atomic>
#include <chrono>
#include <thread>
#include <vector>

#include <windows.h>
#include <tlhelp32.h>

namespace HangWatch {
namespace {

// 心跳超时阈值：主线程定时器是 2 秒，正常抖动远小于此值；取 15 秒既能容忍
// 一次系统级卡顿（如 netsh 占用），又能在真正卡死时尽快取证。
constexpr qint64 kStallMs = 15000;
// 卡住期间的追加间隔（避免每秒刷爆磁盘）
constexpr qint64 kReportIntervalMs = 60000;
// 心跳定时器间隔（与 SessionManager 的看门狗定时器保持一致）
constexpr int kTickMs = 2000;

std::atomic<bool>     g_running{false};
std::atomic<bool>     g_stopping{false};
std::atomic<qint64>   g_lastBeat{0};
std::atomic<qint64>   g_lastReport{0};

QMutex   g_phaseMutex;
QString  g_phase;

QString  g_logDir;

QString (*g_snapshotFn)() = nullptr;

std::thread g_thread;

qint64 nowMs()
{
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

QString phaseSnapshot()
{
    QMutexLocker lock(&g_phaseMutex);
    return g_phase;
}

// 进程内全部线程 id（凭 Toolhelp 快照；无需 NtQueryInformationThread）
QStringList processThreadIds()
{
    QStringList ids;
    const DWORD pid = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return ids;

    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(te.th32OwnerProcessID)
                && te.th32OwnerProcessID == pid) {
                ids << QString::number(te.th32ThreadID);
            }
            te.dwSize = sizeof(te);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return ids;
}

// 把现场写进独立的 .hang.log：独立文件 = 不会和主线程持有的日志句柄互相干扰。
void writeReport(qint64 stalledMs, bool recovered)
{
    if (g_logDir.isEmpty())
        return;

    QDir().mkpath(g_logDir);
    const QString date = QDateTime::currentDateTime().toString(QStringLiteral("yyyy-MM-dd"));
    QFile f(g_logDir + QStringLiteral("/SCUTNetLogin_") + date + QStringLiteral(".hang.log"));
    if (!f.open(QIODevice::Append | QIODevice::Text))
        return;
    QTextStream s(&f);
    const QString ts = QDateTime::currentDateTime().toString(QStringLiteral("yyyy-MM-dd hh:mm:ss.zzz"));

    if (recovered) {
        s << ts << QStringLiteral(" [RECOVERED] 主线程已恢复响应（累计卡住约 %1 秒）")
                 .arg(stalledMs / 1000) << Qt::endl;
        s.flush();
        return;
    }

    s << QStringLiteral("==================== ") << ts << QStringLiteral(" ====================") << Qt::endl;
    s << QStringLiteral("[HANG] 主线程超过 %1 秒没有任何心跳，界面此时必然无响应。")
             .arg(kStallMs / 1000) << Qt::endl;
    s << QStringLiteral("[HANG] 已卡住约 %1 秒；当前阶段: %2")
             .arg(stalledMs / 1000)
             .arg(phaseSnapshot().isEmpty() ? QStringLiteral("(未记录)") : phaseSnapshot()) << Qt::endl;

    // 线程清单：卡死时线程数一般不变，但"多出来的线程"常对应泄漏的 netsh/pcap 等待
    const QStringList tids = processThreadIds();
    s << QStringLiteral("[HANG] 进程线程数=%1  线程ID=[%2]")
             .arg(tids.size())
             .arg(tids.join(QLatin1Char(','))) << Qt::endl;

    // 网络现场：静态 IP / 校园 DNS / 默认路由残留都会在这里直接暴露
    if (g_snapshotFn) {
        const QString dump = g_snapshotFn();
        for (const QString& line : dump.split(QLatin1Char('\n'))) {
            if (!line.isEmpty())
                s << QStringLiteral("[HANG] ") << line << Qt::endl;
        }
    }

    s << QStringLiteral("[HANG] 提示：若「阶段」停在 pcap_open_live/pcap_next_ex，说明卡在 Npcap "
                        "内核调用（常见于合盖不睡、网卡被电源管理挂起）；可在设备管理器把网卡"
                        "「允许计算机关闭此设备以节约电源」取消勾选。") << Qt::endl;
    s << Qt::endl;
    s.flush();
}

void monitorLoop()
{
    while (!g_stopping.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        if (g_stopping.load())
            break;

        const qint64 beat = g_lastBeat.load();
        if (beat == 0)
            continue;   // 还没开始心跳（启动阶段）

        const qint64 stalled = nowMs() - beat;
        const qint64 last    = g_lastReport.load();

        if (stalled > kStallMs) {
            if (last == 0 || nowMs() - last > kReportIntervalMs) {
                g_lastReport.store(nowMs());
                writeReport(stalled, /*recovered=*/false);
            }
        } else if (last != 0) {
            g_lastReport.store(0);
            writeReport(stalled, /*recovered=*/true);
        }
    }
}

} // namespace

void start(const QString& logDir)
{
    if (g_running.exchange(true))
        return;
    g_logDir = logDir;
    g_stopping.store(false);
    g_lastBeat.store(nowMs());
    g_lastReport.store(0);
    g_thread = std::thread(monitorLoop);
}

void stop()
{
    if (!g_running.exchange(false))
        return;
    g_stopping.store(true);
    if (g_thread.joinable())
        g_thread.join();
}

void heartbeat()
{
    g_lastBeat.store(nowMs());
}

void setPhase(const QString& phase)
{
    QMutexLocker lock(&g_phaseMutex);
    g_phase = phase;
}

QString phase()
{
    return phaseSnapshot();
}

void setSnapshotProvider(QString (*fn)())
{
    g_snapshotFn = fn;
}

bool stalled()
{
    const qint64 beat = g_lastBeat.load();
    return beat != 0 && (nowMs() - beat) > kStallMs;
}

} // namespace HangWatch
