#include "log/log_manager.h"
#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QTextStream>
#include <QTimer>
#include <QDebug>
#include <QMetaObject>
#include <atomic>

namespace {
// Info 日志的攒批间隔：兼顾"崩溃时少丢日志"与"不逐条同步落盘"
constexpr int kFlushIntervalMs = 500;
}

// ============================================================================
// 构造
// ============================================================================

LogManager::LogManager(QObject* parent)
    : QObject(parent)
{
}

// ============================================================================
// 文件持久化（槽）
// ============================================================================

namespace {
// Qt 消息处理器的目标（原子：处理器可能来自任意线程，安装/清空在主线程）
std::atomic<LogManager*> g_qtMessageSink{nullptr};
}

LogManager::~LogManager()
{
    // 先摘掉 Qt 消息转发，避免处理器把消息投递给正在析构的对象
    LogManager* expected = this;
    g_qtMessageSink.compare_exchange_strong(expected, nullptr);
    flushStream();
    if (m_logFile.isOpen())
        m_logFile.close();
}

void LogManager::installQtMessageHandler(LogManager* sink)
{
    g_qtMessageSink.store(sink);
    qInstallMessageHandler([](QtMsgType type, const QMessageLogContext&, const QString& msg) {
        LogManager* target = g_qtMessageSink.load();
        if (!target)
            return;
        // 只区分"需要用户注意"与"仅记录"两档，与本项目 LogLevel 对齐
        const int level = (type == QtWarningMsg || type == QtCriticalMsg || type == QtFatalMsg)
                              ? static_cast<int>(LogLevel::Warning)
                              : static_cast<int>(LogLevel::Info);
        // 队列投递：处理器可能在任意线程（含系统线程），只能投递不能直接写文件
        QMetaObject::invokeMethod(target, "onLogMessage", Qt::QueuedConnection,
                                  Q_ARG(QString, QStringLiteral("[Qt] ") + msg),
                                  Q_ARG(int, level));
    });
}

void LogManager::onLogMessage(const QString& message, int level)
{
    ensureFileForDate();
    if (!m_logFile.isOpen())
        return;   // 打开失败静默丢弃，不影响主流程

    m_stream << fileTimestamp()
             << " [" << levelTag(level) << "] "
             << message << Qt::endl;
    m_dirty = true;

    // Warning/Error 立即落盘：这类消息之后往往紧接着崩溃或退出，不能留在缓冲区；
    // Info 攒批落盘——调试模式的帧级日志逐条 flush 会造成大量小同步写（GUI 线程）。
    if (level >= static_cast<int>(LogLevel::Warning)) {
        flushStream();
        return;
    }
    if (!m_flushTimer) {
        m_flushTimer = new QTimer(this);
        m_flushTimer->setSingleShot(true);
        m_flushTimer->setInterval(kFlushIntervalMs);
        connect(m_flushTimer, &QTimer::timeout, this, &LogManager::flushStream);
    }
    if (!m_flushTimer->isActive())
        m_flushTimer->start();
}

void LogManager::flushStream()
{
    if (!m_dirty || !m_logFile.isOpen())
        return;
    m_stream.flush();
    m_dirty = false;
}

void LogManager::ensureFileForDate()
{
    const QString date = QDateTime::currentDateTime().toString(QStringLiteral("yyyy-MM-dd"));
    if (m_currentLogDate == date)
        return;   // 当天已处理过（成功或失败都不再重复尝试）

    // 跨日轮转：先把旧文件刷盘关闭，再打开当日文件
    if (m_logFile.isOpen()) {
        flushStream();
        m_logFile.close();
        m_stream.setDevice(nullptr);
    }
    m_currentLogDate = date;

    QDir().mkpath(logDir());
    m_logFile.setFileName(logDir() + QStringLiteral("/SCUTNetLogin_") + date + QStringLiteral(".log"));
    if (!m_logFile.open(QIODevice::Append | QIODevice::Text)) {
        // 打开失败静默跳过日志（不影响主流程），记录一次警告便于排查。
        // 注意：m_currentLogDate 已置为当日，故不会每条日志都重试并重复告警。
        qWarning().noquote() << "无法打开日志文件:" << m_logFile.fileName()
                             << m_logFile.errorString();
        return;
    }
    m_stream.setDevice(&m_logFile);
}

// ============================================================================
// HTML 格式化（供 UI 层使用）
// ============================================================================

QString LogManager::formatHtml(const QString& message, int level)
{
    const char* color = "#9ca3af";  // info gray
    switch (static_cast<LogLevel>(level)) {
    case LogLevel::Warning: color = "#f59e0b"; break;
    case LogLevel::Error:   color = "#ef4444"; break;
    default: break;
    }

    return QStringLiteral("<span style='color:%1;'>%2 %3</span>")
        .arg(QLatin1String(color),
             timestamp(),
             message.toHtmlEscaped());
}

// ============================================================================
// 内部工具
// ============================================================================

QString LogManager::timestamp()
{
    return QDateTime::currentDateTime().toString(QStringLiteral("hh:mm:ss"));
}

QString LogManager::fileTimestamp()
{
    return QDateTime::currentDateTime().toString(QStringLiteral("yyyy-MM-dd hh:mm:ss.zzz"));
}

QString LogManager::logDir()
{
    return QCoreApplication::applicationDirPath() + QStringLiteral("/log");
}

const char* LogManager::levelTag(int level)
{
    switch (static_cast<LogLevel>(level)) {
    case LogLevel::Warning: return "WARN";
    case LogLevel::Error:   return "ERROR";
    default:                return "INFO";
    }
}
