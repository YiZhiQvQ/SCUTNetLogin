#include "log/log_manager.h"
#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QTextStream>
#include <QDebug>

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

LogManager::~LogManager()
{
    if (m_logFile.isOpen())
        m_logFile.close();
}

void LogManager::onLogMessage(const QString& message, int level)
{
    ensureFileForDate();
    if (!m_logFile.isOpen())
        return;   // 打开失败静默丢弃，不影响主流程

    QTextStream stream(&m_logFile);
    stream << fileTimestamp()
           << " [" << levelTag(level) << "] "
           << message << Qt::endl;
    stream.flush();   // 立即落盘，避免崩溃/退出时丢失
}

void LogManager::ensureFileForDate()
{
    const QString date = QDateTime::currentDateTime().toString(QStringLiteral("yyyy-MM-dd"));
    if (m_logFile.isOpen() && m_currentLogDate == date)
        return;

    // 跨日轮转：先关闭旧文件再打开当日文件
    if (m_logFile.isOpen())
        m_logFile.close();

    QDir().mkpath(logDir());
    m_logFile.setFileName(logDir() + QStringLiteral("/SCUTNetLogin_") + date + QStringLiteral(".log"));
    if (!m_logFile.open(QIODevice::Append | QIODevice::Text)) {
        // 打开失败静默跳过日志（不影响主流程），记录一次警告便于排查
        qWarning().noquote() << "无法打开日志文件:" << m_logFile.fileName()
                             << m_logFile.errorString();
    }
    m_currentLogDate = date;
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
