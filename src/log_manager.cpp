#include "log_manager.h"
#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QTextStream>

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

void LogManager::onLogMessage(const QString& message, int level)
{
    QDir().mkpath(logDir());

    const QString fileName = logDir() + QStringLiteral("/SCUTNetLogin_")
                             + QDateTime::currentDateTime().toString(QStringLiteral("yyyy-MM-dd"))
                             + QStringLiteral(".log");

    QFile logFile(fileName);
    if (logFile.open(QIODevice::Append | QIODevice::Text)) {
        QTextStream stream(&logFile);
        stream << fileTimestamp()
               << " [" << levelTag(level) << "] "
               << message << Qt::endl;
    }
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
