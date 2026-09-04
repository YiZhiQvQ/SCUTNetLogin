#ifndef LOG_MANAGER_H
#define LOG_MANAGER_H

#include <QObject>
#include <QString>
#include <QFile>
#include "core/log_level.h"

// ============================================================================
// LogManager — 日志文件持久化（与 UI 彻底解耦）
//
// 职责：
//   - 按日轮转写入 log/SCUTNetLogin_YYYY-MM-DD.log
//   - 保持当日文件句柄打开，避免每条日志重复 open/close
//   - 提供静态工具方法用于 HTML 格式化（供 UI 层复用）
//
// 使用方式：
//   - 将 LogManager 的 onLogMessage 槽连接到任意 logMessage 信号即可
//   - MainWindow 调用 LogManager::formatHtml() 获取 HTML 片段用于 UI 显示
//
// 线程：onLogMessage 经 QueuedConnection 一律在主线程执行，m_logFile 无需加锁。
// ============================================================================

class LogManager : public QObject {
    Q_OBJECT

public:
    explicit LogManager(QObject* parent = nullptr);
    ~LogManager() override;

    // 格式化日志为 UI 显示的 HTML 片段（纯静态，无副作用）
    static QString formatHtml(const QString& message, int level);

public slots:
    // 接收日志消息并持久化到文件
    void onLogMessage(const QString& message, int level);

private:
    // 确保当日日志文件已打开（跨日自动轮转：关闭旧文件、打开新文件）
    void ensureFileForDate();

    static QString timestamp();          // "hh:mm:ss" 格式
    static QString fileTimestamp();      // "yyyy-MM-dd hh:mm:ss.zzz" 格式
    static QString logDir();             // exe同目录下的 log/
    static const char* levelTag(int level);

    QFile   m_logFile;                   // 当日日志文件（持久句柄）
    QString m_currentLogDate;            // 已打开文件的日期 "yyyy-MM-dd"
};

#endif // LOG_MANAGER_H
