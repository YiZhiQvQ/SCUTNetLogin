#ifndef LOG_MANAGER_H
#define LOG_MANAGER_H

#include <QObject>
#include <QString>
#include <QFile>
#include <QTextStream>
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
// 线程：onLogMessage 一律在主线程执行（连接方与接收方同线程），m_logFile 无需加锁。
// ============================================================================

class LogManager : public QObject {
    Q_OBJECT

public:
    explicit LogManager(QObject* parent = nullptr);
    ~LogManager() override;

    // 格式化日志为 UI 显示的 HTML 片段（纯静态，无副作用）
    static QString formatHtml(const QString& message, int level);

    // 安装 Qt 消息处理器，把 qDebug/qWarning/qCritical 统一转发到 sink 的当日日志文件。
    // 为什么需要：本程序是 GUI 子系统程序、没有控制台，Qt 默认只把消息送到
    // OutputDebugString（Release 下无人可见）；而代码里有多处把 qWarning 当诊断通道
    // （网卡枚举失败、netsh 失败详情、autostart 变更等），不接管道就等于没有。
    // 跨线程安全：处理器只做一次队列投递（QMetaObject::invokeMethod），由 sink 所在
    // 线程执行实际写入。sink 销毁时置空（原子），避免投递到已析构对象。
    static void installQtMessageHandler(LogManager* sink);

public slots:
    // 接收日志消息并持久化到文件
    void onLogMessage(const QString& message, int level);

private:
    // 确保当日日志文件已打开（跨日自动轮转：关闭旧文件、打开新文件）
    void ensureFileForDate();
    // 把缓冲的日志刷到磁盘（Warning/Error 立即调用，Info 由定时器触发）
    void flushStream();

    static QString timestamp();          // "hh:mm:ss" 格式
    static QString fileTimestamp();      // "yyyy-MM-dd hh:mm:ss.zzz" 格式
    static QString logDir();             // exe同目录下的 log/
    static const char* levelTag(int level);

    QFile       m_logFile;               // 当日日志文件（持久句柄）
    QTextStream m_stream;                // 常驻流（随文件开关重建，避免每条日志新建）
    QString     m_currentLogDate;        // 已处理过的日期 "yyyy-MM-dd"（含打开失败）
    bool        m_dirty = false;         // 有未落盘内容
    QTimer*     m_flushTimer = nullptr;  // Info 攒批落盘（单发，惰性创建）
};

#endif // LOG_MANAGER_H
