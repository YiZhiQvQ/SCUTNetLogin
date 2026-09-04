#ifndef LOG_LEVEL_H
#define LOG_LEVEL_H

// ============================================================================
// 日志级别 — 独立于协议定义，供各工作进程 / SessionManager / LogManager / UI 复用
// ============================================================================

enum class LogLevel {
    Info = 0,
    Warning = 1,
    Error = 2
};

#endif // LOG_LEVEL_H
