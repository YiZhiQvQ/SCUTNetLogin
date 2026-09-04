#ifndef NOTIFICATION_PARSER_H
#define NOTIFICATION_PARSER_H

#include <QString>

// ============================================================================
// 802.1X Notification 服务器通知解析 — 纯函数，无 EapProcess / pcap 依赖
//
// 从 EapProcess::parseNotification 提取的数据驱动查表逻辑，独立成纯函数以便
// 单元测试覆盖（README 的"常见错误"表即为现成用例）：
//   1. "prefix + code" 格式（userid error / Authentication Fail ErrCode=）
//   2. 无 code 的简单前缀错误
//   3. 无法识别时 description 为空，调用方仅记录原始通知
// ============================================================================

namespace NotificationParser {

struct Result {
    QString description;    // 用户可读的中文描述（空 = 未识别）
    bool    sleepRequired = false;  // 夜间禁网等，需休眠等待到 6:00 再重试
    bool    permanent     = false;  // 永久性错误（凭证/账户状态），自动重试无意义
};

// 解析服务器 Notification payload 文本
Result describe(const QString& msg);

} // namespace NotificationParser

#endif // NOTIFICATION_PARSER_H
