#include "eap/notification_parser.h"

namespace NotificationParser {

Result describe(const QString& msg)
{
    Result r;

    // --- Code-based 错误: "prefix + code" 格式 ---
    struct CodePattern {
        QStringView prefix;
        int         codeOffset;  // code 子串起始位置（从 prefix 尾部算起）
    };
    static const CodePattern kCodePatterns[] = {
        { QStringLiteral("userid error"),                 13 },
        { QStringLiteral("Authentication Fail ErrCode="), 28 },
    };

    // "code → 中文描述" 查找表（两个 pattern 共享）。
    // permanent = 凭证/账户状态类错误：自动重试无法自行恢复，交给上层停止重试；
    // sleepRequired 优先于 permanent（ErrCode=16 夜间禁网由睡眠重试机制处理）。
    struct CodeMessage { QStringView code; const char* msg; bool sleepReq = false; bool permanent = false; };
    static const CodeMessage kCodeMessages[] = {
        { QStringLiteral("0"),  "用户名或密码错误", false, true },
        { QStringLiteral("1"),  "账号不存在",       false, true },
        { QStringLiteral("2"),  "用户名或密码错误", false, true },
        { QStringLiteral("3"),  "用户名或密码错误", false, true },
        { QStringLiteral("4"),  "该账号可能已过期", false, true },
        { QStringLiteral("5"),  "该账号已被停用",   false, true },
        { QStringLiteral("9"),  "该账号可能已过期", false, true },
        { QStringLiteral("11"), "不允许进行RADIUS认证", false, true },
        { QStringLiteral("16"), "当前时段禁止上网，程序将休眠等待", true,  false },
        { QStringLiteral("30"), "该账号流量/时长已用尽", false, true },
        { QStringLiteral("63"), "该账号流量/时长已用尽", false, true },
    };

    for (const auto& pattern : kCodePatterns) {
        if (!msg.startsWith(pattern.prefix))
            continue;

        QStringView code = QStringView(msg).mid(pattern.codeOffset).trimmed();
        // 前导零归一化：服务器可能发送 "ErrCode=05" 等带前导零的码，与表内 "5" 等价
        while (code.size() > 1 && code.front() == QLatin1Char('0'))
            code = code.mid(1);
        for (const auto& cm : kCodeMessages) {
            if (code == cm.code) {
                r.description    = QString::fromUtf8(cm.msg);
                r.sleepRequired  = cm.sleepReq;
                r.permanent      = cm.permanent;
                return r;
            }
        }
        return r;  // prefix 匹配但 code 未知 — 不再尝试其他 pattern
    }

    // --- 简单前缀匹配错误（无 code） ---
    // 注意：AdminReset / Mac,IP / In use 均为"可能自行恢复"的暂时性错误，
    // 保留自动重试；flowover 为永久性错误，停止自动重试。
    static const struct { QStringView prefix; const char* msg; bool permanent; } kSimpleErrors[] = {
        { QStringLiteral("AdminReset"),           "管理员已重置连接",     false },
        { QStringLiteral("Mac, IP, NASip, PORT"), "当前IP/MAC地址不允许登录", false },
        { QStringLiteral("flowover"),             "流量已用尽",           true  },
        { QStringLiteral("In use"),               "该账号正在使用中（多设备在线）", false },
    };

    for (const auto& entry : kSimpleErrors) {
        if (msg.startsWith(entry.prefix)) {
            r.description = QString::fromUtf8(entry.msg);
            r.permanent   = entry.permanent;
            return r;
        }
    }

    return r;  // 未识别
}

} // namespace NotificationParser
