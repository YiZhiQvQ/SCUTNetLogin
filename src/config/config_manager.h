#ifndef CONFIG_MANAGER_H
#define CONFIG_MANAGER_H

#include <QString>
#include "core/protocol.h"

// 配置持久化数据的纯数据结构 — 从 UI 控件解耦
struct AppConfig {
    QString username;
    QString password;       // 明文，由调用方决定是否编码
    QString host;
    QString dns;
    QString backupDns;
    QString interfaceName;  // pcap 设备名
    QString manualMac;
    QString manualIp;
    QString manualMask      = "255.255.255.0";
    QString manualGateway;
    bool    savePassword    = false;
    bool    autoSetNetwork  = true;    // 默认开启：连接时配置静态 IP（首次使用需填 IP/DNS，已有配置不受影响）
    bool    autoStart       = true;    // 默认开启：开机自启动
    bool    autoConnect     = true;    // 默认开启：打开程序自动发起连接（静默启动恒自动连，不受此值影响）
    // 无线模块（Portal 认证）
    QString connectMode     = "auto";          // auto / wired / wireless
    QString wifiSsids       = "scut-student";  // SSID 白名单，逗号分隔；空 = 任意
    bool    logoutOnExit    = false;           // 退出程序时注销无线连接（可选，默认不登出）
};

// UI 数据比较（"保存配置"脏检测等）
inline bool operator==(const AppConfig& a, const AppConfig& b)
{
    return a.username      == b.username
        && a.password      == b.password
        && a.host          == b.host
        && a.dns           == b.dns
        && a.backupDns     == b.backupDns
        && a.interfaceName == b.interfaceName
        && a.manualMac     == b.manualMac
        && a.manualIp      == b.manualIp
        && a.manualMask    == b.manualMask
        && a.manualGateway == b.manualGateway
        && a.savePassword   == b.savePassword
        && a.autoSetNetwork == b.autoSetNetwork
        && a.autoStart      == b.autoStart
        && a.autoConnect    == b.autoConnect
        && a.connectMode    == b.connectMode
        && a.wifiSsids      == b.wifiSsids
        && a.logoutOnExit   == b.logoutOnExit;
}

inline bool operator!=(const AppConfig& a, const AppConfig& b) { return !(a == b); }

namespace ConfigManager {

// 配置文件默认路径（exe 同目录下的 config.ini）
QString defaultPath();

// 从 config.ini 读取配置，密码自动 Base64 解码
AppConfig load(const QString& configPath);

// 写入 config.ini，若 savePassword 为 true 则密码 Base64 编码
void save(const QString& configPath, const AppConfig& cfg);

// AppConfig → AuthConfig 转换（静态字段：username/password/host/dns/mac/ip）
AuthConfig toAuthConfig(const AppConfig& cfg);

// 填充 AuthConfig 的运行时字段（hostname、DNS server IP 解析、IP 回退）
// 调用时机：toAuthConfig 之后、传入 SessionManager 之前
void resolveAuthConfig(AuthConfig& config);

// 联网方式字符串 ↔ 枚举（未知/空串回落为 Auto；UI 与 SessionManager 共用）
ConnectMode connectModeFromString(const QString& s);
QString     connectModeToString(ConnectMode m);

} // namespace ConfigManager

#endif // CONFIG_MANAGER_H
