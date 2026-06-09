#ifndef CONFIG_MANAGER_H
#define CONFIG_MANAGER_H

#include <QString>
#include "protocol.h"

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
    bool    autoSetNetwork  = false;
    bool    autoStart       = false;
    bool    autoConnect     = false;
};

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

} // namespace ConfigManager

#endif // CONFIG_MANAGER_H
