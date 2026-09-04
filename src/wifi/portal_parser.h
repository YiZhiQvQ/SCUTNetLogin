#ifndef PORTAL_PARSER_H
#define PORTAL_PARSER_H

#include <QByteArray>
#include <QJsonObject>
#include <QString>
#include <QUrl>
#include <cstdint>

// ============================================================================
// 无线 Portal 协议纯逻辑 — Dr.COM WebLoginID 4.0 eportal（SCUT scut-student）
//
// 仅依赖 QtCore + Windows API（MultiByteToWideChar 解码 GBK 错误文案；无
// wlanapi/Npcap），可被单元测试直接编译。所有字段名与取值来自 2026-09-03
// 实机抓取（a79.htm 变量 / a41.js / a40.js / loadConfig / online_list 响应），
// 详见 docs/wifi_auth_logic.md。
// ============================================================================

namespace PortalParser {

// 门户页（a79.htm）内嵌 JS 全局变量 + 302 URL 派生的参数集
struct PortalVars {
    // 认证服务器
    QString v4serip;             // 认证服务器 IP（authlogin 目标，如 192.168.53.229）
    int     authLoginPort = 801; // HTTP 登录端口（authloginport；HTTPS 用 802）
    QString authLoginPath;       // 传统登录路径（eportal/?c=ACSetting&a=Login）
    QString authUserField = QStringLiteral("DDDDD");
    QString authPassField = QStringLiteral("upass");
    QString authSuccess;         // 成功标志页文件名（Dr.COMWebLoginID_3.htm）
    QString authFail;            // 失败标志页文件名（Dr.COMWebLoginID_2.htm）
    QString charset;             // 页面字符集（gb2312/gbk 等，仅错误文案展示用）
    // 客户端专属参数（页面生成，原样透传给登录接口；不自行推导）
    QString mip;                 // 用户 IP 的零填充数字串
    QString ipm;                 // 服务器 IP 的 hex
    QString ss1, ss2, ss3, ss4, ss5, ss6;
    QString v46ip;               // 用户 IPv4（v46ip）
    QString vlanid;
    QString gno;                 // Gno（0000）
    QString wlanacip;            // AC IP（302 Location 的 wlanacip 参数）
    qint64  timet = -1;          // 页面生成时间戳（unix，秒）

    // 解析失败的字段留空；调用方据此决定重试/放弃
    bool isValid() const { return !v4serip.isEmpty() && !v46ip.isEmpty(); }
};

// 从门户页原始字节（GBK 编码无碍——值域全为 ASCII）+ 302 终点 URL 解析变量集
PortalVars parse(const QByteArray& page, const QUrl& pageUrl);

// --- 纯计算（观测值锚定，单测校验）---
// 10.197.183.251 → "010197183251"（每段 3 位补零连接）
QString computeMip(const uint8_t ip[4]);
// 192.168.53.229 → "c0a835e5"（每段 hex 2 位）
QString computeIpm(const uint8_t ip[4]);
// 用户 IP → "0ac5b7fb"（同 ipm 算法）
QString computeSs3(const uint8_t ip[4]);

// 注：/drcom/login 风格登录参数（DDDDD/upass/0MKKey/R1..R6/para）不在生产使用——
// 登录走 eportal portal/login（sendLoginBody 手搭表单），该协议知识仅存档于
// docs/wifi_auth_logic.md §5。

// 从 JSONP 响应体（"drNNNN({...})" / "jsonpReturn({...})"）提取 JSON 对象
// 解析失败返回空对象
QJsonObject extractJsonp(const QByteArray& body);

// 登录响应判定：result==1||"ok" → Success；
// result==0 → Failure（retryable 依据 msga/msg 文案启发式）；
// 其它/解析失败 → Unknown(retryable=true)
enum class Verdict { Success, Failure, Unknown };
struct VerdictResult {
    Verdict  verdict  = Verdict::Unknown;
    bool     retryable = true;
    QString  message;   // 服务器错误文案（msga 按 GB18030→系统编码解码；解码失败回退原始字节）
};
VerdictResult classify(const QByteArray& jsonpBody);

// online_list 会话条目是否属于本机（多端共享网关/同网段时列表可能含他机会话）：
//   ① 服务器归属标记 is_owner_ip=1；② online_ip 命中本机 IP（点分十进制）；
//   ③ user_account 命中登录账号（后端存 "<账号>@wifi"，登录可无后缀）；
//   ④ online_mac 命中本机接口 MAC（localMacHex 全零=未取到，不参与比较）
bool isOwnSession(const QJsonObject& session, const QString& localIp,
                  const QString& username, const QString& localMacHex = QString());

// online_list 查询 URL（三处调用点统一构造，防服务器厂商参数漂移）：
//   <origin>:<port>/eportal/portal/online_list?user_account=&user_password=123&
//   wlan_user_mac=<大写6B hex>&wlan_user_ip=<整数>&curr_user_ip=<整数>&
//   jsVersion=4.1.3&callback=<drNNNN>&v=<随机>&lang=zh
// macHex 全零（"000000000000"）即协议约定的"空 MAC"值；callback/v 由调用方生成
QUrl buildOnlineListUrl(const QString& portalOrigin, int eportalPort,
                        quint32 ipInt, const QString& macHex,
                        const QString& jsVersion,
                        const QString& callback, int vRand);

} // namespace PortalParser

#endif // PORTAL_PARSER_H
