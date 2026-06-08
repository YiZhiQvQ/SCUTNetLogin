#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <cstdint>
#include <QString>

// 日志级别
enum class LogLevel {
    Info = 0,
    Warning = 1,
    Error = 2
};

#pragma pack(push, 1)

// ============================================================================
// 一、EAPOL / 802.1X 协议结构体 (IEEE 802.1X-2010)
// ============================================================================

// 以太网头部（14 字节）
struct EthHeader {
    uint8_t  dest_mac[6];
    uint8_t  src_mac[6];
    uint16_t eth_type;          // 0x888E = 802.1X EAPOL
};

// EAPOL 头部（4 字节）
struct EAPOLHeader {
    uint8_t  version;           // 固定 0x01
    uint8_t  packet_type;       // EAPOL-Start / EAPOL-Logoff / EAP-Packet
    uint16_t length;            // body 长度 (网络字节序)，Start/Logoff 为 0
};

// EAP 头部（4+1 字节，type 字段仅在 code == Request/Response 时存在）
struct EAPHeader {
    uint8_t  code;              // Request / Response / Success / Failure
    uint8_t  id;                // 请求-应答匹配标识
    uint16_t length;            // EAP 包总长度 (网络字节序)
    uint8_t  type;              // Identity / MD5-Challenge / Notification
};

// ============================================================================
// 二、DrCOM UDP 私有协议结构体 — 逆向自 SCUT 校园网
// ============================================================================

// --- MiscAlive: 初始探测包 (8 字节) ---
// 发送此包向服务器宣告客户端存在，服务器回复 MiscResponseAlive 进入下一步
struct DrcomMiscAlive {
    uint8_t  magic;             // 0x07 = DRCOM_UDP_MAGIC
    uint8_t  seq;               // 序列号
    uint16_t length;            // 0x0008 (小端)
    uint8_t  flag;              // 0x01
    uint8_t  reserved[3];       // {0x00, 0x00, 0x00}
};

// --- MiscInfo: 设备/主机信息包 (244 字节) ---
// 服务器收到后回复 MiscResponseInfo，内含 16 字节加密块
struct DrcomMiscInfo {
    uint8_t  magic;             // 0x07
    uint8_t  subtype;           // 0x01
    uint16_t length;            // 0xF4 = 244
    uint8_t  flag;              // 0x03
    uint8_t  username_len;      // 用户名实际字节数 (≤ 25)
    uint8_t  src_mac[6];        // 本机 MAC
    uint8_t  src_ip[4];         // 本机 IPv4
    uint8_t  unknown1[4];       // {0x02, 0x22, 0x00, 0x2a} 用途不明
    uint8_t  flux[4];           // 流量计数器 (由服务器下发)
    uint8_t  cks32[4];          // 32位校验和 (初始种子 {0xc7, 0x2f, 0x31, 0x01})
    uint8_t  cks_temp[4];       // 校验计算时临时写 126，计算后恢复 0
    char     host_info[44];     // username + hostname 拼接，剩余填 0
    uint8_t  dns1[4];           // 主 DNS (大端)
    uint8_t  dns2[4];           // 备用 DNS (大端)
    uint8_t  padding1[8];       // 全 0
    uint8_t  unknown2[4];       // {0x94, 0x00, 0x00, 0x00} 用途不明
    uint8_t  os_major[4];       // Windows 主版本号 (小端)
    uint8_t  os_minor[4];       // Windows 次版本号 (小端)
    uint8_t  os_build[4];       // Windows Build 号 (小端)
    uint8_t  os_unknown[4];     // {0x02, 0x00, 0x00, 0x00}
    uint8_t  version[64];       // DrCOM 客户端版本字符串 "DrCOM\0..."
    uint8_t  hash[64];          // 客户端哈希 (40 字节 SHA1 hex + 填充)
    uint8_t  tail_padding[4];   // 补齐至 244 字节
};

// --- MiscHeartbeat: 心跳握手包 (40 字节) ---
// hb_subtype == 1 时由客户端发送；hb_subtype == 3 时包含 IP 和 cks16 校验
struct DrcomMiscHeartbeat {
    uint8_t  magic;             // offset 0:  0x07
    uint8_t  counter;           // offset 1:  递增计数器
    uint16_t length;            // offset 2:  0x28 = 40
    uint8_t  flag;              // offset 4:  0x0b
    uint8_t  hb_subtype;        // offset 5:  0x01 或 0x03
    uint8_t  fixed[2];          // offset 6:  {0xdc, 0x02}
    uint8_t  rnd[2];            // offset 8:  随机数
    uint8_t  reserved1[6];      // offset 10: 全 0
    uint8_t  flux[4];           // offset 16: 流量计数器
    uint8_t  pre_cks16[4];      // offset 20: 全 0 (cks16 计算覆盖此区域)
    uint8_t  cks16[4];          // offset 24: cks16 计算结果 (仅 hb_subtype==3 写入)
    uint8_t  local_ip[4];       // offset 28: 本机 IPv4 (仅 hb_subtype==3)
    uint8_t  reserved2[8];      // offset 32: 全 0
};

// --- Alive: 在线保活包 (38 字节) ---
struct DrcomAlive {
    uint8_t  magic;             // 0xFF
    uint8_t  md5_data[16];      // EAP-MD5 认证结果的前 16 字节
    uint8_t  padding[3];        // {0x00, 0x00, 0x00}
    uint8_t  info[16];          // 服务器下发的解密信息 (回传)
    uint16_t timestamp;         // Unix 时间戳低 16 位 (小端)
};

// --- 通用 UDP 响应头 (5 字节) ---
// 所有 DrCOM UDP 响应包的前 5 字节共享此结构
struct DrcomUdpHeader {
    uint8_t  magic;             // 0x07
    uint8_t  seq;               // 序列号 (与请求对应)
    uint16_t length;            // 包长
    uint8_t  subtype;           // 子类型 (决定后续解析方式)
};

// --- MiscResponseAlive (≥12 字节): 对 MiscAlive 的响应 ---
// header.subtype == 0x02
struct DrcomMiscResponseAlive {
    DrcomUdpHeader header;
    uint8_t  reserved[3];
    uint8_t  flux[4];           // 服务器下发的初始流量值
};

// --- MiscResponseInfo (≥32 字节): 对 MiscInfo 的响应 ---
// header.subtype == 0x04
struct DrcomMiscResponseInfo {
    DrcomUdpHeader header;
    uint8_t  reserved[11];
    uint8_t  encrypted[16];     // 加密信息块 (解密后得到 m_decryptedInfo)
};

// --- MiscHeartbeatResponse (≥6 字节): 心跳响应 ---
// header.subtype == 0x0b
struct DrcomMiscHeartbeatResponse {
    DrcomUdpHeader header;
    uint8_t  hb_subtype;        // 0x02: 回 heartbeat3; 0x04: 周期完成
    // 如果 hb_subtype == 0x02, 后面还有 flux[4] at offset 16
};

#pragma pack(pop)

// ============================================================================
// 三、认证配置 & 状态枚举
// ============================================================================

// 认证状态枚举（EAP 认证流程状态机）
enum class AuthState {
    Idle,                       // 空闲
    SendingStart,               // 已发 EAPOL-Start，等待 Request/Identity
    SendingIdentity,            // 已发 Identity 应答，等待 MD5-Challenge
    SendingMD5Challenge,        // 已发 MD5 应答，等待 Success/Failure
    Authenticated,              // 认证成功，处于心跳维持状态
    Failed,                     // 认证失败
    Stopped                     // 用户主动断开
};

// UDP 握手状态枚举（DrCOM UDP 心跳协议状态机）
enum class UdpState {
    Idle,                       // 空闲
    WaitingAliveResponse,       // 已发 MiscAlive，等待 0x02 响应
    WaitingInfoResponse,        // 已发 MiscInfo，等待 0x04 响应
    Online,                     // 心跳维持中
    Stopped                     // 用户主动断开
};

// 认证配置（跨 EapProcess / UdpProcess 共享）
struct AuthConfig {
    QString  interfaceName;     // pcap 设备名 (如 \Device\NPF_{GUID})
    QString  username;
    QString  password;
    QString  host;              // 认证服务器主机名 (如 s.scut.edu.cn)
    QString  dnsServer;         // 主 DNS 地址
    QString  hostname;          // 本机主机名
    uint8_t  localMac[6] = {};
    uint8_t  localIp[4]  = {};
    uint8_t  serverIp[4] = {};
};

#endif // PROTOCOL_H
