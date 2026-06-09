#ifndef CONSTANTS_H
#define CONSTANTS_H

#include <array>
#include <cstdint>

// ============================================================================
// 一、IEEE 802.1X / EAPOL 标准协议常量
// ============================================================================

// 802.1X 组播 MAC 地址 (IEEE Std 802.1X, Clause 8.13.2)
constexpr std::array<uint8_t, 6> EAPOL_MULTICAST_MAC = { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x03 };

// 以太网帧类型: EAPOL (802.1X)
constexpr uint16_t ETHERTYPE_EAPOL = 0x888E;

// EAPOL 版本 (802.1X-2010 固定为 1)
constexpr uint8_t EAPOL_VERSION = 0x01;

// EAPOL 包类型 (IEEE 802.1X, Table 8-2)
constexpr uint8_t EAPOL_TYPE_EAP_PACKET  = 0x00;  // EAP-Packet
constexpr uint8_t EAPOL_TYPE_EAPOL_START = 0x01;  // EAPOL-Start
constexpr uint8_t EAPOL_TYPE_EAPOL_LOGOFF = 0x02; // EAPOL-Logoff

// EAP 代码 (RFC 3748, Section 4)
constexpr uint8_t EAP_CODE_REQUEST  = 0x01;
constexpr uint8_t EAP_CODE_RESPONSE = 0x02;
constexpr uint8_t EAP_CODE_SUCCESS  = 0x03;
constexpr uint8_t EAP_CODE_FAILURE  = 0x04;

// EAP 类型 (RFC 3748 / IANA EAP Method Type Numbers)
constexpr uint8_t EAP_TYPE_IDENTITY       = 0x01;  // Identity
constexpr uint8_t EAP_TYPE_NOTIFICATION   = 0x02;  // Notification
constexpr uint8_t EAP_TYPE_MD5_CHALLENGE  = 0x04;  // MD5-Challenge (EAP-MD5)

// EAPOL 帧最小长度 (Eth 14 + EAPOL 4 + EAP 4 = 22)
constexpr int EAPOL_MIN_FRAME_SIZE = 22;
// EAP 头部偏移 (Eth 14 + EAPOL 4 = 18)
constexpr int EAP_HEADER_OFFSET = 18;
// EAP Payload 偏移 (Eth 14 + EAPOL 4 + EAP 4 + Type 1 = 23)
constexpr int EAP_PAYLOAD_OFFSET = 23;


// ============================================================================
// 二、DrCOM 私有扩展 — Identity / MD5 Challenge 响应中的附加字段
//    协议逆向自 Ruijie/H3C 校园网 DrCOM 认证
// ============================================================================

// Identity 响应 payload 尾部固定字段（5 字节）
// 结构: {0x00, "Da", 0x00, 0x00}
// 含义: 第一个0x00分割用户名; "Da"为DrCOM厂商标签; 后两个0x00为扩展标志位
constexpr std::array<uint8_t, 5> DRCOM_IDENTITY_RESPONSE_SUFFIX = { 0x00, 0x44, 0x61, 0x00, 0x00 };

// MD5-Challenge 响应 payload 中，MD5值+用户名之后的固定字段（5 字节）
// 结构: {0x00, "Da", 0x2a, 0x00}
constexpr std::array<uint8_t, 5> DRCOM_MD5_RESPONSE_SUFFIX = { 0x00, 0x44, 0x61, 0x2a, 0x00 };

// ============================================================================
// 三、DrCOM UDP 心跳/握手协议常量 — 逆向自 SCUT 校园网
// ============================================================================

// UDP 服务器端口
constexpr uint16_t DRCOM_UDP_PORT = 61440;

// UDP 心跳间隔 & 超时 (ms)
constexpr int DRCOM_HEARTBEAT_INTERVAL = 30000;
constexpr int DRCOM_HEARTBEAT_TIMEOUT  = 10000;

// UDP 包类型标记（第 0 字节）
constexpr uint8_t DRCOM_UDP_MAGIC = 0x07;
// Alive 包类型标记
constexpr uint8_t DRCOM_ALIVE_MAGIC = 0xFF;

// --- MiscAlive / MiscInfo 子类型 (data[4]) ---
constexpr uint8_t DRCOM_SUBTYPE_MISC_ALIVE          = 0x01;  // 请求 alive
constexpr uint8_t DRCOM_SUBTYPE_MISC_RESPONSE_ALIVE  = 0x02;  // 响应 alive → 发 MiscInfo
constexpr uint8_t DRCOM_SUBTYPE_MISC_INFO            = 0x03;  // MiscInfo 包
constexpr uint8_t DRCOM_SUBTYPE_MISC_RESPONSE_INFO   = 0x04;  // 响应 info → 解密信息 + 开始心跳
constexpr uint8_t DRCOM_SUBTYPE_MISC_HEARTBEAT_ALIVE = 0x06;  // 心跳 alive 响应 → 发 heartbeat1
constexpr uint8_t DRCOM_SUBTYPE_MISC_HEARTBEAT       = 0x0b;  // 心跳包

// --- Heartbeat 子类型 (data[5]，仅当 data[4]==0x0b) ---
// 客户端 → 服务器
constexpr uint8_t DRCOM_HB_CLIENT_QUERY   = 0x01;  // 客户端心跳查询 (heartbeat1)
constexpr uint8_t DRCOM_HB_CLIENT_CONFIRM = 0x03;  // 客户端心跳确认 (heartbeat3, 含 cks16+IP)
// 服务器 → 客户端
constexpr uint8_t DRCOM_HB_SUBTYPE_RESPONSE1 = 0x02;  // 响应 heartbeat1 → 发 heartbeat3
constexpr uint8_t DRCOM_HB_SUBTYPE_ACK       = 0x04;  // 心跳周期完成 ACK

// --- MiscInfo 包固定字段 ---
constexpr uint16_t DRCOM_MISC_INFO_LENGTH = 0xF4;   // 244 字节
constexpr uint8_t  DRCOM_MISC_INFO_FLAG   = 0x03;   // data[4]
constexpr uint8_t  DRCOM_MISC_INFO_CMD    = 0x01;   // data[1] — 协议命令/版本标记

// MiscInfo 中各段的偏移量
constexpr int DRCOM_MISC_OFFSET_USERNAME_LEN  = 5;
constexpr int DRCOM_MISC_OFFSET_SRC_MAC       = 6;
constexpr int DRCOM_MISC_OFFSET_SRC_IP        = 12;
constexpr int DRCOM_MISC_OFFSET_UNKNOWN1      = 16;
constexpr int DRCOM_MISC_OFFSET_FLUX          = 20;
constexpr int DRCOM_MISC_OFFSET_CKS32         = 24;
constexpr int DRCOM_MISC_OFFSET_CKS32_TEMP    = 28;  // 校验计算时临时置 126
constexpr int DRCOM_MISC_OFFSET_HOST_INFO     = 32;
constexpr int DRCOM_MISC_HOST_INFO_SIZE       = 44;
constexpr int DRCOM_MISC_OFFSET_DNS1          = 76;
constexpr int DRCOM_MISC_OFFSET_DNS2          = 80;
constexpr int DRCOM_MISC_OFFSET_UNKNOWN2      = 92;
constexpr int DRCOM_MISC_OFFSET_OS_MAJOR      = 96;
constexpr int DRCOM_MISC_OFFSET_OS_MINOR      = 100;
constexpr int DRCOM_MISC_OFFSET_OS_BUILD      = 104;
constexpr int DRCOM_MISC_OFFSET_OS_UNKNOWN    = 108;
constexpr int DRCOM_MISC_OFFSET_VERSION       = 112;
constexpr int DRCOM_MISC_VERSION_SIZE         = 64;
constexpr int DRCOM_MISC_OFFSET_HASH          = 176;
constexpr int DRCOM_MISC_HASH_SIZE            = 64;
constexpr int DRCOM_MISC_MAX_USERNAME_LEN     = 25;

// MiscInfo 固定字段值
constexpr std::array<uint8_t, 4> DRCOM_MISC_UNKNOWN1  = { 0x02, 0x22, 0x00, 0x2a };
constexpr std::array<uint8_t, 4> DRCOM_MISC_CKSPARAM  = { 0xc7, 0x2f, 0x31, 0x01 };  // cks32 初始种子
constexpr std::array<uint8_t, 4> DRCOM_MISC_UNKNOWN2  = { 0x94, 0x00, 0x00, 0x00 };
// 以下 OS 版本字段为 DrCOM 协议兼容的伪装值 (Windows 8 = 6.2.9200)。
// 实际 OS 版本仅影响 MiscInfo 包内容，不影响认证流程；
// 如需真实版本，可通过 RtlGetVersion 动态获取并填充。
constexpr std::array<uint8_t, 4> DRCOM_MISC_OS_MAJOR  = { 0x06, 0x00, 0x00, 0x00 };
constexpr std::array<uint8_t, 4> DRCOM_MISC_OS_MINOR  = { 0x02, 0x00, 0x00, 0x00 };
constexpr std::array<uint8_t, 4> DRCOM_MISC_OS_BUILD  = { 0xf0, 0x23, 0x00, 0x00 };
constexpr std::array<uint8_t, 4> DRCOM_MISC_OS_UNKNOWN = { 0x02, 0x00, 0x00, 0x00 };
// DrCOM 客户端版本字符串 "DrCOM\0\x96\x02\x2a"
constexpr std::array<uint8_t, 9> DRCOM_MISC_VERSION = { 0x44, 0x72, 0x43, 0x4f, 0x4d, 0x00, 0x96, 0x02, 0x2a };
// 客户端哈希 (SHA1)
constexpr char    DRCOM_MISC_HASH[]        = "4eb81fc048a5585b7dfe1783155241a328b103c6";
constexpr size_t  DRCOM_MISC_HASH_LEN      = sizeof(DRCOM_MISC_HASH) - 1;  // 40 chars (excludes null)

// cks32 计算相关常量
constexpr uint8_t  DRCOM_CKS32_TEMP_VALUE  = 126;      // 偏移28临时填充值
constexpr uint32_t DRCOM_CKS32_MULTIPLIER  = 19680126;  // 校验和乘数
constexpr size_t   DRCOM_CKS32_LOOP_SIZE   = 244;       // cks32 遍历字节数
constexpr uint32_t DRCOM_CKS16_MULTIPLIER  = 711;       // cks16 乘数
constexpr size_t   DRCOM_CKS16_LOOP_SIZE   = 40;        // cks16 遍历字节数

// --- Heartbeat 包固定字段 ---
constexpr uint16_t DRCOM_HB_LENGTH     = 0x28;   // 40 字节
constexpr uint8_t  DRCOM_HB_FLAG       = 0x0b;
constexpr uint8_t  DRCOM_HB_FIXED1     = 0xdc;
constexpr uint8_t  DRCOM_HB_FIXED2     = 0x02;

// --- Alive 包结构大小 ---
constexpr int DRCOM_ALIVE_MD5_SIZE    = 16;

// --- MiscAlive 包 (8 字节) ---
constexpr size_t DRCOM_MISC_ALIVE_SIZE = 8;

// ============================================================================
// 四、解密算法（DrCOM 私有加密）
// ============================================================================

// 校园网锐捷 DrCOM 私有加密/解密：按字节索引 i 进行循环左移 i%8 位
// 加密 = 解密（对称），用于 MiscResponseInfo (subtype 0x04) 载荷的 16 字节加密块
// 解密公式: decrypted[i] = (encrypted[i] << (i & 7)) | (encrypted[i] >> (8 - (i & 7)))

// ============================================================================
// 五、EAP 认证流程参数
// ============================================================================

// 认证超时 & 重发间隔 (ms)
constexpr int EAP_RETRANSMIT_INTERVAL = 3000;
// pcap 收包超时 (ms) — 必须为 1ms，配合 20ms 轮询计时器使用
constexpr int PCAP_READ_TIMEOUT = 1;

// ============================================================================
// 六、默认网络配置
// ============================================================================

// SCUT 校园网 HTTP 重定向主机（认证前DNS劫持指向）
constexpr const char* DEFAULT_HOST = "s.scut.edu.cn";
// SCUT 校园网默认 DNS 服务器
constexpr std::array<uint8_t, 4> DEFAULT_SERVER_IP = { 202, 38, 193, 33 };
constexpr const char* DEFAULT_DNS = "202.38.193.33";

// ============================================================================
// 七、UI / 应用常量
// ============================================================================

// 后台任务等待超时 (ms)
constexpr int BG_TASK_WAIT_TIMEOUT = 20000;
// netsh 命令超时 (ms)
constexpr int NETSH_TIMEOUT = 15000;
// 静态 IP 设置安全超时 (ms) — 超过此时间未完成则强制恢复状态
constexpr int IP_SETUP_TIMEOUT = 30000;
// 自动连接延迟 (ms)
constexpr int AUTO_CONNECT_DELAY = 800;
// 静默启动连接延迟 (ms)
constexpr int SILENT_CONNECT_DELAY = 1000;
// 网卡清理等待 (ms)
constexpr int PORT_CLEANUP_WAIT = 2000;
// 静态 IP 设置后等待 (ms)
constexpr int IP_SETTLE_WAIT = 1000;
// PCAP 快照长度
constexpr int PCAP_SNAPLEN = 1514;

// 以太网头部字节数
constexpr int ETH_HEADER_SIZE = 14;

#endif // CONSTANTS_H
