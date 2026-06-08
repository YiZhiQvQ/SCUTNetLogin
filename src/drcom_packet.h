#ifndef DRCOM_PACKET_H
#define DRCOM_PACKET_H

#include <array>
#include <cstdint>
#include "protocol.h"
#include "constants.h"

// ============================================================================
// DrCOM UDP 私有协议封包 — 纯数据构造（无 I/O 依赖，可单独单测）
// ============================================================================

namespace DrcomPacket {

// 构造 MiscAlive 初始探测包（8 字节）
DrcomMiscAlive buildMiscAlive();

// 构造 MiscInfo 设备信息包（244 字节）
// 注：调用者须在返回后用 computeCks32 计算校验和，并将结果覆盖 m_md5Data 前 4 字节
DrcomMiscInfo buildMiscInfo(const AuthConfig& config, const uint8_t* flux);

// 构造 Alive 在线保活包（38 字节）
DrcomAlive buildAlive(const uint8_t* md5Data, const uint8_t* decryptedInfo);

// 构造 MiscHeartbeat 心跳握手包（40 字节）
// hbSubtype: 0x01 = heartbeat1, 0x03 = heartbeat3 (含 cks16 + localIp)
DrcomMiscHeartbeat buildMiscHeartbeat(uint8_t counter, uint8_t hbSubtype,
                                       const uint8_t* rnd, const uint8_t* flux,
                                       const uint8_t* localIp);

// MiscInfo 包 32 位校验和（会修改 data 中 DRCOM_MISC_OFFSET_CKS32 位置的 4 字节）
uint32_t computeCks32(uint8_t* data, size_t len);

// Heartbeat 包 16 位校验和（会修改 data 中 DRCOM_MISC_OFFSET_CKS32 位置的 4 字节）
uint32_t computeCks16(uint8_t* data, size_t len);

// DrCOM 私有循环左移加解密（对称算法）
void decryptDrcom(const uint8_t* encrypted, uint8_t* output, size_t size);

} // namespace DrcomPacket

#endif // DRCOM_PACKET_H
