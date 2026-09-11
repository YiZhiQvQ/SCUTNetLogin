#ifndef DRCOM_PACKET_H
#define DRCOM_PACKET_H

#include <array>
#include <cstdint>
#include "core/protocol.h"
#include "core/constants.h"

// ============================================================================
// DrCOM UDP 私有协议封包 — 纯数据构造（无 I/O 依赖，可单独单测）
// ============================================================================

namespace DrcomPacket {

// 构造 MiscAlive 初始探测包（8 字节）
DrcomMiscAlive buildMiscAlive();

// 构造 MiscInfo 设备信息包（244 字节）
// 注：调用者须在返回后用 computeCks32 计算校验和（结果写入包内 offset 24）
DrcomMiscInfo buildMiscInfo(const AuthConfig& config, const uint8_t* flux);

// 构造 Alive 在线保活包（38 字节）
DrcomAlive buildAlive(const uint8_t* md5Data, const uint8_t* decryptedInfo);

// 构造 MiscHeartbeat 心跳握手包（40 字节）
// hbSubtype: 0x01 = heartbeat1, 0x03 = heartbeat3 (含 cks16 + localIp)
DrcomMiscHeartbeat buildMiscHeartbeat(uint8_t counter, uint8_t hbSubtype,
                                       const uint8_t* rnd, const uint8_t* flux,
                                       const uint8_t* localIp);

// MiscInfo 包 32 位校验和。会把结果写回 data 中 DRCOM_MISC_OFFSET_CKS32 的 4 字节，
// 因此【不可重复调用】：同缓冲区二次计算时 offset 24 已非种子，结果不同。
// 契约：每包由 buildMiscInfo 构建后调用一次。
uint32_t computeCks32(uint8_t* data, size_t len);

// Heartbeat 包 16 位校验和。同上：写回 offset 24，每包仅调用一次。
uint32_t computeCks16(uint8_t* data, size_t len);

// DrCOM 私有"循环左移 i&7 位"变换。收发双方用同一变换构成对称，
// 但变换本身不是自反的（连续应用两次 ≠ 原值）。服务器密文经本函数还原。
void decryptDrcom(const uint8_t* encrypted, uint8_t* output, size_t size);

} // namespace DrcomPacket

#endif // DRCOM_PACKET_H
