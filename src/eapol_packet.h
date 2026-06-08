#ifndef EAPOL_PACKET_H
#define EAPOL_PACKET_H

#include <vector>
#include <cstdint>
#include <QByteArray>
#include <QString>
#include "protocol.h"
#include "constants.h"

// ============================================================================
// EAPOL / 802.1X 帧构建 — 纯数据构造（无 pcap 依赖，可单独单测）
// ============================================================================

namespace EapolPacket {

// 构造 EAPOL 帧骨架（96 字节缓冲区），不填 dest_mac
// 调用者需自行填充 EthHeader::dest_mac
std::vector<uint8_t> buildEapolFrame(const uint8_t* srcMac,
                                      uint8_t eapolType,
                                      uint16_t eapolBodyLen);

// 构造 EAP Response 帧（Identity 或 MD5-Challenge），自动填充所有头部
std::vector<uint8_t> buildEapResponseFrame(const uint8_t* srcMac,
                                            const uint8_t* destMac,
                                            uint8_t eapType,
                                            uint8_t requestId,
                                            const QByteArray& payload);

// Ruijie/H3C/DrCOM 私有 EAP-MD5 计算: MD5(id + password + challenge)
QByteArray calculateMD5(uint8_t identifier,
                        const QString& password,
                        const QByteArray& challenge);

// 构造 Identity Response 的 payload（含 DrCOM 后缀 + client IP）
QByteArray buildIdentityPayload(const QByteArray& username,
                                 const uint8_t* clientIp);

// 构造 MD5-Challenge Response 的 payload（含 MD5 值 + username + DrCOM 后缀 + client IP）
QByteArray buildMd5ChallengePayload(const QByteArray& md5Result,
                                      const QByteArray& username,
                                      const uint8_t* clientIp);

} // namespace EapolPacket

#endif // EAPOL_PACKET_H
