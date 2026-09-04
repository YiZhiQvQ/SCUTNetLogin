#include "eap/eapol_packet.h"
#include <QCryptographicHash>
#include <winsock2.h>
#include <cstring>

namespace EapolPacket {

// ============================================================================
// EAPOL 帧骨架
// ============================================================================

std::vector<uint8_t> buildEapolFrame(const uint8_t* srcMac,
                                      uint8_t eapolType,
                                      uint16_t eapolBodyLen)
{
    // 动态分配精确帧大小: Eth头(14) + EAPOL头(4) + EAPOL body
    // 避免中文用户名等长 payload 导致固定 96 字节缓冲区溢出
    const size_t frameSize = ETH_HEADER_SIZE + sizeof(EAPOLHeader) + eapolBodyLen;
    std::vector<uint8_t> frame(frameSize, 0);
    EthHeader*   eth   = reinterpret_cast<EthHeader*>(frame.data());
    EAPOLHeader* eapol = reinterpret_cast<EAPOLHeader*>(frame.data() + ETH_HEADER_SIZE);

    memcpy(eth->src_mac, srcMac, 6);
    eth->eth_type = htons(ETHERTYPE_EAPOL);

    eapol->version     = EAPOL_VERSION;
    eapol->packet_type = eapolType;
    eapol->length      = htons(eapolBodyLen);

    return frame;
}

// ============================================================================
// EAP Response 帧
// ============================================================================

std::vector<uint8_t> buildEapResponseFrame(const uint8_t* srcMac,
                                            const uint8_t* destMac,
                                            uint8_t eapType,
                                            uint8_t requestId,
                                            const QByteArray& payload)
{
    uint16_t bodyLen = static_cast<uint16_t>(5 + payload.size());
    auto frame = buildEapolFrame(srcMac, EAPOL_TYPE_EAP_PACKET, bodyLen);

    // 填充目标 MAC
    memcpy(reinterpret_cast<EthHeader*>(frame.data())->dest_mac, destMac, 6);

    // 填充 EAP 头部
    EAPHeader* eap = reinterpret_cast<EAPHeader*>(frame.data() + EAP_HEADER_OFFSET);
    eap->code   = EAP_CODE_RESPONSE;
    eap->id     = requestId;
    eap->length = htons(bodyLen);
    eap->type   = eapType;

    // 复制 payload
    memcpy(frame.data() + EAP_PAYLOAD_OFFSET, payload.data(), payload.size());

    return frame;
}

// ============================================================================
// MD5 计算 — Ruijie/H3C 私有 EAP-MD5 扩展: MD5(id + password + challenge)
// ============================================================================

QByteArray calculateMD5(uint8_t identifier, const QString& password,
                        const QByteArray& challenge)
{
    QByteArray data;
    data.append(static_cast<char>(identifier));
    QByteArray pwdUtf8 = password.toUtf8();
    data.append(pwdUtf8);
    data.append(challenge);
    const QByteArray digest = QCryptographicHash::hash(data, QCryptographicHash::Md5);

    // 及时清除内存中的明文密码副本（QString 本身不可安全清零，
    // 至少保证本地临时缓冲不残留密码原文；认证结果 digest 不含明文）
    pwdUtf8.fill('\0');
    data.fill('\0');

    return digest;
}

// ============================================================================
// Payload 构造
// ============================================================================

QByteArray buildIdentityPayload(const QByteArray& username,
                                 const uint8_t* clientIp)
{
    QByteArray payload;
    payload.append(username);
    payload.append(reinterpret_cast<const char*>(DRCOM_IDENTITY_RESPONSE_SUFFIX.data()),
                   DRCOM_IDENTITY_RESPONSE_SUFFIX.size());
    payload.append(reinterpret_cast<const char*>(clientIp), 4);
    return payload;
}

QByteArray buildMd5ChallengePayload(const QByteArray& md5Result,
                                      const QByteArray& username,
                                      const uint8_t* clientIp)
{
    QByteArray payload;
    payload.append(static_cast<char>(md5Result.size()));
    payload.append(md5Result);
    payload.append(username);
    payload.append(reinterpret_cast<const char*>(DRCOM_MD5_RESPONSE_SUFFIX.data()),
                   DRCOM_MD5_RESPONSE_SUFFIX.size());
    payload.append(reinterpret_cast<const char*>(clientIp), 4);
    return payload;
}

// ============================================================================
// EAP 帧解析（从 EapProcess::parsePacket 提取的纯函数，可独立单测）
// ============================================================================

bool parseEapPacket(const QByteArray& data, EAPHeader* outEapHeader, QByteArray* outPayload)
{
    if (data.size() < EAPOL_MIN_FRAME_SIZE)
        return false;

    const EthHeader* eth = reinterpret_cast<const EthHeader*>(data.data());
    if (eth->eth_type != htons(ETHERTYPE_EAPOL))
        return false;

    const EAPOLHeader* eapol = reinterpret_cast<const EAPOLHeader*>(data.data() + ETH_HEADER_SIZE);
    if (eapol->version != EAPOL_VERSION || eapol->packet_type != EAPOL_TYPE_EAP_PACKET)
        return false;

    // EAP 头部 = code(1) + id(1) + length(2) [+ type(1)，仅 Request/Response]。
    // 基础 4 字节只需帧长 ≥ 22；type 字节（第 5 字节）仅在帧足够长时才读取，
    // 避免对恰好 22 字节的 Success/Failure 帧越界读取（EAP_HEADER_OFFSET+sizeof > 帧长）。
    if (data.size() < EAP_HEADER_OFFSET + 4)
        return false;

    EAPHeader hdr = {};
    memcpy(&hdr, data.data() + EAP_HEADER_OFFSET, 4);
    const bool hasType = (hdr.code == EAP_CODE_REQUEST || hdr.code == EAP_CODE_RESPONSE);
    if (hasType) {
        if (data.size() < EAP_HEADER_OFFSET + 5)
            return false;
        hdr.type = static_cast<uint8_t>(data.at(EAP_HEADER_OFFSET + 4));
    }
    *outEapHeader = hdr;

    // payload 长度：Request/Response 含 type 字节（len-5）；Success/Failure 无
    // type 字节（len-4）。旧实现对 Success/Failure 也按 len-5 计算，长 1 字节的
    // 奇异帧会少算 payload——此处按 EAP 头部结构精确计算。
    const int payloadOffset = EAP_HEADER_OFFSET + 4 + (hasType ? 1 : 0);
    const int payloadSize   = ntohs(hdr.length) - (hasType ? 5 : 4);

    if (payloadSize > 0 && data.size() >= payloadOffset + payloadSize)
        *outPayload = data.mid(payloadOffset, payloadSize);

    return true;
}

} // namespace EapolPacket
