#include "udp/drcom_packet.h"
#include "network/network.h"
#include <QDateTime>
#include <QHostAddress>
#include <algorithm>
#include <cstring>

namespace DrcomPacket {

// ============================================================================
// MiscAlive: 初始探测包 (8 字节)
// ============================================================================

DrcomMiscAlive buildMiscAlive()
{
    DrcomMiscAlive pkt = {};
    pkt.magic  = DRCOM_UDP_MAGIC;
    pkt.seq    = 0x00;
    pkt.length = DRCOM_MISC_ALIVE_SIZE;
    pkt.flag   = DRCOM_SUBTYPE_MISC_ALIVE;
    return pkt;
}

// ============================================================================
// MiscInfo: 设备/主机信息包 (244 字节)
// ============================================================================

DrcomMiscInfo buildMiscInfo(const AuthConfig& config, const uint8_t* flux)
{
    DrcomMiscInfo info = {};

    info.magic   = DRCOM_UDP_MAGIC;
    info.subtype = DRCOM_MISC_INFO_CMD;
    info.length  = DRCOM_MISC_INFO_LENGTH;
    info.flag    = DRCOM_MISC_INFO_FLAG;

    QByteArray userUtf8 = config.username.toUtf8();
    int usernameLen = static_cast<int>(std::min<size_t>(userUtf8.size(), DRCOM_MISC_MAX_USERNAME_LEN));
    info.username_len = static_cast<uint8_t>(usernameLen);

    memcpy(info.src_mac,  config.localMac, 6);
    memcpy(info.src_ip,   config.localIp,  4);
    memcpy(info.unknown1, DRCOM_MISC_UNKNOWN1.data(), DRCOM_MISC_UNKNOWN1.size());

    memcpy(info.flux,  flux, 4);
    memcpy(info.cks32, DRCOM_MISC_CKSPARAM.data(), DRCOM_MISC_CKSPARAM.size());

    // host_info (44 字节): username + hostname 拼接
    memcpy(info.host_info, userUtf8.constData(), usernameLen);
    int maxHostLen = DRCOM_MISC_HOST_INFO_SIZE - usernameLen;
    QByteArray hostUtf8 = config.hostname.toUtf8();
    int hostnameLen = static_cast<int>(std::min<size_t>(hostUtf8.size(), static_cast<size_t>(maxHostLen)));
    memcpy(info.host_info + usernameLen, hostUtf8.constData(), hostnameLen);

    // DNS (大端序)
    QHostAddress dnsAddr(config.dnsServer);
    if (dnsAddr.protocol() == QAbstractSocket::IPv4Protocol) {
        Network::ipv4ToBytes(dnsAddr, info.dns1);
        memcpy(info.dns2, info.dns1, 4);
    }

    memcpy(info.unknown2,   DRCOM_MISC_UNKNOWN2.data(),  DRCOM_MISC_UNKNOWN2.size());
    memcpy(info.os_major,   DRCOM_MISC_OS_MAJOR.data(),  DRCOM_MISC_OS_MAJOR.size());
    memcpy(info.os_minor,   DRCOM_MISC_OS_MINOR.data(),  DRCOM_MISC_OS_MINOR.size());
    memcpy(info.os_build,   DRCOM_MISC_OS_BUILD.data(),  DRCOM_MISC_OS_BUILD.size());
    memcpy(info.os_unknown, DRCOM_MISC_OS_UNKNOWN.data(), DRCOM_MISC_OS_UNKNOWN.size());
    memcpy(info.version, DRCOM_MISC_VERSION.data(), DRCOM_MISC_VERSION.size());
    memcpy(info.hash,    DRCOM_MISC_HASH,     DRCOM_MISC_HASH_LEN);

    return info;
}

// ============================================================================
// Alive: 在线保活包 (38 字节)
// ============================================================================

DrcomAlive buildAlive(const uint8_t* md5Data, const uint8_t* decryptedInfo)
{
    DrcomAlive alive = {};

    alive.magic = DRCOM_ALIVE_MAGIC;

    if (md5Data)
        memcpy(alive.md5_data, md5Data, DRCOM_ALIVE_MD5_SIZE);

    if (decryptedInfo)
        memcpy(alive.info, decryptedInfo, 16);

    alive.timestamp = static_cast<uint16_t>(QDateTime::currentSecsSinceEpoch());

    return alive;
}

// ============================================================================
// MiscHeartbeat: 心跳握手包 (40 字节)
// ============================================================================

DrcomMiscHeartbeat buildMiscHeartbeat(uint8_t counter, uint8_t hbSubtype,
                                       const uint8_t* rnd, const uint8_t* flux,
                                       const uint8_t* localIp)
{
    DrcomMiscHeartbeat hb = {};
    hb.magic      = DRCOM_UDP_MAGIC;
    hb.counter    = counter;
    hb.length     = DRCOM_HB_LENGTH;
    hb.flag       = DRCOM_HB_FLAG;
    hb.hb_subtype = hbSubtype;
    hb.fixed[0]   = DRCOM_HB_FIXED1;
    hb.fixed[1]   = DRCOM_HB_FIXED2;

    if (rnd)
        memcpy(hb.rnd, rnd, 2);
    if (flux)
        memcpy(hb.flux, flux, 4);

    if (hbSubtype == DRCOM_HB_CLIENT_CONFIRM && localIp)
        memcpy(hb.local_ip, localIp, 4);

    return hb;
}

// ============================================================================
// 校验和计算
// ============================================================================

uint32_t computeCks32(uint8_t* data, size_t len)
{
    uint8_t saved = data[DRCOM_MISC_OFFSET_CKS32_TEMP];
    data[DRCOM_MISC_OFFSET_CKS32_TEMP] = DRCOM_CKS32_TEMP_VALUE;

    uint32_t s = 0;
    for (size_t i = 0; i < len; i += 4) {
        uint32_t val;
        memcpy(&val, &data[i], 4);
        s ^= val;
    }
    s = static_cast<uint32_t>((static_cast<uint64_t>(s) * DRCOM_CKS32_MULTIPLIER) & 0xFFFFFFFF);
    memcpy(&data[DRCOM_MISC_OFFSET_CKS32], &s, 4);

    data[DRCOM_MISC_OFFSET_CKS32_TEMP] = saved;
    return s;
}

uint32_t computeCks16(uint8_t* data, size_t len)
{
    uint16_t s = 0;
    for (size_t i = 0; i < len; i += 2) {
        uint16_t val;
        memcpy(&val, &data[i], 2);
        s ^= val;
    }
    uint32_t result = static_cast<uint32_t>(s) * DRCOM_CKS16_MULTIPLIER;
    memcpy(&data[DRCOM_MISC_OFFSET_CKS32], &result, 4);
    return result;
}

// ============================================================================
// 加解密
// ============================================================================

void decryptDrcom(const uint8_t* encrypted, uint8_t* output, size_t size)
{
    for (size_t i = 0; i < size; ++i) {
        int shift = static_cast<int>(i) & 0x07;
        output[i] = ((encrypted[i] << shift) | (encrypted[i] >> (8 - shift))) & 0xFF;
    }
}

} // namespace DrcomPacket
