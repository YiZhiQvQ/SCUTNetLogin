#include "core/byte_utils.h"

namespace ByteUtils {

namespace {
// 12 位十六进制校验（仅允许 0-9 / A-F / a-f，分隔符已在上层剥离）
bool isHex12(const QString& s)
{
    if (s.size() != 12)
        return false;
    for (const QChar& c : s) {
        if (c.isDigit())
            continue;
        const QChar upper = c.toUpper();
        if (upper < QLatin1Char('A') || upper > QLatin1Char('F'))
            return false;
    }
    return true;
}
} // namespace

void ipv4ToBytes(const QHostAddress& addr, uint8_t* out)
{
    const quint32 ipv4 = addr.toIPv4Address();
    out[0] = (ipv4 >> 24) & 0xFF;
    out[1] = (ipv4 >> 16) & 0xFF;
    out[2] = (ipv4 >> 8) & 0xFF;
    out[3] = ipv4 & 0xFF;
}

bool isMacZero(const uint8_t* mac)
{
    for (int i = 0; i < 6; ++i)
        if (mac[i]) return false;
    return true;
}

bool isIpZero(const uint8_t* ip)
{
    for (int i = 0; i < 4; ++i)
        if (ip[i]) return false;
    return true;
}

QString normalizeMac(const QString& mac)
{
    QString hex = mac.trimmed();
    hex.remove(':');
    hex.remove('-');
    hex.remove('.');   // 支持 Cisco 风格 "0011.2233.4455"
    // 校验长度与十六进制字符集：仅长度正确但含非 hex 字符（如 "GGGG..."）
    // 时返回空，避免把非法 MAC 传给后面的适配器查找
    if (!isHex12(hex))
        return QString();
    return hex.toUpper();
}

} // namespace ByteUtils
