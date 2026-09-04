#ifndef BYTE_UTILS_H
#define BYTE_UTILS_H

#include <QString>
#include <QByteArray>
#include <QHostAddress>
#include <cstdint>

// ============================================================================
// 字节/地址工具 — 纯函数、零 I/O 依赖
//
// 从 network 模块中抽取的纯数据处理函数，供封包构造（drcom_packet）、UDP 进程、
// 配置解析等模块复用，同时让这些模块可以脱离 pcap/IPHLPAPI 依赖单独编译测试。
// ============================================================================

namespace ByteUtils {

// IPv4 地址转大端序字节数组（QHostAddress::toIPv4Address 为 host 序，转网络序写入）
void ipv4ToBytes(const QHostAddress& addr, uint8_t* out);

// 检查 6 字节 MAC 地址是否全零
bool isMacZero(const uint8_t* mac);

// 检查 4 字节 IPv4 地址是否全零
bool isIpZero(const uint8_t* ip);

// MAC 地址标准化：去分隔符（':' / '-' / '.'）、转大写；非法格式返回空字符串
QString normalizeMac(const QString& mac);

// 帧/包十六进制转储：每字节两位大写十六进制，以空格分隔；超过 maxBytes 时截断并
// 标注总长。纯格式化，供调试输出（EAP/UDP 帧级 hex）复用。maxBytes<=0 表示不截断。
QString hexDump(const QByteArray& data, int maxBytes = 96);

} // namespace ByteUtils

#endif // BYTE_UTILS_H
