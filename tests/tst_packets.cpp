#include <QtTest>
#include <winsock2.h>   // htons / ntohs（协议头为网络字节序）

#include "eap/eapol_packet.h"
#include "udp/drcom_packet.h"
#include "core/byte_utils.h"
#include "core/connection_builder.h"
#include "core/deferred_signals.h"
#include "eap/notification_parser.h"
#include "config/config_manager.h"
#include "config/credential.h"
#include "network/network.h"

#include <QTemporaryDir>
#include <QSettings>
#include <QDir>
#include <QNetworkInterface>

// ============================================================================
// 测试桩：ConfigManager::resolveAuthConfig 引用了 Network::findInterface（生产实现在
// network.cpp，需链接 Npcap SDK）。测试聚焦配置读写回环，不涉及网卡解析，
// 用返回无效接口的桩替换，使测试工程保持无 Npcap SDK 依赖。
// ============================================================================
namespace Network {
QNetworkInterface findInterface(const QString&, const QString&)
{
    return QNetworkInterface();
}
} // namespace Network

// ============================================================================
// 单元测试 — 协议纯函数回归护栏
//
// 说明：
//   - MD5 参考值由独立工具（md5sum）计算，非实现导出；
//   - cks32/cks16 黄金值是从已上线实现捕获的回归基线：算法本身源自对
//     校园网 DrCOM 服务器的逆向，独立参考值无法离线获得。捕获基线用于
//     防止将来无意的行为漂移。
// ============================================================================

namespace {

// 构造一个确定性的测试用 AuthConfig
AuthConfig makeTestConfig()
{
    AuthConfig c;
    c.interfaceName = QStringLiteral("\\Device\\NPF_{TEST-GUID}");
    c.username = QStringLiteral("student2026");
    c.password = QStringLiteral("test");
    c.host     = QStringLiteral("s.scut.edu.cn");
    c.dnsServer = QStringLiteral("202.38.193.33");
    c.hostname  = QStringLiteral("TESTHOST");
    const uint8_t mac[6] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
    const uint8_t ip[4]  = { 202, 38, 193, 33 };
    memcpy(c.localMac, mac, 6);
    memcpy(c.localIp,  ip,  4);
    return c;
}

// 构造 Eth + EAPOL + EAP 帧（供 parseEapPacket 测试）
// eapolType: 0=EAP-Packet；eapBody: EAP 体（code + id + length [+ type + payload]）
QByteArray makeEapFrame(uint8_t eapolType, const QByteArray& eapBody)
{
    QByteArray f;
    const uint8_t eth[12] = { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x03,
                              0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
    f.append(reinterpret_cast<const char*>(eth), sizeof(eth));
    const uint16_t ethType = htons(ETHERTYPE_EAPOL);
    f.append(reinterpret_cast<const char*>(&ethType), 2);

    uint8_t eapol[4] = { EAPOL_VERSION, eapolType, 0, 0 };
    const uint16_t bodyLen = htons(static_cast<uint16_t>(eapBody.size()));
    memcpy(eapol + 2, &bodyLen, 2);
    f.append(reinterpret_cast<const char*>(eapol), sizeof(eapol));
    f.append(eapBody);
    return f;
}

// 构造 EAP 体：code + id + eapLength [+ type + payload]
QByteArray makeEapBody(uint8_t code, uint8_t id, const QByteArray& payload = QByteArray(),
                       bool withType = false, uint8_t type = 0)
{
    QByteArray b;
    b.append(static_cast<char>(code));
    b.append(static_cast<char>(id));
    const int hdrSize = withType ? 5 : 4;
    const uint16_t eapLen = htons(static_cast<uint16_t>(hdrSize + payload.size()));
    b.append(reinterpret_cast<const char*>(&eapLen), 2);
    if (withType)
        b.append(static_cast<char>(type));
    b.append(payload);
    return b;
}

} // namespace

class TestPackets : public QObject {
    Q_OBJECT

private slots:
    // ---------- ByteUtils ----------
    void ipv4ToBytes_bigEndian();
    void normalizeMac_formats();
    void normalizeMac_invalidHex();
    void isZero_checks();

    // ---------- EapolPacket ----------
    void buildEapolFrame_sizesAndHeader();
    void buildEapResponseFrame_structure();
    void calculateMD5_knownVectors();
    void parseEapPacket_validRequest();
    void parseEapPacket_responseMd5();
    void parseEapPacket_successFrame();
    void parseEapPacket_malformed();

    // ---------- DrcomPacket：结构 ----------
    void buildMiscAlive_layout();
    void buildMiscInfo_layout();
    void buildMiscInfo_truncation();
    void buildAlive_layout();
    void buildMiscHeartbeat_layout();

    // ---------- DrcomPacket：校验和 ----------
    void computeCks32_properties();
    void computeCks16_properties();

    // ---------- DrcomPacket：加解密 ----------
    void decryptDrcom_roundtrip();

    // ---------- ConnectionBuilder ----------
    void build_loopbackRejected();
    void build_credentialValidation();
    void build_staticIpValidation();
    void build_invalidIpRejected();
    void build_staticIpOk();
    void build_noStaticIpOk();

    // ---------- NotificationParser ----------
    void notificationParser_knownCodes();
    void notificationParser_simpleErrors();
    void notificationParser_unknown();
    void notificationParser_edgeCases();

    // ---------- DeferredSignalQueue ----------
    void deferredQueue_order();

    // ---------- Credential / ConfigManager ----------
    void credential_roundtrip();
    void configManager_roundtrip();
    void configManager_legacyBase64Fallback();
};

// ============================================================================
// ByteUtils
// ============================================================================

void TestPackets::ipv4ToBytes_bigEndian()
{
    uint8_t out[4] = {};
    ByteUtils::ipv4ToBytes(QHostAddress(QStringLiteral("192.168.1.100")), out);
    QCOMPARE(out[0], 192);
    QCOMPARE(out[1], 168);
    QCOMPARE(out[2], 1);
    QCOMPARE(out[3], 100);
}

void TestPackets::normalizeMac_formats()
{
    QCOMPARE(ByteUtils::normalizeMac(QStringLiteral("00-11-22-33-44-55")),
             QStringLiteral("001122334455"));
    QCOMPARE(ByteUtils::normalizeMac(QStringLiteral("00:11:22:33:44:55")),
             QStringLiteral("001122334455"));
    QCOMPARE(ByteUtils::normalizeMac(QStringLiteral("0011.2233.4455")),   // Cisco 风格
             QStringLiteral("001122334455"));
    QCOMPARE(ByteUtils::normalizeMac(QStringLiteral("001122334455")),
             QStringLiteral("001122334455"));
    QCOMPARE(ByteUtils::normalizeMac(QStringLiteral("")), QString());
    QCOMPARE(ByteUtils::normalizeMac(QStringLiteral("00-11-22")), QString()); // 非法长度
}

void TestPackets::isZero_checks()
{
    uint8_t macZero[6]   = { 0, 0, 0, 0, 0, 0 };
    uint8_t macNonZero[6] = { 0, 0, 0, 0, 0, 1 };
    QVERIFY(ByteUtils::isMacZero(macZero));
    QVERIFY(!ByteUtils::isMacZero(macNonZero));

    uint8_t ipZero[4]    = { 0, 0, 0, 0 };
    uint8_t ipNonZero[4] = { 0, 0, 0, 1 };
    QVERIFY(ByteUtils::isIpZero(ipZero));
    QVERIFY(!ByteUtils::isIpZero(ipNonZero));
}

// ============================================================================
// EapolPacket
// ============================================================================

void TestPackets::buildEapolFrame_sizesAndHeader()
{
    // EAPOL-Start：Eth(14) + EAPOL(4) + body(0) = 18 字节
    auto start = EapolPacket::buildEapolFrame(makeTestConfig().localMac,
                                              EAPOL_TYPE_EAPOL_START, 0);
    QCOMPARE(start.size(), 18);
    const auto* eth = reinterpret_cast<const EthHeader*>(start.data());
    QCOMPARE(ntohs(eth->eth_type), static_cast<int>(ETHERTYPE_EAPOL));
    const auto* eapol = reinterpret_cast<const EAPOLHeader*>(start.data() + ETH_HEADER_SIZE);
    QCOMPARE(eapol->version, static_cast<int>(EAPOL_VERSION));
    QCOMPARE(eapol->packet_type, static_cast<int>(EAPOL_TYPE_EAPOL_START));
    QCOMPARE(ntohs(eapol->length), 0);
    QVERIFY(memcmp(eth->src_mac, makeTestConfig().localMac, 6) == 0);
}

void TestPackets::buildEapResponseFrame_structure()
{
    const auto cfg = makeTestConfig();
    const uint8_t destMac[6] = { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x03 };
    const QByteArray payload = QByteArray::fromHex("0102030405");

    auto frame = EapolPacket::buildEapResponseFrame(cfg.localMac, destMac,
                                                    EAP_TYPE_IDENTITY, 0x07, payload);
    QCOMPARE(frame.size(), 14 + 4 + 5 + 5);  // Eth+EAPOL+EAP头(含type)+payload

    const auto* eth = reinterpret_cast<const EthHeader*>(frame.data());
    QVERIFY(memcmp(eth->dest_mac, destMac, 6) == 0);
    QVERIFY(memcmp(eth->src_mac, cfg.localMac, 6) == 0);

    const auto* eap = reinterpret_cast<const EAPHeader*>(frame.data() + EAP_HEADER_OFFSET);
    QCOMPARE(eap->code, static_cast<int>(EAP_CODE_RESPONSE));
    QCOMPARE(eap->id, 0x07);
    QCOMPARE(ntohs(eap->length), 5 + payload.size());
    QCOMPARE(eap->type, static_cast<int>(EAP_TYPE_IDENTITY));

    QByteArray copied(reinterpret_cast<const char*>(frame.data() + EAP_PAYLOAD_OFFSET),
                      payload.size());
    QCOMPARE(copied, payload);
}

void TestPackets::calculateMD5_knownVectors()
{
    // 参考值由独立工具 md5sum 计算：MD5(0x01 + "test" + "abc")
    QCOMPARE(EapolPacket::calculateMD5(0x01, QStringLiteral("test"),
                                       QByteArrayLiteral("abc")).toHex(),
             QByteArrayLiteral("0d0d87d4c27bcbfc0133864c69118158"));

    // MD5(0x0f + "1234567890abcdef" + "0123456789abcdef")
    QCOMPARE(EapolPacket::calculateMD5(0x0f, QStringLiteral("1234567890abcdef"),
                                       QByteArrayLiteral("0123456789abcdef")).toHex(),
             QByteArrayLiteral("3b69ab1109016bfde3682d2ad28ec6f8"));
}

// ============================================================================
// DrcomPacket：结构
// ============================================================================

void TestPackets::buildMiscAlive_layout()
{
    auto pkt = DrcomPacket::buildMiscAlive();
    QCOMPARE(static_cast<int>(sizeof(pkt)), 8);
    QCOMPARE(static_cast<int>(pkt.magic), 0x07);
    QCOMPARE(pkt.seq, 0x00);
    QCOMPARE(pkt.length, 0x0008);
    QCOMPARE(static_cast<int>(pkt.flag), DRCOM_SUBTYPE_MISC_ALIVE);
}

void TestPackets::buildMiscInfo_layout()
{
    const auto cfg = makeTestConfig();
    const uint8_t flux[4] = { 0xde, 0xad, 0xbe, 0xef };
    auto info = DrcomPacket::buildMiscInfo(cfg, flux);

    QCOMPARE(static_cast<int>(sizeof(info)), DRCOM_MISC_INFO_LENGTH);
    QCOMPARE(static_cast<int>(info.magic), 0x07);
    QCOMPARE(static_cast<int>(info.subtype), DRCOM_MISC_INFO_CMD);
    QCOMPARE(info.length, DRCOM_MISC_INFO_LENGTH);
    QCOMPARE(static_cast<int>(info.flag), DRCOM_MISC_INFO_FLAG);

    // username_len == 实际 UTF-8 字节数
    QCOMPARE(static_cast<int>(info.username_len), cfg.username.toUtf8().size());

    // MAC / IP 拷贝
    QVERIFY(memcmp(info.src_mac, cfg.localMac, 6) == 0);
    QVERIFY(memcmp(info.src_ip,  cfg.localIp,  4) == 0);

    // flux 拷贝
    QVERIFY(memcmp(info.flux, flux, 4) == 0);

    // cks32 初始种子
    QVERIFY(memcmp(info.cks32, DRCOM_MISC_CKSPARAM.data(), 4) == 0);

    // host_info = username + hostname
    QByteArray hostInfo(reinterpret_cast<const char*>(info.host_info),
                        DRCOM_MISC_HOST_INFO_SIZE);
    QVERIFY(hostInfo.startsWith(cfg.username.toUtf8()));
    QVERIFY(hostInfo.contains(cfg.hostname.toUtf8()));

    // DNS1/DNS2 == 202.38.193.33 大端
    const uint8_t dns[] = { 202, 38, 193, 33 };
    QVERIFY(memcmp(info.dns1, dns, 4) == 0);
    QVERIFY(memcmp(info.dns2, dns, 4) == 0);

    // 版本 / 哈希
    QVERIFY(memcmp(info.version, DRCOM_MISC_VERSION.data(), DRCOM_MISC_VERSION.size()) == 0);
    QVERIFY(memcmp(info.hash, DRCOM_MISC_HASH, DRCOM_MISC_HASH_LEN) == 0);
}

void TestPackets::buildMiscInfo_truncation()
{
    AuthConfig cfg = makeTestConfig();
    cfg.username = QString::fromUtf8(QByteArray(30, 'x').toHex());  // 60 字节，远超 25 上限
    cfg.hostname = QStringLiteral("VERYLONGHOSTNAME_OVERFLOW_TEST"); // 30 字节
    const uint8_t flux[4] = { 0, 0, 0, 0 };

    auto info = DrcomPacket::buildMiscInfo(cfg, flux);
    QCOMPARE(static_cast<int>(info.username_len), DRCOM_MISC_MAX_USERNAME_LEN);

    QByteArray userUtf8 = cfg.username.toUtf8();
    QByteArray hostUtf8 = cfg.hostname.toUtf8();
    QCOMPARE(userUtf8.size(), 60);
    QCOMPARE(hostUtf8.size(), 30);

    QByteArray hostInfo(reinterpret_cast<const char*>(info.host_info),
                        DRCOM_MISC_HOST_INFO_SIZE);

    // host_info = username(截断到25) + hostname(截断到剩余19) = 恰好 44 字节铺满
    const int maxHostLen = DRCOM_MISC_HOST_INFO_SIZE - DRCOM_MISC_MAX_USERNAME_LEN; // 19
    QVERIFY(hostInfo.startsWith(userUtf8.left(DRCOM_MISC_MAX_USERNAME_LEN)));
    QVERIFY(hostInfo.mid(DRCOM_MISC_MAX_USERNAME_LEN)
                .startsWith(hostUtf8.left(maxHostLen)));
    QCOMPARE(DRCOM_MISC_MAX_USERNAME_LEN + maxHostLen, DRCOM_MISC_HOST_INFO_SIZE);
}

void TestPackets::buildAlive_layout()
{
    const uint8_t md5[DRCOM_ALIVE_MD5_SIZE] = { 0, 1, 2, 3, 4, 5, 6, 7,
                                                8, 9, 10, 11, 12, 13, 14, 15 };
    const uint8_t info[16] = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
                               0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99 };
    auto alive = DrcomPacket::buildAlive(md5, info);
    QCOMPARE(static_cast<int>(sizeof(alive)), 38);
    QCOMPARE(static_cast<int>(alive.magic), DRCOM_ALIVE_MAGIC);
    QVERIFY(memcmp(alive.md5_data, md5, DRCOM_ALIVE_MD5_SIZE) == 0);
    QVERIFY(memcmp(alive.info, info, 16) == 0);
}

void TestPackets::buildMiscHeartbeat_layout()
{
    const uint8_t rnd[2] = { 0x12, 0x34 };
    const uint8_t flux[4] = { 0x01, 0x02, 0x03, 0x04 };
    auto hb = DrcomPacket::buildMiscHeartbeat(0x05, DRCOM_HB_CLIENT_CONFIRM,
                                              rnd, flux, makeTestConfig().localIp);
    QCOMPARE(static_cast<int>(sizeof(hb)), 40);
    QCOMPARE(static_cast<int>(hb.magic), DRCOM_UDP_MAGIC);
    QCOMPARE(hb.counter, 0x05);
    QCOMPARE(hb.length, DRCOM_HB_LENGTH);
    QCOMPARE(static_cast<int>(hb.hb_subtype), DRCOM_HB_CLIENT_CONFIRM);
    QVERIFY(memcmp(hb.rnd, rnd, 2) == 0);
    QVERIFY(memcmp(hb.flux, flux, 4) == 0);
    QVERIFY(memcmp(hb.local_ip, makeTestConfig().localIp, 4) == 0);

    // 不带 localIp 的 query 子类型 local_ip 应为全 0
    auto q = DrcomPacket::buildMiscHeartbeat(0x01, DRCOM_HB_CLIENT_QUERY, rnd, flux, nullptr);
    QCOMPARE(static_cast<int>(q.hb_subtype), DRCOM_HB_CLIENT_QUERY);
    QCOMPARE(q.local_ip[0] | q.local_ip[1] | q.local_ip[2] | q.local_ip[3], 0);
}

// ============================================================================
// DrcomPacket：校验和
// ============================================================================

void TestPackets::computeCks32_properties()
{
    auto cfg = makeTestConfig();
    const uint8_t flux[4] = { 0, 0, 0, 0 };
    auto info = DrcomPacket::buildMiscInfo(cfg, flux);

    // 计算后 cks_temp 临时字节必须恢复为 0
    QCOMPARE(info.cks_temp[0] | info.cks_temp[1] | info.cks_temp[2] | info.cks_temp[3], 0);

    const uint32_t sum = DrcomPacket::computeCks32(reinterpret_cast<uint8_t*>(&info),
                                                   sizeof(info));

    // 返回值与写入包内 offset 24 的字节一致（小端）
    const uint8_t* p = reinterpret_cast<const uint8_t*>(&info) + DRCOM_MISC_OFFSET_CKS32;
    const uint32_t stored = static_cast<uint32_t>(p[0])
                          | static_cast<uint32_t>(p[1]) << 8
                          | static_cast<uint32_t>(p[2]) << 16
                          | static_cast<uint32_t>(p[3]) << 24;
    QCOMPARE(sum, stored);

    // 确定性：注意必须【重新构建】包再算第二次 —— computeCks32 会把结果写回
    // 包内 offset 24，同一缓冲区二次计算时该处已非种子，结果必然不同（这是
    // 设计如此：生产代码每包构建后只调用一次）。这里验证"新包 → 同结果"。
    auto info2 = DrcomPacket::buildMiscInfo(cfg, flux);
    const uint32_t sum2 = DrcomPacket::computeCks32(reinterpret_cast<uint8_t*>(&info2),
                                                    sizeof(info2));
    QCOMPARE(sum, sum2);

    // 回归基线（从已上线实现捕获，防漂移）：对新构建的测试包首次计算的值
    QCOMPARE(sum, 222571522u);
}

void TestPackets::computeCks16_properties()
{
    const uint8_t rnd[2] = { 0x12, 0x34 };
    const uint8_t flux[4] = { 0x01, 0x02, 0x03, 0x04 };
    auto hb = DrcomPacket::buildMiscHeartbeat(0x05, DRCOM_HB_CLIENT_CONFIRM,
                                              rnd, flux, makeTestConfig().localIp);
    const uint32_t sum = DrcomPacket::computeCks16(reinterpret_cast<uint8_t*>(&hb),
                                                   sizeof(hb));

    const uint8_t* p = reinterpret_cast<const uint8_t*>(&hb) + DRCOM_MISC_OFFSET_CKS32;
    const uint32_t stored = static_cast<uint32_t>(p[0])
                          | static_cast<uint32_t>(p[1]) << 8
                          | static_cast<uint32_t>(p[2]) << 16
                          | static_cast<uint32_t>(p[3]) << 24;
    QCOMPARE(sum, stored);

    // 回归基线（从已上线实现捕获，防漂移）：0x8A8D75
    QCOMPARE(sum, 9080181u);
}

// ============================================================================
// DrcomPacket：加解密
// ============================================================================

void TestPackets::decryptDrcom_roundtrip()
{
    // decryptDrcom 是按字节循环左移 (i & 7) 位，并非自反变换（往返两次 ≠ 原值），
    // 收发双方用同一变换构成"对称"。这里按手工可验的移位规则逐字节断言：
    // 变量不能叫 "small"（该名字是 Windows SDK 头文件中的宏）
    uint8_t sample[4] = { 0x01, 0x80, 0x81, 0xAA };
    uint8_t out[4] = {};
    DrcomPacket::decryptDrcom(sample, out, 4);

    // i=0: 左移0 → 原值
    QCOMPARE(static_cast<int>(out[0]), 0x01);
    // i=1: 循环左移1 → 0x80 变 0x01
    QCOMPARE(static_cast<int>(out[1]), 0x01);
    // i=2: 0x81 循环左移2 → 0x81<<2=0x204&0xFF=0x04, 0x81>>6=0x02 → 0x04|0x02=0x06
    QCOMPARE(static_cast<int>(out[2]), 0x06);
    // i=3: 0xAA 循环左移3 → 0xAA<<3=0x550&0xFF=0x50, 0xAA>>5=0x05 → 0x50|0x05=0x55
    QCOMPARE(static_cast<int>(out[3]), 0x55);
}

// ============================================================================
// ConnectionBuilder
// ============================================================================

namespace {

// 构造一个"默认合法"的连接输入
ConnectionBuilder::Input makeConnectInput()
{
    ConnectionBuilder::Input in;
    in.pcapName       = QStringLiteral("\\Device\\NPF_{TEST-GUID}");
    in.displayText    = QStringLiteral("以太网");
    in.username       = QStringLiteral("student2026");
    in.password       = QStringLiteral("test");
    in.mac            = QStringLiteral("001122334455");
    in.autoSetNetwork = true;
    in.adapterName    = QStringLiteral("以太网");
    in.ip      = QStringLiteral("192.168.1.100");
    in.mask    = QStringLiteral("255.255.255.0");
    in.gateway = QStringLiteral("192.168.1.1");
    in.dns1    = QStringLiteral("202.38.193.33");
    in.dns2    = QStringLiteral("8.8.8.8");
    return in;
}

} // namespace

void TestPackets::build_loopbackRejected()
{
    auto in = makeConnectInput();
    in.displayText = QStringLiteral("Loopback Pseudo-Interface");
    auto r = ConnectionBuilder::build(in);
    QVERIFY(!r.ok);
    QVERIFY(r.error.contains(QStringLiteral("回环")));

    in = makeConnectInput();
    in.pcapName = QStringLiteral("\\Device\\NPF_Loopback");
    r = ConnectionBuilder::build(in);
    QVERIFY(!r.ok);
    QVERIFY(r.error.contains(QStringLiteral("回环")));
}

void TestPackets::build_credentialValidation()
{
    // 用户名或密码为空 → 拒绝
    auto in = makeConnectInput();
    in.username.clear();
    auto r = ConnectionBuilder::build(in);
    QVERIFY(!r.ok);
    QVERIFY(r.error.contains(QStringLiteral("用户名")));

    in = makeConnectInput();
    in.password.clear();
    r = ConnectionBuilder::build(in);
    QVERIFY(!r.ok);
    QVERIFY(r.error.contains(QStringLiteral("密码")));

    // 仅空白用户名同样拒绝
    in = makeConnectInput();
    in.username = QStringLiteral("   ");
    r = ConnectionBuilder::build(in);
    QVERIFY(!r.ok);
}

void TestPackets::build_staticIpValidation()
{
    // MAC 为空
    auto in = makeConnectInput();
    in.mac.clear();
    auto r = ConnectionBuilder::build(in);
    QVERIFY(!r.ok);
    QVERIFY(r.error.contains(QStringLiteral("MAC")));

    // 适配器名未解析到
    in = makeConnectInput();
    in.adapterName.clear();
    r = ConnectionBuilder::build(in);
    QVERIFY(!r.ok);
    QVERIFY(r.error.contains(QStringLiteral("适配器")));

    // 缺少字段（只缺 IP 与网关，掩码/DNS 完整 → 报错中只含所缺项）
    in = makeConnectInput();
    in.ip.clear();
    in.gateway.clear();
    r = ConnectionBuilder::build(in);
    QVERIFY(!r.ok);
    QVERIFY(r.error.contains(QStringLiteral("IPv4地址")));
    QVERIFY(r.error.contains(QStringLiteral("默认网关")));
    QVERIFY(!r.error.contains(QStringLiteral("子网掩码")));
    QVERIFY(!r.error.contains(QStringLiteral("主DNS")));
}

void TestPackets::build_staticIpOk()
{
    auto in = makeConnectInput();
    auto r = ConnectionBuilder::build(in);
    QVERIFY(r.ok);
    QVERIFY(r.needStaticIp);
    QCOMPARE(r.ipConfig.adapterName, QStringLiteral("以太网"));
    QCOMPARE(r.ipConfig.ip, QStringLiteral("192.168.1.100"));
    QCOMPARE(r.ipConfig.mask, QStringLiteral("255.255.255.0"));
    QCOMPARE(r.ipConfig.gateway, QStringLiteral("192.168.1.1"));
    QCOMPARE(r.ipConfig.dns1, QStringLiteral("202.38.193.33"));
    QCOMPARE(r.ipConfig.dns2, QStringLiteral("8.8.8.8"));
    QCOMPARE(r.ipConfig.mac, QStringLiteral("001122334455"));
}

void TestPackets::build_noStaticIpOk()
{
    auto in = makeConnectInput();
    in.autoSetNetwork = false;
    auto r = ConnectionBuilder::build(in);
    QVERIFY(r.ok);
    QVERIFY(!r.needStaticIp);
}

// ============================================================================
// NotificationParser
// ============================================================================

void TestPackets::notificationParser_knownCodes()
{
    // 密码/账号类错误 → permanent（不应自动重试）
    auto r = NotificationParser::describe(QStringLiteral("userid error 1"));
    QCOMPARE(r.description, QStringLiteral("账号不存在"));
    QVERIFY(!r.sleepRequired);
    QVERIFY(r.permanent);

    r = NotificationParser::describe(QStringLiteral("userid error 2"));
    QCOMPARE(r.description, QStringLiteral("用户名或密码错误"));
    QVERIFY(r.permanent);

    r = NotificationParser::describe(QStringLiteral("userid error 4"));
    QCOMPARE(r.description, QStringLiteral("该账号可能已过期"));
    QVERIFY(r.permanent);

    r = NotificationParser::describe(QStringLiteral("Authentication Fail ErrCode=11"));
    QCOMPARE(r.description, QStringLiteral("不允许进行RADIUS认证"));
    QVERIFY(r.permanent);

    r = NotificationParser::describe(QStringLiteral("Authentication Fail ErrCode=30"));
    QCOMPARE(r.description, QStringLiteral("该账号流量/时长已用尽"));
    QVERIFY(r.permanent);

    // 夜间禁网 → sleepRequired，且非 permanent
    r = NotificationParser::describe(QStringLiteral("Authentication Fail ErrCode=16"));
    QCOMPARE(r.description, QStringLiteral("当前时段禁止上网，程序将休眠等待"));
    QVERIFY(r.sleepRequired);
    QVERIFY(!r.permanent);
}

void TestPackets::notificationParser_simpleErrors()
{
    // flowover → permanent
    auto r = NotificationParser::describe(QStringLiteral("flowover"));
    QCOMPARE(r.description, QStringLiteral("流量已用尽"));
    QVERIFY(r.permanent);

    // AdminReset / In use / Mac,IP → 暂时性，保留自动重试
    r = NotificationParser::describe(QStringLiteral("AdminReset"));
    QCOMPARE(r.description, QStringLiteral("管理员已重置连接"));
    QVERIFY(!r.permanent);

    r = NotificationParser::describe(QStringLiteral("In use"));
    QCOMPARE(r.description, QStringLiteral("该账号正在使用中（多设备在线）"));
    QVERIFY(!r.permanent);

    r = NotificationParser::describe(QStringLiteral("Mac, IP, NASip, PORT"));
    QCOMPARE(r.description, QStringLiteral("当前IP/MAC地址不允许登录"));
    QVERIFY(!r.permanent);
}

void TestPackets::notificationParser_unknown()
{
    // 无法识别 → description 为空，调用方仅记录原文
    auto r = NotificationParser::describe(QStringLiteral("Some unknown server message"));
    QVERIFY(r.description.isEmpty());
    QVERIFY(!r.sleepRequired);
    QVERIFY(!r.permanent);

    // prefix 匹配但 code 未知 → 不再尝试其他 pattern，同样视为未识别
    r = NotificationParser::describe(QStringLiteral("userid error 999"));
    QVERIFY(r.description.isEmpty());
}

// ============================================================================
// 新增回归用例：解析 / 校验 / 队列 / 配置回环
// ============================================================================

void TestPackets::normalizeMac_invalidHex()
{
    QCOMPARE(ByteUtils::normalizeMac(QStringLiteral("ZZZZZZZZZZZZ")), QString());        // 全非 hex
    QCOMPARE(ByteUtils::normalizeMac(QStringLiteral("00-11-22-33-44-ZZ")), QString());  // 段内非法字符
    QCOMPARE(ByteUtils::normalizeMac(QStringLiteral("0011223344GG")), QString());
    QCOMPARE(ByteUtils::normalizeMac(QStringLiteral(" 001122334455 ")), QStringLiteral("001122334455"));  // 首尾空白容忍
}

void TestPackets::parseEapPacket_validRequest()
{
    const QByteArray eapBody = makeEapBody(EAP_CODE_REQUEST, 0x07,
                                           QByteArrayLiteral("test"), true, EAP_TYPE_IDENTITY);
    const QByteArray frame = makeEapFrame(EAPOL_TYPE_EAP_PACKET, eapBody);

    EAPHeader hdr{};
    QByteArray payload;
    QVERIFY(EapolPacket::parseEapPacket(frame, &hdr, &payload));
    QCOMPARE(static_cast<int>(hdr.code), static_cast<int>(EAP_CODE_REQUEST));
    QCOMPARE(static_cast<int>(hdr.id), 0x07);
    QCOMPARE(static_cast<int>(hdr.type), static_cast<int>(EAP_TYPE_IDENTITY));
    QCOMPARE(payload, QByteArrayLiteral("test"));
}

void TestPackets::parseEapPacket_responseMd5()
{
    // Response MD5-Challenge：payload 首字节为 value-size（16），随后为挑战
    const QByteArray chal = QByteArray(16, static_cast<char>(0x5A));
    QByteArray eapPayload;
    eapPayload.append(static_cast<char>(16));
    eapPayload.append(chal);
    const QByteArray eapBody = makeEapBody(EAP_CODE_RESPONSE, 0x0A, eapPayload, true, EAP_TYPE_MD5_CHALLENGE);
    const QByteArray frame = makeEapFrame(EAPOL_TYPE_EAP_PACKET, eapBody);

    EAPHeader hdr{};
    QByteArray payload;
    QVERIFY(EapolPacket::parseEapPacket(frame, &hdr, &payload));
    QCOMPARE(static_cast<int>(hdr.code), static_cast<int>(EAP_CODE_RESPONSE));
    QCOMPARE(static_cast<int>(hdr.type), static_cast<int>(EAP_TYPE_MD5_CHALLENGE));
    QCOMPARE(payload, eapPayload);
}

void TestPackets::parseEapPacket_successFrame()
{
    // Success：无 type 字节（EAP len=4）→ payload 为空
    const QByteArray frame = makeEapFrame(EAPOL_TYPE_EAP_PACKET,
                                          makeEapBody(EAP_CODE_SUCCESS, 0x01));
    EAPHeader hdr{};
    QByteArray payload;
    QVERIFY(EapolPacket::parseEapPacket(frame, &hdr, &payload));
    QCOMPARE(static_cast<int>(hdr.code), static_cast<int>(EAP_CODE_SUCCESS));
    QVERIFY(payload.isEmpty());

    // Success 后跟随 1 字节（异常/扩展帧）：无 type 结构应切出 1 字节 payload
    // （回归护栏：旧实现按 len-5 计算会漏掉这 1 字节）
    const QByteArray frame2 = makeEapFrame(EAPOL_TYPE_EAP_PACKET,
                                           makeEapBody(EAP_CODE_SUCCESS, 0x02,
                                                        QByteArray(1, static_cast<char>(0xAA))));
    EAPHeader hdr2{};
    QByteArray payload2;
    QVERIFY(EapolPacket::parseEapPacket(frame2, &hdr2, &payload2));
    QCOMPARE(payload2, QByteArray(1, static_cast<char>(0xAA)));
}

void TestPackets::parseEapPacket_malformed()
{
    EAPHeader hdr{};
    QByteArray payload;

    // 长度不足
    QVERIFY(!EapolPacket::parseEapPacket(QByteArray(10, '\0'), &hdr, &payload));

    // 非 EAPOL 以太网类型（IPv4 0x0800）
    QByteArray bad = makeEapFrame(EAPOL_TYPE_EAP_PACKET,
                                  makeEapBody(EAP_CODE_REQUEST, 1, {}, true, EAP_TYPE_IDENTITY));
    bad[12] = 0x08; bad[13] = 0x00;
    QVERIFY(!EapolPacket::parseEapPacket(bad, &hdr, &payload));

    // EAPOL 版本不符
    QByteArray badVer = makeEapFrame(EAPOL_TYPE_EAP_PACKET,
                                     makeEapBody(EAP_CODE_REQUEST, 1, {}, true, EAP_TYPE_IDENTITY));
    badVer[14] = 0x02;
    QVERIFY(!EapolPacket::parseEapPacket(badVer, &hdr, &payload));

    // EAPOL-Start（非 EAP-Packet）
    const QByteArray start = makeEapFrame(EAPOL_TYPE_EAPOL_START, QByteArray());
    QVERIFY(!EapolPacket::parseEapPacket(start, &hdr, &payload));

    // Request 缺 type 字节（EAP len=4）
    const QByteArray noType = makeEapFrame(EAPOL_TYPE_EAP_PACKET, makeEapBody(EAP_CODE_REQUEST, 1));
    QVERIFY(!EapolPacket::parseEapPacket(noType, &hdr, &payload));
}

void TestPackets::build_invalidIpRejected()
{
    // IPv4 段越界
    auto in = makeConnectInput();
    in.ip = QStringLiteral("999.1.1.1");
    auto r = ConnectionBuilder::build(in);
    QVERIFY(!r.ok);
    QVERIFY(r.error.contains(QStringLiteral("格式无效")));

    // 段数不足（"255.255.0" 会被部分解析器当作 255.255.0.0 接受，此处必须拒绝）
    in = makeConnectInput();
    in.mask = QStringLiteral("255.255.0");
    r = ConnectionBuilder::build(in);
    QVERIFY(!r.ok);

    // 非数字 DNS
    in = makeConnectInput();
    in.dns2 = QStringLiteral("abc");
    r = ConnectionBuilder::build(in);
    QVERIFY(!r.ok);

    // 合法值仍通过
    in = makeConnectInput();
    r = ConnectionBuilder::build(in);
    QVERIFY(r.ok);
}

void TestPackets::notificationParser_edgeCases()
{
    // "userid error" 与 "ErrCode=" 前缀共享同一张 code 表：16 均可睡眠重试
    auto r = NotificationParser::describe(QStringLiteral("userid error 16"));
    QCOMPARE(r.description, QStringLiteral("当前时段禁止上网，程序将休眠等待"));
    QVERIFY(r.sleepRequired);
    QVERIFY(!r.permanent);

    // 前导零码归一化：ErrCode=05 == 5（账号停用）
    r = NotificationParser::describe(QStringLiteral("Authentication Fail ErrCode=05"));
    QCOMPARE(r.description, QStringLiteral("该账号已被停用"));
    QVERIFY(r.permanent);

    // 尾部空格（服务器报文常见）
    r = NotificationParser::describe(QStringLiteral("userid error 3 "));
    QCOMPARE(r.description, QStringLiteral("用户名或密码错误"));

    // "0" 是有效码：不能把全零码归一化成空串
    r = NotificationParser::describe(QStringLiteral("userid error 0"));
    QCOMPARE(r.description, QStringLiteral("用户名或密码错误"));
}

void TestPackets::deferredQueue_order()
{
    DeferredSignalQueue<int> q;
    QVERIFY(q.isEmpty());

    q.append(1);
    q.append(2);
    q.append(3);
    QVector<int> seen;
    q.flush([&seen](int v) { seen.append(v); });
    QCOMPARE(seen, QVector<int>({1, 2, 3}));
    QVERIFY(q.isEmpty());

    // clear 后无残留
    q.append(42);
    q.clear();
    QVERIFY(q.isEmpty());
}

void TestPackets::credential_roundtrip()
{
    const QByteArray enc = Credential::encryptPassword(QStringLiteral("p@ss w0rd 中文"));
    QVERIFY(!enc.isEmpty());
    QCOMPARE(Credential::decryptPassword(enc), QStringLiteral("p@ss w0rd 中文"));

    // 空输入安全
    QVERIFY(Credential::encryptPassword(QString()).isEmpty());
    QVERIFY(Credential::decryptPassword(QByteArray()).isEmpty());
}

void TestPackets::configManager_roundtrip()
{
    // 注：用普通 mkpath 工作目录而非 QTemporaryDir——某些受控环境下
    // QTemporaryDir 创建的目录对本进程后续写入不可见（QSettings 写盘静默失败）
    const QString workDir = QDir::currentPath() + QStringLiteral("/cfg_roundtrip_workdir");
    QVERIFY(QDir().mkpath(workDir));
    const QString path = workDir + QStringLiteral("/config.ini");

    AppConfig cfg;
    cfg.username      = QStringLiteral("stu2026");
    cfg.password      = QStringLiteral("secret!");
    cfg.host          = QStringLiteral("s.scut.edu.cn");
    cfg.dns           = QStringLiteral("202.38.193.33");
    cfg.backupDns     = QStringLiteral("8.8.8.8");
    cfg.interfaceName = QStringLiteral("\\Device\\NPF_{GUID}");
    cfg.manualMac     = QStringLiteral("00:11:22:33:44:55");
    cfg.manualIp      = QStringLiteral("192.168.1.100");
    cfg.manualMask    = QStringLiteral("255.255.255.0");
    cfg.manualGateway = QStringLiteral("192.168.1.1");
    cfg.savePassword  = true;
    cfg.autoSetNetwork = true;
    cfg.autoStart      = true;
    cfg.autoConnect    = true;

    ConfigManager::save(path, cfg);

    const AppConfig loaded = ConfigManager::load(path);
    QCOMPARE(loaded.username, cfg.username);
    QCOMPARE(loaded.password, cfg.password);   // DPAPI 加密后应能解密回原值
    QCOMPARE(loaded.host, cfg.host);
    QCOMPARE(loaded.dns, cfg.dns);
    QCOMPARE(loaded.backupDns, cfg.backupDns);
    QCOMPARE(loaded.interfaceName, cfg.interfaceName);
    QCOMPARE(loaded.manualMac, cfg.manualMac);
    QCOMPARE(loaded.manualIp, cfg.manualIp);
    QCOMPARE(loaded.manualMask, cfg.manualMask);
    QCOMPARE(loaded.manualGateway, cfg.manualGateway);
    QVERIFY(loaded.savePassword);
    QVERIFY(loaded.autoSetNetwork);
    QVERIFY(loaded.autoStart);
    QVERIFY(loaded.autoConnect);

    // 清理工作目录（失败时忽略，不影响断言结果）
    QDir(workDir).removeRecursively();
}

void TestPackets::configManager_legacyBase64Fallback()
{
    const QString workDir = QDir::currentPath() + QStringLiteral("/cfg_roundtrip_workdir");
    QVERIFY(QDir().mkpath(workDir));
    const QString path = workDir + QStringLiteral("/config.ini");

    // 模拟旧版本：password = Base64(明文)，DPAPI 解密必然失败 → 应回退为直接 Base64 解码。
    // 注意：旧实现写入的是无组默认段 [General]（显式 beginGroup("General") 在 Qt 6.11
    // 会转义为 [%General]，与历史格式不兼容——见 config_manager.cpp load 内注释）
    {
        QSettings s(path, QSettings::IniFormat);
        s.setValue("password", QStringLiteral("legacyPwd").toLatin1().toBase64());
        s.setValue("username", QStringLiteral("oldUser"));
    }

    const AppConfig loaded = ConfigManager::load(path);
    QCOMPARE(loaded.username, QStringLiteral("oldUser"));
    QCOMPARE(loaded.password, QStringLiteral("legacyPwd"));
    QVERIFY(loaded.savePassword);

    // 清理工作目录（失败时忽略，不影响断言结果）
    QDir(workDir).removeRecursively();
}

QTEST_APPLESS_MAIN(TestPackets)
#include "tst_packets.moc"
