#include "udp_process.h"
#include "constants.h"
#include "network.h"
#include <QNetworkDatagram>
#include <QDateTime>
#include <QHostInfo>
#include <QRandomGenerator>
#include <algorithm>
#include <cstring>

// ============================================================================
// 辅助函数 (匿名 namespace)
// ============================================================================
namespace {

// 计算 MiscInfo 包的 32 位校验和
uint32_t computeCks32(uint8_t* data, size_t len) {
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

// 计算心跳包 16 位校验和
uint32_t computeCks16(uint8_t* data, size_t len) {
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

// DrCOM 私有加密/解密（对称）：按字节索引 i 进行循环左移 (i & 7) 位
void decryptDrcom(const uint8_t* encrypted, uint8_t* output, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        int shift = static_cast<int>(i) & 0x07;
        output[i] = ((encrypted[i] << shift) | (encrypted[i] >> (8 - shift))) & 0xFF;
    }
}

} // anonymous namespace

// ============================================================================
// 构造 / 析构
// ============================================================================

UdpProcess::UdpProcess(QObject* parent)
    : QObject(parent) {}

UdpProcess::~UdpProcess() { stop(); }

void UdpProcess::setConfig(const AuthConfig& config)
{
    QMutexLocker locker(&m_mutex);
    m_config = config;
}

void UdpProcess::setMd5Data(const QByteArray& md5Data)
{
    QMutexLocker locker(&m_mutex);
    m_md5Data = md5Data;
}

void UdpProcess::log(LogLevel level, const QString& msg)
{
    emit logMessage(msg, static_cast<int>(level));
}

// ============================================================================
// 发包辅助
// ============================================================================

void UdpProcess::sendUdpPacket(const char* data, size_t len)
{
    m_socket->write(data, static_cast<qint64>(len));
    m_timeoutTimer->start();
}

// ============================================================================
// start / stop
// ============================================================================

void UdpProcess::start() {
    QMutexLocker locker(&m_mutex);

    if (!m_heartbeatTimer) {
        m_heartbeatTimer = new QTimer(this);
        m_heartbeatTimer->setInterval(DRCOM_HEARTBEAT_INTERVAL);
        connect(m_heartbeatTimer, &QTimer::timeout, this, &UdpProcess::sendHeartbeat, Qt::UniqueConnection);
    }
    if (!m_timeoutTimer) {
        m_timeoutTimer = new QTimer(this);
        m_timeoutTimer->setInterval(DRCOM_HEARTBEAT_TIMEOUT);
        m_timeoutTimer->setSingleShot(true);
        connect(m_timeoutTimer, &QTimer::timeout, this, &UdpProcess::onHeartbeatTimeout, Qt::UniqueConnection);
    }
    if (!m_socket) {
        m_socket = new QUdpSocket(this);
        connect(m_socket, &QUdpSocket::readyRead, this, &UdpProcess::onReadyRead, Qt::UniqueConnection);
    }

    QHostInfo hostInfo = QHostInfo::fromName(m_config.host);
    if (hostInfo.addresses().isEmpty()) {
        log(LogLevel::Error, "无法解析服务器地址: " + m_config.host);
        return;
    }
    QHostAddress serverAddr = hostInfo.addresses().first();

    m_socket->connectToHost(serverAddr, DRCOM_UDP_PORT);
    log(LogLevel::Info, QString("连接 UDP 服务器: %1:%2").arg(serverAddr.toString()).arg(DRCOM_UDP_PORT));

    m_running = true;
    m_counter = 0;
    m_flux.fill(0);
    m_rnd.fill(0);
    m_decryptedInfo.fill(0);

    emit stateChanged("运行中", "开始UDP握手");
    sendMiscAlive();
}

void UdpProcess::stop() {
    QMutexLocker locker(&m_mutex);

    m_running = false;
    if (m_heartbeatTimer) {
        m_heartbeatTimer->stop();
        delete m_heartbeatTimer;
        m_heartbeatTimer = nullptr;
    }
    if (m_timeoutTimer) {
        m_timeoutTimer->stop();
        delete m_timeoutTimer;
        m_timeoutTimer = nullptr;
    }
    if (m_socket) {
        m_socket->close();
        delete m_socket;
        m_socket = nullptr;
    }
}

// ============================================================================
// 发包函数
// ============================================================================

void UdpProcess::sendMiscAlive() {
    DrcomMiscAlive pkt = {};
    pkt.magic  = DRCOM_UDP_MAGIC;
    pkt.seq    = 0x00;
    pkt.length = DRCOM_MISC_ALIVE_SIZE;
    pkt.flag   = DRCOM_SUBTYPE_MISC_ALIVE;

    sendUdpPacket(reinterpret_cast<const char*>(&pkt), sizeof(pkt));
}

void UdpProcess::sendMiscInfo() {
    if (Network::isMacZero(m_config.localMac) || Network::isIpZero(m_config.localIp)) {
        log(LogLevel::Error, QString("错误: MAC或IP为零! MAC=%1 IP=%2")
            .arg(QByteArray(reinterpret_cast<const char*>(m_config.localMac), 6).toHex())
            .arg(QByteArray(reinterpret_cast<const char*>(m_config.localIp), 4).toHex()));
        return;
    }

    DrcomMiscInfo info = {};

    info.magic   = DRCOM_UDP_MAGIC;
    info.subtype = 0x01;
    info.length  = DRCOM_MISC_INFO_LENGTH;
    info.flag    = DRCOM_MISC_INFO_FLAG;

    QByteArray userUtf8 = m_config.username.toUtf8();
    int usernameLen = static_cast<int>(std::min<size_t>(userUtf8.size(), DRCOM_MISC_MAX_USERNAME_LEN));
    info.username_len = static_cast<uint8_t>(usernameLen);

    memcpy(info.src_mac,  m_config.localMac, 6);
    memcpy(info.src_ip,   m_config.localIp,  4);
    memcpy(info.unknown1, DRCOM_MISC_UNKNOWN1.data(), DRCOM_MISC_UNKNOWN1.size());

    memcpy(info.flux,     m_flux.data(), m_flux.size());
    memcpy(info.cks32,    DRCOM_MISC_CKSPARAM.data(), DRCOM_MISC_CKSPARAM.size());

    // host_info (44 字节): username + hostname 拼接
    memcpy(info.host_info, userUtf8.constData(), usernameLen);
    int maxHostLen = DRCOM_MISC_HOST_INFO_SIZE - usernameLen;
    QByteArray hostUtf8 = m_config.hostname.toUtf8();
    int hostnameLen = static_cast<int>(std::min<size_t>(hostUtf8.size(), static_cast<size_t>(maxHostLen)));
    memcpy(info.host_info + usernameLen, hostUtf8.constData(), hostnameLen);

    // DNS (大端序)
    QHostAddress dnsAddr(m_config.dnsServer);
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

    uint32_t cks = computeCks32(reinterpret_cast<uint8_t*>(&info), sizeof(info));

    // cks32 低 4 字节覆盖 m_md5Data 的前 4 字节（协议要求）
    if (m_md5Data.size() >= 4)
        memcpy(m_md5Data.data(), &cks, 4);

    sendUdpPacket(reinterpret_cast<const char*>(&info), sizeof(info));
}

void UdpProcess::sendAlive() {
    DrcomAlive alive = {};

    alive.magic = DRCOM_ALIVE_MAGIC;

    if (m_md5Data.size() >= DRCOM_ALIVE_MD5_SIZE)
        memcpy(alive.md5_data, m_md5Data.data(), DRCOM_ALIVE_MD5_SIZE);

    memcpy(alive.info, m_decryptedInfo.data(), m_decryptedInfo.size());

    alive.timestamp = static_cast<uint16_t>(QDateTime::currentSecsSinceEpoch());

    sendUdpPacket(reinterpret_cast<const char*>(&alive), sizeof(alive));
}

void UdpProcess::sendMiscHeartbeat(uint8_t hbSubtype) {
    ++m_counter;
    if (hbSubtype == 0x01) {
        for (auto& b : m_rnd)
            b = static_cast<uint8_t>(QRandomGenerator::global()->bounded(256));
    }

    DrcomMiscHeartbeat hb = {};
    hb.magic      = DRCOM_UDP_MAGIC;
    hb.counter    = m_counter;
    hb.length     = DRCOM_HB_LENGTH;
    hb.flag       = DRCOM_HB_FLAG;
    hb.hb_subtype = hbSubtype;
    hb.fixed[0]   = DRCOM_HB_FIXED1;
    hb.fixed[1]   = DRCOM_HB_FIXED2;
    memcpy(hb.rnd,  m_rnd.data(),  m_rnd.size());
    memcpy(hb.flux, m_flux.data(), m_flux.size());

    if (hbSubtype == 0x03) {
        memcpy(hb.local_ip, m_config.localIp, 4);
        computeCks16(reinterpret_cast<uint8_t*>(&hb), sizeof(hb));
    }

    sendUdpPacket(reinterpret_cast<const char*>(&hb), sizeof(hb));
}

// ============================================================================
// 心跳定时器
// ============================================================================

void UdpProcess::sendHeartbeat() {
    QMutexLocker locker(&m_mutex);
    if (m_running)
        sendAlive();
}

void UdpProcess::onHeartbeatTimeout() {
    QMutexLocker locker(&m_mutex);
    if (!m_running) return;
    sendAlive();
    emit heartbeatFailed();
}

// ============================================================================
// 收包处理
// ============================================================================

void UdpProcess::onReadyRead() {
    QMutexLocker locker(&m_mutex);

    while (m_socket->hasPendingDatagrams()) {
        QByteArray data = m_socket->receiveDatagram().data();

        if (data.size() < static_cast<int>(sizeof(DrcomUdpHeader)))
            continue;

        const DrcomUdpHeader* hdr = reinterpret_cast<const DrcomUdpHeader*>(data.constData());
        if (hdr->magic != DRCOM_UDP_MAGIC)
            continue;

        m_timeoutTimer->stop();

        switch (hdr->subtype) {
        case DRCOM_SUBTYPE_MISC_RESPONSE_ALIVE: {
            if (data.size() >= static_cast<int>(sizeof(DrcomMiscResponseAlive)))
                memcpy(m_flux.data(), data.constData() + 8, m_flux.size());
            sendMiscInfo();
            break;
        }
        case DRCOM_SUBTYPE_MISC_RESPONSE_INFO: {
            if (data.size() >= static_cast<int>(sizeof(DrcomMiscResponseInfo))) {
                decryptDrcom(reinterpret_cast<const uint8_t*>(data.constData() + 16),
                             m_decryptedInfo.data(), m_decryptedInfo.size());
                log(LogLevel::Info, "解密信息: " +
                    QByteArray(reinterpret_cast<const char*>(m_decryptedInfo.data()),
                               static_cast<int>(m_decryptedInfo.size())).toHex());
                m_heartbeatTimer->start();
                emit stateChanged("在线", "心跳稳定");
                sendAlive();
            }
            break;
        }
        case DRCOM_SUBTYPE_MISC_HEARTBEAT_ALIVE:
            sendMiscHeartbeat(0x01);
            break;

        case DRCOM_SUBTYPE_MISC_HEARTBEAT: {
            if (data.size() < static_cast<int>(sizeof(DrcomMiscHeartbeatResponse)))
                break;
            const DrcomMiscHeartbeatResponse* hbResp =
                reinterpret_cast<const DrcomMiscHeartbeatResponse*>(data.constData());
            if (hbResp->hb_subtype == DRCOM_HB_SUBTYPE_RESPONSE1) {
                if (data.size() >= 20)
                    memcpy(m_flux.data(), data.constData() + 16, m_flux.size());
                sendMiscHeartbeat(0x03);
            } else if (hbResp->hb_subtype == DRCOM_HB_SUBTYPE_ACK) {
                m_timeoutTimer->stop();
                log(LogLevel::Info, "心跳周期完成");
            }
            break;
        }
        default:
            break;
        }
    }
}
