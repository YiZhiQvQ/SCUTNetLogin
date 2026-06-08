#include "udp_process.h"
#include "constants.h"
#include "network.h"
#include "drcom_packet.h"
#include <QNetworkDatagram>
#include <QHostInfo>
#include <QRandomGenerator>

// ============================================================================
// 构造 / 析构
// ============================================================================

UdpProcess::UdpProcess(QObject* parent)
    : QObject(parent)
{
    m_socket = new QUdpSocket(this);
    connect(m_socket, &QUdpSocket::readyRead, this, &UdpProcess::onReadyRead, Qt::UniqueConnection);

    m_heartbeatTimer = new QTimer(this);
    m_heartbeatTimer->setInterval(DRCOM_HEARTBEAT_INTERVAL);
    connect(m_heartbeatTimer, &QTimer::timeout, this, &UdpProcess::sendHeartbeat, Qt::UniqueConnection);

    m_timeoutTimer = new QTimer(this);
    m_timeoutTimer->setInterval(DRCOM_HEARTBEAT_TIMEOUT);
    m_timeoutTimer->setSingleShot(true);
    connect(m_timeoutTimer, &QTimer::timeout, this, &UdpProcess::onHeartbeatTimeout, Qt::UniqueConnection);
}

UdpProcess::~UdpProcess()
{
    stop();
}

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

    m_running = true;
    m_counter = 0;
    m_flux.fill(0);
    m_rnd.fill(0);
    m_decryptedInfo.fill(0);

    emit stateChanged(QStringLiteral("运行中"), QStringLiteral("正在解析服务器地址..."));

    m_udpState = UdpState::WaitingAliveResponse;

    // 异步 DNS 查询，避免阻塞 UDP 工作线程
    QHostInfo::lookupHost(m_config.host, this, [this](const QHostInfo& hostInfo) {
        QMutexLocker locker(&m_mutex);
        if (!m_running) return;

        if (hostInfo.addresses().isEmpty()) {
            log(LogLevel::Error, QStringLiteral("无法解析服务器地址: ") + m_config.host);
            return;
        }
        QHostAddress serverAddr = hostInfo.addresses().first();

        m_socket->connectToHost(serverAddr, DRCOM_UDP_PORT);
        log(LogLevel::Info, QStringLiteral("连接 UDP 服务器: %1:%2").arg(serverAddr.toString()).arg(DRCOM_UDP_PORT));
        sendMiscAlive();
    });
}

void UdpProcess::stop() {
    QMutexLocker locker(&m_mutex);

    m_running = false;
    m_udpState = UdpState::Stopped;

    m_heartbeatTimer->stop();
    m_timeoutTimer->stop();
    m_socket->close();
}

// ============================================================================
// 发包函数
// ============================================================================

void UdpProcess::sendMiscAlive() {
    auto pkt = DrcomPacket::buildMiscAlive();
    sendUdpPacket(reinterpret_cast<const char*>(&pkt), sizeof(pkt));
}

void UdpProcess::sendMiscInfo() {
    if (Network::isMacZero(m_config.localMac) || Network::isIpZero(m_config.localIp)) {
        log(LogLevel::Error, QString("错误: MAC或IP为零! MAC=%1 IP=%2")
            .arg(QByteArray(reinterpret_cast<const char*>(m_config.localMac), 6).toHex())
            .arg(QByteArray(reinterpret_cast<const char*>(m_config.localIp), 4).toHex()));
        return;
    }

    auto info = DrcomPacket::buildMiscInfo(m_config, m_flux.data());
    uint32_t cks = DrcomPacket::computeCks32(reinterpret_cast<uint8_t*>(&info), sizeof(info));

    // cks32 低 4 字节覆盖 m_md5Data 的前 4 字节（协议要求）
    if (m_md5Data.size() >= 4)
        memcpy(m_md5Data.data(), &cks, 4);

    sendUdpPacket(reinterpret_cast<const char*>(&info), sizeof(info));
}

void UdpProcess::sendAlive() {
    auto alive = DrcomPacket::buildAlive(
        m_md5Data.size() >= DRCOM_ALIVE_MD5_SIZE ? reinterpret_cast<const uint8_t*>(m_md5Data.data()) : nullptr,
        m_decryptedInfo.data());
    sendUdpPacket(reinterpret_cast<const char*>(&alive), sizeof(alive));
}

void UdpProcess::sendMiscHeartbeat(uint8_t hbSubtype) {
    ++m_counter;
    if (hbSubtype == 0x01) {
        for (auto& b : m_rnd)
            b = static_cast<uint8_t>(QRandomGenerator::global()->bounded(256));
    }

    auto hb = DrcomPacket::buildMiscHeartbeat(m_counter, hbSubtype,
                                               m_rnd.data(), m_flux.data(),
                                               hbSubtype == 0x03 ? m_config.localIp : nullptr);

    if (hbSubtype == 0x03)
        DrcomPacket::computeCks16(reinterpret_cast<uint8_t*>(&hb), sizeof(hb));

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
            m_udpState = UdpState::WaitingInfoResponse;
            sendMiscInfo();
            break;
        }
        case DRCOM_SUBTYPE_MISC_RESPONSE_INFO: {
            if (data.size() >= static_cast<int>(sizeof(DrcomMiscResponseInfo))) {
                DrcomPacket::decryptDrcom(reinterpret_cast<const uint8_t*>(data.constData() + 16),
                                          m_decryptedInfo.data(), m_decryptedInfo.size());
                log(LogLevel::Info, "解密信息: " +
                    QByteArray(reinterpret_cast<const char*>(m_decryptedInfo.data()),
                               static_cast<int>(m_decryptedInfo.size())).toHex());
                m_heartbeatTimer->start();
                m_udpState = UdpState::Online;
                emit online();
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
