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
    m_md5Result = md5Data;
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
    qint64 written = m_socket->write(data, static_cast<qint64>(len));
    if (written < 0) {
        log(LogLevel::Error, QStringLiteral("UDP 发送失败: ") + m_socket->errorString());
        // 不在此处 emit heartbeatFailed()——心跳失败统一由 onHeartbeatTimeout 超时机制
        // 检测，避免因瞬时 write 错误加速触发 3 次断连阈值
        return;
    }
    if (written != static_cast<qint64>(len)) {
        log(LogLevel::Warning, QStringLiteral("UDP 部分发送: %1/%2 字节").arg(written).arg(len));
    }
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
        log(LogLevel::Error, QStringLiteral("无法发送 MiscInfo: 本机 MAC 或 IP 地址未获取，"
                                             "请检查网卡是否已连接网络"));
        return;
    }

    auto info = DrcomPacket::buildMiscInfo(m_config, m_flux.data());
    m_cks32 = DrcomPacket::computeCks32(reinterpret_cast<uint8_t*>(&info), sizeof(info));

    sendUdpPacket(reinterpret_cast<const char*>(&info), sizeof(info));
}

void UdpProcess::sendAlive() {
    // 构造 Alive 包的 md5_data 字段：前 4 字节 = cks32，后 12 字节 = MD5 结果 [4..15]
    std::array<uint8_t, DRCOM_ALIVE_MD5_SIZE> aliveMd5{};
    if (m_md5Result.size() >= DRCOM_ALIVE_MD5_SIZE) {
        memcpy(aliveMd5.data(), &m_cks32, 4);
        memcpy(aliveMd5.data() + 4, m_md5Result.constData() + 4, DRCOM_ALIVE_MD5_SIZE - 4);
    }
    auto alive = DrcomPacket::buildAlive(aliveMd5.data(), m_decryptedInfo.data());
    sendUdpPacket(reinterpret_cast<const char*>(&alive), sizeof(alive));
}

void UdpProcess::sendMiscHeartbeat(uint8_t hbSubtype) {
    ++m_counter;
    if (hbSubtype == DRCOM_HB_CLIENT_QUERY) {
        for (auto& b : m_rnd)
            b = static_cast<uint8_t>(QRandomGenerator::global()->bounded(256));
    }

    auto hb = DrcomPacket::buildMiscHeartbeat(m_counter, hbSubtype,
                                               m_rnd.data(), m_flux.data(),
                                               hbSubtype == DRCOM_HB_CLIENT_CONFIRM ? m_config.localIp : nullptr);

    if (hbSubtype == DRCOM_HB_CLIENT_CONFIRM)
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
            sendMiscHeartbeat(DRCOM_HB_CLIENT_QUERY);
            break;

        case DRCOM_SUBTYPE_MISC_HEARTBEAT: {
            if (data.size() < static_cast<int>(sizeof(DrcomMiscHeartbeatResponse)))
                break;
            const DrcomMiscHeartbeatResponse* hbResp =
                reinterpret_cast<const DrcomMiscHeartbeatResponse*>(data.constData());
            if (hbResp->hb_subtype == DRCOM_HB_SUBTYPE_RESPONSE1) {
                if (data.size() >= 20)
                    memcpy(m_flux.data(), data.constData() + 16, m_flux.size());
                sendMiscHeartbeat(DRCOM_HB_CLIENT_CONFIRM);
            } else if (hbResp->hb_subtype == DRCOM_HB_SUBTYPE_ACK) {
                m_timeoutTimer->stop();
                emit heartbeatOk();
            }
            break;
        }
        default:
            break;
        }
    }
}
