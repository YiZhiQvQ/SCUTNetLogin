#include "udp/udp_process.h"
#include "core/byte_utils.h"
#include "core/constants.h"
#include "udp/drcom_packet.h"
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

// ============================================================================
// 信号缓冲（持锁期间仅缓冲，解锁后统一发出 — 与 EapProcess 模式一致）
// ============================================================================

void UdpProcess::log(LogLevel level, const QString& msg)
{
    m_pending.append({PendingSignal::Kind::Log, QString(), msg, static_cast<int>(level)});
}

void UdpProcess::deferStateChanged(const QString& state, const QString& msg)
{
    m_pending.append({PendingSignal::Kind::StateChanged, state, msg, 0});
}

void UdpProcess::deferOnline()
{
    m_pending.append({PendingSignal::Kind::Online, QString(), QString(), 0});
}

void UdpProcess::deferHeartbeatFailed()
{
    m_pending.append({PendingSignal::Kind::HeartbeatFailed, QString(), QString(), 0});
}

void UdpProcess::deferHeartbeatOk()
{
    m_pending.append({PendingSignal::Kind::HeartbeatOk, QString(), QString(), 0});
}

void UdpProcess::flushPending()
{
    m_pending.flush([this](const PendingSignal& p) {
        switch (p.kind) {
        case PendingSignal::Kind::Log:
            emit logMessage(p.msg, p.logLevel);
            break;
        case PendingSignal::Kind::StateChanged:
            emit stateChanged(p.state, p.msg);
            break;
        case PendingSignal::Kind::Online:
            emit online();
            break;
        case PendingSignal::Kind::HeartbeatFailed:
            emit heartbeatFailed();
            break;
        case PendingSignal::Kind::HeartbeatOk:
            emit heartbeatOk();
            break;
        }
    });
}

// ============================================================================
// 发包辅助
// ============================================================================

void UdpProcess::sendUdpPacket(const char* data, size_t len)
{
    qint64 written = m_socket->write(data, static_cast<qint64>(len));
    // 发送失败/部分发送【静默】处理：
    // 本网络环境服务器不响应 UDP 心跳属常见现象（不影响上网），且心跳失败在
    // 上层本就是有意忽略（见 SessionManager::onHeartbeatFailed()），因此不在
    // 界面日志打发送失败信息（"UDP 部分发送 0/N"刷屏且无诊断价值）。
    // 仅保留超时判定（onHeartbeatTimeout，同样静默）。
    if (written < 0)
        return;
    m_timeoutTimer->start();
}

// ============================================================================
// start / stop
// ============================================================================

void UdpProcess::start()
{
    {
        QMutexLocker locker(&m_mutex);

        m_running = true;
        m_counter = 0;
        m_miscInfoRetryCount = 0;
        m_flux.fill(0);
        m_rnd.fill(0);
        m_decryptedInfo.fill(0);

        deferStateChanged(QStringLiteral("运行中"), QStringLiteral("正在解析服务器地址..."));

        // 代数计数器：使任何先前 start() 发起、尚未完成的 DNS 回调失效，
        // 避免重连场景下旧回调携带过期结果覆盖新会话
        const int generation = ++m_startGeneration;

        // 异步 DNS 查询，避免阻塞 UDP 工作线程
        QHostInfo::lookupHost(m_config.host, this, [this, generation](const QHostInfo& hostInfo) {
            QMutexLocker locker(&m_mutex);
            if (!m_running || generation != m_startGeneration)
                return;

            if (hostInfo.addresses().isEmpty()) {
                // 解析失败：仅记录错误。按项目设计（与心跳超时同理），UDP 会话
                // 建立失败不触发断连/重连——802.1X 认证已成功，网络本身可用。
                log(LogLevel::Error, QStringLiteral("无法解析服务器地址: ") + m_config.host);
                locker.unlock();
                flushPending();
                return;
            }
            QHostAddress serverAddr = hostInfo.addresses().first();

            m_socket->connectToHost(serverAddr, DRCOM_UDP_PORT);
            log(LogLevel::Info, QStringLiteral("连接 UDP 服务器: %1:%2").arg(serverAddr.toString()).arg(DRCOM_UDP_PORT));
            sendMiscAlive();
            locker.unlock();
            flushPending();
        });
    }
    flushPending();  // start() 同步段缓冲的 stateChanged 在此发出
}

void UdpProcess::stop()
{
    QMutexLocker locker(&m_mutex);

    ++m_startGeneration;   // 使进行中的 DNS 回调失效（stop 后不接受任何迟到结果）
    m_running = false;

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
    if (ByteUtils::isMacZero(m_config.localMac) || ByteUtils::isIpZero(m_config.localIp)) {
        // 观测层处理：本机 MAC/IP 未就绪时无法发 MiscInfo，会话将停滞
        // （EAP 已成功，网络本身可用，不影响上网）。限次重试，避免刷屏。
        const bool exhausted = m_miscInfoRetryCount >= DRCOM_MISC_INFO_MAX_RETRIES;
        log(exhausted ? LogLevel::Error : LogLevel::Warning,
            exhausted
                ? QStringLiteral("无法发送 MiscInfo: 本机 MAC/IP 仍未就绪，UDP 会话停滞")
                : QStringLiteral("无法发送 MiscInfo: 本机 MAC 或 IP 地址未获取，"
                                 "请检查网卡是否已连接网络，%1 秒后重试")
                      .arg(DRCOM_MISC_INFO_RETRY_INTERVAL / 1000));

        if (!exhausted) {
            ++m_miscInfoRetryCount;
            QTimer::singleShot(DRCOM_MISC_INFO_RETRY_INTERVAL, this, [this]() {
                QMutexLocker l(&m_mutex);
                if (!m_running || m_miscInfoRetryCount > DRCOM_MISC_INFO_MAX_RETRIES)
                    return;
                sendMiscInfo();
                l.unlock();
                flushPending();
            });
        }
        return;
    }

    m_miscInfoRetryCount = 0;   // 发送成功，重试计数清零

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
    locker.unlock();
    flushPending();   // 发送失败产生的缓冲日志在此发出
}

void UdpProcess::onHeartbeatTimeout() {
    QMutexLocker locker(&m_mutex);
    if (!m_running) return;
    sendAlive();
    deferHeartbeatFailed();   // 上层静默忽略（有意设计，见 SessionManager::onHeartbeatFailed）
    locker.unlock();
    flushPending();
}

// ============================================================================
// 收包处理
// ============================================================================

void UdpProcess::onReadyRead() {
    QMutexLocker locker(&m_mutex);

    // 运行态守卫：stop() 后 socket 关闭，但 Qt 缓冲区可能残留上一次会话的数据报，
    // 忽略它们，避免对已停止的会话发响应包
    if (!m_running)
        return;

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
            if (data.size() >= static_cast<int>(sizeof(DrcomMiscResponseAlive))) {
                const auto* resp = reinterpret_cast<const DrcomMiscResponseAlive*>(data.constData());
                memcpy(m_flux.data(), resp->flux, m_flux.size());
            }
            sendMiscInfo();
            break;
        }
        case DRCOM_SUBTYPE_MISC_RESPONSE_INFO: {
            if (data.size() >= static_cast<int>(sizeof(DrcomMiscResponseInfo))) {
                const auto* resp = reinterpret_cast<const DrcomMiscResponseInfo*>(data.constData());
                DrcomPacket::decryptDrcom(resp->encrypted,
                                          m_decryptedInfo.data(), m_decryptedInfo.size());
                log(LogLevel::Info, "解密信息: " +
                    QByteArray(reinterpret_cast<const char*>(m_decryptedInfo.data()),
                               static_cast<int>(m_decryptedInfo.size())).toHex());
                m_heartbeatTimer->start();
                deferOnline();
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
            const auto* hbResp = reinterpret_cast<const DrcomMiscHeartbeatResponse*>(data.constData());
            if (hbResp->hb_subtype == DRCOM_HB_SUBTYPE_RESPONSE1) {
                // 完整布局 (≥20 字节) 时才读取 flux；仅收到 6 字节基础头也可正常回应
                if (data.size() >= static_cast<int>(sizeof(DrcomMiscHeartbeatResponseFlux))) {
                    const auto* fluxResp =
                        reinterpret_cast<const DrcomMiscHeartbeatResponseFlux*>(data.constData());
                    memcpy(m_flux.data(), fluxResp->flux, m_flux.size());
                }
                sendMiscHeartbeat(DRCOM_HB_CLIENT_CONFIRM);
            } else if (hbResp->hb_subtype == DRCOM_HB_SUBTYPE_ACK) {
                m_timeoutTimer->stop();
                deferHeartbeatOk();
            }
            break;
        }
        default:
            break;
        }
    }

    locker.unlock();
    flushPending();
}
