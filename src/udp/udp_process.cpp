#include "udp/udp_process.h"
#include "core/byte_utils.h"
#include "core/constants.h"
#include "core/retry_policy.h"
#include "udp/drcom_packet.h"
#include <QNetworkDatagram>
#include <QHostInfo>
#include <QRandomGenerator>

namespace {

// DrCOM UDP 子类型 → 可读名称（调试输出用）。0x0b 之后的心跳包子类型见
// DRCOM_HB_SUBTYPE_*（仅 debug 回显，无协议语义）。
QString udpSubtypeName(uint8_t s)
{
    switch (s) {
    case DRCOM_SUBTYPE_MISC_ALIVE:           return QStringLiteral("MiscAlive(请求)");
    case DRCOM_SUBTYPE_MISC_RESPONSE_ALIVE:  return QStringLiteral("MiscResponseAlive(响应)");
    case DRCOM_SUBTYPE_MISC_INFO:            return QStringLiteral("MiscInfo");
    case DRCOM_SUBTYPE_MISC_RESPONSE_INFO:   return QStringLiteral("MiscResponseInfo(解密信息)");
    case DRCOM_SUBTYPE_MISC_HEARTBEAT_ALIVE: return QStringLiteral("HeartbeatAlive(响应)");
    case DRCOM_SUBTYPE_MISC_HEARTBEAT:       return QStringLiteral("Heartbeat");
    default: return QStringLiteral("0x%1").arg(s, 2, 16, QLatin1Char('0')).toUpper();
    }
}

} // namespace

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

void UdpProcess::setDebugLogEnabled(bool on)
{
    m_debugLog.store(on);
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
    if (m_debugLog.load()) {
        const QByteArray frame(data, static_cast<int>(len));
        QString label = QStringLiteral("UDP?");
        if (len >= 1 && static_cast<uint8_t>(data[0]) == DRCOM_ALIVE_MAGIC)
            label = QStringLiteral("Alive");
        else if (len >= sizeof(DrcomUdpHeader)
                 && static_cast<uint8_t>(data[0]) == DRCOM_UDP_MAGIC)
            label = udpSubtypeName(reinterpret_cast<const DrcomUdpHeader*>(data)->subtype);
        log(LogLevel::Info, QStringLiteral("[调试][UDP 发] %1 %2")
                                .arg(label, ByteUtils::hexDump(frame)));
    }

    const qint64 written = m_socket->write(data, static_cast<qint64>(len));
    // 发送失败/部分发送【静默】处理：
    // 本网络环境服务器不响应 UDP 心跳属常见现象（不影响上网），且心跳失败在
    // 上层本就是有意忽略（见 SessionManager::onHeartbeatFailed()），因此不在
    // 界面日志打发送失败信息（"UDP 部分发送 0/N"刷屏且无诊断价值）。
    // 但【看门狗必须照常武装】：否则 socket 进入错误态后既不重发也不超时，
    // 握手/心跳状态机会永久静默停摆（连一条日志都没有）。武装后由状态机按
    // "限次重发 → 放弃并记一条日志"推进。
    if (written < 0 && m_debugLog.load())
        log(LogLevel::Info, QStringLiteral("[调试] UDP 发送返回错误，仍武装看门狗继续推进"));
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
        m_handshakeDone = false;
        m_handshakeRetryCount = 0;
        m_heartbeatAlive = true;
        m_cks32 = 0;            // 上一会话的校验和不得残留（本轮 MAC/IP 未就绪时会被沿用）
        m_md5MissingLogged = false;
        m_flux.fill(0);
        m_rnd.fill(0);
        m_decryptedInfo.fill(0);
        // 注意：m_md5Result【不】在此复位——它由 SessionManager::onEapSuccess 在
        // 排队 start() 之前同步注入（setMd5Data），清掉会让 Alive 包丢失认证摘要。

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
            // 优先 IPv4：DrCOM 各包的地址字段都是 4 字节 IPv4（MiscInfo.src_ip、
            // heartbeat3 的 local_ip），若解析先给出 IPv6，会话会建立在一个协议
            // 根本无法表达的地址族上。仅在无 IPv4 时才退回第一个地址。
            QHostAddress serverAddr;
            const auto addresses = hostInfo.addresses();
            for (const QHostAddress& a : addresses) {
                if (a.protocol() == QAbstractSocket::IPv4Protocol) {
                    serverAddr = a;
                    break;
                }
            }
            if (serverAddr.isNull() && !addresses.isEmpty())
                serverAddr = addresses.first();

            m_socket->connectToHost(serverAddr, DRCOM_UDP_PORT);
            if (m_debugLog.load())
                log(LogLevel::Info, QStringLiteral("[调试] 连接 UDP 服务器: %1:%2").arg(serverAddr.toString()).arg(DRCOM_UDP_PORT));
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
            const int gen = m_startGeneration;
            QTimer::singleShot(DRCOM_MISC_INFO_RETRY_INTERVAL, this, [this, gen]() {
                QMutexLocker l(&m_mutex);
                // 代数守卫：若 stop→start（重连）落在 5 秒重试窗口内，旧一轮的重试
                // 不得打进新会话（EapProcess 的 2s 清理定时器用的是同一约定）
                if (!m_running || gen != m_startGeneration
                    || m_miscInfoRetryCount > DRCOM_MISC_INFO_MAX_RETRIES)
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
    } else if (!m_md5MissingLogged) {
        // 摘要未就绪：发出去的是全零 md5_data（服务器必然不认）。只提示一次，
        // 避免每 30s 刷屏；EAP 成功后 SessionManager 会重新注入摘要。
        m_md5MissingLogged = true;
        log(LogLevel::Warning,
            QStringLiteral("DrCOM 认证摘要未就绪，心跳包暂不含有效 md5（等待重新认证）"));
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

    if (m_handshakeDone) {
        // 会话已建立：重发 Alive 维持心跳。仅在首次失联时提示一次——看门狗每 10s 到期，
        // 逐次打日志会刷屏；上层对 heartbeatFailed 本就静默忽略（有意设计，见
        // SessionManager::onHeartbeatFailed），所以这是用户唯一的可见信号
        if (m_heartbeatAlive) {
            m_heartbeatAlive = false;
            log(LogLevel::Warning, QStringLiteral("DrCOM 心跳无响应，正在重试（不影响上网）"));
        }
        sendAlive();
        deferHeartbeatFailed();
    } else if (RetryPolicy::udpHandshakeOnTimeout(m_handshakeRetryCount,
                                                  DRCOM_HANDSHAKE_MAX_RETRIES)
               == RetryPolicy::UdpTimeoutAction::ResendMiscAlive) {
        // 握手未完成：正确动作是重发 MiscAlive，而非一个从未握手成功的会话的 Alive 包。
        // 历史缺陷：此处无条件 sendAlive()，而 m_heartbeatTimer 只在收到 MiscResponseInfo
        // 时才启动，导致服务器不响应时以 10s 节奏无限重发（且 m_decryptedInfo 全零，
        // 是半成品包）。阈值判据见 RetryPolicy::udpHandshakeOnTimeout（可单测）。
        ++m_handshakeRetryCount;
        sendMiscAlive();
    } else {
        // 重试次数用尽：不再发包，因而看门狗不会被重新武装、事件循环到此为止，
        // 这条日志也就只出现一次。不影响上网——EAP 成功即已放行端口。
        log(LogLevel::Warning,
            QStringLiteral("DrCOM 服务器未响应，UDP 会话未能建立，已停止心跳（不影响上网）"));
    }
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

    // 每轮上限（与 EapProcess::drainPackets 同一取舍）：持锁期间无限制处理数据报会让
    // 心跳超时判定、日志与状态信号长期阻塞；余量留给下一次 readyRead 事件。
    int processed = 0;
    while (processed < DRCOM_MAX_DATAGRAMS_PER_ROUND && m_socket->hasPendingDatagrams()) {
        ++processed;
        QByteArray data = m_socket->receiveDatagram().data();

        if (data.size() < static_cast<int>(sizeof(DrcomUdpHeader)))
            continue;

        const DrcomUdpHeader* hdr = reinterpret_cast<const DrcomUdpHeader*>(data.constData());
        if (hdr->magic != DRCOM_UDP_MAGIC)
            continue;

        if (m_debugLog.load()) {
            log(LogLevel::Info, QStringLiteral("[调试][UDP 收] %1 %2")
                                    .arg(udpSubtypeName(hdr->subtype), ByteUtils::hexDump(data)));
        }

        m_timeoutTimer->stop();
        // 服务器有响应即刷新握手重试预算：仅在"持续无响应"时才限次放弃，
        // 服务器偶发回包（链路抖动）不应被计入放弃条件
        m_handshakeRetryCount = 0;
        // 心跳健康度：失联后收到任何回包即视为恢复（同属"服务器在响应"，只在转变点各记一条）
        if (!m_heartbeatAlive) {
            m_heartbeatAlive = true;
            log(LogLevel::Info, QStringLiteral("DrCOM 心跳已恢复"));
        }

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
                if (m_debugLog.load())
                    log(LogLevel::Info, "[调试] 解密信息: " +
                        QByteArray(reinterpret_cast<const char*>(m_decryptedInfo.data()),
                                   static_cast<int>(m_decryptedInfo.size())).toHex());
                // 边沿触发：本分支会因服务器重传 / 重复握手而多次到达，一次性动作
                // （成功日志、online 信号、心跳定时器启动）只在首次执行——否则会重复
                // 刷屏并重复向上层宣告上线。m_handshakeDone 同时决定超时看门狗走哪条分支。
                if (!m_handshakeDone) {
                    m_handshakeDone = true;
                    // 成功路径的唯一可见输出：非调试模式下若不打这条，用户开了开关
                    // 也无从判断 UDP 会话到底有没有建起来（只有失败会说话）
                    log(LogLevel::Info,
                        QStringLiteral("DrCOM UDP 会话已建立，开始心跳保活（%1 秒间隔）")
                            .arg(DRCOM_HEARTBEAT_INTERVAL / 1000));
                    m_heartbeatTimer->start();
                    deferOnline();
                }
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
