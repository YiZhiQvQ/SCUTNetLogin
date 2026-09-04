#include "eap/eap_process.h"
#include "core/constants.h"
#include "eap/eapol_packet.h"
#include "eap/notification_parser.h"
#include <QThread>
#include <QDebug>
#include <pcap.h>
#include <winsock2.h>

// ============================================================================
// 构造 / 析构
// ============================================================================

EapProcess::EapProcess(QObject* parent)
    : QObject(parent)
{
    memcpy(m_switchMac, EAPOL_MULTICAST_MAC.data(), EAPOL_MULTICAST_MAC.size());
}

EapProcess::~EapProcess()
{
    // 静默清理：对象销毁期间不再发信号（stop() 的 deferState/flushPending 在
    // 析构路径下没有接收者，且可能在跨线程删除时投递无意义的状态变更）。
    // 线程事件循环已退出，不存在并发槽调用，无需加锁。
    m_stopRequested = true;
    m_running       = false;
    if (m_pollTimer)
        m_pollTimer->stop();
    if (m_handle) {
        sendEapolLogoff();
        closeDevice();
    }
}

void EapProcess::setConfig(AuthConfig config)
{
    QMutexLocker locker(&m_mutex);
    m_config = std::move(config);
}

void EapProcess::log(LogLevel level, const QString& msg)
{
    m_pending.append({PendingSignal::Kind::Log, AuthState::Idle, msg,
                      QByteArray(), static_cast<int>(level)});
}

void EapProcess::deferState(AuthState state, const QString& msg, bool retryable)
{
    m_pending.append({PendingSignal::Kind::StateChanged, state, msg, QByteArray(), 0, retryable});
}

void EapProcess::deferEapSuccess(const QByteArray& md5)
{
    m_pending.append({PendingSignal::Kind::EapSuccess, AuthState::Idle, QString(), md5, 0});
}

void EapProcess::deferSleepRequired()
{
    m_pending.append({PendingSignal::Kind::SleepRequired, AuthState::Idle, QString(),
                      QByteArray(), 0});
}

void EapProcess::flushPending()
{
    m_pending.flush([this](const PendingSignal& p) {
        switch (p.kind) {
        case PendingSignal::Kind::StateChanged:
            emit stateChanged(p.state, p.msg, p.retryable);
            break;
        case PendingSignal::Kind::EapSuccess:
            emit eapSuccess(p.md5);
            break;
        case PendingSignal::Kind::SleepRequired:
            emit sleepRequired();
            break;
        case PendingSignal::Kind::Log:
            emit logMessage(p.msg, p.logLevel);
            break;
        }
    });
}

// ============================================================================
// pcap 设备管理
// ============================================================================

bool EapProcess::openDevice()
{
    // 防御：已有句柄先关闭（重复 start()/restart() 时不泄漏旧 pcap 句柄）
    if (m_handle)
        closeDevice();

    char errbuf[PCAP_ERRBUF_SIZE];
    QByteArray name = m_config.interfaceName.toLocal8Bit();
    m_handle = pcap_open_live(name.constData(), PCAP_SNAPLEN, 1, PCAP_READ_TIMEOUT, errbuf);
    if (!m_handle) {
        m_lastError = QString::fromLocal8Bit(errbuf);
        return false;
    }

    struct bpf_program fp;
    if (pcap_compile(m_handle, &fp, "ether proto 0x888e", 1, PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_setfilter(m_handle, &fp);
        pcap_freecode(&fp);
    } else {
        // 过滤器编译失败不致命：无过滤器也能工作（会收到全部流量），
        // 记入 UI 日志通道便于用户感知
        log(LogLevel::Warning, QStringLiteral("BPF 过滤器编译失败，将无过滤器运行: ")
                                   + QString::fromUtf8(pcap_geterr(m_handle)));
    }
    return true;
}

void EapProcess::closeDevice()
{
    if (m_handle) {
        pcap_close(m_handle);
        m_handle = nullptr;
    }
}

bool EapProcess::sendPacket(const uint8_t* data, size_t len)
{
    if (!m_handle)
        return false;
    return pcap_sendpacket(m_handle, data, static_cast<int>(len)) == 0;
}

QByteArray EapProcess::receivePacket()
{
    if (!m_handle)
        return QByteArray();

    struct pcap_pkthdr* header;
    const u_char* pkt_data;
    const int ret = pcap_next_ex(m_handle, &header, &pkt_data);
    if (ret == 1) {
        m_pcapErrorLogged = false;   // 恢复收包，重置错误节流标志
        // 注意：用 caplen 而非 len —— pcap 只保证 caplen 字节有效（snaplen 截断
        // 巨型帧时 len > caplen，按 len 拷贝会越界读）。
        return QByteArray(reinterpret_cast<const char*>(pkt_data), header->caplen);
    }

    // ret == -1 表示 pcap 错误（ret == 0 是普通超时，正常忽略）。
    // 错误通常是持续性的，同一错误只记录一次日志，避免每 20ms 轮询刷屏。
    if (ret == -1 && !m_pcapErrorLogged) {
        m_pcapErrorLogged = true;
        log(LogLevel::Warning, QStringLiteral("pcap 读取错误: ")
                                   + QString::fromLocal8Bit(pcap_geterr(m_handle)));
    }

    return QByteArray();
}

// ============================================================================
// 帧组装辅助函数
// ============================================================================

std::vector<uint8_t> EapProcess::buildEapolFrame(uint8_t eapolType, uint16_t eapolBodyLen) const
{
    return EapolPacket::buildEapolFrame(m_config.localMac, eapolType, eapolBodyLen);
}

// ============================================================================
// EAPOL Start / Logoff
// ============================================================================

void EapProcess::sendEapolStart()
{
    auto frame = buildEapolFrame(EAPOL_TYPE_EAPOL_START, 0);
    memcpy(reinterpret_cast<EthHeader*>(frame.data())->dest_mac,
           EAPOL_MULTICAST_MAC.data(), EAPOL_MULTICAST_MAC.size());
    sendPacket(frame.data(), frame.size());
}

void EapProcess::sendEapolLogoff()
{
    auto frame = buildEapolFrame(EAPOL_TYPE_EAPOL_LOGOFF, 0);
    memcpy(reinterpret_cast<EthHeader*>(frame.data())->dest_mac, m_switchMac, 6);
    sendPacket(frame.data(), frame.size());
}

// ============================================================================
// EAP Response (Identity / MD5-Challenge 统一入口)
// ============================================================================

void EapProcess::sendEapResponse(uint8_t eapType, uint8_t requestId,
                                  const QByteArray& payload, QByteArray& lastPacket)
{
    auto frame = EapolPacket::buildEapResponseFrame(m_config.localMac, m_switchMac,
                                                     eapType, requestId, payload);

    lastPacket = QByteArray(reinterpret_cast<const char*>(frame.data()),
                             static_cast<int>(frame.size()));
    sendPacket(frame.data(), frame.size());
}

// ============================================================================
// 收包解析
// ============================================================================

bool EapProcess::isMulticastMac(const uint8_t* mac)
{
    return (mac[0] & 0x01) != 0;
}

// ============================================================================
// 服务器通知解析 — 数据驱动查表已提取为纯函数 NotificationParser::describe
// （见 eap/notification_parser.h，可独立单测）。此处仅保留 EapProcess 侧副作用：
// 日志、夜间休眠（sleepRequired）、永久错误标记（retryable=false）。
// ============================================================================

void EapProcess::parseNotification(const QString& msg)
{
    log(LogLevel::Error, QStringLiteral("服务器通知: ") + msg);

    const NotificationParser::Result r = NotificationParser::describe(msg);
    if (r.description.isEmpty()) {
        // 未识别的通知：仅记录原文，保持原行为
        return;
    }

    log(LogLevel::Error, r.description);
    if (r.sleepRequired) {
        deferSleepRequired();
    } else if (r.permanent) {
        // 永久性错误：立即判定认证失败且不可自动重试。
        // 服务器在 Notification 后通常还会发送 EAP-Failure 帧，故同时记录
        // m_permanentFailure，使后续 Failure 帧的 Failed 状态也携带 retryable=false。
        m_permanentFailure = true;
        deferState(AuthState::Failed, QStringLiteral("认证失败"), /*retryable=*/false);
    }
}

// ============================================================================
// 超时重发
// ============================================================================

void EapProcess::onTimeout()
{
    switch (m_currentState) {
    case AuthState::SendingStart:
        sendEapolStart();
        break;
    case AuthState::SendingIdentity:
        if (!m_lastIdentityPacket.isEmpty())
            sendPacket(reinterpret_cast<const uint8_t*>(m_lastIdentityPacket.data()),
                       m_lastIdentityPacket.size());
        break;
    case AuthState::SendingMD5Challenge:
        if (!m_lastMd5Packet.isEmpty())
            sendPacket(reinterpret_cast<const uint8_t*>(m_lastMd5Packet.data()),
                       m_lastMd5Packet.size());
        break;
    default:
        break;
    }
}

// ============================================================================
// start / stop — 基于 QTimer 轮询
// ============================================================================

void EapProcess::start()
{
    QMutexLocker locker(&m_mutex);

    // 会话代数：使先前 start() 遗留的异步单发定时器（2 秒端口清理）失效
    const int gen = ++m_startGeneration;

    m_running       = true;
    m_stopRequested = false;
    m_currentState  = AuthState::Idle;
    m_permanentFailure = false;
    m_pcapErrorLogged  = false;

    if (!openDevice()) {
        deferState(AuthState::Failed, "打开网卡失败: " + m_lastError);
        locker.unlock();
        flushPending();
        return;
    }

    if (!m_pollTimer) {
        m_pollTimer = new QTimer(this);
        m_pollTimer->setInterval(20);
        connect(m_pollTimer, &QTimer::timeout, this, &EapProcess::onPollTimeout);
    }

    deferState(AuthState::SendingStart, "清理端口状态...");
    sendEapolLogoff();

    QTimer::singleShot(PORT_CLEANUP_WAIT, this, [this, gen]() {
        QMutexLocker l(&m_mutex);
        // 代数守卫：stop()/restart() 已换代 -> 本次 start() 的清理定时器作废，
        // 避免"断开后 2 秒内重连"时旧定时器对第二次会话发多余的 EAPOL-Start
        // 并把状态机打回 SendingStart
        if (gen != m_startGeneration || !m_running || m_stopRequested)
            return;

        deferState(AuthState::SendingStart, "发送探测请求...");
        sendEapolStart();
        m_currentState = AuthState::SendingStart;

        m_retransmitTimer.start();
        m_pollTimer->start();

        l.unlock();
        flushPending();
    });

    locker.unlock();
    flushPending();
}

void EapProcess::stop()
{
    QMutexLocker locker(&m_mutex);

    ++m_startGeneration;   // 使本会话遗留的异步单发定时器失效
    m_stopRequested = true;
    m_running       = false;

    if (m_pollTimer)
        m_pollTimer->stop();

    if (m_handle)
        sendEapolLogoff();

    closeDevice();

    m_currentState = AuthState::Stopped;
    deferState(AuthState::Stopped, "已断开");

    locker.unlock();
    flushPending();
}

void EapProcess::restart()
{
    // 自动重连专用：原子"复位 + 重启"。持锁完成设备复位（含 EAPOL-Logoff），
    // 不发射 Stopped 状态信号（重连期上层状态为 Authenticating，Stopped 会把
    // 应用状态机错误回退为 Disconnected）；设备关闭/重开完成后再调用 start()。
    {
        QMutexLocker locker(&m_mutex);

        ++m_startGeneration;   // 作废先前 start() 遗留的异步定时器
        m_stopRequested = true;
        m_running       = false;

        if (m_pollTimer)
            m_pollTimer->stop();

        if (m_handle)
            sendEapolLogoff();

        closeDevice();

        m_currentState = AuthState::Stopped;
    }

    // 重新加锁执行启动（start() 内部会取新代数并复位全部会话状态）
    start();
}

// ============================================================================
// 定时器槽 — 拆分为 drainPackets / processEapPacket / handleEapRequest / checkRetransmit
// ============================================================================

QVector<QByteArray> EapProcess::drainPackets()
{
    QVector<QByteArray> packets;
    // 每轮上限：pcap 读超时 1ms，恶意/异常 EAPOL 洪泛时无上限循环会长时间
    // 持锁占用 m_mutex 并阻塞日志与状态信号；余量留到下一轮 20ms 轮询。
    constexpr int kMaxPacketsPerRound = 64;
    while (packets.size() < kMaxPacketsPerRound) {
        QByteArray packet = receivePacket();
        if (packet.isEmpty())
            break;
        packets.append(std::move(packet));
    }
    return packets;
}

// 返回 false 表示致命错误，调用者须 unlock 后调用 stop()
bool EapProcess::processEapPacket(const QByteArray& packet)
{
    // 防御：捕获到短于以太网头的畸形帧时直接跳过，避免对 eth 头部越界读
    if (packet.size() < ETH_HEADER_SIZE)
        return true;

    const EthHeader* eth = reinterpret_cast<const EthHeader*>(packet.data());

    // 握手过程中嗅探交换机 MAC（后续单播用）
    if (m_currentState == AuthState::Idle || m_currentState == AuthState::SendingStart) {
        if (!isMulticastMac(eth->src_mac))
            memcpy(m_switchMac, eth->src_mac, 6);
    }

    EAPHeader eapHeader;
    QByteArray payload;
    if (!EapolPacket::parseEapPacket(packet, &eapHeader, &payload))
        return true;  // 非 EAP 包，跳过

    m_retransmitTimer.restart();
    m_retransmitLogCount = 0;   // 收到有效 EAP 包，重置重发日志节流计数

    if (eapHeader.code == EAP_CODE_REQUEST) {
        handleEapRequest(eapHeader, payload);
    } else if (eapHeader.code == EAP_CODE_SUCCESS) {
        if (m_currentState != AuthState::Authenticated) {
            log(LogLevel::Info, QStringLiteral("802.1X 认证成功！保持后台监听心跳..."));
            m_currentState = AuthState::Authenticated;
            deferState(AuthState::Authenticated, QStringLiteral("认证成功"));
            deferEapSuccess(m_md5Result);
        }
    } else if (eapHeader.code == EAP_CODE_FAILURE) {
        log(LogLevel::Error, QStringLiteral("认证被拒绝 (可能是冷却期，稍等1分钟再试)"));
        m_currentState = AuthState::Failed;
        // 若本次认证已被 Notification 判定为永久性错误（如密码错误），
        // 携带 retryable=false，上层停止自动重试
        deferState(AuthState::Failed, QStringLiteral("认证失败"), !m_permanentFailure);
        return false;  // 致命错误，调用者负责 stop()
    }

    return true;
}

void EapProcess::handleEapRequest(const EAPHeader& hdr, const QByteArray& payload)
{
    QByteArray userUtf8 = m_config.username.toUtf8();

    switch (hdr.type) {
    case EAP_TYPE_IDENTITY: {
        if (m_currentState != AuthState::Authenticated) {
            log(LogLevel::Info, QStringLiteral("收到 Identity 请求，正在回应..."));
            m_currentState = AuthState::SendingIdentity;
        }
        // 已认证状态下也静默回应（心跳检测），不写日志避免刷屏
        QByteArray idPayload = EapolPacket::buildIdentityPayload(userUtf8, m_config.localIp);
        sendEapResponse(EAP_TYPE_IDENTITY, hdr.id, idPayload, m_lastIdentityPacket);
        break;
    }
    case EAP_TYPE_MD5_CHALLENGE: {
        if (m_currentState != AuthState::Authenticated) {
            log(LogLevel::Info, QStringLiteral("收到 MD5 挑战，计算回应..."));
            m_currentState = AuthState::SendingMD5Challenge;
        }
        if (payload.size() > 1) {
            uint8_t md5Size = static_cast<uint8_t>(payload[0]);
            QByteArray challenge = payload.mid(1, md5Size);
            m_md5Result = EapolPacket::calculateMD5(hdr.id, m_config.password, challenge);

            QByteArray md5Payload = EapolPacket::buildMd5ChallengePayload(
                m_md5Result, userUtf8, m_config.localIp);
            sendEapResponse(EAP_TYPE_MD5_CHALLENGE, hdr.id, md5Payload, m_lastMd5Packet);
        }
        break;
    }
    case EAP_TYPE_NOTIFICATION:
        parseNotification(QString::fromUtf8(payload));
        break;
    }
}

void EapProcess::checkRetransmit()
{
    if (m_currentState == AuthState::Authenticated || m_currentState == AuthState::Idle)
        return;

    if (m_retransmitTimer.hasExpired(EAP_RETRANSMIT_INTERVAL)) {
        // 节流：首次与每第 N 次重发才记日志，避免长时间无响应时每 3s 刷屏
        if (++m_retransmitLogCount == 1
            || m_retransmitLogCount % RETRANSMIT_LOG_INTERVAL == 0)
            log(LogLevel::Warning, QStringLiteral("等待交换机响应中..."));
        onTimeout();
        m_retransmitTimer.restart();
    }
}

void EapProcess::onPollTimeout()
{
    if (!m_running || m_stopRequested)
        return;

    QMutexLocker locker(&m_mutex);

    // 先收集所有包的处理结果，再决定是否 stop()
    // stop() 内部会加锁，因此必须在 locker 作用域外调用
    const auto packets = drainPackets();
    bool fatalError = false;
    for (const auto& pkt : packets) {
        if (!processEapPacket(pkt)) {
            fatalError = true;
            break;
        }
    }

    // 处理与日志均在持锁状态下仅做缓冲，解锁后统一发出
    if (fatalError) {
        locker.unlock();
        flushPending();
        stop();          // stop() 自身也会解锁后 flush
        return;
    }

    checkRetransmit();

    locker.unlock();
    flushPending();
}
