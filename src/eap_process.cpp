#include "eap_process.h"
#include "constants.h"
#include "eapol_packet.h"
#include <QThread>
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
    stop();
}

void EapProcess::setConfig(AuthConfig config)
{
    QMutexLocker locker(&m_mutex);
    m_config = std::move(config);
}

void EapProcess::log(LogLevel level, const QString& msg)
{
    emit logMessage(msg, static_cast<int>(level));
}

// ============================================================================
// pcap 设备管理
// ============================================================================

bool EapProcess::openDevice()
{
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
    if (pcap_next_ex(m_handle, &header, &pkt_data) == 1)
        return QByteArray(reinterpret_cast<const char*>(pkt_data), header->len);

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
    m_currentIdentifier = requestId;

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

bool EapProcess::parsePacket(const QByteArray& data, EAPHeader* outEapHeader,
                              QByteArray* outPayload)
{
    if (data.size() < EAPOL_MIN_FRAME_SIZE)
        return false;

    const EthHeader* eth = reinterpret_cast<const EthHeader*>(data.data());
    if (eth->eth_type != htons(ETHERTYPE_EAPOL))
        return false;

    const EAPOLHeader* eapol = reinterpret_cast<const EAPOLHeader*>(data.data() + ETH_HEADER_SIZE);
    if (eapol->version != EAPOL_VERSION || eapol->packet_type != EAPOL_TYPE_EAP_PACKET)
        return false;

    *outEapHeader = *reinterpret_cast<const EAPHeader*>(data.data() + EAP_HEADER_OFFSET);

    int payloadOffset = EAP_HEADER_OFFSET + 4 + (outEapHeader->type != 0 ? 1 : 0);
    int payloadSize   = ntohs(outEapHeader->length) - 5;

    if (payloadSize > 0 && data.size() >= payloadOffset + payloadSize)
        *outPayload = data.mid(payloadOffset, payloadSize);

    return true;
}

// ============================================================================
// 服务器通知解析 — 数据驱动查表，消除 if-else 链
// ============================================================================

void EapProcess::parseNotification(const QString& msg)
{
    log(LogLevel::Error, QStringLiteral("服务器通知: ") + msg);

    // --- Code-based 错误: "prefix + code" 格式 ---
    struct CodePattern {
        QStringView prefix;
        int         codeOffset;  // code 子串起始位置（从 prefix 尾部算起）
    };
    static const CodePattern kCodePatterns[] = {
        { QStringLiteral("userid error"),                 13 },
        { QStringLiteral("Authentication Fail ErrCode="), 28 },
    };

    // "code → 中文描述" 查找表（两个 pattern 共享），sleepReq 标记需休眠等待
    struct CodeMessage { QStringView code; const char* msg; bool sleepReq = false; };
    static const CodeMessage kCodeMessages[] = {
        { QStringLiteral("0"),  "用户名或密码错误" },
        { QStringLiteral("1"),  "账号不存在" },
        { QStringLiteral("2"),  "用户名或密码错误" },
        { QStringLiteral("3"),  "用户名或密码错误" },
        { QStringLiteral("4"),  "该账号可能已过期" },
        { QStringLiteral("5"),  "该账号已被停用" },
        { QStringLiteral("9"),  "该账号可能已过期" },
        { QStringLiteral("11"), "不允许进行RADIUS认证" },
        { QStringLiteral("16"), "当前时段禁止上网，程序将休眠等待", true },
        { QStringLiteral("30"), "该账号流量/时长已用尽" },
        { QStringLiteral("63"), "该账号流量/时长已用尽" },
    };

    for (const auto& pattern : kCodePatterns) {
        if (!msg.startsWith(pattern.prefix))
            continue;

        QStringView code = QStringView(msg).mid(pattern.codeOffset).trimmed();
        for (const auto& cm : kCodeMessages) {
            if (code == cm.code) {
                log(LogLevel::Error, cm.msg);
                if (cm.sleepReq)
                    emit sleepRequired();
                return;
            }
        }
        return;  // prefix 匹配但 code 未知 — 不再尝试其他 pattern
    }

    // --- 简单前缀匹配错误（无 code） ---
    static const struct { QStringView prefix; const char* msg; } kSimpleErrors[] = {
        { QStringLiteral("AdminReset"),           "管理员已重置连接" },
        { QStringLiteral("Mac, IP, NASip, PORT"), "当前IP/MAC地址不允许登录" },
        { QStringLiteral("flowover"),             "流量已用尽" },
        { QStringLiteral("In use"),               "该账号正在使用中（多设备在线）" },
    };

    for (const auto& entry : kSimpleErrors) {
        if (msg.startsWith(entry.prefix)) {
            log(LogLevel::Error, entry.msg);
            return;
        }
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

    m_running       = true;
    m_stopRequested = false;
    m_currentState  = AuthState::Idle;

    if (!openDevice()) {
        emit stateChanged(AuthState::Failed, "打开网卡失败: " + m_lastError);
        return;
    }

    if (!m_pollTimer) {
        m_pollTimer = new QTimer(this);
        m_pollTimer->setInterval(20);
        connect(m_pollTimer, &QTimer::timeout, this, &EapProcess::onPollTimeout);
    }

    emit stateChanged(AuthState::SendingStart, "清理端口状态...");
    sendEapolLogoff();

    QTimer::singleShot(PORT_CLEANUP_WAIT, this, [this]() {
        QMutexLocker l(&m_mutex);
        if (!m_running || m_stopRequested)
            return;

        emit stateChanged(AuthState::SendingStart, "发送探测请求...");
        sendEapolStart();
        m_currentState = AuthState::SendingStart;

        m_retransmitTimer.start();
        m_pollTimer->start();
    });
}

void EapProcess::stop()
{
    QMutexLocker locker(&m_mutex);

    m_stopRequested = true;
    m_running       = false;

    if (m_pollTimer)
        m_pollTimer->stop();

    if (m_handle)
        sendEapolLogoff();

    closeDevice();

    m_currentState = AuthState::Stopped;
    emit stateChanged(AuthState::Stopped, "已断开");
}

// ============================================================================
// 定时器槽 — 拆分为 drainPackets / processEapPacket / handleEapRequest / checkRetransmit
// ============================================================================

QVector<QByteArray> EapProcess::drainPackets()
{
    QVector<QByteArray> packets;
    while (true) {
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
    const EthHeader* eth = reinterpret_cast<const EthHeader*>(packet.data());

    // 早期握手中嗅探交换机 MAC（用于后续单播）
    if (m_currentState == AuthState::Idle || m_currentState == AuthState::SendingStart) {
        if (!isMulticastMac(eth->src_mac))
            memcpy(m_switchMac, eth->src_mac, 6);
    }

    EAPHeader eapHeader;
    QByteArray payload;
    if (!parsePacket(packet, &eapHeader, &payload))
        return true;  // 非 EAP 包，跳过

    m_retransmitTimer.restart();

    if (eapHeader.code == EAP_CODE_REQUEST) {
        handleEapRequest(eapHeader, payload);
    } else if (eapHeader.code == EAP_CODE_SUCCESS) {
        if (m_currentState != AuthState::Authenticated) {
            log(LogLevel::Info, QStringLiteral("802.1X 认证成功！保持后台监听心跳..."));
            m_currentState = AuthState::Authenticated;
            emit stateChanged(AuthState::Authenticated, QStringLiteral("认证成功"));
            emit eapSuccess(m_md5Result);
        }
    } else if (eapHeader.code == EAP_CODE_FAILURE) {
        log(LogLevel::Error, QStringLiteral("认证被拒绝 (可能是冷却期，稍等1分钟再试)"));
        m_currentState = AuthState::Failed;
        emit stateChanged(AuthState::Failed, QStringLiteral("认证失败"));
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

    if (fatalError) {
        locker.unlock();
        stop();
        return;
    }

    checkRetransmit();
}
