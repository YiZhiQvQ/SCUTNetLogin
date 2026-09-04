#include "core/session_manager.h"
#include "core/byte_utils.h"
#include "core/constants.h"
#include "network/network.h"
#include "wifi/wlan_media.h"
#include "log/log_manager.h"
#include <QNetworkInterface>
#include <QTimer>
#include <QMetaObject>
#include <QHostAddress>
#include <QDateTime>

// ============================================================================
// 构造 / 析构
// ============================================================================

SessionManager::SessionManager(QObject* parent)
    : QObject(parent)
{
    initProcesses();
}

SessionManager::~SessionManager()
{
    setState(AppConnectionState::Disconnected);

    // 退出前必须恢复 DHCP：若连接时设置了静态 IP，任何退出路径（含进程被杀、
    // 崩溃、绕过 onQuitApp 的关闭）都不能把静态 IP 残留在机器上，否则离开
    // 校园网后无法上网。用 BlockingQueuedConnection 确保恢复完成后再退出。
    if (m_wasStaticIpSet && !m_ipCfg.adapterName.isEmpty()) {
        QMetaObject::invokeMethod(m_networkWorker, "doSetDhcp", Qt::BlockingQueuedConnection,
                                  Q_ARG(QString, m_ipCfg.adapterName));
        m_wasStaticIpSet = false;
    }

    QMetaObject::invokeMethod(m_eapProcess, "stop", Qt::QueuedConnection);
    QMetaObject::invokeMethod(m_udpProcess, "stop", Qt::QueuedConnection);
    // 注意：这里【不】调 WebAuthProcess::stop()（它会发 mac/unbind 解绑）——
    // "退出时是否注销无线"已由 MainWindow::onQuitApp → stopConnection(勾选) 决定；
    // 析构只终止进程（stopSession 无任何 HTTP），保证"未勾选注销"时门户会话保持在线。
    QMetaObject::invokeMethod(m_webAuthProcess, "stopSession", Qt::QueuedConnection);

    m_eapThread.quit();
    m_eapThread.wait();
    m_udpThread.quit();
    m_udpThread.wait();
    m_networkThread.quit();
    m_networkThread.wait();
    m_wifiThread.quit();
    m_wifiThread.wait();

    // 惰性线程：若线程从未启动，QThread::finished 不会发出，deleteLater 也永不
    // 触发，需显式释放 worker 避免退出泄漏（已启动的线程仍走 deleteLater 路径）
    if (!m_eapThread.isRunning() && !m_eapThread.isFinished() && m_eapProcess) {
        delete m_eapProcess;
        m_eapProcess = nullptr;
    }
    if (!m_udpThread.isRunning() && !m_udpThread.isFinished() && m_udpProcess) {
        delete m_udpProcess;
        m_udpProcess = nullptr;
    }
    if (!m_wifiThread.isRunning() && !m_wifiThread.isFinished() && m_webAuthProcess) {
        delete m_webAuthProcess;
        m_webAuthProcess = nullptr;
    }
}

// ============================================================================
// 初始化子线程 & 工作对象
// ============================================================================

void SessionManager::initProcesses()
{
    // -- EAP 认证线程 --
    m_eapProcess = new EapProcess();
    m_eapProcess->moveToThread(&m_eapThread);
    connect(&m_eapThread, &QThread::finished, m_eapProcess, &QObject::deleteLater);
    connect(m_eapProcess, &EapProcess::stateChanged, this, &SessionManager::onEapStateChanged);
    connect(m_eapProcess, &EapProcess::logMessage,   this, &SessionManager::logMessage);
    connect(m_eapProcess, &EapProcess::eapSuccess,   this, &SessionManager::onEapSuccess);
    connect(m_eapProcess, &EapProcess::sleepRequired, this, [this]() {
        QMetaObject::invokeMethod(m_eapProcess, "stop", Qt::QueuedConnection);
        QMetaObject::invokeMethod(m_udpProcess, "stop", Qt::QueuedConnection);
        scheduleNextRetry(QStringLiteral("当前时段禁止上网，将在明早 6:00 自动重试"));
    });

    // -- UDP 心跳线程 --
    // 注意：UDP 进程的日志/状态信号必须连接，否则其"解析服务器地址"、"连接
    // UDP 服务器"、心跳失败等消息全部静默丢失（历史遗漏，已修复）
    m_udpProcess = new UdpProcess();
    m_udpProcess->moveToThread(&m_udpThread);
    connect(&m_udpThread, &QThread::finished, m_udpProcess, &QObject::deleteLater);
    connect(m_udpProcess, &UdpProcess::logMessage, this, &SessionManager::logMessage);
    connect(m_udpProcess, &UdpProcess::stateChanged, this, [this](const QString& state, const QString& msg) {
        emit logMessage(msg.isEmpty() ? state : state + QStringLiteral(": ") + msg, 0);
    });
    connect(m_udpProcess, &UdpProcess::online, this, &SessionManager::onUdpOnline);
    // EAP / UDP 线程【惰性启动】——在首次 startAuth() 时才拉起，程序仅开托盘不连接时不
    // 空转两个线程。注意：网络线程保持急切启动（setAutoStart / 析构恢复 DHCP 都可能
    // 在从未连接的情况下发生，见下方注释）。

    // -- 网络配置线程（netsh/schtasks） --
    m_networkWorker = new NetworkWorker();
    m_networkWorker->moveToThread(&m_networkThread);
    connect(&m_networkThread, &QThread::finished, m_networkWorker, &QObject::deleteLater);
    connect(m_networkWorker, &NetworkWorker::staticIpDone, this, [this]() {
        onStaticIpDone(m_ipSetupGeneration);   // 传递当前设置代次（旧一轮完成被丢弃）
    });
    connect(m_networkWorker, &NetworkWorker::staticIpFailed, this, [this](const QString& error) {
        onStaticIpFailed(error, m_ipSetupGeneration);
    });
    connect(m_networkWorker, &NetworkWorker::autoStartDone,  this, &SessionManager::onAutoStartDone);
    m_networkThread.start();

    // -- 无线 Portal 认证线程（懒启动：首次无线连接才拉起，同 EAP/UDP 约定） --
    m_webAuthProcess = new WebAuthProcess();
    m_webAuthProcess->moveToThread(&m_wifiThread);
    connect(&m_wifiThread, &QThread::finished, m_webAuthProcess, &QObject::deleteLater);
    connect(m_webAuthProcess, &WebAuthProcess::stateChanged, this, &SessionManager::onWifiStateChanged);
    connect(m_webAuthProcess, &WebAuthProcess::online,       this, &SessionManager::onWifiOnline);
    connect(m_webAuthProcess, &WebAuthProcess::logMessage,   this, &SessionManager::logMessage);

    // -- 日志文件持久化 --
    m_logManager = new LogManager(this);
    connect(this, &SessionManager::logMessage, m_logManager, &LogManager::onLogMessage);
}

// ============================================================================
// 连接 / 断开 主逻辑
// ============================================================================

void SessionManager::startConnection(const AuthConfig& config, const StaticIpConfig& ipCfg,
                                     ConnectMode mode, const QStringList& allowedSsids)
{
    if (m_state != AppConnectionState::Disconnected)
        return;
    // 人工连接会取消任何挂机中的切换（挂机仅由链路切换注册）
    m_postLogoutAction = PostLogoutAction::None;
    if (m_postLogoutTimeout)
        m_postLogoutTimeout->stop();

    m_config        = config;
    m_ipCfg         = ipCfg;
    m_wasStaticIpSet = false;
    m_connectMode   = mode;
    m_ssidWhitelist = allowedSsids;
    m_wiredFailStreak = 0;    // 用户主动发起：有线失败计数清零（auto 回退语义从零开始）
    m_autoWaitEnabled = true; // 用户手动连接：恢复自动就绪重连

    // 后端决策（纯函数；auto 模式有线优先，无线仅当 SSID 命中白名单）
    const auto decision = decideBackend();
    if (decision.backend == ConnectionBuilder::AuthBackend::None) {
        // 启动先判断、未就绪即静默等待：不弹"未检测到网络"警告，等到有线接入或匹配
        // 校园 Wi-Fi 连上（就绪监听）再自动认证；reason 仅留诊断
        qWarning().noquote() << "auth backend undecided:" << decision.reason;
        emit logMessage(QStringLiteral("等待网络就绪：插入网线或连接校园 Wi-Fi 后将自动认证..."), 0);
        setState(AppConnectionState::Disconnected);
        // auto 模式：既定时重扫（5 分钟兜底），更即时地监听有线路由/匹配 Wi-Fi 就绪即触发认证
        scheduleReconnect();
        startAutoWait();
        return;
    }
    m_activeBackend = (decision.backend == ConnectionBuilder::AuthBackend::WiredEap)
                          ? ActiveBackend::WiredEap
                          : ActiveBackend::PortalWifi;

    if (m_activeBackend == ActiveBackend::PortalWifi) {
        // 无线 Portal 认证基于 DHCP 分配的地址：忽略静态 IP 配置（webPortal 流程不读 ipCfg）
        startWifiAuth();
        return;
    }

    // ---- 有线（完整流程：勾选静态IP则先设置，然后认证） ----
    startWiredBackend();
}

// 有线后端的"完整流程"入口（手动连接与链路切换共用）：
// 勾选了"连接时配置静态IP"→ SettingNetwork（设置+代次防护）→ 完成后 startAuth；
// 否则直接 startAuth。【不要】用 startAuth 跳过此段——链路切换（插网线→有线）时
// 从未配置过静态 IP，跳过后有线口停留在无 IP/DHCP 未完成的中间态。
void SessionManager::startWiredBackend()
{
    if (!m_ipCfg.adapterName.isEmpty()) {
        setState(AppConnectionState::SettingNetwork);
        m_wasStaticIpSet = true;

        emit logMessage(QStringLiteral("正在设置静态IP: %1 / %2 / %3 ...")
                        .arg(m_ipCfg.ip, m_ipCfg.mask, m_ipCfg.gateway), 0);

        // 代次防护：模式即时切换可能在同一设置阶段发起第二次连接——旧一组的
        // 完成回调/超时不得误触新一组（onStaticIpDone/onStaticIpFailed 校验代数）
        ++m_ipSetupGeneration;
        const int gen = m_ipSetupGeneration;

        // 安全超时
        QTimer::singleShot(IP_SETUP_TIMEOUT, this, [this, gen]() {
            if (gen == m_ipSetupGeneration && m_state == AppConnectionState::SettingNetwork) {
                emit logMessage(QStringLiteral("静态IP设置超时，请检查适配器名和网络配置"), 2);
                // netsh 可能已部分应用（如 IP 已设、DNS 失败），回滚到 DHCP 避免残留
                restoreDhcp();
                setState(AppConnectionState::Disconnected);
            }
        });

        QMetaObject::invokeMethod(m_networkWorker, "doSetStaticIp", Qt::QueuedConnection,
                                  Q_ARG(QString, m_ipCfg.adapterName),
                                  Q_ARG(QString, m_ipCfg.ip),
                                  Q_ARG(QString, m_ipCfg.mask),
                                  Q_ARG(QString, m_ipCfg.gateway),
                                  Q_ARG(QString, m_ipCfg.dns1),
                                  Q_ARG(QString, m_ipCfg.dns2));
    } else {
        startAuth();
    }
}

void SessionManager::startAuth(bool restartEap)
{
    // 惰性启动认证线程（首次认证时拉起，此后保持运行直至进程退出）
    if (!m_eapThread.isRunning())
        m_eapThread.start();
    if (!m_udpThread.isRunning())
        m_udpThread.start();

    setState(AppConnectionState::Authenticating);
    emit logMessage(QStringLiteral("开始802.1X认证..."), 0);

    // 注意顺序：setConfig 为同步直调，先于 invokeMethod("start"/"restart") 的
    // 排队事件完成，因此工作线程处理启动槽时必然已拿到最新配置
    m_eapProcess->setConfig(m_config);
    m_udpProcess->setConfig(m_config);

    QMetaObject::invokeMethod(m_eapProcess, restartEap ? "restart" : "start", Qt::QueuedConnection);
}

void SessionManager::startWifiAuth()
{
    // 防御：任何残留的链路监视在无线会话中都必须停止（显式模式/模式切换/
    // 重连路径下，auto 切换计时器若存活会制造"插网线→切有线"的幽灵动作）
    stopLinkWatch();

    // 惰性启动无线认证线程（首次无线认证时拉起）
    if (!m_wifiThread.isRunning())
        m_wifiThread.start();

    // 运行期字段：用实际 Wi-Fi 接口的 IP/MAC 覆盖 AuthConfig
    // （门户参数 mip/ipm/ss3/ss5 必须来自无线口的 DHCP 地址；用户"设置静态IP"里
    //   填的是有线地址，不能沿用——resolveAuthConfig 从 pcap 选中适配器（通常为
    //   有线网卡）预填 localIp，故此处【无条件】覆盖，而非常见的"仅当为零则补"。
    //   无线口无 IPv4 时循环不命中 → 保留原值兜底，不覆盖为全零。）
    const WlanMedia::WlanInfo wlan = WlanMedia::currentWifiConnection();
    if (wlan.connected) {
        m_config.wifiSsid = wlan.ssid;
        if (!wlan.ifGuid.isEmpty()) {
            const QNetworkInterface iface = QNetworkInterface::interfaceFromName(wlan.ifGuid);
            if (iface.isValid()) {
                for (const auto& entry : iface.addressEntries()) {
                    if (entry.ip().protocol() == QAbstractSocket::IPv4Protocol
                        && entry.ip().toIPv4Address() != 0) {
                        ByteUtils::ipv4ToBytes(entry.ip(), m_config.localIp);
                        break;
                    }
                }
                const QByteArray hw = QByteArray::fromHex(
                    ByteUtils::normalizeMac(iface.hardwareAddress()).toLatin1());
                if (hw.size() == 6)
                    memcpy(m_config.localMac, hw.constData(), 6);
                else
                    memset(m_config.localMac, 0, 6);   // 取不到时置零（协议约定全零=空 MAC）
            }
        }
    }

    setState(AppConnectionState::WiFiConnecting);
    emit logMessage(QStringLiteral("开始校园网无线认证（SSID: %1）...").arg(m_config.wifiSsid), 0);
    m_webAuthProcess->setConfig(m_config);
    QMetaObject::invokeMethod(m_webAuthProcess, "start", Qt::QueuedConnection);
}

ConnectionBuilder::BackendDecision SessionManager::decideBackend() const
{
    return ConnectionBuilder::resolveAuthBackend(
        m_connectMode,
        Network::ethernetLinkUp(),
        WlanMedia::currentWifiConnection().ssid,
        m_ssidWhitelist);
}

bool SessionManager::isWifiUiLive() const
{
    return m_activeBackend == ActiveBackend::PortalWifi
        && (m_state == AppConnectionState::WiFiConnecting
            || m_state == AppConnectionState::Connected);
}

// ============================================================================
// 有线插入监视（auto 模式）：无线在线时常驻轮询以太网链路，检测到网线插入即切有线
// ============================================================================

void SessionManager::startLinkWatch()
{
    if (m_connectMode != ConnectMode::Auto)
        return;                          // 防御：恒 auto；显式模式不应有联动监视
    m_lastEthernetUp = Network::ethernetLinkUp();   // 重置边沿基线：启动时静默，只记后续转变
    if (!m_linkWatchTimer) {
        m_linkWatchTimer = new QTimer(this);
        // 2s 轮询：拔线"立即断开"语义的最坏感知延迟（原先 5s；GetAdaptersAddresses 开销极小）
        m_linkWatchTimer->setInterval(2000);
        connect(m_linkWatchTimer, &QTimer::timeout, this, [this]() {
            // 连接联动监视（有线↔无线双向，仅 auto 模式、且稳定在线时运行）：
            //   · 无线在线 + 有线网线插入 → 延迟 CONNECT_SWITCH_DELAY_MS 切有线
            //     （等链路/端口稳定，避免立刻发 802.1X 被拒"认证被拒绝"）
            //   · 有线在线 + 网线拔出     → 【立即】断开（用户定义：拔线即断开，
            //     不做任何延时/复查），按 m_wasStaticIpSet 恢复 DHCP；不自动切无线
            //     （转入无线由用户点「连接」决定）
            if (m_connectMode != ConnectMode::Auto)
                return;                  // 防御：残留 tick（切换后已停止监视）
            if (m_state != AppConnectionState::Connected) {
                stopLinkWatch();         // 非稳定在线：由上线路径重新拉起
                return;
            }

            // 边沿日志：链路状态每次转变只打一行，并标注当前会话后端——
            // 直接说明"网线变化是否影响当前连接"（无线会话不受有线网线影响）
            const bool ethUp = Network::ethernetLinkUp();
            if (ethUp != m_lastEthernetUp) {
                m_lastEthernetUp = ethUp;
                const QString backend = (m_activeBackend == ActiveBackend::WiredEap)
                                            ? QStringLiteral("有线") : QStringLiteral("无线");
                emit logMessage(ethUp
                                    ? QStringLiteral("有线网卡: 检测到网线已插入（链路 Up，会话: %1）").arg(backend)
                                    : QStringLiteral("有线网卡: 网线已拔除（链路 Down，会话: %1）").arg(backend), 0);
            }

            if (m_activeBackend == ActiveBackend::PortalWifi) {
                if (!ethUp)
                    return;   // 无线会话不依赖有线链路（上一条 edge log 已标注"会话: 无线"）
                emit logMessage(QStringLiteral("检测到有线网卡已插入，%1 秒后自动切换为有线认证...")
                                    .arg(CONNECT_SWITCH_DELAY_MS / 1000), 0);
                stopLinkWatch();         // 切换期间暂停，避免重复触发
                QTimer::singleShot(CONNECT_SWITCH_DELAY_MS, this, [this]() {
                    if (m_state != AppConnectionState::Connected
                        || m_activeBackend != ActiveBackend::PortalWifi
                        || !Network::ethernetLinkUp()) {
                        emit logMessage(QStringLiteral("有线网线已插入，但 3 秒复查时条件已变化，取消自动切换"), 1);
                        startLinkWatch();   // 条件已变（拔出/状态变化）：重启监视等待下次判定
                        return;
                    }
                    emit logMessage(QStringLiteral("正在切换为有线认证（先注销无线）..."), 0);
                    stopConnection();        // 结束无线会话（发出异步解绑）
                    // 时序（用户要求）：等无线注销完成（unbind 回调 → Stopped）→
                    // 物理断开 Wi-Fi → 有线完整流程；Stopped 缺失时由兜底定时器继续
                    beginWiredSwitchAfterLogout();
                    // 成功/失败后的路径会自动重建监视（onEapSuccess / 无线 Online）
                });
                return;
            }

            if (m_activeBackend == ActiveBackend::WiredEap) {
                if (ethUp)
                    return;
                // 用户定义（定案）：网线拔出 = 立即断开，不做任何延时/复查/容忍。
                // stopConnection 内部按 m_wasStaticIpSet 判断是否恢复 DHCP；
                // 【不】自动切无线——转入无线由用户点「连接」决定（auto 决策：
                // 无有线 + Wi-Fi 命中白名单 → 无线）。
                emit logMessage(QStringLiteral("有线网线已拔出，正在断开有线..."), 0);
                stopLinkWatch();
                stopConnection();
                return;
            }

            stopLinkWatch();             // 其它后端（None）：无联动意义
        });
    }
    m_linkWatchTimer->start();
}

void SessionManager::stopLinkWatch()
{
    if (m_linkWatchTimer)
        m_linkWatchTimer->stop();
}

void SessionManager::stopConnection(bool logoutWifi, bool userInitiated)
{
    if (m_reconnectTimer)
        m_reconnectTimer->stop();
    stopLinkWatch();    // 断开/退出/切走时停止有线插入监视
    if (userInitiated) {
        // 用户主动断开/退出：停止自动就绪重连（直到下次手动连接恢复）
        m_autoWaitEnabled = false;
        stopAutoWait();
    }
    // 新的人工断开取消挂机（挂机中的切换交给下一轮判定/人工连接）
    m_postLogoutAction = PostLogoutAction::None;
    if (m_postLogoutTimeout)
        m_postLogoutTimeout->stop();

    if (m_state == AppConnectionState::Disconnected)
        return;

    QMetaObject::invokeMethod(m_eapProcess, "stop", Qt::QueuedConnection);
    QMetaObject::invokeMethod(m_udpProcess, "stop", Qt::QueuedConnection);
    // 无线注销与否由调用方决定：用户点"断开"或退出且勾选了退出登出 → 注销；
    // 否则（退出未勾选）仅结束无线会话、不注销（保持 Wi-Fi 连接与在线状态）。
    if (m_activeBackend == ActiveBackend::PortalWifi && logoutWifi)
        QMetaObject::invokeMethod(m_webAuthProcess, "stop", Qt::QueuedConnection);
    m_activeBackend = ActiveBackend::None;

    restoreDhcp();
    setState(AppConnectionState::Disconnected);
}

void SessionManager::setAutoStart(bool enable)
{
    QMetaObject::invokeMethod(m_networkWorker, "doSetAutoStart", Qt::QueuedConnection,
                              Q_ARG(bool, enable));
}

// ============================================================================
// DHCP 恢复
// ============================================================================

void SessionManager::restoreDhcp()
{
    if (!m_wasStaticIpSet || m_ipCfg.adapterName.isEmpty())
        return;

    m_wasStaticIpSet = false;
    QMetaObject::invokeMethod(m_networkWorker, "doSetDhcp", Qt::QueuedConnection,
                              Q_ARG(QString, m_ipCfg.adapterName));
}

// ============================================================================
// 状态机
// ============================================================================

void SessionManager::setState(AppConnectionState state)
{
    if (m_state == state)
        return;
    m_state = state;
    emit stateChanged(state);
}

// ============================================================================
// 信号回调
// ============================================================================

void SessionManager::onEapStateChanged(AuthState state, const QString& message, bool retryable)
{
    // Stopped 的"已断开"消息仅在主状态已回 Disconnected 时输出——联动切换
    // （插网线/拔网线→旧会话停止→新会话立即排队）会让日志先出现"已断开"、
    // 随后又是新认证日志，误导用户（状态机此时已是 Authenticating）。
    if (!message.isEmpty()
        && (state != AuthState::Stopped || m_state == AppConnectionState::Disconnected))
        emit logMessage(message, state == AuthState::Failed ? 2 : 0);

    if (state == AuthState::Failed) {
        if (m_activeBackend == ActiveBackend::WiredEap)
            ++m_wiredFailStreak;   // auto 回退无线用（onEapSuccess 清零）
        // 永久性错误（凭证/账户状态，如密码错误、账号停用、流量用尽）：
        // 自动重试无法自行恢复，停止重试，等待用户手动处理
        handleAuthFailed(retryable);
    } else if (state == AuthState::Stopped) {
        // 普通 stop()（用户断开/停止）会发 Stopped；自动重连路径的 restart()
        // 不发。防御性守卫：即使未来某条路径在认证中排队了 stop()，也禁止
        // 把 Authenticating 回退为 Disconnected（否则连接/断开按钮错位）。
        handleWorkerStopped(AppConnectionState::Authenticating);
    }
}

void SessionManager::onEapSuccess(const QByteArray& md5Data)
{
    if (m_reconnectTimer && m_reconnectTimer->isActive()) {
        m_reconnectTimer->stop();
        emit logMessage(QStringLiteral("自动重连成功！"), 0);
    } else {
        emit logMessage(QStringLiteral("认证成功，可以上网了！"), 0);
    }
    m_wiredFailStreak = 0;   // 有线成功：auto 回退计数清零
    stopAutoWait();          // 已上线：不再需要就绪监听
    setState(AppConnectionState::Connected);
    startLinkWatch();        // 有线在线：联动监视（拔网线→自动切无线）
    m_udpProcess->setMd5Data(md5Data);
    QMetaObject::invokeMethod(m_udpProcess, "start", Qt::QueuedConnection);
}

void SessionManager::onUdpOnline()
{
    setState(AppConnectionState::Connected);
}

void SessionManager::onStaticIpDone(int gen)
{
    // 代次防护：模式即时切换会发起新一轮设置——旧一轮的完成回调必须丢弃
    if (gen != m_ipSetupGeneration || m_state != AppConnectionState::SettingNetwork)
        return;
    emit logMessage(QStringLiteral("静态IP设置完成，开始认证..."), 0);
    startAuth();
}

void SessionManager::onStaticIpFailed(const QString& error, int gen)
{
    if (gen != m_ipSetupGeneration)
        return;   // 旧一轮的失败：新一轮按自己的回调处理
    emit logMessage(QStringLiteral("静态IP设置失败: ") + error, 2);
    // 回滚：静态 IP 可能已部分应用（如 IP 已设、DNS 失败），恢复 DHCP 避免残留
    restoreDhcp();
    setState(AppConnectionState::Disconnected);
}

void SessionManager::onHeartbeatFailed()
{
    // 本网络环境 DrCOM 服务器【不回复】UDP 心跳包，但网络连接实际正常。
    // 因此心跳超时一律静默忽略，绝不触发断连/自动重连——否则每次心跳超时
    // 都会误判为断网，导致频繁断线。断线检测只依赖 EAP 层失败（认证被拒、
    // 服务器踢线），见 AuthState::Failed 处理与 sleepRequired()。
}

void SessionManager::onAutoStartDone(bool ok, const QString& error)
{
    if (ok)
        emit logMessage(QStringLiteral("开机自启动设置成功"), 0);
    else
        emit logMessage(QStringLiteral("开机自启动设置失败: ") + error, 2);
}

// ============================================================================
// 无线 Portal 反馈（镜像 EAP 语义）
// ============================================================================

void SessionManager::onWifiStateChanged(WifiAuthState state, const QString& message, bool retryable)
{
    // 同 onEapStateChanged：切换窗口内的 Stopped 消息不刷屏（主状态未回 Disconnected 前）
    if (!message.isEmpty()
        && (state != WifiAuthState::Stopped || m_state == AppConnectionState::Disconnected))
        emit logMessage(message, state == WifiAuthState::Failed ? 2 : 0);

    switch (state) {
    case WifiAuthState::Online:
        // 上线（登录成功或探测直接判定在线）：停止重连排程；auto 模式下开启网线插入监视
        // 守卫：用户已断开/后端已切换（stopConnection 先置活性态为 None/Disconnected，
        // 工作线程滞后的 Online 此刻才到达）→ 丢弃，防止状态回翻 Connected
        if (!isWifiUiLive())
            return;
        if (m_reconnectTimer && m_reconnectTimer->isActive())
            m_reconnectTimer->stop();
        stopAutoWait();          // 已上线：不再需要就绪监听
        setState(AppConnectionState::Connected);
        startLinkWatch();
        break;

    case WifiAuthState::Failed:
        // 与有线同一套调度（夜间直接等到 6:00，白天 5 分钟间隔）
        handleAuthFailed(retryable, QStringLiteral("无线认证失败，将在明早 6:00 自动重试"));
        // 注意：这里【不】调用 WebAuthProcess::stop()——stop() 会执行 eportal
        // mac/unbind 解绑下线（那是"用户点断开/退出注销"才应有的动作）。
        // 认证失败后 Wi-Fi 仍应保持关联，等调度器重新 start()（start 自身会
        // 递增代数并清空未完成请求），重试不依赖先进程复位。
        break;

    case WifiAuthState::Stopped:
        // 防御守卫：与 onEapStateChanged(Stopped) 同型——仅当不在 WiFiConnecting
        // 时才回退 Disconnected
        handleWorkerStopped(AppConnectionState::WiFiConnecting);
        // 注销确认完成：链路切换的挂机动作（断Wi-Fi→有线认证）在此续跑
        onWifiLogoutFinished();
        break;

    default:
        // Probing / FetchingPortal / LoggingIn —— 保持 WiFiConnecting，文案已在日志
        break;
    }
}

void SessionManager::onWifiOnline()
{
    // online 信号（与 stateChanged(Online) 互补的冗余路径，幂等）。与 Online case
    // 同守卫：断连后到达的滞后在线必须丢弃；顺带保证 startLinkWatch 恰好执行一次
    if (!isWifiUiLive())
        return;
    setState(AppConnectionState::Connected);
    startLinkWatch();
}

void SessionManager::onSystemResume()
{
    // 睡眠/待机期间进程被挂起：Qt 定时器基于单调时钟（QPC），Windows 在部分
    // 电源状态下单调时钟在睡眠期间不走或走得不准，因此"距 6:00 的重连等待"
    // 不会因睡眠而过期——早上唤醒后定时器仍要等完剩余时长（最坏拖到下午），
    // 表现为"待机一晚，早晨屏幕亮了却还是断开"。
    //
    // 唤醒后必须用墙钟重新评估重连排程：
    //  - 没有待执行的重连排程（在线 / 手动停用 / 永久错误停止）→ 不干预；
    //  - 已过 6:00（白天）→ 立即重试；
    //  - 仍在夜间 → 重排到最近的 6:00。
    if (m_reconnectTimer && m_reconnectTimer->isActive()) {
        emit logMessage(QStringLiteral("已从待机唤醒，检查自动重连状态..."), 0);
        onReconnectTimeout();   // 内部有状态守卫 + 夜间重排 + 白天立即重连
    }

    // 无线在线/认证中的定时器同样受单调时钟影响：唤醒即重探测
    // （checkNow 内部丢弃进行中的旧回调并重新探测在线状态）
    if (m_activeBackend == ActiveBackend::PortalWifi)
        QMetaObject::invokeMethod(m_webAuthProcess, "checkNow", Qt::QueuedConnection);
}

void SessionManager::startAutoWait()
{
    if (!m_autoWaitEnabled || m_connectMode != ConnectMode::Auto)
        return;                    // 用户已手动断开或非自动模式：不做自动就绪重连
    if (!m_autoWaitTimer) {
        m_autoWaitTimer = new QTimer(this);
        m_autoWaitTimer->setInterval(2000);   // 就绪检测：短轮询，Wi-Fi/网线一就绪即触发
        connect(m_autoWaitTimer, &QTimer::timeout, this, &SessionManager::onAutoWaitTick);
    }
    m_autoWaitTimer->start();
}

void SessionManager::stopAutoWait()
{
    if (m_autoWaitTimer)
        m_autoWaitTimer->stop();
}

void SessionManager::onAutoWaitTick()
{
    if (!m_autoWaitEnabled || m_connectMode != ConnectMode::Auto)
        return;
    if (m_state != AppConnectionState::Disconnected)
        return;                    // 已在认证/在线：由对应路径停止监听

    // ① 有线优先：物理有线已接入 → 有线认证
    if (Network::ethernetLinkUp()) {
        if (m_reconnectTimer)
            m_reconnectTimer->stop();
        stopAutoWait();
        m_activeBackend = ActiveBackend::WiredEap;   // 同步后端：isWifiUiLive/链路监视等依赖它
        emit logMessage(QStringLiteral("检测到有线网卡已接入，自动开始有线认证..."), 0);
        startWiredBackend();
        return;
    }
    // ② 否则：匹配白名单的 Wi-Fi 已连上 → 无线认证（解决"开机自启早于 Wi-Fi 连接"）
    const WlanMedia::WlanInfo wlan = WlanMedia::currentWifiConnection();
    if (wlan.connected && ConnectionBuilder::ssidMatch(wlan.ssid, m_ssidWhitelist)) {
        if (m_reconnectTimer)
            m_reconnectTimer->stop();
        stopAutoWait();
        m_activeBackend = ActiveBackend::PortalWifi;   // 同步后端：否则 Online 被 isWifiUiLive 丢弃，UI 停在"正在认证"
        emit logMessage(QStringLiteral("检测到校园 Wi-Fi（%1），自动开始无线认证...").arg(wlan.ssid), 0);
        startWifiAuth();
        return;
    }
    // ③ 均未就绪：保持监听，等待有线接入或 Wi-Fi 出现
}

void SessionManager::scheduleReconnect()
{
    if (!m_reconnectTimer) {
        m_reconnectTimer = new QTimer(this);
        m_reconnectTimer->setSingleShot(true);
        connect(m_reconnectTimer, &QTimer::timeout, this, &SessionManager::onReconnectTimeout);
    }
    // 夜间直接等到 6:00 再触发，白天按固定间隔，避免通宵刷屏
    m_reconnectTimer->start(msecsToNextRetry());
}

void SessionManager::scheduleNextRetry(const QString& nightMessage)
{
    emit logMessage(isNightWindow()
                        ? nightMessage
                        : QStringLiteral("认证失败，将在 %1 分钟后自动重试")
                              .arg(kReconnectIntervalMs / 60000),
                    1);
    setState(AppConnectionState::Disconnected);
    scheduleReconnect();
}

void SessionManager::handleAuthFailed(bool retryable, const QString& nightMessage)
{
    if (retryable) {
        // 与时段相关的失败（夜间 6:00 / 白天 5 分钟间隔同一套调度）。
        // 【不要】在此进入就绪监听：那会让 onAutoWaitTick 2 秒内再次触发认证，
        // 失败→再监听 无限刷屏，并绕过夜间 6:00 / 5 分钟节流。失败重试只走
        // scheduleNextRetry 的定时（到点 onReconnectTimeout 再按需重建监听）。
        scheduleNextRetry(nightMessage);
    } else {
        // 永久性错误（凭证/账户状态）：停止自动重试
        if (m_reconnectTimer)
            m_reconnectTimer->stop();
        emit logMessage(QStringLiteral("该错误无法自动恢复，已停止自动重试，请检查账号信息后手动连接"), 1);
        setState(AppConnectionState::Disconnected);
    }
}

void SessionManager::handleWorkerStopped(AppConnectionState guardState)
{
    // 防御守卫：即使未来某条路径在认证中排队了 stop()，也禁止把认证中状态
    // 回退为 Disconnected（否则连接/断开按钮错位）
    if (m_state != guardState)
        setState(AppConnectionState::Disconnected);
}

void SessionManager::beginWiredSwitchAfterLogout()
{
    // 链路切换的挂机注册：注销（mac/unbind）的确认信号为 Stopped；万一未发射
    // （进程未启动等），兜底定时器保证切换仍继续。
    m_postLogoutAction = PostLogoutAction::SwitchToWired;
    if (!m_postLogoutTimeout) {
        m_postLogoutTimeout = new QTimer(this);
        m_postLogoutTimeout->setSingleShot(true);
        connect(m_postLogoutTimeout, &QTimer::timeout, this, &SessionManager::onPostLogoutTimeout);
    }
    m_postLogoutTimeout->start(WIFI_LOGOUT_TIMEOUT_MS + 2000);
}

void SessionManager::onWifiLogoutFinished()
{
    if (m_postLogoutAction != PostLogoutAction::SwitchToWired)
        return;
    m_postLogoutAction = PostLogoutAction::None;
    if (m_postLogoutTimeout)
        m_postLogoutTimeout->stop();

    emit logMessage(QStringLiteral("无线已注销，断开 Wi-Fi 并开始有线认证..."), 0);
    WlanMedia::disconnectWifi();     // 物理断开 Wi-Fi：切换后不残留无线关联
    startWiredBackend();             // 有线完整流程：静态IP勾选→设置→认证，否则直接认证
}

void SessionManager::onPostLogoutTimeout()
{
    if (m_postLogoutAction != PostLogoutAction::SwitchToWired)
        return;
    m_postLogoutAction = PostLogoutAction::None;

    emit logMessage(QStringLiteral("注销确认超时，直接断开 Wi-Fi 并开始有线认证..."), 1);
    WlanMedia::disconnectWifi();
    startWiredBackend();
}

bool SessionManager::isNightWindow() const
{
    return QDateTime::currentDateTime().time().hour() < 6;
}

int SessionManager::msecsToNextRetry() const
{
    if (!isNightWindow())
        return kReconnectIntervalMs;
    const QDateTime now = QDateTime::currentDateTime();
    return static_cast<int>(now.msecsTo(QDateTime(now.date(), QTime(6, 0))));
}

void SessionManager::onReconnectTimeout()
{
    if (m_state != AppConnectionState::Disconnected)
        return;
    stopAutoWait();   // 正式重试：停掉就绪监听（触发后由相应路径重新按需启动）

    // 防御分支：定时器可能按旧间隔触发且尚未跨过夜间窗口（如连接被重置后重入），
    // 若仍在夜间则重新等待到 6:00
    if (isNightWindow()) {
        m_reconnectTimer->start(msecsToNextRetry());
        return;
    }

    emit logMessage(QStringLiteral("尝试重新连接..."), 0);

    switch (m_activeBackend) {
    case ActiveBackend::WiredEap:
    case ActiveBackend::PortalWifi:
        // 重试前复判后端：重试间隔可达 5 分钟（或一夜），期间模式/SSID 白名单/
        // 链路可能已变（拔了网线、改了联网方式、校园 Wi-Fi 更换）——不复判会让
        // 过期的后端反复重连，白名单变更也迟迟不生效。
        {
            const auto decision = decideBackend();
            if (decision.backend == ConnectionBuilder::AuthBackend::None) {
                qWarning().noquote() << "auth backend undecided:" << decision.reason;
                emit logMessage(QStringLiteral("等待网络就绪：插入网线或连接校园 Wi-Fi 后将自动认证..."), 0);
                m_activeBackend = ActiveBackend::None;
                scheduleReconnect();
                startAutoWait();
                break;
            }
            // auto 模式：有线连续认证失败（≥2，常因交换机/端口不认证或环境暂不可用）
            // 且 Wi-Fi 仍关联并命中白名单时，回退无线——避免"插了网线却断网"。用户手动
            // 重连或有线成功（onEapSuccess）即清零；若后期线缆环境恢复，切回自动仍先试有线。
            if (m_activeBackend == ActiveBackend::WiredEap
                && m_connectMode == ConnectMode::Auto
                && m_wiredFailStreak >= 2) {
                const WlanMedia::WlanInfo wlan = WlanMedia::currentWifiConnection();
                if (wlan.connected
                    && ConnectionBuilder::ssidMatch(wlan.ssid, m_ssidWhitelist)) {
                    emit logMessage(QStringLiteral("有线连续认证失败，自动回退无线认证..."), 1);
                    m_activeBackend = ActiveBackend::PortalWifi;
                    startWifiAuth();
                    break;
                }
                // 切有线时通常已物理断开 Wi-Fi：无法自动回退，明确提示（继续按有线重试）
                emit logMessage(QStringLiteral("有线认证失败，且未关联校园 Wi-Fi，无法自动回退无线"), 1);
            }
            const ActiveBackend desired = (decision.backend == ConnectionBuilder::AuthBackend::WiredEap)
                                              ? ActiveBackend::WiredEap
                                              : ActiveBackend::PortalWifi;
            if (desired != m_activeBackend) {
                // 后端切换（如 auto 下拔网线→无线）：无线进程在 Failed 后已空闲
                // （无运行中定时器），新周期 start() 递增代数即可丢弃旧回调，无需 stop()
                if (desired == ActiveBackend::WiredEap)
                    QMetaObject::invokeMethod(m_udpProcess, "stop", Qt::QueuedConnection);
                m_activeBackend = desired;
            }
            if (desired == ActiveBackend::WiredEap) {
                // 跳过静态IP设置阶段（IP 已在上次连接时配置好），直接开始认证。
                // EAP 用原子的 restart()（复位设备 + 重启，不发射 Stopped），不再依赖
                // "队列 stop → 队列 start" 的顺序契约；UDP 会话在失败时已停止，直接 start。
                QMetaObject::invokeMethod(m_udpProcess, "stop", Qt::QueuedConnection);
                startAuth(/*restartEap=*/true);
            } else {
                // 重新完整走无线流程（内部会先探测在线状态，已在线则直接回 Online）
                startWifiAuth();
            }
        }
        break;

    case ActiveBackend::None:
        // auto 扫描态（无链路/SSID 不匹配）：重演一次决策，不重跑静态 IP（从未设置过）
        {
            const auto decision = decideBackend();
            if (decision.backend == ConnectionBuilder::AuthBackend::None) {
                qWarning().noquote() << "auth backend undecided:" << decision.reason;
                emit logMessage(QStringLiteral("等待网络就绪：插入网线或连接校园 Wi-Fi 后将自动认证..."), 0);
                scheduleReconnect();
                startAutoWait();
                break;
            }
            m_activeBackend = (decision.backend == ConnectionBuilder::AuthBackend::WiredEap)
                                  ? ActiveBackend::WiredEap
                                  : ActiveBackend::PortalWifi;
            if (m_activeBackend == ActiveBackend::WiredEap)
                startAuth(/*restartEap=*/true);
            else
                startWifiAuth();
        }
        break;
    }
}
