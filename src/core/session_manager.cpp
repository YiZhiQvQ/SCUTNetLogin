#include "core/session_manager.h"
#include "core/byte_utils.h"
#include "core/constants.h"
#include "core/retry_policy.h"
#include "config/config_manager.h"
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
    // 校园网后无法上网。用 BlockingQueuedConnection 确保恢复完成后再退出：
    // 阻塞调用排在已投递的异步恢复之后执行，返回即代表"恢复已落地"
    // （setDhcp 幂等，重复执行无副作用）。
    // 目标网卡取 m_staticIpAdapter（与 m_ipCfg 分离，见头文件）：若中途换过网卡配置，
    // 只认"真正被写过静态 IP 的那块"，否则会恢复错网卡、旧网卡永久残留。
    const QString dhcpAdapter = !m_staticIpAdapter.isEmpty() ? m_staticIpAdapter
                                                             : m_ipCfg.adapterName;
    if (!dhcpAdapter.isEmpty() && (m_wasStaticIpSet || m_dhcpRestorePending)) {
        QMetaObject::invokeMethod(m_networkWorker, "doSetDhcp", Qt::BlockingQueuedConnection,
                                  Q_ARG(QString, dhcpAdapter));
        m_wasStaticIpSet = false;
        m_dhcpRestorePending = false;
        m_staticIpAdapter.clear();
    }

    QMetaObject::invokeMethod(m_eapProcess, "stop", Qt::QueuedConnection);
    stopUdpIfRunning();
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
        stopUdpIfRunning();
        scheduleNextRetry(QStringLiteral("当前时段禁止上网，将在明早 6:01 自动重试"));
    });

    // -- UDP 心跳线程 --
    // 注意：UDP 进程的日志/状态信号必须连接，否则其"解析服务器地址"、"连接
    // UDP 服务器"、心跳失败等消息全部静默丢失（历史遗漏，已修复）
    m_udpProcess = new UdpProcess();
    m_udpProcess->moveToThread(&m_udpThread);
    connect(&m_udpThread, &QThread::finished, m_udpProcess, &QObject::deleteLater);
    connect(m_udpProcess, &UdpProcess::logMessage, this, &SessionManager::logMessage);
    connect(m_udpProcess, &UdpProcess::stateChanged, this, [this](const QString& state, const QString& msg) {
        // "运行中: 正在解析服务器地址..." 属启动过程细节，仅调试时输出
        if (m_debugLog)
            emit logMessage(QStringLiteral("[调试] ") + (msg.isEmpty() ? state : state + QStringLiteral(": ") + msg), 0);
    });
    connect(m_udpProcess, &UdpProcess::online, this, &SessionManager::onUdpOnline);
    // EAP / UDP 线程【惰性启动】——在首次 startAuth() 时才拉起，程序仅开托盘不连接时不
    // 空转两个线程。注意：网络线程保持急切启动（setAutoStart / 析构恢复 DHCP 都可能
    // 在从未连接的情况下发生，见下方注释）。

    // -- 网络配置线程（netsh/schtasks） --
    m_networkWorker = new NetworkWorker();
    m_networkWorker->moveToThread(&m_networkThread);
    connect(&m_networkThread, &QThread::finished, m_networkWorker, &QObject::deleteLater);
    // 代次必须由信号携带（请求时盖章），不能在投递时读 m_ipSetupGeneration——
    // 那等于给陈旧完成事件盖上最新代次，代次校验会恒真而失效
    connect(m_networkWorker, &NetworkWorker::staticIpDone,   this, &SessionManager::onStaticIpDone);
    connect(m_networkWorker, &NetworkWorker::staticIpFailed, this, &SessionManager::onStaticIpFailed);
    connect(m_networkWorker, &NetworkWorker::autoStartDone,  this, &SessionManager::onAutoStartDone);
    connect(m_networkWorker, &NetworkWorker::dhcpDone,       this, &SessionManager::onDhcpDone);
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
    // 把 Qt 自身的 qWarning/qCritical 也接进日志文件：GUI 程序没有控制台，
    // 否则网卡枚举失败、netsh 失败详情、autostart 变更等诊断信息全部不可见
    LogManager::installQtMessageHandler(m_logManager);
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
    m_retryAttempt    = 0;    // 重试序号同样从零开始（日志语义）
    m_autoWaitEnabled = true; // 用户手动连接：恢复自动就绪重连

    // 调试：每次连接尝试输出一次完整网卡枚举（直击"为什么判定有线"）
    if (m_debugLog)
        logAdapterDump(Network::dumpAdapters());

    // 后端决策（纯函数；auto 模式有线优先，无线仅当 SSID 命中白名单）
    const auto decision = decideBackend();
    if (decision.backend == ConnectionBuilder::AuthBackend::None) {
        // 启动先判断、未就绪即静默等待：不弹"未检测到网络"警告，等到有线接入或匹配
        // 校园 Wi-Fi 连上（就绪监听）再自动认证；reason 仅留诊断
        qWarning().noquote() << "auth backend undecided:" << decision.reason;
        emit logMessage(QStringLiteral("等待网络就绪：插入网线或连接校园 Wi-Fi 后将自动认证..."), 0);
        // 放弃本轮有线意图：若上一会话的静态 IP 还留在网卡上，先恢复 DHCP（用户要求：
        // 有线连不上时必须把机器还给 DHCP，而不是留在静态 IP 上）
        restoreDhcp();
        // 状态由 startAutoWait() 置为 WaitingForNetwork（UI 亮「取消」），不要在此
        // setState(Disconnected)——那会让界面显示"未连接"从而亮出"连接"按钮
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
    // 同步后端标识：本函数的三条入口（人工连接 / auto 就绪监听 / 无线注销后切换）
    // 中，只有"无线→有线自动切换"没有在外层设置它——留成 None 会让相邻逻辑失效：
    //   · onEapSuccess 的活性守卫（误丢合法的认证成功）
    //   · startLinkWatch 的"拔网线→断开"分支（None 走 stopLinkWatch，拔线不再响应）
    m_activeBackend = ActiveBackend::WiredEap;

    // 有线认证的运行时输入必须在【此刻】重算：点击"连接"时可能还没插网线（网卡无
    // IPv4 → localIp=0），而认证在插线后才发生（见函数注释）
    refreshWiredRuntimeFields();

    if (m_debugLog) {
        const QString ipText = QStringLiteral("%1.%2.%3.%4")
                                   .arg(m_config.localIp[0]).arg(m_config.localIp[1])
                                   .arg(m_config.localIp[2]).arg(m_config.localIp[3]);
        const QString macText = QByteArray(reinterpret_cast<const char*>(m_config.localMac), 6)
                                    .toHex(' ').toUpper();
        debugLog(QStringLiteral("有线认证输入: 网卡=%1, 静态IP=%2, localIp=%3, localMac=%4")
                     .arg(m_config.interfaceName,
                          m_ipCfg.ip.isEmpty() ? QStringLiteral("(未启用)") : m_ipCfg.ip,
                          ipText, macText));
    }

    // 静态 IP 判据 = 用户勾选（ConnectionBuilder 保证勾选时 ip 非空且参数合法）。
    // adapterName 允许为空：等待网线插入的场景下点击连接时还未插线/未选中网卡，
    // 到真正认证的时刻才解析（解析不到则告警并跳过静态 IP，而不是让认证带着
    // "未配置的静态 IP"必然失败）
    if (!m_ipCfg.ip.isEmpty()) {
        if (m_ipCfg.adapterName.isEmpty())
            m_ipCfg.adapterName = resolveWiredAdapterName();
        if (m_ipCfg.adapterName.isEmpty()) {
            emit logMessage(QStringLiteral("未找到可用的有线网卡，本次跳过静态IP配置"
                                           "（若认证失败请在「设置」中刷新网卡并查询MAC）"), 1);
            startAuth();
            return;
        }

        setState(AppConnectionState::SettingNetwork);
        m_wasStaticIpSet = true;
        m_staticIpAdapter = m_ipCfg.adapterName;   // 记住真正被写入静态 IP 的网卡
        m_staticIpPending = true;                  // 请求在途：此间的 DHCP 回执不得清跟踪

        emit logMessage(QStringLiteral("正在设置静态IP: %1 / %2 / %3 ...")
                        .arg(m_ipCfg.ip, m_ipCfg.mask, m_ipCfg.gateway), 0);

        // 代次防护：用户可能在设置阶段再次发起连接（断线重连/链路切换/手动点连接）
        // ——旧一组的完成回调/超时不得误触新一组
        // （onStaticIpDone/onStaticIpFailed 校验代数；代数由 worker 随信号回传）
        ++m_ipSetupGeneration;
        const int gen = m_ipSetupGeneration;

        // 安全超时
        QTimer::singleShot(IP_SETUP_TIMEOUT, this, [this, gen]() {
            if (gen == m_ipSetupGeneration && m_state == AppConnectionState::SettingNetwork) {
                emit logMessage(QStringLiteral("静态IP设置超时，请检查适配器名和网络配置"), 2);
                m_staticIpPending = false;
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
                                  Q_ARG(QString, m_ipCfg.dns2),
                                  Q_ARG(int, gen));
    } else {
        startAuth();
    }
}

// 有线认证运行时字段的现场重算（认证时刻调用，见头文件注释）：
//   · 未启用静态 IP → localIp 取当前有线口真实的 IPv4（UI 里残留的历史地址可能与
//     实际分配地址不一致，会让 EAP 响应带上错误 IP 被服务端 "Mac, IP, NASip, PORT" 拒绝）；
//   · 启用静态 IP → localIp 就是用户配置的静态 IP，绝不覆盖；仅在为 0 时回填；
//   · localMac 全零 → 用当前有线口 MAC 回填（非零视为用户有意指定，如换了网卡但要
//     沿用已注册的 MAC，不覆盖）；
//   · 接口无效（Npcap 名变更/网卡未就绪）→ 仅调试记录，不改变任何字段。
void SessionManager::refreshWiredRuntimeFields()
{
    const QNetworkInterface iface = Network::findInterface(m_config.interfaceName);
    if (!iface.isValid()) {
        if (m_debugLog)
            debugLog(QStringLiteral("有线认证输入：未能把 pcap 网卡名 %1 映射到系统网卡，"
                                    "沿用配置中的 IP/MAC")
                         .arg(m_config.interfaceName));
        return;
    }

    const bool staticIpIntent = !m_ipCfg.ip.isEmpty();
    // 启用静态 IP 且已有非零地址 → 保留（那是用户配置的静态 IP）；否则取网卡真实 IPv4
    const bool needLiveIp = !staticIpIntent || ByteUtils::isIpZero(m_config.localIp);
    if (needLiveIp) {
        for (const auto& entry : iface.addressEntries()) {
            if (entry.ip().protocol() == QAbstractSocket::IPv4Protocol
                && entry.ip().toIPv4Address() != 0) {
                ByteUtils::ipv4ToBytes(entry.ip(), m_config.localIp);
                break;
            }
        }
    }

    if (ByteUtils::isMacZero(m_config.localMac)) {
        const QByteArray hw = QByteArray::fromHex(
            ByteUtils::normalizeMac(iface.hardwareAddress()).toLatin1());
        if (hw.size() == 6)
            memcpy(m_config.localMac, hw.constData(), 6);
    }
}

// 静态 IP 的 netsh 目标网卡在认证时刻解析：配置里预解析的名字 → MAC 反查 → pcap 网卡名。
// 返回空表示无法定位（调用方跳过静态 IP 并告警，绝不以空网卡名调用 netsh）。
QString SessionManager::resolveWiredAdapterName()
{
    if (!m_ipCfg.adapterName.isEmpty())
        return m_ipCfg.adapterName;
    if (!m_ipCfg.mac.isEmpty()) {
        const QString byMac = Network::adapterNameByMac(m_ipCfg.mac);
        if (!byMac.isEmpty())
            return byMac;
    }
    const QNetworkInterface iface = Network::findInterface(m_config.interfaceName);
    if (iface.isValid() && !iface.name().isEmpty())
        return iface.name();
    return QString();
}

void SessionManager::startAuth(bool restartEap)
{
    // 惰性启动认证线程（首次认证时拉起，此后保持运行直至进程退出）
    if (!m_eapThread.isRunning())
        m_eapThread.start();
    // UDP 线程同样惰性，且额外受 DrCOM 心跳开关门控（默认关闭）——关闭时该线程
    // 自始至终不启动，析构走 delete m_udpProcess 分支（见 ~SessionManager）
    if (m_drcomHeartbeat && !m_udpThread.isRunning())
        m_udpThread.start();

    setState(AppConnectionState::Authenticating);
    emit logMessage(QStringLiteral("开始802.1X认证..."), 0);

    // 注意顺序：setConfig 为同步直调，先于 invokeMethod("start"/"restart") 的
    // 排队事件完成，因此工作线程处理启动槽时必然已拿到最新配置
    m_eapProcess->setConfig(m_config);
    if (m_drcomHeartbeat)
        m_udpProcess->setConfig(m_config);

    QMetaObject::invokeMethod(m_eapProcess, restartEap ? "restart" : "start", Qt::QueuedConnection);
}

// 统一的"停 UDP 会话"入口：仅在 UDP 线程确实在运行（= 开了心跳且已连接过）时投递。
// 关闭心跳（默认）时该线程从未启动，投递会留下永不执行的事件，等线程被拉起时
// 先于新会话的 start 执行（约定见 setDrcomHeartbeatEnabled）。
void SessionManager::stopUdpIfRunning()
{
    if (m_udpThread.isRunning())
        QMetaObject::invokeMethod(m_udpProcess, "stop", Qt::QueuedConnection);
}

void SessionManager::startWifiAuth()
{
    // 防御：任何残留的链路监视在无线会话中都必须停止（显式模式/模式切换/
    // 重连路径下，auto 切换计时器若存活会制造"插网线→切有线"的幽灵动作）
    stopLinkWatch();
    m_activeBackend = ActiveBackend::PortalWifi;   // 同步后端：isWifiUiLive/链路监视依赖它

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

ConnectionBuilder::BackendDecision SessionManager::decideBackend()
{
    const bool        ethUp = Network::ethernetLinkUp();
    const QString     ssid  = WlanMedia::currentWifiConnection().ssid;
    const auto        decision = ConnectionBuilder::resolveAuthBackend(
        m_connectMode, ethUp, ssid, m_ssidWhitelist);

    if (m_debugLog) {
        auto backendName = [](ConnectionBuilder::AuthBackend b) {
            switch (b) {
            case ConnectionBuilder::AuthBackend::WiredEap:   return QStringLiteral("有线 802.1X");
            case ConnectionBuilder::AuthBackend::PortalWifi: return QStringLiteral("无线 Portal");
            default:                                          return QStringLiteral("None");
            }
        };
        debugLog(QStringLiteral("后端决策: 模式=%1, 有线链路=%2, 当前SSID=%3, 白名单=[%4] → 后端=%5%6")
                     .arg(ConfigManager::connectModeToString(m_connectMode),
                          ethUp ? QStringLiteral("Up") : QStringLiteral("Down"),
                          ssid.isEmpty() ? QStringLiteral("(无)") : ssid,
                          m_ssidWhitelist.join(QStringLiteral(", ")),
                          backendName(decision.backend),
                          decision.reason.isEmpty()
                              ? QString()
                              : QStringLiteral("（%1）").arg(decision.reason)));
    }
    return decision;
}

bool SessionManager::isWifiUiLive() const
{
    return m_activeBackend == ActiveBackend::PortalWifi
        && (m_state == AppConnectionState::WiFiConnecting
            || m_state == AppConnectionState::Connected);
}

// ============================================================================
// 有线插入监视（auto 模式）：网线插入/拔出时联动切换
//   事件源：Network::LinkMonitor（系统接口变更通知，零轮询）
//           + 低频兜底轮询（防漏事件；通知注册失败时退回 2s 轮询）
// ============================================================================

// 惰性创建接口变更通知（进程内唯一）。注册失败（老系统/受限环境）时保持 nullptr，
// 调用方据此退回定时轮询。
void SessionManager::ensureLinkMonitor()
{
    if (m_linkMonitor)
        return;
    auto* monitor = new Network::LinkMonitor(this);
    if (!monitor->start()) {
        qWarning().noquote() << "接口变更通知注册失败，链路检测退回定时轮询";
        monitor->deleteLater();
        return;
    }
    m_linkMonitor = monitor;
    // 通知直接驱动两个消费者：链路联动监视 + 就绪监听。二者首行都有模式/状态守卫，
    // 非运行期收到通知是无副作用的空转。
    connect(m_linkMonitor, &Network::LinkMonitor::linkChanged,
            this, &SessionManager::onLinkWatchTick);
    connect(m_linkMonitor, &Network::LinkMonitor::linkChanged,
            this, &SessionManager::onAutoWaitTick);
}

void SessionManager::startLinkWatch()
{
    if (m_connectMode != ConnectMode::Auto)
        return;                          // 防御：恒 auto；显式模式不应有联动监视
    m_lastEthernetUp = Network::ethernetLinkUp();   // 重置边沿基线：启动时静默，只记后续转变
    ensureLinkMonitor();
    if (!m_linkWatchTimer) {
        m_linkWatchTimer = new QTimer(this);
        // 通知可用时只做低频兜底（漏事件保险）；注册失败才按 2s 轮询
        m_linkWatchTimer->setInterval(m_linkMonitor ? LINK_RESYNC_INTERVAL_MS
                                                    : LINK_POLL_INTERVAL_MS);
        connect(m_linkWatchTimer, &QTimer::timeout, this, &SessionManager::onLinkWatchTick);
    }
    m_linkWatchRunning = true;   // 通知与轮询共用同一"运行中"开关（见头文件注释）
    m_linkWatchTimer->start();
}

// 链路状态复核（系统通知与兜底轮询共用；须可重入/幂等）
void SessionManager::onLinkWatchTick()
{
    // 运行中开关：stopLinkWatch() 之后接口变更通知仍会到达，必须在此拦下——
    // 否则"切换期间暂停"失效，会重复打切换日志并叠加多个 3 秒切换定时器
    if (!m_linkWatchRunning)
        return;
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
                emit logMessage(QStringLiteral("有线网线已插入，但 %1 秒复查时条件已变化，取消自动切换")
                                    .arg(CONNECT_SWITCH_DELAY_MS / 1000), 1);
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
}

void SessionManager::stopLinkWatch()
{
    m_linkWatchRunning = false;   // 通知路径也必须停（见 onLinkWatchTick 首行）
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

    // 收尾顺序（重要）：有会话时才停工作进程；DHCP 恢复必须【在】提前返回之前执行——
    // 等待态（WaitingForNetwork）取消、以及"认证失败后已回 Disconnected 但静态 IP 仍
    // 在网卡上"的情形都靠这里兜底，提前 return 会让恢复被跳过（用户报告的问题 1）
    if (m_state != AppConnectionState::Disconnected) {
        QMetaObject::invokeMethod(m_eapProcess, "stop", Qt::QueuedConnection);
        stopUdpIfRunning();
        // 无线注销与否由调用方决定：用户点"断开"或退出且勾选了退出登出 → 注销；
        // 否则（退出未勾选）仅结束无线会话、不注销（保持 Wi-Fi 连接与在线状态）。
        if (m_activeBackend == ActiveBackend::PortalWifi && logoutWifi)
            QMetaObject::invokeMethod(m_webAuthProcess, "stop", Qt::QueuedConnection);
        m_activeBackend = ActiveBackend::None;
        m_staticIpPending = false;
    }

    restoreDhcp();
    setState(AppConnectionState::Disconnected);
}

void SessionManager::setAutoStart(bool enable)
{
    QMetaObject::invokeMethod(m_networkWorker, "doSetAutoStart", Qt::QueuedConnection,
                              Q_ARG(bool, enable));
}

void SessionManager::setDebugLogEnabled(bool on)
{
    m_debugLog = on;
    // 转发给三个工作进程：各自输出帧级/阶段级追踪（worker 线程用原子标志自读）
    m_eapProcess->setDebugLogEnabled(on);
    m_udpProcess->setDebugLogEnabled(on);
    m_webAuthProcess->setDebugLogEnabled(on);
}

void SessionManager::setDrcomHeartbeatEnabled(bool on)
{
    if (m_drcomHeartbeat == on)
        return;
    m_drcomHeartbeat = on;

    // 关闭：立即停掉已运行的 UDP 会话（线程保留至进程退出，由析构统一回收）。
    // 线程从未启动时不投递——否则事件队列里会留下一个永不执行的 stop。
    // 开启：不在此处启动——UDP 会话必须跟在一次成功的 802.1X 之后，由下个连接周期的
    // startAuth()/onEapSuccess() 拉起（UI 文案已说明"修改后下次连接生效"）。
    if (!on)
        stopUdpIfRunning();
}

void SessionManager::debugLog(const QString& message)
{
    if (m_debugLog)
        emit logMessage(QStringLiteral("[调试] ") + message, 0);
}

void SessionManager::logAdapterDump(const QString& dump)
{
    if (!m_debugLog)
        return;
    // dumpAdapters 返回多行文本：逐行单独发射，UI 与当日日志各获一行（可读/可检索）
    const QStringList lines = dump.split(QLatin1Char('\n'));
    for (const QString& line : lines) {
        if (!line.trimmed().isEmpty())
            debugLog(line);
    }
}

// ============================================================================
// DHCP 恢复
// ============================================================================

void SessionManager::restoreDhcp()
{
    // 目标网卡以"真正被写入静态 IP 的那块"为准；m_ipCfg 会被下一次 startConnection
    // 覆盖，若只认它，旧网卡上的静态 IP 将永远不再被恢复（用户报告的问题 1）
    const QString adapter = !m_staticIpAdapter.isEmpty() ? m_staticIpAdapter
                                                         : m_ipCfg.adapterName;
    if (adapter.isEmpty())
        return;
    if (!m_wasStaticIpSet && !m_dhcpRestorePending)
        return;                        // 既没设过静态 IP，也没有未落地的恢复请求

    // 关键：m_wasStaticIpSet 保持为真，直到 worker 回执（onDhcpDone）确认落地。
    // 若在此处提前清零，析构的安全网（以该标志为唯一条件）就会在恢复真正执行前
    // 失效——而"stopConnection → restoreDhcp → quit → ~SessionManager"正是
    // 最常见的退出路径。
    m_dhcpRestorePending = true;
    QMetaObject::invokeMethod(m_networkWorker, "doSetDhcp", Qt::QueuedConnection,
                              Q_ARG(QString, adapter));
}

void SessionManager::onDhcpDone(bool ok, const QString& error)
{
    m_dhcpRestorePending = false;
    if (ok) {
        // 请求在途期间可能已进入新一轮静态 IP 设置（doSetStaticIp 排在本次 doSetDhcp
        // 之后执行）：此时绝不能清跟踪，否则新设的静态 IP 到退出时不会被恢复
        if (m_staticIpPending)
            return;
        m_wasStaticIpSet = false;
        m_staticIpAdapter.clear();
        return;
    }
    // 恢复失败：保留 m_wasStaticIpSet，析构的阻塞收尾会再试一次；同时明确告知用户
    // （这是"机器留在静态 IP 上"这类最难自查的故障，不能静默）
    emit logMessage(QStringLiteral("恢复 DHCP 失败（静态 IP 可能仍留在网卡上）: %1").arg(error), 2);
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
        // 普通 stop()（用户断开/停止）会发 Stopped；自动重连路径的 restart() 不发。
        //
        // 归属守卫：只有"当前后端仍是有线"时，这条 Stopped 才代表当前会话的结束。
        // 反例（实测日志复现）：拔网线 → 链路联动 stopConnection() 置后端 None 并
        // 排队 EAP stop → 同一刻就绪监听发现 Wi-Fi 命中、立刻切无线（状态
        // WiFiConnecting）→ 迟到的 EAP Stopped 若照单全收，handleWorkerStopped 会把
        // 刚建立的无线会话静默打回 Disconnected：随后的无线 Online 被 isWifiUiLive()
        // 丢弃（界面停在未连接），再被下一次就绪监听触发成"第二次认证"。
        // 已由 stopConnection 收尾的路径不需要这条 Stopped 再动状态（那时本就是
        // Disconnected，回退是空操作）。
        if (m_activeBackend == ActiveBackend::WiredEap)
            handleWorkerStopped(AppConnectionState::Authenticating);
    }
}

void SessionManager::onEapSuccess(const QByteArray& md5Data)
{
    // 活性守卫（与无线侧 isWifiUiLive 同型）：用户已断开 / 后端已切走时，工作线程
    // 排队到达的认证成功必须丢弃——否则会把状态翻回 Connected（UI 显示已连接，
    // 但实际没有会话，也没有链路监视）
    if (m_activeBackend != ActiveBackend::WiredEap)
        return;

    if (m_reconnectTimer && m_reconnectTimer->isActive()) {
        m_reconnectTimer->stop();
        emit logMessage(QStringLiteral("自动重连成功！"), 0);
    } else {
        emit logMessage(QStringLiteral("认证成功，可以上网了！"), 0);
    }
    m_wiredFailStreak = 0;   // 有线成功：auto 回退计数清零
    m_retryAttempt    = 0;   // 已上线：重试序号清零
    stopAutoWait();          // 已上线：不再需要就绪监听
    setState(AppConnectionState::Connected);
    startLinkWatch();        // 有线在线：联动监视（拔网线→自动切无线）

    // DrCOM UDP 保活（默认关闭）：EAP 成功已经放行端口、状态也已置 Connected，
    // 此模块只是可选的会话保活，关闭时完全不发起
    if (m_drcomHeartbeat) {
        m_udpProcess->setMd5Data(md5Data);
        QMetaObject::invokeMethod(m_udpProcess, "start", Qt::QueuedConnection);
    }
}

void SessionManager::onUdpOnline()
{
    // 活性守卫：同 onEapSuccess——DrCOM 握手完成可能在上层已断开/切走之后才排队到达
    if (m_activeBackend != ActiveBackend::WiredEap)
        return;
    setState(AppConnectionState::Connected);
}

void SessionManager::onStaticIpDone(int gen)
{
    // 代次防护：新一轮连接会递增代数——旧一轮的完成回调必须丢弃
    if (gen != m_ipSetupGeneration || m_state != AppConnectionState::SettingNetwork)
        return;
    m_staticIpPending = false;
    emit logMessage(QStringLiteral("静态IP设置完成，开始认证..."), 0);
    startAuth();
}

void SessionManager::onStaticIpFailed(const QString& error, int gen)
{
    if (gen != m_ipSetupGeneration)
        return;   // 旧一轮的失败：新一轮按自己的回调处理
    m_staticIpPending = false;
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
        m_retryAttempt = 0;      // 已上线：重试序号清零
        stopAutoWait();          // 已上线：不再需要就绪监听
        setState(AppConnectionState::Connected);
        startLinkWatch();
        break;

    case WifiAuthState::Failed:
        // 与有线同一套调度（夜间直接等到 6:01，白天 5 分钟间隔）
        handleAuthFailed(retryable, QStringLiteral("无线认证失败，将在明早 6:01 自动重试"));
        // 注意：这里【不】调用 WebAuthProcess::stop()——stop() 会执行 eportal
        // mac/unbind 解绑下线（那是"用户点断开/退出注销"才应有的动作）。
        // 认证失败后 Wi-Fi 仍应保持关联，等调度器重新 start()（start 自身会
        // 递增代数并清空未完成请求），重试不依赖先进程复位。
        break;

    case WifiAuthState::Stopped:
        // 归属守卫：与 onEapStateChanged(Stopped) 同型——只有当前后端仍是无线时才有
        // 状态回退可言（否则是已被 stopConnection 收尾的旧会话）
        if (m_activeBackend == ActiveBackend::PortalWifi)
            handleWorkerStopped(AppConnectionState::WiFiConnecting);
        // 注销确认完成：链路切换的挂机动作（断Wi-Fi→有线认证）在此续跑。
        // 与后端归属无关（切换时后端已被置为 None），必须始终调用。
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
    // 电源状态下单调时钟在睡眠期间不走或走得不准，因此"距 6:01 的重连等待"
    // 不会因睡眠而过期——早上唤醒后定时器仍要等完剩余时长（最坏拖到下午），
    // 表现为"待机一晚，早晨屏幕亮了却还是断开"。
    //
    // 唤醒后必须用墙钟重新评估重连排程：
    //  - 没有待执行的重连排程（在线 / 手动停用 / 永久错误停止）→ 不干预；
    //  - 已过 6:01（白天）→ 立即重试；
    //  - 仍在夜间 → 重排到最近的 6:01。
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
    // 有线就绪由系统接口变更通知即时触发（网线一插即认证）；Wi-Fi 关联状态无廉价
    // 通知，保留 2s 轮询（适配器枚举已带缓存，单次开销极小）
    ensureLinkMonitor();
    if (!m_autoWaitTimer) {
        m_autoWaitTimer = new QTimer(this);
        m_autoWaitTimer->setInterval(2000);   // 就绪检测：短轮询，Wi-Fi/网线一就绪即触发
        connect(m_autoWaitTimer, &QTimer::timeout, this, &SessionManager::onAutoWaitTick);
    }
    m_autoWaitRunning = true;   // 通知与轮询共用同一"运行中"开关（见头文件注释）
    m_autoWaitTimer->start();
    // 进入等待态：UI 由此亮「取消」（原「断开」按钮），用户可随时结束等待。
    // 只有 autoWaitEnabled 且 auto 模式（= 真的开起了监听）才置位，保证
    // "WaitingForNetwork ⇔ 正在等待（监听或重连排程）"的不变式。
    setState(AppConnectionState::WaitingForNetwork);
}

void SessionManager::stopAutoWait()
{
    // 注意：本函数【不】改主状态。退出等待态由调用方负责（上线路径会立刻置
    // SettingNetwork/Authenticating/Connected；取消路径由 stopConnection 统一回
    // Disconnected），否则 stopAutoWait 会在 onEapSuccess 前制造一次 Disconnected 闪烁。
    m_autoWaitRunning = false;   // 通知路径也必须停（见 onAutoWaitTick 首行）
    if (m_autoWaitTimer)
        m_autoWaitTimer->stop();
}

void SessionManager::onAutoWaitTick()
{
    // 运行中开关：stopAutoWait()（已上线 / 失败退避 / 用户取消）之后接口变更通知
    // 仍会到达，若不拦下会让"失败后立刻再认证"绕过 5 分钟 / 夜间 6:01 的重试节流
    if (!m_autoWaitRunning)
        return;
    if (!m_autoWaitEnabled || m_connectMode != ConnectMode::Auto)
        return;
    // 等待态（WaitingForNetwork）是就绪监听唯一合法的前提状态；其余（认证中/在线/
    // 已取消）都不应再触发认证
    if (m_state != AppConnectionState::WaitingForNetwork
        && m_state != AppConnectionState::Disconnected)
        return;

    // ① 有线优先：物理有线已接入 → 等链路稳定后再认证
    if (Network::ethernetLinkUp()) {
        if (m_reconnectTimer)
            m_reconnectTimer->stop();
        stopAutoWait();          // 状态保持 WaitingForNetwork（本函数不改状态）
        if (m_debugLog) {
            logAdapterDump(Network::dumpAdapters());
            debugLog(QStringLiteral("自动就绪监听：有线链路 Up → 选有线（%1 秒链路稳定等待）")
                         .arg(AUTO_WIRED_SETTLE_DELAY_MS / 1000));
        }
        // 链路稳定等待：就绪监听的触发时刻就是"插入瞬间"（接口变更通知），此时端口/
        // 交换机侧 802.1X 往往还没就绪，立刻发 EAPOL-Start 会吃 EAP-Failure——该失败
        // 按"致命"处理，会直接进 5 分钟/夜间重试，表现为"第一次自动有线认证固定失败、
        // 手动再连一次就好"。与"无线→有线联动切换"路径用同一套延时。
        emit logMessage(QStringLiteral("检测到有线网卡已接入，%1 秒后自动开始有线认证...")
                            .arg(AUTO_WIRED_SETTLE_DELAY_MS / 1000), 0);
        QTimer::singleShot(AUTO_WIRED_SETTLE_DELAY_MS, this, [this]() {
            // 等待期间用户点了「取消」（m_autoWaitEnabled=false）或链路又掉了 → 放弃本次
            if (!m_autoWaitEnabled || m_connectMode != ConnectMode::Auto
                || m_state != AppConnectionState::WaitingForNetwork)
                return;   // 用户已取消 / 已被其它路径接管：静默作废本次延时启动
            if (!Network::ethernetLinkUp()) {
                emit logMessage(QStringLiteral("有线链路复查未通过，继续等待网络就绪..."), 1);
                startAutoWait();   // 回到就绪监听，等下一次插入
                return;
            }
            m_activeBackend = ActiveBackend::WiredEap;   // 同步后端：isWifiUiLive/链路监视等依赖它
            startWiredBackend();
        });
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
        if (m_debugLog)
            debugLog(QStringLiteral("自动就绪监听：无线命中（SSID=%1）→ 选无线").arg(wlan.ssid));
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
    // 夜间直接等到 6:01 再触发，白天按固定间隔，避免通宵刷屏
    m_reconnectTimer->start(msecsToNextRetry());
}

void SessionManager::scheduleNextRetry(const QString& nightMessage)
{
    ++m_retryAttempt;
    // 固定间隔 + 重试序号：不做指数退避是刻意的——本程序的重试是"用户插上网线/连上
    // Wi-Fi 后多久能上网"的唯一路径（失败后不进入就绪监听，见 handleAuthFailed 注释），
    // 退避到 15~30 分钟会让恢复明显变慢；而整夜刷屏已由"夜间等到 6:01"覆盖。
    // 序号只是让长时间连续失败在日志里可分辨。
    emit logMessage(isNightWindow()
                        ? nightMessage
                        : QStringLiteral("认证失败，将在 %1 分钟后自动重试（第 %2 次）")
                              .arg(kReconnectIntervalMs / 60000).arg(m_retryAttempt),
                    1);
    // 重试等待同样是可以取消的等待：UI 亮「取消」，点它即停掉重连定时器（用户要求）
    setState(AppConnectionState::WaitingForNetwork);
    scheduleReconnect();
}

void SessionManager::handleAuthFailed(bool retryable, const QString& nightMessage)
{
    // 本轮有线会话结束：把静态 IP 还给 DHCP（用户明确要求：有线连不上时要恢复 DHCP，
    // 否则机器会带着校园静态 IP 离开校园网，且退出前一直无法上网）。
    // 重试路径（onReconnectTimeout→startWiredBackend）会按需重新配置静态 IP。
    restoreDhcp();

    if (retryable) {
        // 与时段相关的失败（夜间 6:01 / 白天 5 分钟间隔同一套调度）。
        // 【不要】在此进入就绪监听：那会让 onAutoWaitTick 2 秒内再次触发认证，
        // 失败→再监听 无限刷屏，并绕过夜间 6:01 / 5 分钟节流。失败重试只走
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
    // 回退为 Disconnected（否则连接/断开按钮错位）。等待态同理：等待 UI 由
    // 重连排程/就绪监听驱动，迟到的 Stopped 不得把它打回"未连接"（按钮会错位成
    // 可用「连接」而实际仍在等待）。
    if (m_state == guardState
        || m_state == AppConnectionState::Disconnected
        || m_state == AppConnectionState::WaitingForNetwork)
        return;
    // 状态回退曾是【静默】的：出问题时日志里既没有"已断开"也没有回退记录，
    // 只剩"界面停在未连接/又认证了一次"这种表象。调试模式下留一条痕迹。
    debugLog(QStringLiteral("工作进程已停止，状态回退为未连接（原状态=%1）")
                 .arg(static_cast<int>(m_state)));
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
    return RetryPolicy::isNightWindow(QDateTime::currentDateTime());
}

int SessionManager::msecsToNextRetry() const
{
    // 单次取时：原先 isNightWindow() 与 msecsToNextRetry() 各取一次"现在"，
    // 恰在午夜/6:01 边界上会得到互相矛盾的结果（见 RetryPolicy::nextRetryDelayMs）
    return RetryPolicy::nextRetryDelayMs(QDateTime::currentDateTime(), kReconnectIntervalMs);
}

void SessionManager::onReconnectTimeout()
{
    // 重连排程可能在两种状态下到点：Disconnected（含人工断开前的残留）与
    // WaitingForNetwork（重试等待/就绪等待——UI 显示为可取消的等待）
    if (m_state != AppConnectionState::Disconnected
        && m_state != AppConnectionState::WaitingForNetwork)
        return;
    stopAutoWait();   // 正式重试：停掉就绪监听（触发后由相应路径重新按需启动）

    // 防御分支：定时器可能按旧间隔触发且尚未跨过夜间窗口（如连接被重置后重入），
    // 若仍在夜间则重新等待到 6:01
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
                restoreDhcp();   // 放弃有线意图：静态 IP 还给 DHCP（见 handleAuthFailed）
                scheduleReconnect();
                startAutoWait();
                break;
            }
            // auto 模式：有线连续认证失败（≥2，常因交换机/端口不认证或环境暂不可用）
            // 且 Wi-Fi 仍关联并命中白名单时，回退无线——避免"插了网线却断网"。用户手动
            // 重连或有线成功（onEapSuccess）即清零；若后期线缆环境恢复，切回自动仍先试有线。
            if (m_activeBackend == ActiveBackend::WiredEap
                && m_connectMode == ConnectMode::Auto
                && m_wiredFailStreak >= RetryPolicy::kWiredFallbackThreshold) {
                // 外层守卫只为"不满足条件时省掉一次 wlanapi 查询"；判据本身在纯函数里
                const WlanMedia::WlanInfo wlan = WlanMedia::currentWifiConnection();
                if (m_debugLog)
                    debugLog(QStringLiteral("重连复判：有线失败次数=%1（≥%2），准备回退无线")
                                 .arg(m_wiredFailStreak).arg(RetryPolicy::kWiredFallbackThreshold));
                RetryPolicy::WifiFallbackInput fb;
                fb.autoMode        = (m_connectMode == ConnectMode::Auto);
                fb.wiredFailStreak = m_wiredFailStreak;
                fb.wifiConnected   = wlan.connected;
                fb.ssidMatched     = ConnectionBuilder::ssidMatch(wlan.ssid, m_ssidWhitelist);
                if (RetryPolicy::shouldFallbackToWifi(fb)) {
                    emit logMessage(QStringLiteral("有线连续认证失败，自动回退无线认证..."), 1);
                    restoreDhcp();   // 转无线：静态 IP 不再有意义，还给 DHCP
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
                // （无运行中定时器），新周期 start() 递增代数即可丢弃旧回调，无需 stop()。
                // UDP 侧不在此处停：下面 desired==WiredEap 分支本就统一停一次
                // （原先两处都停，同一路径上重复投递两次 stop）
                if (desired == ActiveBackend::PortalWifi)
                    restoreDhcp();   // 切无线：静态 IP 还给 DHCP
                m_activeBackend = desired;
            }
            if (desired == ActiveBackend::WiredEap) {
                // 走完整有线流程（而不是只 startAuth）：失败时已恢复 DHCP，静态 IP 必须
                // 在这里重新应用；startWiredBackend 同时会在认证时刻重算 localIp/MAC
                // 并解析 netsh 目标网卡（见其函数注释）。
                // EAP 侧 start() 自身会 closeDevice + resetSessionState，等价于 restart()
                // 的复位效果，不再依赖"队列 stop → 队列 start"的顺序契约。
                stopUdpIfRunning();
                startWiredBackend();
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
                restoreDhcp();
                scheduleReconnect();
                startAutoWait();
                break;
            }
            m_activeBackend = (decision.backend == ConnectionBuilder::AuthBackend::WiredEap)
                                  ? ActiveBackend::WiredEap
                                  : ActiveBackend::PortalWifi;
            // 有线一律走完整流程：等待期间静态 IP 已还给 DHCP（进入等待时 restoreDhcp），
            // 这里必须重新应用，否则会出现"认证带着未配置的静态 IP 必然失败"
            if (m_activeBackend == ActiveBackend::WiredEap)
                startWiredBackend();
            else
                startWifiAuth();
        }
        break;
    }
}
