#include "core/session_manager.h"
#include "core/constants.h"
#include "network/network.h"
#include "log/log_manager.h"
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

    m_eapThread.quit();
    m_eapThread.wait();
    m_udpThread.quit();
    m_udpThread.wait();
    m_networkThread.quit();
    m_networkThread.wait();

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
    connect(m_networkWorker, &NetworkWorker::staticIpDone,   this, &SessionManager::onStaticIpDone);
    connect(m_networkWorker, &NetworkWorker::staticIpFailed, this, &SessionManager::onStaticIpFailed);
    connect(m_networkWorker, &NetworkWorker::autoStartDone,  this, &SessionManager::onAutoStartDone);
    m_networkThread.start();

    // -- 日志文件持久化 --
    m_logManager = new LogManager(this);
    connect(this, &SessionManager::logMessage, m_logManager, &LogManager::onLogMessage);
}

// ============================================================================
// 连接 / 断开 主逻辑
// ============================================================================

void SessionManager::startConnection(const AuthConfig& config, const StaticIpConfig& ipCfg)
{
    if (m_state != AppConnectionState::Disconnected)
        return;

    m_config = config;
    m_ipCfg  = ipCfg;
    m_wasStaticIpSet = false;

    if (!ipCfg.adapterName.isEmpty()) {
        setState(AppConnectionState::SettingNetwork);
        m_wasStaticIpSet = true;

        emit logMessage(QStringLiteral("正在设置静态IP: %1 / %2 / %3 ...")
                        .arg(ipCfg.ip, ipCfg.mask, ipCfg.gateway), 0);

        // 安全超时
        QTimer::singleShot(IP_SETUP_TIMEOUT, this, [this]() {
            if (m_state == AppConnectionState::SettingNetwork) {
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

void SessionManager::stopConnection()
{
    if (m_reconnectTimer)
        m_reconnectTimer->stop();

    if (m_state == AppConnectionState::Disconnected)
        return;

    QMetaObject::invokeMethod(m_eapProcess, "stop", Qt::QueuedConnection);
    QMetaObject::invokeMethod(m_udpProcess, "stop", Qt::QueuedConnection);

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
    if (!message.isEmpty())
        emit logMessage(message, state == AuthState::Failed ? 2 : 0);

    if (state == AuthState::Failed) {
        if (retryable) {
            scheduleNextRetry();
        } else {
            // 永久性错误（凭证/账户状态，如密码错误、账号停用、流量用尽）：
            // 自动重试无法自行恢复，停止重试，等待用户手动处理
            if (m_reconnectTimer)
                m_reconnectTimer->stop();
            emit logMessage(QStringLiteral("该错误无法自动恢复，已停止自动重试，请检查账号信息后手动连接"), 1);
            setState(AppConnectionState::Disconnected);
        }
    } else if (state == AuthState::Stopped) {
        // 普通 stop()（用户断开/停止）会发 Stopped；自动重连路径的 restart()
        // 不发。防御性守卫：即使未来某条路径在认证中排队了 stop()，也禁止
        // 把 Authenticating 回退为 Disconnected（否则连接/断开按钮错位）。
        if (m_state != AppConnectionState::Authenticating)
            setState(AppConnectionState::Disconnected);
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
    setState(AppConnectionState::Connected);
    m_udpProcess->setMd5Data(md5Data);
    QMetaObject::invokeMethod(m_udpProcess, "start", Qt::QueuedConnection);
}

void SessionManager::onUdpOnline()
{
    setState(AppConnectionState::Connected);
}

void SessionManager::onStaticIpDone()
{
    if (m_state != AppConnectionState::SettingNetwork)
        return;
    emit logMessage(QStringLiteral("静态IP设置完成，开始认证..."), 0);
    startAuth();
}

void SessionManager::onStaticIpFailed(const QString& error)
{
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
    if (!m_reconnectTimer || !m_reconnectTimer->isActive())
        return;

    emit logMessage(QStringLiteral("已从待机唤醒，检查自动重连状态..."), 0);
    onReconnectTimeout();   // 内部有状态守卫 + 夜间重排 + 白天立即重连
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

    // 防御分支：定时器可能按旧间隔触发且尚未跨过夜间窗口（如连接被重置后重入），
    // 若仍在夜间则重新等待到 6:00
    if (isNightWindow()) {
        m_reconnectTimer->start(msecsToNextRetry());
        return;
    }

    emit logMessage(QStringLiteral("尝试重新连接..."), 0);

    // 跳过静态IP设置阶段（IP 已在上次连接时配置好），直接开始认证。
    // EAP 用原子的 restart()（复位设备 + 重启，不发射 Stopped），不再依赖
    // "队列 stop → 队列 start" 的顺序契约；UDP 会话在失败时已停止，直接 start。
    QMetaObject::invokeMethod(m_udpProcess, "stop", Qt::QueuedConnection);
    startAuth(/*restartEap=*/true);
}
