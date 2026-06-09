#include "session_manager.h"
#include "constants.h"
#include "network.h"
#include "log_manager.h"
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

    QMetaObject::invokeMethod(m_eapProcess, "stop", Qt::QueuedConnection);
    QMetaObject::invokeMethod(m_udpProcess, "stop", Qt::QueuedConnection);

    m_eapThread.quit();
    m_eapThread.wait();
    m_udpThread.quit();
    m_udpThread.wait();
    m_networkThread.quit();
    m_networkThread.wait();
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
        const int hour = QDateTime::currentDateTime().time().hour();
        if (hour < 6) {
            emit logMessage(QStringLiteral("当前时段禁止上网，将在明早 6:00 自动重试"), 2);
        } else {
            emit logMessage(QStringLiteral("认证失败，将在 %1 分钟后自动重试")
                            .arg(kReconnectIntervalMs / 60000), 1);
        }
        QMetaObject::invokeMethod(m_eapProcess, "stop", Qt::QueuedConnection);
        QMetaObject::invokeMethod(m_udpProcess, "stop", Qt::QueuedConnection);
        setState(AppConnectionState::Disconnected);
        scheduleReconnect();
    });
    m_eapThread.start();

    // -- UDP 心跳线程 --
    m_udpProcess = new UdpProcess();
    m_udpProcess->moveToThread(&m_udpThread);
    connect(&m_udpThread, &QThread::finished, m_udpProcess, &QObject::deleteLater);
    connect(m_udpProcess, &UdpProcess::online,        this, &SessionManager::onUdpOnline);
    connect(m_udpProcess, &UdpProcess::logMessage,    this, &SessionManager::logMessage);
    connect(m_udpProcess, &UdpProcess::heartbeatFailed, this, &SessionManager::onHeartbeatFailed);
    connect(m_udpProcess, &UdpProcess::heartbeatOk,     this, [this]() {
        m_heartbeatFailCount = 0;  // 心跳成功后重置失败计数，仅连续失败才触发断连
    });
    m_udpThread.start();

    // -- 网络配置线程（netsh/schtasks） --
    m_networkWorker = new NetworkWorker();
    m_networkWorker->moveToThread(&m_networkThread);
    connect(&m_networkThread, &QThread::finished, m_networkWorker, &QObject::deleteLater);
    connect(m_networkWorker, &NetworkWorker::staticIpDone,   this, &SessionManager::onStaticIpDone);
    connect(m_networkWorker, &NetworkWorker::staticIpFailed, this, &SessionManager::onStaticIpFailed);
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
    m_heartbeatFailCount = 0;

    if (!ipCfg.adapterName.isEmpty()) {
        setState(AppConnectionState::SettingNetwork);
        m_wasStaticIpSet = true;

        emit logMessage(QStringLiteral("正在设置静态IP: %1 / %2 / %3 ...")
                        .arg(ipCfg.ip, ipCfg.mask, ipCfg.gateway), 0);

        // 安全超时
        QTimer::singleShot(IP_SETUP_TIMEOUT, this, [this]() {
            if (m_state == AppConnectionState::SettingNetwork) {
                emit logMessage(QStringLiteral("静态IP设置超时，请检查适配器名和网络配置"), 2);
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

void SessionManager::startAuth()
{
    setState(AppConnectionState::Authenticating);
    emit logMessage(QStringLiteral("开始802.1X认证..."), 0);

    m_eapProcess->setConfig(m_config);
    m_udpProcess->setConfig(m_config);

    QMetaObject::invokeMethod(m_eapProcess, "start", Qt::QueuedConnection);
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

void SessionManager::onEapStateChanged(AuthState state, const QString& message)
{
    if (!message.isEmpty())
        emit logMessage(message, state == AuthState::Failed ? 2 : 0);

    if (state == AuthState::Failed) {
        const int hour = QDateTime::currentDateTime().time().hour();
        if (hour < 6) {
            emit logMessage(QStringLiteral("认证失败，将在明早 6:00 自动重试"), 1);
        } else {
            emit logMessage(QStringLiteral("认证失败，将在 %1 分钟后自动重试")
                            .arg(kReconnectIntervalMs / 60000), 1);
        }
        setState(AppConnectionState::Disconnected);
        scheduleReconnect();
    } else if (state == AuthState::Stopped) {
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
    m_heartbeatFailCount = 0;  // 重置心跳失败计数
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
    setState(AppConnectionState::Disconnected);
}

void SessionManager::onHeartbeatFailed()
{
    // DrCOM 服务器经常不回复心跳包但网络仍正常，心跳超时静默忽略
}

void SessionManager::scheduleReconnect()
{
    if (!m_reconnectTimer) {
        m_reconnectTimer = new QTimer(this);
        m_reconnectTimer->setSingleShot(true);
        connect(m_reconnectTimer, &QTimer::timeout, this, &SessionManager::onReconnectTimeout);
    }
    m_reconnectTimer->start(kReconnectIntervalMs);
}

void SessionManager::onReconnectTimeout()
{
    if (m_state != AppConnectionState::Disconnected)
        return;

    // 夜间 0:00-6:00 不重试，等到 6:00 再开始，避免通宵刷屏
    const int hour = QDateTime::currentDateTime().time().hour();
    if (hour < 6) {
        QDateTime now = QDateTime::currentDateTime();
        QDateTime sixAm(now.date(), QTime(6, 0));
        qint64 msecsToSix = now.msecsTo(sixAm);
        m_reconnectTimer->start(static_cast<int>(msecsToSix));
        return;
    }

    emit logMessage(QStringLiteral("尝试重新连接..."), 0);

    // 跳过静态IP设置阶段（IP 已在上次连接时配置好），直接开始认证
    QMetaObject::invokeMethod(m_eapProcess, "stop", Qt::QueuedConnection);
    QMetaObject::invokeMethod(m_udpProcess, "stop", Qt::QueuedConnection);
    startAuth();
}
