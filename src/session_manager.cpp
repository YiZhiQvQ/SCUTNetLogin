#include "session_manager.h"
#include "constants.h"
#include "network.h"
#include <QTimer>
#include <QMetaObject>
#include <QHostAddress>

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
        emit logMessage(QStringLiteral("当前时段禁止上网，已自动断开"), 2);
        stopConnection();
    });
    m_eapThread.start();

    // -- UDP 心跳线程 --
    m_udpProcess = new UdpProcess();
    m_udpProcess->moveToThread(&m_udpThread);
    connect(&m_udpThread, &QThread::finished, m_udpProcess, &QObject::deleteLater);
    connect(m_udpProcess, &UdpProcess::online,        this, &SessionManager::onUdpOnline);
    connect(m_udpProcess, &UdpProcess::logMessage,    this, &SessionManager::logMessage);
    connect(m_udpProcess, &UdpProcess::heartbeatFailed, this, &SessionManager::onHeartbeatFailed);
    m_udpThread.start();

    // -- 网络配置线程（netsh/schtasks） --
    m_networkWorker = new NetworkWorker();
    m_networkWorker->moveToThread(&m_networkThread);
    connect(&m_networkThread, &QThread::finished, m_networkWorker, &QObject::deleteLater);
    connect(m_networkWorker, &NetworkWorker::staticIpDone,   this, &SessionManager::onStaticIpDone);
    connect(m_networkWorker, &NetworkWorker::staticIpFailed, this, &SessionManager::onStaticIpFailed);
    m_networkThread.start();
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
        emit logMessage(QStringLiteral("认证失败，正在恢复DHCP..."), 1);
        restoreDhcp();
        setState(AppConnectionState::Disconnected);
    } else if (state == AuthState::Stopped) {
        setState(AppConnectionState::Disconnected);
    }
}

void SessionManager::onEapSuccess(const QByteArray& md5Data)
{
    emit logMessage(QStringLiteral("认证成功，可以上网了！"), 0);
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
    m_heartbeatFailCount++;
    if (m_heartbeatFailCount >= kMaxHeartbeatFailures) {
        emit logMessage(QStringLiteral("心跳连续失败 %1 次，连接可能已断开")
                        .arg(m_heartbeatFailCount), 2);
        stopConnection();
    }
}
