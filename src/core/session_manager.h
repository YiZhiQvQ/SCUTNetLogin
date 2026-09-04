#ifndef SESSION_MANAGER_H
#define SESSION_MANAGER_H

#include <QObject>
#include <QThread>
#include "core/protocol.h"
#include "eap/eap_process.h"
#include "udp/udp_process.h"
#include "network/network_worker.h"

class LogManager;

// ============================================================================
// 应用连接状态机 — 负责整个连接流程的编排
// ============================================================================

enum class AppConnectionState {
    Disconnected,
    SettingNetwork,
    Authenticating,
    Connected
};

class SessionManager : public QObject {
    Q_OBJECT

public:
    explicit SessionManager(QObject* parent = nullptr);
    ~SessionManager() override;

    AppConnectionState state() const { return m_state; }

    // ipCfg.adapterName 非空时先设置静态IP再认证；为空则直接认证
    void startConnection(const AuthConfig& config, const StaticIpConfig& ipCfg = {});
    void stopConnection();

    // 开机自启（通过 Windows Task Scheduler）
    void setAutoStart(bool enable);

    // 系统从待机/睡眠唤醒时由 MainWindow（native event filter）调用：
    // 睡眠期间 Qt 定时器基于单调时钟（部分电源状态下不走/不准），
    // 重连排程（如"距 6:00 再试"）会被整体顺延；唤醒后用墙钟重新评估。
    void onSystemResume();

signals:
    void stateChanged(AppConnectionState state);
    void logMessage(const QString& message, int level);

private slots:
    void onEapStateChanged(AuthState state, const QString& message, bool retryable = true);
    void onEapSuccess(const QByteArray& md5Data);
    void onUdpOnline();
    void onStaticIpDone();
    void onStaticIpFailed(const QString& error);
    void onHeartbeatFailed();
    void onReconnectTimeout();
    void onAutoStartDone(bool ok, const QString& error);

private:
    void initProcesses();
    void startAuth(bool restartEap = false);   // EAP 认证阶段（静态IP完成后调用）
                                               // restartEap=true: 重连路径用原子的
                                               // EapProcess::restart() 替代 stop+start
    void restoreDhcp();
    void setState(AppConnectionState state);

    // --- 自动重连调度 ---
    void scheduleReconnect();
    // 认证失败后的统一处理：按时间段提示 + 进入 Disconnected + 调度重连
    void scheduleNextRetry(const QString& nightMessage
                           = QStringLiteral("认证失败，将在明早 6:00 自动重试"));
    bool isNightWindow() const;            // 0:00-6:00 视为夜间，避免通宵刷屏
    int  msecsToNextRetry() const;         // 夜间 → 距 6:00 毫秒数；白天 → 固定间隔

    // --- 线程 & 工作对象 ---
    QThread        m_eapThread;
    QThread        m_udpThread;
    QThread        m_networkThread;
    EapProcess*    m_eapProcess    = nullptr;
    UdpProcess*    m_udpProcess    = nullptr;
    NetworkWorker* m_networkWorker = nullptr;

    // --- 状态 ---
    AppConnectionState m_state = AppConnectionState::Disconnected;
    AuthConfig     m_config;
    StaticIpConfig m_ipCfg;
    bool           m_wasStaticIpSet = false;

    // --- 日志 ---
    LogManager*    m_logManager = nullptr;

    // --- 自动重连 ---
    QTimer* m_reconnectTimer = nullptr;
    static constexpr int kReconnectIntervalMs = 5 * 60 * 1000;  // 5 分钟

    // 注意：本机网络的心跳超时【不】触发断连/重连。
    // 校园网 DrCOM 服务器经常不回复 UDP 心跳包但网络仍正常，若按心跳超时判定断线
    // 会导致网络被频繁误断。心跳仅用于维持会话，断线检测只依赖 EAP 层失败与
    // 服务器主动踢线（EAP-Failure / 服务器通知），见 onHeartbeatFailed() 注释。
};

#endif // SESSION_MANAGER_H
