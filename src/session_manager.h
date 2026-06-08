#ifndef SESSION_MANAGER_H
#define SESSION_MANAGER_H

#include <QObject>
#include <QThread>
#include "protocol.h"
#include "eap_process.h"
#include "udp_process.h"
#include "network_worker.h"

// ============================================================================
// 应用连接状态机 — 从 MainWindow 抽取，负责整个连接流程的编排
// ============================================================================

enum class AppConnectionState {
    Disconnected,
    SettingNetwork,
    Authenticating,
    Connected
};

// 静态IP配置参数（仅当 autoSetNetwork 时需要）
struct StaticIpConfig {
    QString adapterName;   // netsh 适配器名
    QString ip;
    QString mask;
    QString gateway;
    QString dns1;
    QString dns2;
    QString mac;           // DHCP 恢复用的 MAC 字符串
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

signals:
    void stateChanged(AppConnectionState state);
    void logMessage(const QString& message, int level);

private slots:
    void onEapStateChanged(AuthState state, const QString& message);
    void onEapSuccess(const QByteArray& md5Data);
    void onUdpOnline();
    void onStaticIpDone();
    void onStaticIpFailed(const QString& error);
    void onHeartbeatFailed();

private:
    void initProcesses();
    void startAuth();       // EAP 认证阶段（静态IP完成后调用）
    void restoreDhcp();
    void setState(AppConnectionState state);

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

    // --- 死连接检测 ---
    int m_heartbeatFailCount = 0;
    static constexpr int kMaxHeartbeatFailures = 3;
};

#endif // SESSION_MANAGER_H
