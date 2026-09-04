#ifndef SESSION_MANAGER_H
#define SESSION_MANAGER_H

#include <QObject>
#include <QStringList>
#include <QThread>
#include "core/protocol.h"
#include "core/connection_builder.h"
#include "eap/eap_process.h"
#include "udp/udp_process.h"
#include "network/network_worker.h"
#include "wifi/webauth_process.h"

class LogManager;

// ============================================================================
// 应用连接状态机 — 负责整个连接流程的编排
// ============================================================================

enum class AppConnectionState {
    Disconnected,
    SettingNetwork,
    Authenticating,
    WiFiConnecting,     // 无线 Portal 认证（探测/登录/上线确认）
    Connected
};

// 当前生效的接入后端（自动重连/唤醒/断线检测的分发依据）
enum class ActiveBackend {
    None,        // 无会话（auto 模式扫描态）
    WiredEap,    // 有线 802.1X EAPOL + DrCOM UDP 心跳
    PortalWifi   // 无线 DrCOM Web Portal
};

class SessionManager : public QObject {
    Q_OBJECT

public:
    explicit SessionManager(QObject* parent = nullptr);
    ~SessionManager() override;

    AppConnectionState state() const { return m_state; }
    // 当前生效后端（主线程只读；UI 状态文案"当前连接模式"用）
    ActiveBackend activeBackend() const { return m_activeBackend; }

    // ipCfg.adapterName 非空时先设置静态IP再认证；为空则直接认证
    // mode/allowedSsids：联网方式与无线 SSID 白名单（无线模块，默认参数保持旧调用兼容）
    void startConnection(const AuthConfig& config, const StaticIpConfig& ipCfg = {},
                         ConnectMode mode = ConnectMode::Auto,
                         const QStringList& allowedSsids = {});
    // logoutWifi：true（用户点"断开"）= 无线同时注销；false（退出程序且未勾选退出登出）
    // = 不注销无线连接，仅停止会话（DHCP 恢复/线程收尾照常）。
    // userInitiated：true = 用户主动断开/退出（此后【不】自动就绪重连，直到再次手动连接）。
    void stopConnection(bool logoutWifi = true, bool userInitiated = false);

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
    void onStaticIpDone(int gen);
    void onStaticIpFailed(const QString& error, int gen);
    void onHeartbeatFailed();
    void onReconnectTimeout();
    void onAutoStartDone(bool ok, const QString& error);
    // 无线 Portal 反馈
    void onWifiStateChanged(WifiAuthState state, const QString& message, bool retryable = true);
    void onWifiOnline();

private:
    void initProcesses();
    void startAuth(bool restartEap = false);   // EAP 认证阶段（静态IP完成后调用）
                                               // restartEap=true: 重连路径用原子的
                                               // EapProcess::restart() 替代 stop+start
    void startWiredBackend();                  // 有线完整流程：勾选静态IP→设置→认证（与
                                               // startAuth 的区别：后者跳过网络配置阶段；
                                               // 手动连接与链路切换共用此入口）
    void startWifiAuth();                      // 无线 Portal 认证（刷新 IP/MAC/SSID + 启动进程）
    void restoreDhcp();
    void setState(AppConnectionState state);

    // auto 模式下"无线在线时插入网线→自动切有线"的链路监视（用户要求）
    void startLinkWatch();
    void stopLinkWatch();

    // auto 模式的后端决策（现场取链路/SSID，纯函数决定）
    ConnectionBuilder::BackendDecision decideBackend() const;

    // 无线 "Online" 回调的"仍应生效"守卫：仅当当前会话仍是无线后端且状态处于
    // 连接中/已连接才接受（防止用户断开后滞后的 Online 信号把状态翻回 Connected）
    bool isWifiUiLive() const;

    // --- 自动重连调度 ---
    void scheduleReconnect();
    // 断开态就绪监听（解决"开机自启早于 Wi-Fi 连接"）：仅自动模式且用户未手动断开时
    // 运行，每 2s 检查——有线插入→有线认证；否则匹配白名单 Wi-Fi 连上→无线认证。
    // 触发认证后停止；认证失败重新进入监听。用户点连接恢复自动，点断开/退出停止。
    void startAutoWait();
    void stopAutoWait();
    void onAutoWaitTick();
    QTimer* m_autoWaitTimer = nullptr;
    bool    m_autoWaitEnabled = false;   // 用户手动断开后置 false，直到下次手动连接恢复
    // 认证失败后的统一处理：按时间段提示 + 进入 Disconnected + 调度重连
    void scheduleNextRetry(const QString& nightMessage
                           = QStringLiteral("认证失败，将在明早 6:00 自动重试"));
    bool isNightWindow() const;            // 0:00-6:00 视为夜间，避免通宵刷屏
    int  msecsToNextRetry() const;         // 夜间 → 距 6:00 毫秒数；白天 → 固定间隔

    // 认证失败统一处理（onEapStateChanged / onWifiStateChanged 共用，行为逐字节一致）：
    // retryable → 按时间段调度重连；否则停止自动重试并回 Disconnected
    void handleAuthFailed(bool retryable,
                          const QString& nightMessage = QStringLiteral("认证失败，将在明早 6:00 自动重试"));
    // 链路切换挂机：注册"注销完成后切有线"并启动兜底定时器
    void beginWiredSwitchAfterLogout();
    void onWifiLogoutFinished();    // Stopped 确认路径（注销完成）
    void onPostLogoutTimeout();     // 兜底路径（注销确认信号缺失）
    // 工作进程 Stopped 的防御守卫（guardState = 该进程的"认证中"状态）：
    // 仅当主状态机不在认证中时才允许回退 Disconnected
    void handleWorkerStopped(AppConnectionState guardState);

    // --- 线程 & 工作对象 ---
    QThread         m_eapThread;
    QThread         m_udpThread;
    QThread         m_networkThread;
    QThread         m_wifiThread;
    EapProcess*     m_eapProcess     = nullptr;
    UdpProcess*     m_udpProcess     = nullptr;
    NetworkWorker*  m_networkWorker  = nullptr;
    WebAuthProcess* m_webAuthProcess = nullptr;

    // --- 状态 ---
    AppConnectionState m_state = AppConnectionState::Disconnected;
    AuthConfig     m_config;
    StaticIpConfig m_ipCfg;
    bool           m_wasStaticIpSet = false;
    // 静态IP设置代次：每次进入 SettingNetwork 递增；完成/失败/超时回调携代次校验，
    // 防"模式即时切换后旧一轮完成误触新一轮认证"
    int            m_ipSetupGeneration = 0;

    // --- 无线模块 ---
    ActiveBackend  m_activeBackend = ActiveBackend::None;
    ConnectMode    m_connectMode   = ConnectMode::Auto;
    QStringList    m_ssidWhitelist;
    QTimer*        m_linkWatchTimer = nullptr;   // auto 模式有线插入监视（5s 轮询）
    // auto 模式有线连续失败计数：≥2 次且无线可用时回退无线（防"插网线→切有线→失败→断网"；
    // 有线认证成功或用户重新发起连接时清零）
    int            m_wiredFailStreak = 0;

    // 链路切换（插网线→有线）的挂机动作：等待无线注销（mac/unbind）完成后再
    // 物理断开 Wi-Fi → 有线认证。注销完成由 Stopped 信号确认；缺失时靠兜底
    // 定时器继续（任何新的人工连接/断开都会取消挂机）。
    enum class PostLogoutAction { None, SwitchToWired };
    PostLogoutAction m_postLogoutAction = PostLogoutAction::None;
    QTimer*          m_postLogoutTimeout = nullptr;   // 注销确认兜底（WIFI_LOGOUT_TIMEOUT_MS+2s）
    // 联动监视的上次有线链路状态（边缘检测：只在 插入/拔出 转变时打一行日志，
    // 用于诊断"拔线无反应"——程序看到的链路状态与用户的真实操作是否一致）
    bool           m_lastEthernetUp = false;

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
