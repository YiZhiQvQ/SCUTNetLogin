#ifndef WEBAUTH_PROCESS_H
#define WEBAUTH_PROCESS_H

#include <QByteArray>
#include <QMutex>
#include <QObject>
#include <QString>
#include <atomic>
#include "core/constants.h"
#include "core/deferred_signals.h"
#include "core/protocol.h"
#include "wifi/portal_parser.h"

class QNetworkAccessManager;
class QNetworkReply;
class QNetworkRequest;
class QUrl;
class QTimer;

// ============================================================================
// 无线 Portal 认证进程 — Dr.COM WebLoginID 4.0 eportal（SCUT scut-student）
//
// 生命周期沿袭 EapProcess / UdpProcess：随 m_wifiThread 懒启动；setConfig() 由主线程
// 同步直调；信号经 DeferredSignalQueue 持锁缓冲、解锁 flush；异步延续捕获
// m_startGeneration，start()/stop()/checkNow() 各自递增、不匹配即丢弃。
//
// 单链状态机（每步异步回调互控）：
//   probe（网关 302=未认证→门户；无 302→门户确认在线）
//   → fetchPortalPage → fetchLoadConfig（动态 page_index/login_method/en_md5）
//   → sendLogin（portal/login，浏览器实测路径）→ confirmOnline（online_list 轮询）
//   → Online（60s 轮询回 probe）
//
// 协议依据见 docs/wifi_auth_logic.md。
// ============================================================================

// 无线认证子状态（与 EAP 的 AuthState 镜像）
enum class WifiAuthState {
    Idle,            // 未启动
    Probing,         // 探测在线状态
    FetchingPortal,  // 跟随重定向 + 抓取门户页
    LoggingIn,       // 发送登录 + 等待上线确认
    Online,          // 已上线（登录成功或探测免登）
    Failed,          // 失败（retryable 标志区分可重试/永久）
    Stopped          // 用户主动断开
};

class WebAuthProcess : public QObject {
    Q_OBJECT

public:
    explicit WebAuthProcess(QObject* parent = nullptr);
    ~WebAuthProcess() override;

    // 同步直调：先于排队的 start() 执行，保证工作线程看到最新配置（与 EAP/UDP 契约一致）
    void setConfig(const AuthConfig& config);
    // 调试输出开关：开启后输出无线 Portal 各阶段（探测/解析/login/确认）追踪
    void setDebugLogEnabled(bool on);

public slots:
    void start();
    void stop();        // 用户"断开"：mac/unbind 解绑下线（异步）；不做物理断开，
                        // Wi-Fi 连接由系统/用户自行管理
    void checkNow();    // 立即重探测（系统唤醒 / 手动触发）
    void stopSession(); // 仅结束本进程（代数递增/abort/停定时器），不发 mac/unbind、
                        // 不发射信号——用于"退出且未勾选注销"：门户会话保持在线，
                        // 轮询与请求全部静默终止（SessionManager 析构路径用）

signals:
    void stateChanged(WifiAuthState state, const QString& message, bool retryable = true);
    void online();
    void logMessage(const QString& message, int level);

private:
    // 延迟信号结构（持锁期间追加，flush 后发射，保持产生顺序）
    struct PendingSignal {
        enum class Kind { State, Log, Online } kind = Kind::State;
        WifiAuthState state = WifiAuthState::Idle;
        QString message;
        bool    retryable = true;
        int     level = 0;
    };

    // --- 状态机阶段 ---
    void beginCycle();                    // 入口：probe ① 网关 302 探测（唯一可信、绑 Wi-Fi）
    void probeGateway();                  // ① 网关探测：302→门户；无 302/异常→查门户在线状态
    void queryOnlineStatus();             // ①(b) 无 302：逐个候选域名用 online_list 探测"哪个认识本机会话"，确定当前 zone 域名
    void probeCandidate(int gen);         // ①(b) 探测当前候选校区域名的 online_list（链式推进，见 queryOnlineStatus）
    void tryAlternateDomain();            // 默认域名登录失败且可重试时，换另一候选域名重来（防"错区登不上"）
    void fetchPortalPage(const QUrl& url);// ② 抓取门户页 → 解析
    void fetchPortalRedirect(const QUrl& url, int depth); // ② 手动跟随门户重定向链（成员函数重入，避免递归 std::function 自捕获悬垂）
    void fetchLoadConfig();               // ⑤ 动态配置（page_index/en_md5/login_method）
    void sendLogin();                     // ⑥ 登录前在线检查（已在线→直接上线）
    void sendLoginBody();                 // ⑥（实际登录：portal/login，浏览器实测路径）
    void confirmOnline();                 // ⑦ online_list 上线确认（轮询 8s×N）
    void finishOnline();                  // ⑧ 判定在线：状态 + 启动在线轮询
    void sendUnbindRequest();             // ⑨ stop() 的异步解绑请求（替代嵌套 QEventLoop，时序见 stop())

    // --- QNAM 辅助 ---
    QNetworkRequest makeRequest(const QUrl& url, bool ignoreTls) const;
    void sendJsonpGet(const QUrl& url, bool ignoreTls, int timeoutMs,
                      const std::function<void(const QByteArray&, const QString&)>& onDone);
    bool staleGen(int gen) const;         // 代数/运行态守卫（回调入口统一调用）

    // 门户 URL / JSONP 参数构造（多处复用，防参数漂移）
    QUrl portalUrl(const QByteArray& path) const;  // <origin>:<port><path>（login/loadConfig/unbind 共用骨架）
    void teardown();                      // abort/清空请求 + 停两个定时器（stop/stopSession/checkNow 公共尾部）

    // 运行期本机无线地址（权威：startWifiAuth 已从 Wi-Fi 接口写入 m_config；
    // v46ip 仅作次级兜底——首轮探测时效，但 m_vars 尚未解析）
    quint32 wifiIpInt() const;            // 本地 IP 整数值（用于 online_list 查询参数）
    QString wifiIpString() const;         // 点分十进制（session 归属校验用）
    QString wifiMacHex() const;           // 6 字节大写十六进制（接口未取到时为全零）

    // --- 成员 ---
    AuthConfig  m_config;
    mutable QMutex m_mutex;                                     // 保护 m_running/代数/信号队列
    DeferredSignalQueue<PendingSignal> m_pending;               // 持锁缓冲、解锁后 flush
    int  m_startGeneration = 0;
    bool m_running = false;
    std::atomic<bool> m_debugLog{false};                        // 调试输出（Portal 阶段追踪）

    QNetworkAccessManager* m_nam = nullptr;                     // 工作线程内懒创建
    QTimer* m_pollTimer    = nullptr;                           // 在线期轮询（60s）
    QTimer* m_confirmTimer = nullptr;                           // 上线确认轮询
    QList<QNetworkReply*> m_pendingReplies;                     // stop 时统一 abort

    // 运行期协议数据（每轮检查是否需要重置：以 gen 为准，旧回调被丢弃）
    QString m_gatewayIp;              // 无线网关（探测目标）
    QString m_portalOrigin;           // 门户 scheme://host（不含端口，如 https://s2.scut.edu.cn）
    int     m_eportalPort = EPORTAL_HTTPS_PORT;   // eportal API 端口（页面决定 801/802）
    QString m_loginMethod;            // loadConfig → login_method（统一走 portal/login；空值→默认 "1"）
    bool    m_enMd5 = false;          // loadConfig → en_md5
    int     m_confirmAttempts = 0;    // 上线确认已尝试次数
    int     m_portalFetchRetries = 0; // 门户页抓取瞬态失败重试计数
    int     m_loadConfigRetries = 0;  // loadConfig 瞬态失败重试计数
    // —— 校区域名候选探测（多校区；无 302 时用 online_list 选"认识当前会话"的域名） ——
    int  m_probeIdx = 0;              // 当前探测到第几个候选域名
    bool m_probeSawUsable = false;    // 本次探测是否有候选给出可解析的 online_list 响应
    bool m_domainConfirmed = false;   // 当前 m_portalOrigin 是否已被证实（302 或 online_list 命中）
    bool m_triedAlternate = false;    // 是否已换过校区域名重试（防无限循环）
    // 本次会话是否已向上层宣告"在线"（首次上线才打印确认日志/发 Online 信号；
    // 60 秒在线轮询命中在线时静默续跑，避免重复刷屏）
    bool    m_onlineNotified = false;
    PortalParser::PortalVars m_vars;  // 门户解析结果（本轮）

    // 信号缓冲（持锁 append、解锁 flush，与 EAP/UDP 同惯例）
    void deferState(WifiAuthState s, const QString& msg = QString(), bool retryable = true);
    void deferLog(const QString& msg, int level = 0);
    void deferOnline();
    void flushPending();

    // 调试输出：仅 m_debugLog 时以 [调试] 前缀缓冲到信号队列（与 deferLog 同型）
    void debugLog(const QString& message);
};

#endif // WEBAUTH_PROCESS_H
