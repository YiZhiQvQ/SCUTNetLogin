#ifndef EAP_PROCESS_H
#define EAP_PROCESS_H

#include <QObject>
#include <QTimer>
#include <QElapsedTimer>
#include <QMutex>
#include <atomic>
#include "core/protocol.h"
#include "core/log_level.h"
#include "core/deferred_signals.h"

// Npcap 前向声明（与 pcap.h 中 `typedef struct pcap pcap_t;` 完全一致），
// 避免把 <pcap.h> 泄漏给所有包含本头的模块（session_manager / mainwindow ...）。
struct pcap;
typedef struct pcap pcap_t;

class EapProcess : public QObject {
    Q_OBJECT

public:
    explicit EapProcess(QObject* parent = nullptr);
    ~EapProcess() override;

    void setConfig(AuthConfig config);
    // 调试输出开关：开启后收发 EAPOL 帧输出原始 hex（worker 线程原子自读）
    void setDebugLogEnabled(bool on);

public slots:
    void start();
    void stop();
    // 自动重连专用：复位 + 重启。等价于 stop() + start()，区别在于复位阶段
    // 【不发射 Stopped 状态信号】（重连期上层状态为 Authenticating，Stopped 会把
    // 应用状态机错误回退为 Disconnected），也不依赖"stop→start"的队列顺序契约
    // （见 SessionManager::onReconnectTimeout）。
    // 实现上分两段持锁（先复位、再调 start()），中间锁是放开的——不是"单次持锁"。
    void restart();

signals:
    // retryable=false 表示永久性错误（凭证/账户状态），上层不应自动重试
    void stateChanged(AuthState state, const QString& message, bool retryable = true);
    void logMessage(const QString& message, int level);
    void eapSuccess(const QByteArray& md5Data);
    void sleepRequired();

private slots:
    void onPollTimeout();
    void onTimeout();

private:
    // pcap 设备管理。【不】要求持有 m_mutex：m_handle 只被工作线程访问
    // （start/stop/restart/析构均在该线程内执行），且 pcap_open_live 可能阻塞
    // 数百 ms——放进 m_mutex 会让主线程的 setConfig() 同步干等（见 start()）。
    // ifName 由调用者在锁内取好传进来，避免在锁外读 m_config；
    // bpfWarning 非空表示过滤器编译失败（由调用者在锁内记日志）。
    bool openDevice(const QByteArray& ifName, QString* error, QString* bpfWarning);
    void closeDevice();

    // 发包 / 收包（调用者须持有 m_mutex）
    bool sendPacket(const uint8_t* data, size_t len);
    QByteArray receivePacket();

    // 帧组装
    std::vector<uint8_t> buildEapolFrame(uint8_t eapolType, uint16_t eapolBodyLen) const;

    // 高层发送（调用者须持有 m_mutex）
    void sendEapolStart();
    void sendEapolLogoff();
    void sendEapResponse(uint8_t eapType, uint8_t requestId,
                         const QByteArray& payload, QByteArray& lastPacket);

    void parseNotification(const QString& msg);

    // 会话级状态复位（start()/restart() 起点共用；调用者须持有 m_mutex）。
    // 这些字段若跨会话残留，会出现"用上一会话的 MD5 结果发 Alive"、
    // "Logoff 发往上一会话的交换机 MAC"之类的问题。
    void resetSessionState();

    // 持锁期间只缓冲信号，解锁后由 flushPending() 统一发出。
    // 目的：避免在持有 m_mutex 的临界区内执行槽逻辑，防止未来某处把连接方式
    // 改为 DirectConnection 时产生锁重入/死锁（当前所有信号均为跨线程 Queued）。
    // 调用以下 defer 系列前须持有 m_mutex。
    void log(LogLevel level, const QString& msg);
    void deferState(AuthState state, const QString& msg, bool retryable = true);
    void deferEapSuccess(const QByteArray& md5);
    void deferSleepRequired();
    void flushPending();               // 调用者须【不】持有 m_mutex

    static bool isMulticastMac(const uint8_t* mac);

    // onPollTimeout 子步骤（调用者须持有 m_mutex）
    QVector<QByteArray> drainPackets();
    bool processEapPacket(const QByteArray& packet);   // false = 致命错误，需 stop
    void handleEapRequest(const EAPHeader& hdr, const QByteArray& payload);
    void checkRetransmit();

    // 持锁期间缓冲的信号（按产生顺序发出，保持日志与状态变更的顺序）
    struct PendingSignal {
        enum class Kind { StateChanged, EapSuccess, SleepRequired, Log };
        Kind     kind = Kind::Log;
        AuthState state = AuthState::Idle;
        QString  msg;
        QByteArray md5;
        int      logLevel = 0;
        bool     retryable = true;
    };
    DeferredSignalQueue<PendingSignal> m_pending;

    AuthConfig m_config;

    pcap_t*    m_handle = nullptr;
    QTimer*    m_pollTimer = nullptr;
    QElapsedTimer m_retransmitTimer;

    std::atomic<bool> m_running{false};
    std::atomic<bool> m_stopRequested{false};
    std::atomic<bool> m_debugLog{false};   // 调试输出（帧级 hex）
    AuthState m_currentState = AuthState::Idle;

    // start 代数：start()/stop()/restart() 各递增一次。所有异步延续
    // （2 秒端口清理单发定时器等）捕获发起时的代数，回调时发现代数不匹配
    // 即说明会话已换代，直接丢弃——防止旧 start 的遗留定时器污染新会话。
    int m_startGeneration = 0;

    int         m_retransmitLogCount = 0;   // 重发日志节流计数（收到任何 EAP 包时清零）
    bool        m_permanentFailure = false; // 本次认证已判定为永久性错误（停止自动重试）
    bool        m_pcapErrorLogged = false;  // pcap 读取错误日志节流（同一错误只记一次）
    // "EAP 帧来源与交换机不一致"的告警节流（每会话一次；仅调试可见，见 processEapPacket）
    bool        m_srcMacWarned = false;
    uint8_t     m_switchMac[6];
    QByteArray  m_lastIdentityPacket;
    QByteArray  m_lastMd5Packet;
    QByteArray  m_md5Result;
    QString     m_lastError;       // pcap_open_live 失败时的错误信息

    QMutex m_mutex;
};

#endif // EAP_PROCESS_H
