#ifndef UDP_PROCESS_H
#define UDP_PROCESS_H

#include <QObject>
#include <QUdpSocket>
#include <QTimer>
#include <QMutex>
#include <atomic>
#include <array>
#include "core/protocol.h"
#include "core/log_level.h"
#include "core/deferred_signals.h"

class UdpProcess : public QObject {
    Q_OBJECT

public:
    explicit UdpProcess(QObject* parent = nullptr);
    ~UdpProcess() override;
    void setConfig(const AuthConfig& config);
    void setMd5Data(const QByteArray& md5Data);

public slots:
    void start();
    void stop();

signals:
    void stateChanged(const QString& state, const QString& message);
    void online();              // UDP 握手完成，进入在线心跳状态
    void logMessage(const QString& message, int level);
    void heartbeatFailed();     // 单次心跳超时（上层静默忽略，见 SessionManager::onHeartbeatFailed）
    void heartbeatOk();         // 心跳周期成功完成（服务器 ACK）——保留信号供日志/调试，无断连语义

private slots:
    void onReadyRead();
    void sendHeartbeat();
    void onHeartbeatTimeout();

private:
    void sendUdpPacket(const char* data, size_t len);
    void sendMiscAlive();
    void sendMiscInfo();
    void sendAlive();
    void sendMiscHeartbeat(uint8_t hbSubtype);

    // 与 EapProcess 相同的信号缓冲模式：持锁期间只缓冲，解锁后统一 flush，
    // 避免在持有 m_mutex 的临界区内 emit（防止未来 DirectConnection 死锁）。
    // 调用 defer 系列前须持有 m_mutex；flushPending 须【不】持有。
    struct PendingSignal {
        enum class Kind { Log, StateChanged, Online, HeartbeatFailed, HeartbeatOk };
        Kind     kind = Kind::Log;
        QString  state;
        QString  msg;
        int      logLevel = 0;
    };
    void log(LogLevel level, const QString& msg);
    void deferStateChanged(const QString& state, const QString& msg);
    void deferOnline();
    void deferHeartbeatFailed();
    void deferHeartbeatOk();
    void flushPending();

    DeferredSignalQueue<PendingSignal> m_pending;

    QMutex m_mutex;
    AuthConfig m_config;
    QByteArray m_md5Result;             // EAP-MD5 原始结果（16字节，不可变）
    uint32_t   m_cks32 = 0;             // MiscInfo 校验和（sendMiscInfo 中计算，sendAlive 中拼入前 4 字节）
    std::array<uint8_t, 16> m_decryptedInfo{};
    std::array<uint8_t, 4>  m_flux{};
    std::array<uint8_t, 2>  m_rnd{};

    QUdpSocket* m_socket = nullptr;
    QTimer* m_heartbeatTimer = nullptr;
    QTimer* m_timeoutTimer = nullptr;
    std::atomic<bool> m_running{false};
    uint8_t m_counter = 0;
    int     m_startGeneration = 0;      // start() 代数：使过期的 DNS 回调失效
    int     m_miscInfoRetryCount = 0;   // MiscInfo 发送失败重试计数（见 sendMiscInfo）
};

#endif // UDP_PROCESS_H
