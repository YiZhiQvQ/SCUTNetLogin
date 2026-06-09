#ifndef EAP_PROCESS_H
#define EAP_PROCESS_H

#include <QObject>
#include <QTimer>
#include <QElapsedTimer>
#include <QMutex>
#include <atomic>
#include "protocol.h"
#include <pcap.h>

class EapProcess : public QObject {
    Q_OBJECT

public:
    explicit EapProcess(QObject* parent = nullptr);
    ~EapProcess() override;

    void setConfig(AuthConfig config);

public slots:
    void start();
    void stop();

signals:
    void stateChanged(AuthState state, const QString& message);
    void logMessage(const QString& message, int level);
    void eapSuccess(const QByteArray& md5Data);
    void sleepRequired();

private slots:
    void onPollTimeout();
    void onTimeout();

private:
    // pcap 设备管理（调用者须持有 m_mutex）
    bool openDevice();
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

    bool parsePacket(const QByteArray& data, EAPHeader* outEapHeader, QByteArray* outPayload);
    void log(LogLevel level, const QString& msg);

    static bool isMulticastMac(const uint8_t* mac);

    // onPollTimeout 子步骤（调用者须持有 m_mutex）
    QVector<QByteArray> drainPackets();
    bool processEapPacket(const QByteArray& packet);   // false = 致命错误，需 stop
    void handleEapRequest(const EAPHeader& hdr, const QByteArray& payload);
    void checkRetransmit();

    AuthConfig m_config;

    pcap_t*    m_handle = nullptr;
    QTimer*    m_pollTimer = nullptr;
    QElapsedTimer m_retransmitTimer;

    std::atomic<bool> m_running{false};
    std::atomic<bool> m_stopRequested{false};
    AuthState m_currentState = AuthState::Idle;

    uint8_t     m_currentIdentifier = 0;
    uint8_t     m_switchMac[6];
    QByteArray  m_lastIdentityPacket;
    QByteArray  m_lastMd5Packet;
    QByteArray  m_md5Result;
    QString     m_lastError;       // pcap_open_live 失败时的错误信息

    mutable QMutex m_mutex;
};

#endif // EAP_PROCESS_H
