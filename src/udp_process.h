#ifndef UDP_PROCESS_H
#define UDP_PROCESS_H

#include <QObject>
#include <QUdpSocket>
#include <QTimer>
#include <QMutex>
#include <atomic>
#include <array>
#include "protocol.h"

class UdpProcess : public QObject {
    Q_OBJECT

public:
    explicit UdpProcess(QObject* parent = nullptr);
    ~UdpProcess();
    void setConfig(const AuthConfig& config);
    void setMd5Data(const QByteArray& md5Data);

public slots:
    void start();
    void stop();

signals:
    void stateChanged(const QString& state, const QString& message);
    void online();              // UDP 握手完成，进入在线心跳状态
    void logMessage(const QString& message, int level);
    void heartbeatFailed();

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
    void log(LogLevel level, const QString& msg);

    mutable QMutex m_mutex;
    AuthConfig m_config;
    QByteArray m_md5Data;               // EAP-MD5 结果; sendMiscInfo 覆盖前 4 字节为 cks32
    std::array<uint8_t, 16> m_decryptedInfo{};
    std::array<uint8_t, 4>  m_flux{};
    std::array<uint8_t, 2>  m_rnd{};

    QUdpSocket* m_socket = nullptr;
    QTimer* m_heartbeatTimer = nullptr;
    QTimer* m_timeoutTimer = nullptr;
    std::atomic<bool> m_running{false};
    UdpState m_udpState = UdpState::Idle;
    uint8_t m_counter = 0;
};

#endif // UDP_PROCESS_H
