#ifndef NETWORK_WORKER_H
#define NETWORK_WORKER_H

#include <QObject>

// 后台 worker — 在独立线程中执行 netsh / schtasks 等阻塞操作，避免阻塞 UI
// 线程生命周期由调用者（MainWindow / SessionManager）管理，本类不拥有线程
class NetworkWorker : public QObject {
    Q_OBJECT
public:
    explicit NetworkWorker(QObject* parent = nullptr);
    ~NetworkWorker() override;

signals:
    void staticIpDone();
    void staticIpFailed(const QString& error);

public slots:
    void doSetStaticIp(const QString& adapter, const QString& ip, const QString& mask,
                       const QString& gw, const QString& dns1, const QString& dns2);
    void doSetDhcp(const QString& adapter);
    void doSetAutoStart(bool enable);
};

#endif // NETWORK_WORKER_H
