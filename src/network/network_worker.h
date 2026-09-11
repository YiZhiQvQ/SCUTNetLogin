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
    // generation：请求方（SessionManager）发起时传入的静态 IP 设置代次，原样回传。
    // 必须随信号携带——由接收端在"投递时"去读当前代次会把陈旧完成事件误判为有效
    // （见 SessionManager::onStaticIpDone 的代次校验）。
    void staticIpDone(int generation);
    void staticIpFailed(const QString& error, int generation);
    void autoStartDone(bool ok, const QString& error);
    // DHCP 恢复结果回执：退出前"务必恢复 DHCP"的承诺依赖它确认落地，
    // 失败必须上报（机器会留在静态 IP 上，用户需要知道）
    void dhcpDone(bool ok, const QString& error);

public slots:
    void doSetStaticIp(const QString& adapter, const QString& ip, const QString& mask,
                       const QString& gw, const QString& dns1, const QString& dns2,
                       int generation);
    void doSetDhcp(const QString& adapter);
    void doSetAutoStart(bool enable);
};

#endif // NETWORK_WORKER_H
