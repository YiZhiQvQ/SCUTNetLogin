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
    // 自愈结果：逐条动作说明（成功/失败都回传，由上层落盘）
    void purgeDone(bool clean, const QString& detail);

public slots:
    void doSetStaticIp(const QString& adapter, const QString& ip, const QString& mask,
                       const QString& gw, const QString& dns1, const QString& dns2,
                       int generation);
    void doSetDhcp(const QString& adapter);
    void doSetAutoStart(bool enable);
    // 清理校园静态 IP / 校园 DNS / 环回网关上残留的默认路由（自愈）。
    // 在启动、进入等待态、恢复 DHCP 失败时投递；keepAdapter 为"可以保留校园配置"的
    // 接口（当前在用的有线网卡），为空表示不保留任何接口。
    // campusGateway / campusDns：用于判定"哪块网卡的配置是校园网留下的"，
    // 只有命中这些值的接口才会被恢复成 DHCP（绝不误改用户其它网络设置）。
    void doPurgeStaleConfig(const QString& keepAdapter, const QString& campusGateway,
                            const QStringList& campusDns);
};

#endif // NETWORK_WORKER_H
