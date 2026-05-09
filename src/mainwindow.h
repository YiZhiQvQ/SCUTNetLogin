#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QThread>
#include <QLineEdit>
#include <QCheckBox>
#include <QSystemTrayIcon>
#include <QMenu>
#include <QAction>
#include <QCloseEvent>

#include "protocol.h"
#include "eap_process.h"
#include "udp_process.h"
#include "network.h"

// 应用连接状态机 — 替代分散的 m_isConnected / m_isConnecting / m_authPending
enum class AppConnectionState {
    Disconnected,
    SettingNetwork,
    Authenticating,
    Connected
};

// 持久化后台 worker
class NetworkWorker : public QObject {
    Q_OBJECT
public:
    explicit NetworkWorker(QObject* parent = nullptr);
    ~NetworkWorker();
    void stop();

signals:
    void staticIpDone();
    void staticIpFailed(const QString& error);

public slots:
    void doSetStaticIp(const QString& adapter, const QString& ip, const QString& mask,
                       const QString& gw, const QString& dns1, const QString& dns2);
    void doSetDhcp(const QString& adapter);
    void doSetAutoStart(bool enable);

private:
    QThread m_thread;
};

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(QWidget* parent = nullptr);
    ~MainWindow();

    void setSilentStartup();

protected:
    void closeEvent(QCloseEvent* event) override;
    bool eventFilter(QObject* obj, QEvent* event) override;

private:
    void initEapUdpProcesses();
    void initNetworkWorker();
    void initSystemTray(const QIcon& icon);

    void loadInterfaces();
    void loadConfig();
    void saveConfig();
    void autoDetectNetworkConfig();
    AuthConfig getCurrentConfig();
    void setAutoStartRegistry(bool enable);
    void restoreDhcp();

    void setAppState(AppConnectionState state);
    void setConnectionUi(bool connected, bool enabled);

private slots:
    void on_btnRefresh_clicked();
    void on_btnConnect_clicked();
    void on_btnDisconnect_clicked();
    void on_btnSaveConfig_clicked();

    void onEapStateChanged(AuthState state, const QString& message);
    void onUdpStateChanged(const QString& state, const QString& message);
    void onEapSuccess(const QByteArray& md5Data);
    void onLogMessage(const QString& message, int level);
    void onHeartbeatFailed();

    void startAuthentication();
    void onStaticIpDone();

    void onTrayIconActivated(QSystemTrayIcon::ActivationReason reason);
    void onQuitApp();

private:
    Ui::MainWindow* ui;

    QThread      m_eapThread;
    QThread      m_udpThread;
    EapProcess*  m_eapProcess  = nullptr;
    UdpProcess*  m_udpProcess  = nullptr;
    NetworkWorker* m_networkWorker = nullptr;

    AppConnectionState m_appState = AppConnectionState::Disconnected;
    bool m_wasStaticIpSet = false;
    bool m_isQuitting     = false;

    // 以下控件已移入 .ui 文件，不再动态创建
    QLineEdit*   editMac;
    QLineEdit*   editIp;
    QLineEdit*   editMask;
    QLineEdit*   editGateway;
    QLineEdit*   editBackupDNS;
    QCheckBox*   checkAutoSetNetwork;
    QCheckBox*   checkAutoStart;
    QCheckBox*   checkAutoConnect;

    QSystemTrayIcon* m_trayIcon;
    QMenu*           m_trayMenu;
    QAction*         m_actionConnect;
    QAction*         m_actionDisconnect;
    QAction*         m_actionQuit;
};

#endif // MAINWINDOW_H
