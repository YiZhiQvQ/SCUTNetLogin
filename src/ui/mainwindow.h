#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QSystemTrayIcon>
#include <QMenu>
#include <QAction>
#include <QCloseEvent>
#include <QAbstractNativeEventFilter>
#include <QTimer>

#include "core/protocol.h"
#include "core/session_manager.h"
#include "config/config_manager.h"
#include "network/network.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow, public QAbstractNativeEventFilter {
    Q_OBJECT

public:
    MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override;

    void setSilentStartup();

protected:
    void closeEvent(QCloseEvent* event) override;
    bool eventFilter(QObject* obj, QEvent* event) override;

    // 监听系统唤醒（WM_POWERBROADCAST / PBT_APMRESUME*），把待机期间
    // 顺延的重连排程用墙钟重新评估（见 SessionManager::onSystemResume）
    bool nativeEventFilter(const QByteArray& eventType, void* message, qintptr* result) override;

private:
    void initSessionManager();
    void initSystemTray(const QIcon& icon);

    void loadInterfaces();
    void populateInterfaces(const QList<Network::InterfaceEntry>& interfaces,
                            const QString& preferPcap = QString(),
                            const QString& preferText = QString());
    void loadConfig();
    void saveConfig();
    void autoDetectNetworkConfig();
    AuthConfig getCurrentConfig();
    // 从 UI 控件收集当前配置（saveConfig 与"保存配置"脏检测共用）
    AppConfig collectCurrentCfg();
    void setAutoStartRegistry(bool enable);

    // 自动连接：登录早期网卡可能未就绪，未就绪时按间隔重试
    void autoConnectWithRetry(int attempt = 0);

    void applyStateUI(AppConnectionState state);

    // 自绘状态指示器（断开=灰环 / 连接中=旋转动画 / 已连接=绿色对勾）
    void updateStatusIcon(AppConnectionState state);

    QString autoDetectMacForUI();

private slots:
    void on_btnRefresh_clicked();
    void on_btnConnect_clicked();
    void on_btnDisconnect_clicked();
    void on_btnSaveConfig_clicked();

    void onStateChanged(AppConnectionState state);
    void onLogMessage(const QString& message, int level);

    void onTrayIconActivated(QSystemTrayIcon::ActivationReason reason);
    void onQuitApp();

private:
    Ui::MainWindow* ui;

    SessionManager* m_sessionManager = nullptr;

    bool m_isQuitting = false;

    // 上次保存到 config.ini 的 UI 配置快照："保存配置"按钮的脏检测基准
    AppConfig m_lastSavedConfig;

    // 自动连接重试链标记：静默模式下构造函数的定时器与 setSilentStartup 都会触发自动连接，
    // 用此标记保证只有一个重试链在跑，避免重复日志/重复定时器。
    bool m_autoConnectPending = false;

    // 状态指示器动画（仅连接中运行）
    QTimer* m_statusTimer = nullptr;
    int m_statusAngle = 0;
    AppConnectionState m_statusState = AppConnectionState::Disconnected;

    QSystemTrayIcon* m_trayIcon;
    QMenu*           m_trayMenu;
    QAction*         m_actionConnect;
    QAction*         m_actionDisconnect;
    QAction*         m_actionQuit;
};

#endif // MAINWINDOW_H
