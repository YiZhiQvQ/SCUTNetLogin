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
    // 后台枚举网卡并在完成后填充下拉（prefer* 非空时恢复该选择）。
    // 启动是否枚举由"启动后自动连接"决定：未勾选时不枚举，首次切到「设置」页/
    // 点「刷新」/点「连接」时才调用（见 MainWindow 构造函数注释）。
    void enumerateInterfaces(const QString& preferPcap, const QString& preferText);
    void populateInterfaces(const QList<Network::InterfaceEntry>& interfaces,
                            const QString& preferPcap = QString(),
                            const QString& preferText = QString());
    // 网卡枚举是否已完成（未勾选"启动后自动连接"时启动不枚举，首次需要时才枚举）
    bool m_interfacesLoaded = false;
    bool m_enumerationPending = false;
    // 用户点"连接"时网卡列表尚未就绪：枚举完成后自动续接同一次连接请求（见 connectWithCurrentInput）
    bool m_connectAfterEnumeration = false;
    // config.ini 里保存的 pcap 网卡名：枚举尚未完成/下拉为空时用它兜底（loadConfig 记录）
    QString m_savedInterfaceName;
    // 取消启动期的自动连接重试链（"断开"按钮在等待态同时承担取消职责）
    void cancelPendingAutoConnect();
    void loadConfig();
    void saveConfig();
    void autoDetectNetworkConfig();
    AuthConfig getCurrentConfig();
    // 从 UI 控件收集当前配置（saveConfig 与"保存配置"脏检测共用）
    AppConfig collectCurrentCfg();
    // 「认证服务器」仅在 DrCOM UDP 心跳保活开启时才有意义，关闭时整行置灰
    void updateHostFieldEnabled(bool heartbeatOn);
    void setAutoStartRegistry(bool enable);
    // 自动连接唯一入口（构造函数 / 静默启动共用；守卫在前、日志在后）
    void triggerAutoConnect();

    // 自动连接：登录早期网卡可能未就绪，未就绪时按间隔重试
    void autoConnectWithRetry(int attempt = 0);

    void applyStateUI(AppConnectionState state);

    // 更新"当前连接模式"状态小字（未连接/等待网络/有线/无线（SSID）），由 stateChanged 驱动
    void updateConnectModeLabel(AppConnectionState state);

    // 收集当前窗体输入并启动连接（mode 恒为自动：有线优先、无线兜底；
    // 模式切换功能已按用户要求移除，connectMode 配置键仅向后兼容保留）
    void connectWithCurrentInput();

    // 自绘状态指示器（断开=灰环 / 连接中=旋转动画 / 已连接=绿色对勾）
    void updateStatusIcon(AppConnectionState state);

private slots:
    void on_btnRefresh_clicked();
    void on_btnConnect_clicked();
    void on_btnDisconnect_clicked();
    void on_btnSaveConfig_clicked();
    void on_btnQueryMac_clicked();   // 查询并填充 MAC（不再自动获取，用户手动点击/命令）

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
    // 用此标记保证只有一个重试链在跑，避免重复日志/重复定时器（见 triggerAutoConnect）。
    bool m_autoConnectPending = false;

    // 静默启动（--silent / -s / --minimized）：仅影响自动连接时的日志文案
    bool m_silentStartup = false;

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
