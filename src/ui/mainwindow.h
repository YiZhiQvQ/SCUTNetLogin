#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QSystemTrayIcon>
#include <QMenu>
#include <QAction>
#include <QCloseEvent>

#include "core/protocol.h"
#include "core/session_manager.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override;

    void setSilentStartup();

protected:
    void closeEvent(QCloseEvent* event) override;
    bool eventFilter(QObject* obj, QEvent* event) override;

private:
    void initSessionManager();
    void initSystemTray(const QIcon& icon);

    void loadInterfaces();
    void loadConfig();
    void saveConfig();
    void autoDetectNetworkConfig();
    AuthConfig getCurrentConfig();
    void setAutoStartRegistry(bool enable);

    void applyStateUI(AppConnectionState state);

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

    QSystemTrayIcon* m_trayIcon;
    QMenu*           m_trayMenu;
    QAction*         m_actionConnect;
    QAction*         m_actionDisconnect;
    QAction*         m_actionQuit;
};

#endif // MAINWINDOW_H
