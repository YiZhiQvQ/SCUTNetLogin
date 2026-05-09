#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "constants.h"
#include <QProcess>
#include <QMessageBox>
#include <QSettings>
#include <QNetworkInterface>
#include <QDateTime>
#include <QTimer>
#include <QHostInfo>
#include <QApplication>
#include <QRegularExpression>
#include <QIcon>
#include <QDir>
#include <QPainter>
#include <QPixmap>
#include <QTextCursor>
#include <QClipboard>
#include <QStyle>
#include "network.h"

// ============================================================================
// NetworkWorker 实现
// ============================================================================

NetworkWorker::NetworkWorker(QObject* parent)
    : QObject(parent)
{
    moveToThread(&m_thread);
    m_thread.start();
}

NetworkWorker::~NetworkWorker()
{
    stop();
}

void NetworkWorker::stop()
{
    m_thread.quit();
    m_thread.wait(BG_TASK_WAIT_TIMEOUT);
}

void NetworkWorker::doSetStaticIp(const QString& adapter, const QString& ip,
                                   const QString& mask, const QString& gw,
                                   const QString& dns1, const QString& dns2)
{
    QString error;
    bool ok = Network::setStaticIp(adapter, ip, mask, gw, dns1, dns2, &error);
    QThread::msleep(IP_SETTLE_WAIT);
    if (ok)
        emit staticIpDone();
    else
        emit staticIpFailed(error);
}

void NetworkWorker::doSetDhcp(const QString& adapter)
{
    Network::setDhcp(adapter);
}

void NetworkWorker::doSetAutoStart(bool enable)
{
    QString taskName = "SCUTNetLogin_AutoStart";
    QString appPath = QDir::toNativeSeparators(QCoreApplication::applicationFilePath());

    QProcess proc;
    proc.setCreateProcessArgumentsModifier([](QProcess::CreateProcessArguments* cpa) {
        cpa->flags |= CREATE_NO_WINDOW;
    });

    if (enable) {
        proc.start("schtasks", {
            "/create", "/tn", taskName,
            "/tr", "\"" + appPath + "\" --silent",
            "/sc", "onlogon", "/rl", "highest", "/f"
        });
    } else {
        proc.start("schtasks", {"/delete", "/tn", taskName, "/f"});
    }
    proc.waitForFinished(15000);

    if (proc.exitCode() != 0) {
        QString err = QString::fromLocal8Bit(proc.readAllStandardError());
        if (!err.isEmpty())
            qWarning() << "schtasks error:" << err;
    }
}

// ============================================================================
// 后备图标
// ============================================================================

static QIcon createFallbackIcon()
{
    QPixmap pm(256, 256);
    pm.fill(Qt::transparent);
    QPainter p(&pm);
    p.setRenderHint(QPainter::Antialiasing);
    p.setPen(Qt::NoPen);
    p.setBrush(QColor("#1a73e8"));
    p.drawRoundedRect(8, 8, 240, 240, 48, 48);
    QPen pen(Qt::white, 14, Qt::SolidLine, Qt::RoundCap);
    p.setPen(pen);
    p.setBrush(Qt::NoBrush);
    p.drawArc(88, 120, 80, 48, 0, -180 * 16);
    p.drawArc(98, 152, 60, 48, 0, -180 * 16);
    p.drawArc(110, 180, 36, 48, 0, -180 * 16);
    p.setBrush(Qt::white);
    p.drawEllipse(QPointF(128, 218), 12, 12);
    p.end();
    return QIcon(pm);
}

// ============================================================================
// 构造 / 析构
// ============================================================================

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent), ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    // 绑定 .ui 中已有的控件到成员指针（不再动态创建）
    editMac            = ui->editMac;
    editIp             = ui->editIp;
    editMask           = ui->editMask;
    editGateway        = ui->editGateway;
    editBackupDNS      = ui->editBackupDNS;
    checkAutoSetNetwork = ui->checkAutoSetNetwork;
    checkAutoStart     = ui->checkAutoStart;
    checkAutoConnect   = ui->checkAutoConnect;

    QIcon appIcon(":/SCUTnetwork.ico");
    if (appIcon.isNull())
        appIcon = createFallbackIcon();
    setWindowIcon(appIcon);

    ui->comboInterface->installEventFilter(this);
    ui->comboInterface->setMinimumContentsLength(10);

    initEapUdpProcesses();
    initNetworkWorker();
    loadInterfaces();
    loadConfig();
    autoDetectNetworkConfig();
    initSystemTray(appIcon);

    ui->btnDisconnect->setEnabled(false);

    connect(ui->btnCopyLog, &QPushButton::clicked, this, [this]() {
        QGuiApplication::clipboard()->setText(ui->textLog->toPlainText());
        onLogMessage("日志已复制到剪贴板", 0);
    });

    connect(ui->btnClearLog, &QPushButton::clicked, this, [this]() {
        ui->textLog->clear();
    });

    if (checkAutoConnect->isChecked()) {
        QTimer::singleShot(AUTO_CONNECT_DELAY, this, [this]() {
            onLogMessage("自动连接已开启，正在连接...", 0);
            on_btnConnect_clicked();
        });
    }

    setAppState(AppConnectionState::Disconnected);
}

MainWindow::~MainWindow()
{
    setAppState(AppConnectionState::Disconnected);

    if (m_eapProcess)
        m_eapProcess->stop();
    if (m_udpProcess)
        m_udpProcess->stop();
    m_eapThread.quit();
    m_eapThread.wait();
    m_udpThread.quit();
    m_udpThread.wait();

    if (m_networkWorker) {
        m_networkWorker->stop();
        m_networkWorker->deleteLater();
        m_networkWorker = nullptr;
    }

    delete ui;
}

// ============================================================================
// EAP / UDP / NetworkWorker 初始化
// ============================================================================

void MainWindow::initEapUdpProcesses()
{
    m_eapProcess = new EapProcess();
    m_eapProcess->moveToThread(&m_eapThread);
    connect(&m_eapThread, &QThread::finished, m_eapProcess, &QObject::deleteLater);
    connect(m_eapProcess, &EapProcess::stateChanged,  this, &MainWindow::onEapStateChanged);
    connect(m_eapProcess, &EapProcess::logMessage,   this, &MainWindow::onLogMessage);
    connect(m_eapProcess, &EapProcess::eapSuccess,   this, &MainWindow::onEapSuccess);
    connect(m_eapProcess, &EapProcess::sleepRequired, this, [this]() {
        onLogMessage("当前时段禁止上网，已自动断开", 2);
        on_btnDisconnect_clicked();
    });
    m_eapThread.start();

    m_udpProcess = new UdpProcess();
    m_udpProcess->moveToThread(&m_udpThread);
    connect(&m_udpThread, &QThread::finished, m_udpProcess, &QObject::deleteLater);
    connect(m_udpProcess, &UdpProcess::stateChanged,  this, &MainWindow::onUdpStateChanged);
    connect(m_udpProcess, &UdpProcess::logMessage,    this, &MainWindow::onLogMessage);
    connect(m_udpProcess, &UdpProcess::heartbeatFailed, this, &MainWindow::onHeartbeatFailed);
    m_udpThread.start();
}

void MainWindow::initNetworkWorker()
{
    m_networkWorker = new NetworkWorker();
    connect(m_networkWorker, &NetworkWorker::staticIpDone, this, &MainWindow::onStaticIpDone);
    connect(m_networkWorker, &NetworkWorker::staticIpFailed, this, [this](const QString& error) {
        onLogMessage("静态IP设置失败: " + error, 2);
        setAppState(AppConnectionState::Disconnected);
    });
}

// ============================================================================
// 系统托盘
// ============================================================================

void MainWindow::initSystemTray(const QIcon& icon)
{
    m_actionConnect    = new QAction("连接", this);
    m_actionDisconnect = new QAction("断开", this);
    m_actionQuit       = new QAction("退出", this);
    m_actionDisconnect->setEnabled(false);

    connect(m_actionConnect,    &QAction::triggered, this, &MainWindow::on_btnConnect_clicked);
    connect(m_actionDisconnect, &QAction::triggered, this, &MainWindow::on_btnDisconnect_clicked);
    connect(m_actionQuit,       &QAction::triggered, this, &MainWindow::onQuitApp);

    m_trayMenu = new QMenu(this);
    m_trayMenu->addAction(m_actionConnect);
    m_trayMenu->addAction(m_actionDisconnect);
    m_trayMenu->addSeparator();
    m_trayMenu->addAction(m_actionQuit);

    m_trayIcon = new QSystemTrayIcon(this);
    m_trayIcon->setContextMenu(m_trayMenu);
    m_trayIcon->setToolTip("SCUT 校园网认证 (未连接)");
    m_trayIcon->setIcon(icon);

    connect(m_trayIcon, &QSystemTrayIcon::activated, this, &MainWindow::onTrayIconActivated);
    m_trayIcon->show();
}

void MainWindow::setSilentStartup()
{
    hide();
    if (checkAutoConnect->isChecked()) {
        QTimer::singleShot(SILENT_CONNECT_DELAY, this, [this]() { on_btnConnect_clicked(); });
    }
    m_trayIcon->showMessage("SCUT 校园网认证", "程序已静默启动，点击托盘图标显示窗口",
                            QSystemTrayIcon::Information, 2000);
}

void MainWindow::closeEvent(QCloseEvent* event)
{
    if (m_trayIcon->isVisible() && !m_isQuitting) {
        hide();
        m_trayIcon->showMessage("提示", "程序已最小化到托盘运行",
                                QSystemTrayIcon::Information, 2000);
        event->ignore();
    }
}

bool MainWindow::eventFilter(QObject* obj, QEvent* event)
{
    if (event->type() == QEvent::Wheel && obj == ui->comboInterface) {
        // 禁止滚轮切换网卡选项，将事件转发给滚动区域使页面正常上下滚动
        QCoreApplication::sendEvent(ui->scrollArea->viewport(), event);
        return true;
    }
    return QMainWindow::eventFilter(obj, event);
}

void MainWindow::onTrayIconActivated(QSystemTrayIcon::ActivationReason reason)
{
    if (reason == QSystemTrayIcon::DoubleClick || reason == QSystemTrayIcon::Trigger) {
        show();
        raise();
        activateWindow();
    }
}

void MainWindow::onQuitApp()
{
    m_isQuitting = true;
    if (m_appState != AppConnectionState::Disconnected)
        on_btnDisconnect_clicked();
    m_trayIcon->hide();
    qApp->quit();
}

// ============================================================================
// 网卡列表
// ============================================================================

void MainWindow::loadInterfaces()
{
    ui->comboInterface->clear();

    const auto interfaces = Network::listInterfaces();
    for (const auto& entry : interfaces)
        ui->comboInterface->addItem(entry.displayName, entry.pcapName);

    connect(ui->comboInterface, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &MainWindow::autoDetectNetworkConfig, Qt::UniqueConnection);
}

void MainWindow::autoDetectNetworkConfig()
{
    QString pcapName    = ui->comboInterface->currentData().toString();
    QString displayText = ui->comboInterface->currentText();
    Network::AdapterInfo info = Network::adapterInfo(pcapName, displayText);

    QNetworkInterface matched;
    if (!info.guid.isEmpty())
        matched = QNetworkInterface::interfaceFromName(info.guid);
    if (!matched.isValid() && !info.displayName.isEmpty()) {
        for (const QNetworkInterface& iface : QNetworkInterface::allInterfaces()) {
            if (iface.humanReadableName().compare(info.displayName, Qt::CaseInsensitive) == 0) {
                matched = iface;
                break;
            }
        }
    }
    if (!matched.isValid())
        return;

    for (const QNetworkAddressEntry& entry : matched.addressEntries()) {
        if (entry.ip().protocol() != QAbstractSocket::IPv4Protocol || entry.ip().isLoopback())
            continue;
        if (editIp->text().trimmed().isEmpty())
            editIp->setText(entry.ip().toString());
        if (editMask->text().trimmed().isEmpty() && !entry.netmask().isNull())
            editMask->setText(entry.netmask().toString());
        if (editGateway->text().trimmed().isEmpty()) {
            QHostAddress gwAddr(entry.ip().toIPv4Address()
                                & entry.netmask().toIPv4Address() | 0x00000001);
            editGateway->setText(gwAddr.toString());
        }
        break;
    }

    if (editMac->text().trimmed().isEmpty()) {
        QNetworkInterface iface;
        if (!info.guid.isEmpty())
            iface = QNetworkInterface::interfaceFromName(info.guid);
        if (!iface.isValid())
            iface = matched;
        if (iface.isValid() && !iface.hardwareAddress().isEmpty())
            editMac->setText(iface.hardwareAddress());
    }
}

// ============================================================================
// 配置持久化
// ============================================================================

void MainWindow::loadConfig()
{
    QString configPath = QCoreApplication::applicationDirPath() + "/config.ini";
    QSettings settings(configPath, QSettings::IniFormat);

    ui->editUsername->setText(settings.value("username", "").toString());
    QByteArray pwdBase64 = settings.value("password", "").toByteArray();
    if (!pwdBase64.isEmpty()) {
        ui->editPassword->setText(QString::fromUtf8(QByteArray::fromBase64(pwdBase64)));
        ui->checkSavePassword->setChecked(true);
    }
    ui->editHost->setText(settings.value("host", DEFAULT_HOST).toString());
    ui->editDNSServer->setText(settings.value("dns", DEFAULT_DNS).toString());

    editMac->setText(settings.value("manualMac", "").toString());
    editIp->setText(settings.value("manualIp", "").toString());
    editMask->setText(settings.value("manualMask", "255.255.255.0").toString());
    editGateway->setText(settings.value("manualGateway", "").toString());
    editBackupDNS->setText(settings.value("backupDns", "").toString());

    checkAutoSetNetwork->setChecked(settings.value("autoSetNetwork", false).toBool());
    checkAutoStart->setChecked(settings.value("autoStart", false).toBool());
    checkAutoConnect->setChecked(settings.value("autoConnect", false).toBool());

    QString savedInterface = settings.value("interface", "").toString();
    bool found = false;
    for (int i = 0; i < ui->comboInterface->count(); i++) {
        if (ui->comboInterface->itemData(i).toString() == savedInterface) {
            ui->comboInterface->setCurrentIndex(i);
            found = true;
            break;
        }
    }
    if (!found && !savedInterface.isEmpty())
        settings.remove("interface");
}

void MainWindow::saveConfig()
{
    QString configPath = QCoreApplication::applicationDirPath() + "/config.ini";
    QSettings settings(configPath, QSettings::IniFormat);

    settings.setValue("username",  ui->editUsername->text());
    settings.setValue("host",      ui->editHost->text());
    settings.setValue("dns",       ui->editDNSServer->text());
    settings.setValue("interface", ui->comboInterface->currentData().toString());

    settings.setValue("manualMac",      editMac->text());
    settings.setValue("manualIp",       editIp->text());
    settings.setValue("manualMask",     editMask->text());
    settings.setValue("manualGateway",  editGateway->text());
    settings.setValue("backupDns",      editBackupDNS->text());

    settings.setValue("autoSetNetwork", checkAutoSetNetwork->isChecked());
    settings.setValue("autoStart",      checkAutoStart->isChecked());
    settings.setValue("autoConnect",    checkAutoConnect->isChecked());

    if (ui->checkSavePassword->isChecked())
        settings.setValue("password", ui->editPassword->text().toUtf8().toBase64());
    else
        settings.remove("password");

    setAutoStartRegistry(checkAutoStart->isChecked());
}

// ============================================================================
// 开机自启
// ============================================================================

void MainWindow::setAutoStartRegistry(bool enable)
{
    QMetaObject::invokeMethod(m_networkWorker, "doSetAutoStart", Qt::QueuedConnection,
                              Q_ARG(bool, enable));
}

// ============================================================================
// 连接 / 断开 主逻辑
// ============================================================================

void MainWindow::on_btnConnect_clicked()
{
    if (m_appState != AppConnectionState::Disconnected)
        return;
    if (ui->comboInterface->count() == 0) {
        onLogMessage("未检测到可用网卡，请点击刷新重试", 2);
        return;
    }

    QString pcapName    = ui->comboInterface->currentData().toString();
    QString displayText = ui->comboInterface->currentText();
    Network::AdapterInfo info = Network::adapterInfo(pcapName, displayText);

    if ((!info.displayName.isEmpty() && info.displayName.contains("Loopback", Qt::CaseInsensitive))
        || displayText.contains("Loopback", Qt::CaseInsensitive)
        || pcapName.contains("Loopback", Qt::CaseInsensitive)) {
        onLogMessage("错误：当前选中的是虚拟回环网卡，无法用于认证！", 2);
        return;
    }

    // 自动检测 MAC（如果用户未填写）
    QString macStr = editMac->text().trimmed();
    if (macStr.isEmpty()) {
        QNetworkInterface iface;
        if (!info.guid.isEmpty())
            iface = QNetworkInterface::interfaceFromName(info.guid);
        if (!iface.isValid())
            iface = QNetworkInterface::interfaceFromName(pcapName);
        if (iface.isValid() && !iface.hardwareAddress().isEmpty()) {
            macStr = iface.hardwareAddress();
            editMac->setText(macStr);
        }
    }

    saveConfig();
    ui->textLog->clear();

    if (checkAutoSetNetwork->isChecked()) {
        if (macStr.isEmpty()) {
            onLogMessage("无法获取网卡MAC地址，静态IP配置失败。请手动填写MAC地址或取消静态IP配置。", 2);
            return;
        }

        QString adapterForNetsh = Network::adapterNameByMac(macStr);
        if (adapterForNetsh.isEmpty()) {
            onLogMessage(QString("未找到MAC地址 %1 对应的网络适配器，无法配置静态IP。").arg(macStr), 2);
            return;
        }

        QString ip   = editIp->text().trimmed();
        QString mask = editMask->text().trimmed();
        QString gw   = editGateway->text().trimmed();
        QString dns1 = ui->editDNSServer->text().trimmed();
        QString dns2 = editBackupDNS->text().trimmed();

        QStringList missing;
        if (ip.isEmpty())   missing << "IPv4地址";
        if (mask.isEmpty()) missing << "子网掩码";
        if (gw.isEmpty())   missing << "默认网关";
        if (dns1.isEmpty()) missing << "主DNS";

        if (!missing.isEmpty()) {
            onLogMessage(QString("静态IP配置不完整，缺少: %1。请完善配置后重试。")
                         .arg(missing.join(", ")), 2);
            return;
        }

        setAppState(AppConnectionState::SettingNetwork);
        m_wasStaticIpSet = true;
        ui->btnDisconnect->setEnabled(false);
        m_actionDisconnect->setEnabled(false);

        onLogMessage(QString("正在设置静态IP: %1 / %2 / %3 ...").arg(ip, mask, gw), 0);

        // 安全超时：如果仍卡在 SettingNetwork 状态，强制恢复
        QTimer::singleShot(IP_SETUP_TIMEOUT, this, [this]() {
            if (m_appState == AppConnectionState::SettingNetwork) {
                onLogMessage("静态IP设置超时，请检查适配器名和网络配置", 2);
                setAppState(AppConnectionState::Disconnected);
            }
        });

        QMetaObject::invokeMethod(m_networkWorker, "doSetStaticIp", Qt::QueuedConnection,
                                  Q_ARG(QString, adapterForNetsh), Q_ARG(QString, ip),
                                  Q_ARG(QString, mask), Q_ARG(QString, gw),
                                  Q_ARG(QString, dns1), Q_ARG(QString, dns2));
    } else {
        startAuthentication();
    }
}

void MainWindow::onStaticIpDone()
{
    if (m_appState != AppConnectionState::SettingNetwork)
        return;
    onLogMessage("静态IP设置完成，开始认证...", 0);
    startAuthentication();
}

void MainWindow::startAuthentication()
{
    setAppState(AppConnectionState::Authenticating);
    onLogMessage("开始802.1X认证...", 0);

    AuthConfig config = getCurrentConfig();
    m_eapProcess->setConfig(config);
    m_udpProcess->setConfig(config);

    ui->btnDisconnect->setEnabled(true);
    m_actionDisconnect->setEnabled(true);
    m_trayIcon->setToolTip("SCUT 校园网认证 (连接中...)");

    QMetaObject::invokeMethod(m_eapProcess, "start", Qt::QueuedConnection);
}

void MainWindow::on_btnDisconnect_clicked()
{
    if (m_appState == AppConnectionState::Disconnected)
        return;

    QMetaObject::invokeMethod(m_eapProcess, "stop", Qt::QueuedConnection);
    QMetaObject::invokeMethod(m_udpProcess, "stop", Qt::QueuedConnection);

    restoreDhcp();
    setAppState(AppConnectionState::Disconnected);
}

// ============================================================================
// DHCP 恢复
// ============================================================================

void MainWindow::restoreDhcp()
{
    if (!m_wasStaticIpSet)
        return;
    m_wasStaticIpSet = false;

    QString adapterForNetsh = Network::adapterNameByMac(editMac->text().trimmed());
    if (!adapterForNetsh.isEmpty()) {
        QMetaObject::invokeMethod(m_networkWorker, "doSetDhcp", Qt::QueuedConnection,
                                  Q_ARG(QString, adapterForNetsh));
    }
}

// ============================================================================
// 统一状态机
// ============================================================================

void MainWindow::setConnectionUi(bool connected, bool enabled)
{
    ui->btnConnect->setEnabled(!connected);
    ui->btnDisconnect->setEnabled(connected);
    m_actionConnect->setEnabled(!connected);
    m_actionDisconnect->setEnabled(connected);

    if (!enabled) {
        ui->btnConnect->setEnabled(false);
        ui->btnDisconnect->setEnabled(false);
        m_actionConnect->setEnabled(false);
        m_actionDisconnect->setEnabled(false);
    }
}

void MainWindow::setAppState(AppConnectionState state)
{
    m_appState = state;

    const char* stateProp = "disconnected";
    QString statusIcon;
    QString statusText;
    QString statusHint;
    QString trayTooltip = "SCUT 校园网认证";

    switch (state) {
    case AppConnectionState::Disconnected:
        setConnectionUi(false, true);
        statusIcon  = "●";
        statusText  = "未连接";
        statusHint  = "点击下方按钮开始认证";
        trayTooltip += " (未连接)";
        stateProp   = "disconnected";
        break;

    case AppConnectionState::SettingNetwork:
        setConnectionUi(false, false);
        statusIcon  = "◉";
        statusText  = "正在配置网络...";
        statusHint  = "正在设置静态IP及DNS";
        trayTooltip += " (配置网络中...)";
        stateProp   = "connecting";
        break;

    case AppConnectionState::Authenticating:
        setConnectionUi(true, true);
        statusIcon  = "◉";
        statusText  = "正在认证...";
        statusHint  = "正在发送802.1X认证包";
        trayTooltip += " (认证中...)";
        stateProp   = "connecting";
        break;

    case AppConnectionState::Connected:
        setConnectionUi(true, true);
        statusIcon  = "●";
        statusText  = "已连接";
        statusHint  = "校园网已连接，可以上网";
        trayTooltip += " (已连接)";
        stateProp   = "connected";
        break;
    }

    ui->label_status->setText(statusText);
    ui->labelStatusIcon->setText(statusIcon);
    ui->labelStatusHint->setText(statusHint);
    m_trayIcon->setToolTip(trayTooltip);
    ui->label_status->setProperty("state", stateProp);
    ui->labelStatusIcon->setProperty("state", stateProp);

    ui->label_status->style()->unpolish(ui->label_status);
    ui->label_status->style()->polish(ui->label_status);
    ui->labelStatusIcon->style()->unpolish(ui->labelStatusIcon);
    ui->labelStatusIcon->style()->polish(ui->labelStatusIcon);
}

// ============================================================================
// 信号回调
// ============================================================================

void MainWindow::onEapStateChanged(AuthState state, const QString& message)
{
    if (!message.isEmpty())
        onLogMessage(message, state == AuthState::Failed ? 2 : 0);
    if (state == AuthState::Failed) {
        onLogMessage("认证失败，正在恢复DHCP...", 1);
        restoreDhcp();
        setAppState(AppConnectionState::Disconnected);
    } else if (state == AuthState::Stopped) {
        setAppState(AppConnectionState::Disconnected);
    }
}

void MainWindow::onUdpStateChanged(const QString& state, const QString& /*message*/)
{
    if (state == "在线")
        setAppState(AppConnectionState::Connected);
}

void MainWindow::onEapSuccess(const QByteArray& md5Data)
{
    onLogMessage("认证成功，可以上网了！", 0);
    setAppState(AppConnectionState::Connected);
    m_udpProcess->setMd5Data(md5Data);
    QMetaObject::invokeMethod(m_udpProcess, "start", Qt::QueuedConnection);
}

void MainWindow::onHeartbeatFailed()
{
    // 心跳超时由 UdpProcess::onHeartbeatTimeout 自动重发 Alive 自愈，
    // 此处无需额外处理。偶尔超时是 DrCOM 协议的正常行为。
}

void MainWindow::onLogMessage(const QString& message, int level)
{
    QString color;
    switch (static_cast<LogLevel>(level)) {
    case LogLevel::Info:    color = "#9ca3af"; break;
    case LogLevel::Warning: color = "#f59e0b"; break;
    case LogLevel::Error:   color = "#ef4444"; break;
    }

    QString timestamp = QDateTime::currentDateTime().toString("hh:mm:ss");
    ui->textLog->appendHtml(
        QString("<span style='color:%1;'>%2 %3</span>")
            .arg(color, timestamp, message.toHtmlEscaped()));
    ui->textLog->moveCursor(QTextCursor::End);
}

// ============================================================================
// 按钮 Slot
// ============================================================================

void MainWindow::on_btnRefresh_clicked()
{
    loadInterfaces();
}

void MainWindow::on_btnSaveConfig_clicked()
{
    saveConfig();
    QMessageBox::information(this, "成功", "配置已保存");
}

// ============================================================================
// 当前认证配置组装
// ============================================================================

AuthConfig MainWindow::getCurrentConfig()
{
    AuthConfig config;
    config.username      = ui->editUsername->text();
    config.password      = ui->editPassword->text();
    config.host          = ui->editHost->text();
    config.dnsServer     = ui->editDNSServer->text();
    config.interfaceName = ui->comboInterface->currentData().toString();
    config.hostname      = QHostInfo::localHostName();

    QHostAddress srvAddr(config.dnsServer);
    if (srvAddr.protocol() == QAbstractSocket::IPv4Protocol)
        Network::ipv4ToBytes(srvAddr, config.serverIp);
    else
        memcpy(config.serverIp, DEFAULT_SERVER_IP.data(), DEFAULT_SERVER_IP.size());

    // MAC — 标准化用户输入，若为空则从网卡自动获取
    QString macStr = Network::normalizeMac(editMac->text().trimmed());
    if (!macStr.isEmpty()) {
        QByteArray bytes = QByteArray::fromHex(macStr.toLatin1());
        memcpy(config.localMac, bytes.constData(), 6);
    }
    if (Network::isMacZero(config.localMac)) {
        QNetworkInterface selectedIface =
            QNetworkInterface::interfaceFromName(config.interfaceName);
        if (selectedIface.isValid() && !selectedIface.hardwareAddress().isEmpty()) {
            QString hw = Network::normalizeMac(selectedIface.hardwareAddress());
            if (!hw.isEmpty()) {
                QByteArray bytes = QByteArray::fromHex(hw.toLatin1());
                memcpy(config.localMac, bytes.constData(), 6);
            }
        }
    }

    // IP
    QHostAddress addr(editIp->text().trimmed());
    if (addr.protocol() == QAbstractSocket::IPv4Protocol) {
        Network::ipv4ToBytes(addr, config.localIp);
    } else {
        QNetworkInterface selectedIface =
            QNetworkInterface::interfaceFromName(config.interfaceName);
        for (const auto& entry : selectedIface.addressEntries()) {
            if (entry.ip().protocol() == QAbstractSocket::IPv4Protocol
                && entry.ip().toIPv4Address() != 0) {
                Network::ipv4ToBytes(entry.ip(), config.localIp);
                break;
            }
        }
    }

    return config;
}
