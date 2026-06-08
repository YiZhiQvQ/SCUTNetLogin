#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "constants.h"
#include "config_manager.h"
#include "network.h"
#include <QMessageBox>
#include <QNetworkInterface>
#include <QDateTime>
#include <QTimer>
#include <QHostInfo>
#include <QApplication>
#include <QRegularExpression>
#include <QIcon>
#include <QPainter>
#include <QPixmap>
#include <QTextCursor>
#include <QClipboard>
#include <QStyle>
#include <QDir>
#include <QFile>
#include <QTextStream>


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
    p.setBrush(QColor(QStringLiteral("#1a73e8")));
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

    QIcon appIcon(QStringLiteral(":/SCUTnetwork.ico"));
    if (appIcon.isNull())
        appIcon = createFallbackIcon();
    setWindowIcon(appIcon);

    ui->comboInterface->installEventFilter(this);
    ui->comboInterface->setMinimumContentsLength(10);

    initSessionManager();
    loadInterfaces();
    loadConfig();
    autoDetectNetworkConfig();
    initSystemTray(appIcon);

    ui->btnDisconnect->setEnabled(false);

    connect(ui->btnCopyLog, &QPushButton::clicked, this, [this]() {
        QGuiApplication::clipboard()->setText(ui->textLog->toPlainText());
        onLogMessage(QStringLiteral("日志已复制到剪贴板"), 0);
    });

    connect(ui->btnClearLog, &QPushButton::clicked, this, [this]() {
        ui->textLog->clear();
    });

    if (ui->checkAutoConnect->isChecked()) {
        QTimer::singleShot(AUTO_CONNECT_DELAY, this, [this]() {
            onLogMessage(QStringLiteral("自动连接已开启，正在连接..."), 0);
            on_btnConnect_clicked();
        });
    }

    applyStateUI(AppConnectionState::Disconnected);
}

MainWindow::~MainWindow()
{
    m_isQuitting = true;
    delete ui;
}

// ============================================================================
// SessionManager 初始化
// ============================================================================

void MainWindow::initSessionManager()
{
    m_sessionManager = new SessionManager(this);
    connect(m_sessionManager, &SessionManager::stateChanged, this, &MainWindow::onStateChanged);
    connect(m_sessionManager, &SessionManager::logMessage,   this, &MainWindow::onLogMessage);
}

// ============================================================================
// 系统托盘
// ============================================================================

void MainWindow::initSystemTray(const QIcon& icon)
{
    m_actionConnect    = new QAction(QStringLiteral("连接"), this);
    m_actionDisconnect = new QAction(QStringLiteral("断开"), this);
    m_actionQuit       = new QAction(QStringLiteral("退出"), this);
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
    m_trayIcon->setToolTip(QStringLiteral("SCUT 校园网认证 (未连接)"));
    m_trayIcon->setIcon(icon);

    connect(m_trayIcon, &QSystemTrayIcon::activated, this, &MainWindow::onTrayIconActivated);
    m_trayIcon->show();
}

void MainWindow::setSilentStartup()
{
    hide();
    if (ui->checkAutoConnect->isChecked()) {
        QTimer::singleShot(SILENT_CONNECT_DELAY, this, [this]() { on_btnConnect_clicked(); });
    }
    m_trayIcon->showMessage(QStringLiteral("SCUT 校园网认证"),
                            QStringLiteral("程序已静默启动，点击托盘图标显示窗口"),
                            QSystemTrayIcon::Information, 2000);
}

void MainWindow::closeEvent(QCloseEvent* event)
{
    if (m_trayIcon->isVisible() && !m_isQuitting) {
        hide();
        m_trayIcon->showMessage(QStringLiteral("提示"),
                                QStringLiteral("程序已最小化到托盘运行"),
                                QSystemTrayIcon::Information, 2000);
        event->ignore();
    }
}

bool MainWindow::eventFilter(QObject* obj, QEvent* event)
{
    if (event->type() == QEvent::Wheel && obj == ui->comboInterface) {
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
    if (m_sessionManager->state() != AppConnectionState::Disconnected)
        m_sessionManager->stopConnection();
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
    QNetworkInterface matched = Network::findInterface(pcapName, displayText);
    if (!matched.isValid())
        return;

    for (const QNetworkAddressEntry& entry : matched.addressEntries()) {
        if (entry.ip().protocol() != QAbstractSocket::IPv4Protocol || entry.ip().isLoopback())
            continue;
        if (ui->editIp->text().trimmed().isEmpty())
            ui->editIp->setText(entry.ip().toString());
        if (ui->editMask->text().trimmed().isEmpty() && !entry.netmask().isNull())
            ui->editMask->setText(entry.netmask().toString());
        if (ui->editGateway->text().trimmed().isEmpty()) {
            QHostAddress gwAddr(entry.ip().toIPv4Address()
                                & entry.netmask().toIPv4Address() | 0x00000001);
            ui->editGateway->setText(gwAddr.toString());
        }
        break;
    }

    if (ui->editMac->text().trimmed().isEmpty()
        && !matched.hardwareAddress().isEmpty()) {
        ui->editMac->setText(matched.hardwareAddress());
    }
}

QString MainWindow::autoDetectMacForUI()
{
    QString macStr = ui->editMac->text().trimmed();
    if (!macStr.isEmpty())
        return macStr;

    QString pcapName    = ui->comboInterface->currentData().toString();
    QString displayText = ui->comboInterface->currentText();
    QNetworkInterface iface = Network::findInterface(pcapName, displayText);
    if (iface.isValid() && !iface.hardwareAddress().isEmpty()) {
        macStr = iface.hardwareAddress();
        ui->editMac->setText(macStr);
    }
    return macStr;
}

// ============================================================================
// 配置持久化
// ============================================================================

void MainWindow::loadConfig()
{
    AppConfig cfg = ConfigManager::load(ConfigManager::defaultPath());

    ui->editUsername->setText(cfg.username);
    if (cfg.savePassword) {
        ui->editPassword->setText(cfg.password);
        ui->checkSavePassword->setChecked(true);
    }
    ui->editHost->setText(cfg.host);
    ui->editDNSServer->setText(cfg.dns);

    ui->editMac->setText(cfg.manualMac);
    ui->editIp->setText(cfg.manualIp);
    ui->editMask->setText(cfg.manualMask);
    ui->editGateway->setText(cfg.manualGateway);
    ui->editBackupDNS->setText(cfg.backupDns);

    ui->checkAutoSetNetwork->setChecked(cfg.autoSetNetwork);
    ui->checkAutoStart->setChecked(cfg.autoStart);
    ui->checkAutoConnect->setChecked(cfg.autoConnect);

    for (int i = 0; i < ui->comboInterface->count(); i++) {
        if (ui->comboInterface->itemData(i).toString() == cfg.interfaceName) {
            ui->comboInterface->setCurrentIndex(i);
            break;
        }
    }
}

void MainWindow::saveConfig()
{
    AppConfig cfg;
    cfg.username      = ui->editUsername->text();
    cfg.password      = ui->editPassword->text();
    cfg.host          = ui->editHost->text();
    cfg.dns           = ui->editDNSServer->text();
    cfg.backupDns     = ui->editBackupDNS->text();
    cfg.interfaceName = ui->comboInterface->currentData().toString();
    cfg.manualMac     = ui->editMac->text();
    cfg.manualIp      = ui->editIp->text();
    cfg.manualMask    = ui->editMask->text();
    cfg.manualGateway = ui->editGateway->text();
    cfg.savePassword  = ui->checkSavePassword->isChecked();
    cfg.autoSetNetwork = ui->checkAutoSetNetwork->isChecked();
    cfg.autoStart      = ui->checkAutoStart->isChecked();
    cfg.autoConnect    = ui->checkAutoConnect->isChecked();

    ConfigManager::save(ConfigManager::defaultPath(), cfg);

    setAutoStartRegistry(ui->checkAutoStart->isChecked());
}

void MainWindow::setAutoStartRegistry(bool enable)
{
    m_sessionManager->setAutoStart(enable);
}

// ============================================================================
// 连接 / 断开
// ============================================================================

void MainWindow::on_btnConnect_clicked()
{
    if (m_sessionManager->state() != AppConnectionState::Disconnected)
        return;
    if (ui->comboInterface->count() == 0) {
        onLogMessage(QStringLiteral("未检测到可用网卡，请点击刷新重试"), 2);
        return;
    }

    QString pcapName    = ui->comboInterface->currentData().toString();
    QString displayText = ui->comboInterface->currentText();

    if (displayText.contains(QStringLiteral("Loopback"), Qt::CaseInsensitive)
        || pcapName.contains(QStringLiteral("Loopback"), Qt::CaseInsensitive)) {
        onLogMessage(QStringLiteral("错误：当前选中的是虚拟回环网卡，无法用于认证！"), 2);
        return;
    }

    QString macStr = autoDetectMacForUI();
    saveConfig();
    ui->textLog->clear();

    AuthConfig config = getCurrentConfig();

    if (ui->checkAutoSetNetwork->isChecked()) {
        if (macStr.isEmpty()) {
            onLogMessage(QStringLiteral("无法获取网卡MAC地址，静态IP配置失败。请手动填写MAC地址或取消静态IP配置。"), 2);
            return;
        }

        QString adapterForNetsh = Network::adapterNameByMac(macStr);
        if (adapterForNetsh.isEmpty()) {
            onLogMessage(QStringLiteral("未找到MAC地址 %1 对应的网络适配器，无法配置静态IP。").arg(macStr), 2);
            return;
        }

        QString ip   = ui->editIp->text().trimmed();
        QString mask = ui->editMask->text().trimmed();
        QString gw   = ui->editGateway->text().trimmed();
        QString dns1 = ui->editDNSServer->text().trimmed();
        QString dns2 = ui->editBackupDNS->text().trimmed();

        QStringList missing;
        if (ip.isEmpty())   missing << QStringLiteral("IPv4地址");
        if (mask.isEmpty()) missing << QStringLiteral("子网掩码");
        if (gw.isEmpty())   missing << QStringLiteral("默认网关");
        if (dns1.isEmpty()) missing << QStringLiteral("主DNS");

        if (!missing.isEmpty()) {
            onLogMessage(QStringLiteral("静态IP配置不完整，缺少: %1。请完善配置后重试。")
                         .arg(missing.join(QStringLiteral(", "))), 2);
            return;
        }

        StaticIpConfig ipCfg;
        ipCfg.adapterName = adapterForNetsh;
        ipCfg.ip    = ip;
        ipCfg.mask  = mask;
        ipCfg.gateway = gw;
        ipCfg.dns1  = dns1;
        ipCfg.dns2  = dns2;
        ipCfg.mac   = macStr;

        ui->btnDisconnect->setEnabled(false);
        m_actionDisconnect->setEnabled(false);
        m_sessionManager->startConnection(config, ipCfg);
    } else {
        m_sessionManager->startConnection(config);
    }
}

void MainWindow::on_btnDisconnect_clicked()
{
    if (m_sessionManager->state() == AppConnectionState::Disconnected)
        return;

    m_sessionManager->stopConnection();
}

// ============================================================================
// 统一状态 UI 更新
// ============================================================================

void MainWindow::applyStateUI(AppConnectionState state)
{
    struct StateInfo {
        const char* icon;
        const char* text;
        const char* hint;
        const char* traySuffix;
        const char* styleProp;
        bool connected;
        bool enabled;
    };

    static const StateInfo kStateInfo[] = {
        { "\xe2\x97\x8f", "未连接",           "点击下方按钮开始认证", " (未连接)",         "disconnected", false, true  },
        { "\xe2\x97\x89", "正在配置网络...",   "正在设置静态IP及DNS",  " (配置网络中...)",  "connecting",   false, false },
        { "\xe2\x97\x89", "正在认证...",       "正在发送802.1X认证包", " (认证中...)",      "connecting",   true,  true  },
        { "\xe2\x97\x8f", "已连接",           "校园网已连接，可以上网", " (已连接)",         "connected",    true,  true  },
    };

    const auto& info = kStateInfo[static_cast<int>(state)];

    // 按钮状态
    ui->btnConnect->setEnabled(!info.connected);
    ui->btnDisconnect->setEnabled(info.connected);
    m_actionConnect->setEnabled(!info.connected);
    m_actionDisconnect->setEnabled(info.connected);

    if (!info.enabled) {
        ui->btnConnect->setEnabled(false);
        ui->btnDisconnect->setEnabled(false);
        m_actionConnect->setEnabled(false);
        m_actionDisconnect->setEnabled(false);
    }

    // 标签
    ui->labelStatusIcon->setText(QString::fromUtf8(info.icon));
    ui->label_status->setText(QString::fromUtf8(info.text));
    ui->labelStatusHint->setText(QString::fromUtf8(info.hint));
    m_trayIcon->setToolTip(QStringLiteral("SCUT 校园网认证") + QString::fromUtf8(info.traySuffix));

    // 样式
    ui->label_status->setProperty("state", info.styleProp);
    ui->labelStatusIcon->setProperty("state", info.styleProp);
    ui->label_status->style()->unpolish(ui->label_status);
    ui->label_status->style()->polish(ui->label_status);
    ui->labelStatusIcon->style()->unpolish(ui->labelStatusIcon);
    ui->labelStatusIcon->style()->polish(ui->labelStatusIcon);
}

void MainWindow::onStateChanged(AppConnectionState state)
{
    applyStateUI(state);
}

// ============================================================================
// 日志
// ============================================================================

void MainWindow::onLogMessage(const QString& message, int level)
{
    // --- UI 显示 ---
    QString color;
    const char* levelTag = "INFO";
    switch (static_cast<LogLevel>(level)) {
    case LogLevel::Info:    color = QStringLiteral("#9ca3af"); levelTag = "INFO"; break;
    case LogLevel::Warning: color = QStringLiteral("#f59e0b"); levelTag = "WARN"; break;
    case LogLevel::Error:   color = QStringLiteral("#ef4444"); levelTag = "ERROR"; break;
    }

    QString timestamp = QDateTime::currentDateTime().toString(QStringLiteral("hh:mm:ss"));
    ui->textLog->appendHtml(
        QStringLiteral("<span style='color:%1;'>%2 %3</span>")
            .arg(color, timestamp, message.toHtmlEscaped()));
    ui->textLog->moveCursor(QTextCursor::End);

    // --- 文件日志持久化 ---
    static const QString kLogDir =
        QCoreApplication::applicationDirPath() + QStringLiteral("/log");
    QDir().mkpath(kLogDir);

    QString fileName = kLogDir + QStringLiteral("/SCUTNetLogin_")
                       + QDateTime::currentDateTime().toString(QStringLiteral("yyyy-MM-dd"))
                       + QStringLiteral(".log");
    QFile logFile(fileName);
    if (logFile.open(QIODevice::Append | QIODevice::Text)) {
        QTextStream stream(&logFile);
        stream << QDateTime::currentDateTime().toString(QStringLiteral("yyyy-MM-dd hh:mm:ss.zzz"))
               << " [" << levelTag << "] " << message << Qt::endl;
    }
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
    QMessageBox::information(this, QStringLiteral("成功"), QStringLiteral("配置已保存"));
}

// ============================================================================
// 当前认证配置组装
// ============================================================================

AuthConfig MainWindow::getCurrentConfig()
{
    AppConfig appCfg;
    appCfg.username      = ui->editUsername->text();
    appCfg.password      = ui->editPassword->text();
    appCfg.host          = ui->editHost->text();
    appCfg.dns           = ui->editDNSServer->text();
    appCfg.interfaceName = ui->comboInterface->currentData().toString();
    appCfg.manualMac     = ui->editMac->text();
    appCfg.manualIp      = ui->editIp->text();

    AuthConfig config = ConfigManager::toAuthConfig(appCfg);

    // 运行时字段
    config.hostname = QHostInfo::localHostName();

    QHostAddress srvAddr(config.dnsServer);
    if (srvAddr.protocol() == QAbstractSocket::IPv4Protocol)
        Network::ipv4ToBytes(srvAddr, config.serverIp);
    else
        memcpy(config.serverIp, DEFAULT_SERVER_IP.data(), DEFAULT_SERVER_IP.size());

    // IP 回退：UI 未填时从当前网卡自动获取
    if (Network::isIpZero(config.localIp) && !config.interfaceName.isEmpty()) {
        QNetworkInterface iface = QNetworkInterface::interfaceFromName(config.interfaceName);
        for (const auto& entry : iface.addressEntries()) {
            if (entry.ip().protocol() == QAbstractSocket::IPv4Protocol
                && entry.ip().toIPv4Address() != 0) {
                Network::ipv4ToBytes(entry.ip(), config.localIp);
                break;
            }
        }
    }

    return config;
}
