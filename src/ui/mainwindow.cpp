#include "ui/mainwindow.h"
#include "ui_mainwindow.h"
#include "core/constants.h"
#include "core/connection_builder.h"
#include "config/config_manager.h"
#include "network/network.h"
#include "log/log_manager.h"
#include <QMessageBox>
#include <QNetworkInterface>
#include <QDateTime>
#include <QTimer>
#include <QApplication>
#include <QRegularExpression>
#include <QIcon>
#include <QPainter>
#include <QPixmap>
#include <QTextCursor>
#include <QClipboard>
#include <QStyle>
#include <QPointer>
#include <QThreadPool>
#include <QMetaObject>
#include <QRunnable>
#include <QShortcut>
#include <QSettings>
// 系统唤醒事件（WM_POWERBROADCAST）：须在 Qt 头之后包含 windows.h
#include <windows.h>


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
// 自绘状态指示器（64 逻辑像素，随 DPI 缩放）
//   未连接  ：灰色圆环 + 中点
//   连接中  ：蓝色旋转圆弧（angle 为 0..359 动画相位）
//   已连接  ：绿色渐变圆 + 白色对勾
// ============================================================================

static QPixmap makeStatusIcon(AppConnectionState state, int angle)
{
    const int size = 64;
    const qreal dpr = qApp->devicePixelRatio();
    const int px = qRound(size * dpr);

    QPixmap pm(px, px);
    pm.setDevicePixelRatio(dpr);
    pm.fill(Qt::transparent);

    QPainter p(&pm);
    p.setRenderHint(QPainter::Antialiasing);
    const QPointF c(size / 2.0, size / 2.0);

    if (state == AppConnectionState::Connected) {
        // 绿色渐变圆 + 白色对勾
        QRadialGradient g(c, size * 0.5);
        g.setColorAt(0.0, QColor(QStringLiteral("#34d399")));
        g.setColorAt(1.0, QColor(QStringLiteral("#059669")));
        p.setBrush(g);
        p.setPen(Qt::NoPen);
        p.drawEllipse(c, size * 0.38, size * 0.38);
        QPen pen(Qt::white, 6.5, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin);
        p.setPen(pen);
        p.setBrush(Qt::NoBrush);
        p.drawLine(QPointF(size * 0.27, size * 0.52), QPointF(size * 0.43, size * 0.66));
        p.drawLine(QPointF(size * 0.43, size * 0.66), QPointF(size * 0.72, size * 0.36));
    } else if (state == AppConnectionState::SettingNetwork
               || state == AppConnectionState::Authenticating) {
        // 旋转圆弧 spinner
        p.translate(c);
        p.rotate(angle);
        const QRectF arcRect(-size * 0.30, -size * 0.30, size * 0.60, size * 0.60);
        p.setBrush(Qt::NoBrush);
        p.setPen(QPen(QColor(QStringLiteral("#dbeafe")), 5.5, Qt::SolidLine, Qt::RoundCap));
        p.drawArc(arcRect, 0, 360 * 16);
        p.setPen(QPen(QColor(QStringLiteral("#2f6bff")), 5.5, Qt::SolidLine, Qt::RoundCap));
        p.drawArc(arcRect, 0, -120 * 16);
    } else {
        // 灰色圆环 + 中点
        p.setBrush(Qt::NoBrush);
        p.setPen(QPen(QColor(QStringLiteral("#d3dae6")), 5.5));
        p.drawEllipse(c, size * 0.30, size * 0.30);
        p.setPen(Qt::NoPen);
        p.setBrush(QColor(QStringLiteral("#9aa6b8")));
        p.drawEllipse(c, 6, 6);
    }
    p.end();
    return pm;
}

// ============================================================================
// 构造 / 析构
// ============================================================================

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent), ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    // 监听系统待机/唤醒，修复"待机一晚早上唤醒后仍是断开"（详见 SessionManager::onSystemResume）
    QCoreApplication::instance()->installNativeEventFilter(this);

    QIcon appIcon(QStringLiteral(":/SCUTnetwork.ico"));
    if (appIcon.isNull())
        appIcon = createFallbackIcon();
    setWindowIcon(appIcon);
    ui->labelLogo->setPixmap(appIcon.pixmap(30, 30));

    // 状态指示器动画：仅连接中运行（SettingNetwork / Authenticating）
    m_statusTimer = new QTimer(this);
    m_statusTimer->setInterval(70);
    connect(m_statusTimer, &QTimer::timeout, this, [this]() {
        m_statusAngle = (m_statusAngle + 9) % 360;
        ui->labelStatusIcon->setPixmap(makeStatusIcon(m_statusState, m_statusAngle));
    });

    // 回车快捷：账号→跳到密码，密码→直接连接（纯 UI 便捷，不改认证逻辑）
    connect(ui->editUsername, &QLineEdit::returnPressed, this, [this]() {
        ui->editPassword->setFocus();
    });
    connect(ui->editPassword, &QLineEdit::returnPressed, this, &MainWindow::on_btnConnect_clicked);

    ui->comboInterface->installEventFilter(this);
    ui->comboInterface->setMinimumContentsLength(10);

    initSessionManager();
    loadInterfaces();
    loadConfig();
    autoDetectNetworkConfig();
    initSystemTray(appIcon);

    // 窗口几何记忆（注册表存储，独立于 config.ini 认证配置）
    QSettings uiSettings;
    const QByteArray geometry = uiSettings.value(QStringLiteral("ui/windowGeometry")).toByteArray();
    if (!geometry.isEmpty())
        restoreGeometry(geometry);

    // Ctrl+Enter（主键盘/小键盘）快捷连接
    auto* connectShortcut = new QShortcut(QKeySequence(Qt::CTRL | Qt::Key_Return), this);
    connect(connectShortcut, &QShortcut::activated, this, &MainWindow::on_btnConnect_clicked);
    auto* connectShortcutKp = new QShortcut(QKeySequence(Qt::CTRL | Qt::Key_Enter), this);
    connect(connectShortcutKp, &QShortcut::activated, this, &MainWindow::on_btnConnect_clicked);

    ui->btnDisconnect->setEnabled(false);

    connect(ui->btnCopyLog, &QPushButton::clicked, this, [this]() {
        QGuiApplication::clipboard()->setText(ui->textLog->toPlainText());
    });

    connect(ui->btnClearLog, &QPushButton::clicked, this, [this]() {
        ui->textLog->clear();
    });

    // "开机自启动"不再即时保存/同步：勾选只改界面状态，与其它配置一起在
    // "保存配置"（或点击"连接"时）统一落盘并同步任务计划（见 saveConfig：每次保存都交给
    // NetworkWorker 核对系统任务的实际目标，仅在失配时才重建/删除）。原"勾选即保存"路径已移除。
    // 因此 loadConfig 里恢复勾选也不会触发任何写盘，无需顺序规避。

    if (ui->checkAutoConnect->isChecked()) {
        QTimer::singleShot(AUTO_CONNECT_DELAY, this, [this]() {
            onLogMessage(QStringLiteral("自动连接已开启，正在连接..."), 0);
            if (m_autoConnectPending)
                return;
            m_autoConnectPending = true;
            autoConnectWithRetry();
        });
    }

    applyStateUI(AppConnectionState::Disconnected);
}

MainWindow::~MainWindow()
{
    m_isQuitting = true;
    QCoreApplication::instance()->removeNativeEventFilter(this);
    delete ui;
}

bool MainWindow::nativeEventFilter(const QByteArray& eventType, void* message, qintptr* /*result*/)
{
    if (eventType == "windows_generic_MSG") {
        const MSG* msg = static_cast<const MSG*>(message);
        if (msg->message == WM_POWERBROADCAST
            && (msg->wParam == PBT_APMRESUMEAUTOMATIC || msg->wParam == PBT_APMRESUMESUSPEND)) {
            m_sessionManager->onSystemResume();
        }
    }
    return false;   // 继续传递事件
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
    // 静默启动（--silent / -s / --minimized，对应开机自启的 schtasks 场景）
    // 语义 = 自动连接：README 承诺"静默启动...直接最小化到托盘并自动连接"。
    // 此前要求勾选"启动后自动连接"才发起，导致只勾了"开机自启动"的用户
    // 开机后一直处于断开状态（6:00 自动重试只是进程内定时器，跨不了重启）。
    QTimer::singleShot(SILENT_CONNECT_DELAY, this, [this]() {
        onLogMessage(QStringLiteral("静默启动：自动连接已开启，正在连接..."), 0);
        if (m_autoConnectPending)
            return;
        m_autoConnectPending = true;
        autoConnectWithRetry();
    });
    m_trayIcon->showMessage(QStringLiteral("SCUT 校园网认证"),
                            QStringLiteral("程序已静默启动，点击托盘图标显示窗口"),
                            QSystemTrayIcon::Information, 2000);
}

void MainWindow::closeEvent(QCloseEvent* event)
{
    if (m_trayIcon->isVisible() && !m_isQuitting) {
        // 记录窗口几何（恢复正常模式后再启动时恢复）
        QSettings().setValue(QStringLiteral("ui/windowGeometry"), saveGeometry());
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
    // 构造函数内同步枚举（此时窗口尚未显示，短暂阻塞无感知）
    populateInterfaces(Network::listInterfaces());
}

void MainWindow::populateInterfaces(const QList<Network::InterfaceEntry>& interfaces,
                                    const QString& preferPcap,
                                    const QString& preferText)
{
    ui->comboInterface->clear();
    for (const auto& entry : interfaces)
        ui->comboInterface->addItem(entry.displayName, entry.pcapName);

    // 恢复刷新前的选择（若该设备仍存在）
    if (!preferPcap.isEmpty() || !preferText.isEmpty()) {
        for (int i = 0; i < ui->comboInterface->count(); ++i) {
            if (ui->comboInterface->itemData(i).toString() == preferPcap
                || ui->comboInterface->itemText(i) == preferText) {
                ui->comboInterface->setCurrentIndex(i);
                break;
            }
        }
    }

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
        if (ui->editGateway->text().trimmed().isEmpty() && !entry.netmask().isNull()) {
            const quint32 ip4   = entry.ip().toIPv4Address();
            const quint32 mask4 = entry.netmask().toIPv4Address();
            // 防御：IP 或掩码为 0（网卡尚未获得配置）时跳过，避免把 0.0.0.1 写入网关框
            if (ip4 != 0 && mask4 != 0) {
                // 网关 = 网络地址 + 1（(ip & mask) | 1 在网段末位为 1 时不等价，此处显式求网络地址）
                const quint32 network = ip4 & mask4;
                ui->editGateway->setText(QHostAddress(network + 1).toString());
            }
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

    // 记录加载后的 UI 配置作为"保存配置"脏检测基准
    m_lastSavedConfig = collectCurrentCfg();
}

AppConfig MainWindow::collectCurrentCfg()
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
    return cfg;
}

void MainWindow::saveConfig()
{
    AppConfig cfg = collectCurrentCfg();

    ConfigManager::save(ConfigManager::defaultPath(), cfg);
    m_lastSavedConfig = cfg;   // 更新脏检测基准

    // 开机自启动：每次保存都把「期望状态」交给 NetworkWorker，由它核对系统里任务「实际指向
    // 的目标」是否为当前运行 exe，只有真正失配（任务不存在 / 指向别的 exe / 缺 --silent）时
    // 才 /create 或 /delete。原实现用「勾选状态是否变化」做守卫，一旦 config 已是 autoStart=true
    // 但任务仍指向旧 exe（如从开发版换装到 Program Files），勾选没变就永不重建，自启永远失效。
    // 如今核对发生在任务侧，保存/连接时依旧不会频繁增删任务（worker 查询后直接 no-op）。
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

    // 收集窗体输入，交给 ConnectionBuilder 做校验与组装（纯逻辑，见 core/connection_builder）
    ConnectionBuilder::Input in;
    in.pcapName       = ui->comboInterface->currentData().toString();
    in.displayText    = ui->comboInterface->currentText();
    in.username       = ui->editUsername->text();
    in.password       = ui->editPassword->text();
    in.mac            = autoDetectMacForUI();
    in.autoSetNetwork = ui->checkAutoSetNetwork->isChecked();
    if (in.autoSetNetwork)
        in.adapterName = Network::adapterNameByMac(in.mac);
    in.ip      = ui->editIp->text().trimmed();
    in.mask    = ui->editMask->text().trimmed();
    in.gateway = ui->editGateway->text().trimmed();
    in.dns1    = ui->editDNSServer->text().trimmed();
    in.dns2    = ui->editBackupDNS->text().trimmed();

    // 校验失败直接终止（不持久化、不启动）
    ConnectionBuilder::Result r = ConnectionBuilder::build(in);
    if (!r.ok) {
        onLogMessage(r.error, 2);
        return;
    }

    saveConfig();
    ui->textLog->clear();

    AuthConfig config = getCurrentConfig();
    if (r.needStaticIp) {
        ui->btnDisconnect->setEnabled(false);
        m_actionDisconnect->setEnabled(false);
        m_sessionManager->startConnection(config, r.ipConfig);
    } else {
        m_sessionManager->startConnection(config);
    }
}

// ============================================================================
// 自动连接（带网络未就绪重试）
// ============================================================================

void MainWindow::autoConnectWithRetry(int attempt)
{
    // 任一终点都要清掉链标志，便于事后再次触发自动连接
    if (m_isQuitting) {
        m_autoConnectPending = false;
        return;
    }

    // 已在连接中（用户已手动连接，或某次尝试已启动成功）——整个流程结束
    if (m_sessionManager->state() != AppConnectionState::Disconnected) {
        m_autoConnectPending = false;
        return;
    }

    // 登录早期最常见的网络未就绪信号：Npcap 尚未把网卡枚举出来（count==0），
    // 或走静态IP配置时网卡还没拿到 MAC 地址。这两类是暂时性的，值得重试。
    bool networkNotReady = ui->comboInterface->count() == 0;
    if (!networkNotReady && ui->checkAutoSetNetwork->isChecked())
        networkNotReady = autoDetectMacForUI().isEmpty();

    if (networkNotReady) {
        if (attempt >= AUTO_CONNECT_RETRY_COUNT) {
            onLogMessage(QStringLiteral("自动连接失败：网卡在约 %1 秒内未就绪，已放弃。请点击\"连接\"或\"刷新网卡\"手动重试。")
                             .arg(AUTO_CONNECT_RETRY_COUNT * AUTO_CONNECT_RETRY_INTERVAL / 1000), 1);
            m_autoConnectPending = false;
            return;
        }
        onLogMessage(QStringLiteral("网络尚未就绪，%1 秒后自动重试 (%2/%3) ...")
                         .arg(AUTO_CONNECT_RETRY_INTERVAL / 1000)
                         .arg(attempt + 1).arg(AUTO_CONNECT_RETRY_COUNT), 0);
        // 继续本链：m_autoConnectPending 保持 true，阻止另一个入口开新链
        QTimer::singleShot(AUTO_CONNECT_RETRY_INTERVAL, this, [this, attempt]() {
            autoConnectWithRetry(attempt + 1);
        });
        return;
    }

    // 网卡已就绪，发起真实认证。状态机随即离开 Disconnected 由上面的检查拦截；
    // 若仍停留在 Disconnected，说明是配置/凭证错误（on_btnConnect_clicked 已打印具体原因），
    // 这类错误重试无意义，交由用户修正，不再自动重试。
    m_autoConnectPending = false;
    on_btnConnect_clicked();
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
        QString text;
        QString hint;
        QString traySuffix;
        QString styleProp;
        bool connected;   // true = 连接流程进行中：禁用连接按钮、启用断开按钮
    };

    static const StateInfo kDisconnected = {
        QStringLiteral("未连接"), QStringLiteral("点击下方按钮开始认证"),
        QStringLiteral(" (未连接)"), QStringLiteral("disconnected"), false };
    static const StateInfo kSettingNetwork = {
        QStringLiteral("正在配置网络..."), QStringLiteral("正在设置静态IP及DNS"),
        QStringLiteral(" (配置网络中...)"), QStringLiteral("connecting"), true };
    static const StateInfo kAuthenticating = {
        QStringLiteral("正在认证..."), QStringLiteral("正在发送802.1X认证包"),
        QStringLiteral(" (认证中...)"), QStringLiteral("connecting"), true };
    static const StateInfo kConnected = {
        QStringLiteral("已连接"), QStringLiteral("校园网已连接，可以上网"),
        QStringLiteral(" (已连接)"), QStringLiteral("connected"), true };

    const StateInfo* info = nullptr;
    switch (state) {
    case AppConnectionState::Disconnected:   info = &kDisconnected;   break;
    case AppConnectionState::SettingNetwork: info = &kSettingNetwork; break;
    case AppConnectionState::Authenticating: info = &kAuthenticating; break;
    case AppConnectionState::Connected:      info = &kConnected;      break;
    default:
        return;  // 防御：枚举越界直接忽略（状态由 SessionManager 内部状态机产生）
    }

    // 按钮状态
    ui->btnConnect->setEnabled(!info->connected);
    ui->btnDisconnect->setEnabled(info->connected);
    m_actionConnect->setEnabled(!info->connected);
    m_actionDisconnect->setEnabled(info->connected);

    // 标签
    ui->label_status->setText(info->text);
    ui->labelStatusText->setText(info->text);
    ui->labelStatusHint->setText(info->hint);
    m_trayIcon->setToolTip(QStringLiteral("SCUT 校园网认证") + info->traySuffix);

    // 样式（头部状态胶囊）
    ui->label_status->setProperty("state", info->styleProp);
    ui->label_status->style()->unpolish(ui->label_status);
    ui->label_status->style()->polish(ui->label_status);

    // 自绘状态指示器（连接中带旋转动画）
    updateStatusIcon(state);
}

void MainWindow::updateStatusIcon(AppConnectionState state)
{
    m_statusState = state;
    ui->labelStatusIcon->setPixmap(makeStatusIcon(state, m_statusAngle));

    if (state == AppConnectionState::SettingNetwork
        || state == AppConnectionState::Authenticating) {
        if (!m_statusTimer->isActive())
            m_statusTimer->start();
    } else {
        m_statusTimer->stop();
    }
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
    ui->textLog->appendHtml(LogManager::formatHtml(message, level));
    ui->textLog->moveCursor(QTextCursor::End);
}

// ============================================================================
// 按钮 Slot
// ============================================================================

void MainWindow::on_btnRefresh_clicked()
{
    // 后台枚举网卡（pcap_findalldevs 可能阻塞数百 ms），完成后回主线程填充。
    // QPointer 守卫：窗口销毁后回调安全失效。
    QPointer<MainWindow> guard(this);
    const QString preferPcap = ui->comboInterface->currentData().toString();
    const QString preferText = ui->comboInterface->currentText();

    QThreadPool::globalInstance()->start(QRunnable::create([guard, preferPcap, preferText]() {
        const auto interfaces = Network::listInterfaces();
        QMetaObject::invokeMethod(QCoreApplication::instance(),
                                  [guard, interfaces, preferPcap, preferText]() {
            if (guard)
                guard->populateInterfaces(interfaces, preferPcap, preferText);
        }, Qt::QueuedConnection);
    }));
}

void MainWindow::on_btnSaveConfig_clicked()
{
    // 脏检测：配置未变更时跳过写盘与弹窗（避免"没改也提示已保存"）
    if (collectCurrentCfg() == m_lastSavedConfig) {
        QMessageBox::information(this, QStringLiteral("提示"),
                                 QStringLiteral("配置没有变更，无需保存"));
        return;
    }
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
    ConfigManager::resolveAuthConfig(config);
    return config;
}
