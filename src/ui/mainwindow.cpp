#include "ui/mainwindow.h"
#include "ui_mainwindow.h"
#include "core/constants.h"
#include "core/connection_builder.h"
#include "config/config_manager.h"
#include "network/network.h"
#include "wifi/wlan_media.h"
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

    // 注：系统唤醒事件过滤器在 initSessionManager() 之后安装（见下）——它一装好就可能
    // 收到 WM_POWERBROADCAST 并调用 m_sessionManager，顺序反了就是空指针解引用

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
    // 切换网卡 → 自动填充该网卡的 IP/掩码/网关/MAC（仅填空字段，不覆盖用户输入）
    connect(ui->comboInterface, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &MainWindow::autoDetectNetworkConfig);

    initSessionManager();
    // 监听系统待机/唤醒，修复"待机一晚早上唤醒后仍是断开"（详见 SessionManager::onSystemResume）。
    // 必须在 initSessionManager() 之后：过滤器回调会直接使用 m_sessionManager
    QCoreApplication::instance()->installNativeEventFilter(this);
    // 调试输出：勾选立即生效（运行时开关，无需重启）；配置值随后在 loadConfig 恢复，
    // 并随"保存配置"落盘持久化
    connect(ui->checkDebugLog, &QCheckBox::toggled, this, [this](bool on) {
        if (m_sessionManager)
            m_sessionManager->setDebugLogEnabled(on);
    });
    // DrCOM UDP 心跳保活：关闭方向立即生效（停掉已跑的 UDP 会话），开启方向下次连接生效
    // ——UDP 会话必须跟在一次成功的 802.1X 之后。配置值随后在 loadConfig 恢复。
    connect(ui->checkDrcomHeartbeat, &QCheckBox::toggled, this, [this](bool on) {
        if (m_sessionManager)
            m_sessionManager->setDrcomHeartbeatEnabled(on);
        updateHostFieldEnabled(on);
    });
    // 顺序：先读配置（此时网卡下拉为空，接口名由 loadInterfaces 完成后回填），
    // 再按需后台枚举网卡——两者对控件的影响与"先同步枚举再读配置"一致。
    // 【仅在勾选"启动后自动连接"时】启动即枚举：未勾选时用户明确不需要自动检测网卡，
    // 改为惰性检测——首次切到「设置」页、点「刷新」或点「连接」时才枚举/自动填充。
    // Wi-Fi 侧启动期本就无任何探测（WlanMedia 只在连接流程与"已连接"文案中调用）。
    loadConfig();
    if (ui->checkAutoConnect->isChecked()) {
        loadInterfaces();
        autoDetectNetworkConfig();
    } else {
        // 未勾选自动连接就不做网卡枚举：下拉保持为空，避免"启动即检测网卡"
        onLogMessage(QStringLiteral("已关闭「启动后自动连接」：启动不自动检测网卡，"
                                    "点击「刷新」或切到「设置」页即可检测"), 0);
    }
    // 惰性检测触发点：首次打开「设置」页（网卡下拉所在页）
    connect(ui->tabWidget, &QTabWidget::currentChanged, this, [this](int index) {
        if (index != 0 && !m_interfacesLoaded && !m_enumerationPending)
            loadInterfaces();
    });
    initSystemTray(appIcon);

    // 调试：启用的连接尝试基线（模式恒为自动；SSID 白名单/选中网卡/自动检测 IP 与 MAC）——
    // 供跨机器对照"这台启动时到底把网卡识别成什么"。
    // 注：网卡枚举在后台进行，此处通常仍为空——填充完成后若要对照请看后续"[调试]"行
    if (ui->checkDebugLog->isChecked()) {
        onLogMessage(QStringLiteral("[调试] 配置加载: 联网方式=自动, SSID白名单=%1, 选中网卡=%2, "
                                    "自动检测IP=%3 / MAC=%4")
                         .arg(ui->editSsid->text().trimmed(),
                              ui->comboInterface->currentText().isEmpty()
                                  ? QStringLiteral("(网卡枚举中)") : ui->comboInterface->currentText(),
                              ui->editIp->text(),
                              ui->editMac->text()), 0);
    }

    updateConnectModeLabel(AppConnectionState::Disconnected);   // 初始"当前连接模式：未连接"

    // 窗口几何记忆（注册表存储，独立于 config.ini 认证配置）
    QSettings uiSettings;
    const QByteArray geometry = uiSettings.value(QStringLiteral("ui/windowGeometry")).toByteArray();
    if (!geometry.isEmpty()) {
        restoreGeometry(geometry);
        // 用户要求：启动时不要最大化。closeEvent 的 saveGeometry() 会把"上次是否最大化"
        // 一并存进 ui/windowGeometry，若上次最大化后关到托盘，下次会还原成最大化——故剥掉。
        if (windowState() & Qt::WindowMaximized)
            setWindowState(windowState() & ~Qt::WindowMaximized);
    }

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

    // 日志视图上限：长时间运行（尤其开调试后逐帧日志）时无上限追加会让内存线性增长
    ui->textLog->setMaximumBlockCount(5000);

    // "开机自启动"不再即时保存/同步：勾选只改界面状态，与其它配置一起在
    // "保存配置"（或点击"连接"时）统一落盘并同步任务计划（见 saveConfig：每次保存都交给
    // NetworkWorker 核对系统任务的实际目标，仅在失配时才重建/删除）。原"勾选即保存"路径已移除。
    // 因此 loadConfig 里恢复勾选也不会触发任何写盘，无需顺序规避。

    if (ui->checkAutoConnect->isChecked())
        QTimer::singleShot(AUTO_CONNECT_DELAY, this, &MainWindow::triggerAutoConnect);

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
    m_silentStartup = true;
    // 静默启动（--silent / -s / --minimized，开机自启的 schtasks 场景）
    // 语义 = 自动连接：静默启动总是发起自动连接，与"启动后自动连接"复选框无关。
    // 注意：构造函数可能已按复选框排了一次自动连接，这里排第二次——两次都走
    // triggerAutoConnect，由其开头的守卫保证只真正执行一次、也只打一条日志。
    // 未勾选复选框时构造函数没枚举网卡，而自动连接需要网卡：这里补一次同步枚举请求。
    if (!m_interfacesLoaded && !m_enumerationPending)
        loadInterfaces();
    QTimer::singleShot(SILENT_CONNECT_DELAY, this, &MainWindow::triggerAutoConnect);
    // 静默启动（开机自启）不弹系统托盘消息：用户要求开机自启时避免打扰
}

// 自动连接唯一入口（构造函数 / 静默启动 / 托盘菜单共用）：
// 守卫在前、日志在后——重复排程不会再打一条"正在连接..."的假日志
void MainWindow::triggerAutoConnect()
{
    if (m_isQuitting || m_autoConnectPending)
        return;
    if (m_sessionManager->state() != AppConnectionState::Disconnected)
        return;
    onLogMessage(m_silentStartup
                     ? QStringLiteral("静默启动：自动连接已开启，正在连接...")
                     : QStringLiteral("自动连接已开启，正在连接..."), 0);
    m_autoConnectPending = true;
    autoConnectWithRetry();
}

void MainWindow::closeEvent(QCloseEvent* event)
{
    if (m_trayIcon->isVisible() && !m_isQuitting) {
        // 记录窗口几何（恢复正常模式后再启动时恢复）
        QSettings().setValue(QStringLiteral("ui/windowGeometry"), saveGeometry());
        hide();   // 关闭到托盘：不弹系统消息（用户要求静默）
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
    if (m_sessionManager->state() != AppConnectionState::Disconnected) {
        // 退出时是否无线注销由"退出时注销无线连接"勾选决定（默认不注销，保持在线）。
        // 有线始终正常收尾（恢复 DHCP / 停线程）。
        m_sessionManager->stopConnection(ui->checkLogoutOnExit->isChecked(), /*userInitiated=*/true);
    }
    m_trayIcon->hide();
    qApp->quit();
}

// ============================================================================
// 网卡列表
// ============================================================================

void MainWindow::loadInterfaces()
{
    // 启动/惰性检测入口：优先用 config.ini 里保存的网卡名恢复下拉选择
    enumerateInterfaces(m_savedInterfaceName, QString());
}

// 后台枚举网卡 -> 回主线程填充（prefer* 非空时按它们恢复下拉选择）。
// pcap_findalldevs 可能阻塞数百 ms，故始终放线程池（放在构造函数里会推迟窗口首帧）。
// 下拉原本为空，因此 loadConfig 的"恢复选择"与脏检测基线都以空值落定——填充完成后
// 按配置/刷新前的选择恢复、重算基线、再补自动探测，与"同步枚举后再 loadConfig"
// 的顺序等价（见 on_btnRefresh_clicked 复用的同一实现）。
void MainWindow::enumerateInterfaces(const QString& preferPcap, const QString& preferText)
{
    if (m_enumerationPending)
        return;   // 已有一次枚举在途：完成后统一处理续接（见 m_connectAfterEnumeration）
    m_enumerationPending = true;

    QPointer<MainWindow> guard(this);
    QThreadPool::globalInstance()->start(QRunnable::create([guard, preferPcap, preferText]() {
        const auto interfaces = Network::listInterfaces();
        QMetaObject::invokeMethod(QCoreApplication::instance(),
                                  [guard, interfaces, preferPcap, preferText]() {
            if (!guard)
                return;
            guard->m_enumerationPending = false;
            guard->m_interfacesLoaded = true;
            {
                // 抑制填充过程中的 currentIndexChanged（否则会对逐个条目触发自动探测）
                QSignalBlocker blocker(guard->ui->comboInterface);
                guard->populateInterfaces(interfaces, preferPcap, preferText);
            }
            // 下拉首次有值：重算脏检测基线（loadConfig 那次拿到的是空网卡名）
            guard->m_lastSavedConfig = guard->collectCurrentCfg();
            guard->autoDetectNetworkConfig();
            // 用户在枚举完成前点了"连接"：现在续接同一次连接请求
            if (guard->m_connectAfterEnumeration) {
                guard->m_connectAfterEnumeration = false;
                guard->connectWithCurrentInput();
            }
        }, Qt::QueuedConnection);
    }));
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
    // 注：currentIndexChanged → autoDetectNetworkConfig 的连接在构造函数里建立，
    // 不在此处——本函数被重复调用时不会重复连接，clear() 触发的那次也只是空转
    // （下拉为空时 findInterface 返回无效接口）
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

void MainWindow::on_btnQueryMac_clicked()
{
    // ① 优先用下拉框当前选中网卡（尊重用户选择）；点击反馈由按钮按压变色承担
    QString pcapName    = ui->comboInterface->currentData().toString();
    QString displayText = ui->comboInterface->currentText();
    QNetworkInterface iface = Network::findInterface(pcapName, displayText);
    if (iface.isValid() && !iface.hardwareAddress().isEmpty()) {
        ui->editMac->setText(iface.hardwareAddress());
        return;
    }

    // ② 回退：不依赖下拉框（可能为空/未选中有线卡），遍历系统网卡取"物理有线卡"的 MAC。
    //    仅用于静态 IP（有线场景），故排除回环/虚拟/无线网卡。
    for (const QNetworkInterface& ni : QNetworkInterface::allInterfaces()) {
        const QString mac = ni.hardwareAddress();
        const QString name = ni.name().toLower();
        const QString hr   = ni.humanReadableName().toLower();
        if (mac.isEmpty()
            || name.contains(QLatin1String("loopback"))
            || name.contains(QLatin1String("virtual"))
            || hr.contains(QLatin1String("wi-fi")) || hr.contains(QLatin1String("wireless"))
            || hr.contains(QLatin1String("802.11")) || hr.contains(QLatin1String("wlan"))
            || hr.contains(QLatin1String("bluetooth")))
            continue;
        ui->editMac->setText(mac);
        return;
    }
    onLogMessage(QStringLiteral("未能获取网卡 MAC 地址，请手动填写，或先点击「刷新」选择网卡"), 2);
}

// ============================================================================
// 配置持久化
// ============================================================================

void MainWindow::loadConfig()
{
    AppConfig cfg = ConfigManager::load(ConfigManager::defaultPath());
    // 记住保存的网卡名：未勾选"启动后自动连接"时启动不枚举网卡，下拉为空；此值用于
    // 枚举完成后恢复选择（enumerateInterfaces 的 preferPcap）
    m_savedInterfaceName = cfg.interfaceName;

    ui->editUsername->setText(cfg.username);
    // 双向同步：只在 true 时 setChecked 会留下 .ui 的默认勾选（checked=true）——配置为
    // false 时界面仍显示"记住密码"，脏检测基线也随之记成 true，之后任一保存都会把
    // savePassword=true（可能配着空密码）写回配置
    if (cfg.savePassword) {
        ui->editPassword->setText(cfg.password);
        ui->checkSavePassword->setChecked(true);
    } else {
        ui->checkSavePassword->setChecked(false);
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
    ui->checkLogoutOnExit->setChecked(cfg.logoutOnExit);
    // 调试输出：恢复勾选并立即生效（setChecked 会触发 toggled → setDebugLogEnabled，
    // 此处显式调用保证值同步到 SessionManager；幂等无副作用）
    ui->checkDebugLog->setChecked(cfg.debugLog);
    m_sessionManager->setDebugLogEnabled(cfg.debugLog);

    // DrCOM UDP 心跳保活：同上，显式调用不可省——默认值为 false 且复选框初态即未勾选时
    // setChecked(false) 不触发 toggled，仅靠上面的 lambda 会让「认证服务器」停在可编辑状态
    ui->checkDrcomHeartbeat->setChecked(cfg.drcomHeartbeat);
    m_sessionManager->setDrcomHeartbeatEnabled(cfg.drcomHeartbeat);
    updateHostFieldEnabled(cfg.drcomHeartbeat);

    // 无线 SSID 白名单（联网方式控件已移除，mode 恒为"自动"——config 键仅兼容保留）
    ui->editSsid->setText(cfg.wifiSsids);
    updateConnectModeLabel(AppConnectionState::Disconnected);

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
    cfg.wifiSsids      = ui->editSsid->text().trimmed();
    cfg.logoutOnExit   = ui->checkLogoutOnExit->isChecked();
    cfg.debugLog       = ui->checkDebugLog->isChecked();
    cfg.drcomHeartbeat = ui->checkDrcomHeartbeat->isChecked();
    // cfg.connectMode 不再写入：模式切换功能已移除，恒为"自动"（键仅向后兼容保留）
    return cfg;
}

void MainWindow::updateHostFieldEnabled(bool heartbeatOn)
{
    // 地址框置灰后 text() 仍照常可读，getCurrentConfig() 无需改动——关闭只是表明
    // 该值当前不产生任何行为（有线认证走二层 EAPOL，与服务器地址无关）
    ui->editHost->setEnabled(heartbeatOn);
    ui->label_host->setEnabled(heartbeatOn);
}

void MainWindow::saveConfig()
{
    AppConfig cfg = collectCurrentCfg();

    ConfigManager::save(ConfigManager::defaultPath(), cfg);
    m_lastSavedConfig = cfg;   // 更新脏检测基准

    // 开机自启动：每次保存都把「期望状态」交给 NetworkWorker，由它核对系统里任务「实际指向
    // 的目标」是否为当前运行 exe，只有真正失配（任务不存在 / 指向别的 exe / 缺 --silent）时
    // 才 /create 或 /delete。核对发生在任务侧，保存/连接时不会频繁增删任务（查询后 no-op）。
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
    if (m_sessionManager->state() != AppConnectionState::Disconnected) {
        // 连接中按钮已禁用，但 Ctrl+Enter 快捷键仍可达——给出明确提示
        onLogMessage(m_sessionManager->state() == AppConnectionState::WaitingForNetwork
                         ? QStringLiteral("当前正在等待网络，请先点「取消」结束等待再连接")
                         : QStringLiteral("当前已在连接流程中，请先点「断开」再连接"), 1);
        return;
    }
    connectWithCurrentInput();
}

// 收集当前窗体输入并启动连接。联网方式固定为"自动"（有线优先、无线兜底）——
// 模式切换功能已按用户要求移除：有线/无线由链路状态自动决定，意图不会被误读。
void MainWindow::connectWithCurrentInput()
{
    // 未勾选"启动后自动连接"时启动不枚举网卡：首次点"连接"先补一次枚举，
    // 枚举完成后自动续接本次连接（见 enumerateInterfaces 的完成回调）。
    // 期间按"等待"展示（亮「取消」）——取消后不再续接（见 on_btnDisconnect_clicked）
    if (!m_interfacesLoaded) {
        onLogMessage(QStringLiteral("正在检测网卡，检测完成后将自动继续连接..."), 0);
        m_connectAfterEnumeration = true;
        applyStateUI(AppConnectionState::WaitingForNetwork);
        loadInterfaces();
        return;
    }
    if (ui->comboInterface->count() == 0) {
        onLogMessage(QStringLiteral("未检测到可用网卡，请点击刷新重试"), 2);
        applyStateUI(m_sessionManager->state());   // 结束"等待网卡"展示（若正处于其中）
        return;
    }

    // 收集窗体输入，交给 ConnectionBuilder 做校验与组装（纯逻辑，见 core/connection_builder）
    ConnectionBuilder::Input in;
    in.pcapName       = ui->comboInterface->currentData().toString();
    in.displayText    = ui->comboInterface->currentText();
    in.username       = ui->editUsername->text();
    in.password       = ui->editPassword->text();
    // 静态 IP 是"意图"，不再与"点击连接这一刻是否插着网线"耦合：先启动后插网线时，
    // 点击连接时还没插线，但真正的有线认证发生在插线之后——旧实现用 wiredPlugged
    // 把静态 IP 在这条路径上丢掉，导致"第一次自动有线认证固定失败，手动再连一次就好"
    // （用户报告的问题 3）。是否真的要配置静态 IP、以及配置到哪块网卡，由
    // SessionManager 在认证时刻决定（无线后端本就不读 ipCfg）。
    in.autoSetNetwork = ui->checkAutoSetNetwork->isChecked();
    // MAC 由用户点击「查询」或手动填写；为空时按需从当前选中网卡补一次（不需要插线，
    // 只是给静态 IP 的 netsh 目标用；仍取不到则由 build 给出软提示，见 ConnectionBuilder）
    in.mac = ui->editMac->text().trimmed();
    if (in.autoSetNetwork) {
        if (in.mac.isEmpty()) {
            const QNetworkInterface iface = Network::findInterface(in.pcapName, in.displayText);
            if (iface.isValid() && !iface.hardwareAddress().isEmpty()) {
                in.mac = iface.hardwareAddress();
                ui->editMac->setText(in.mac);
            }
        }
        in.adapterName = Network::adapterNameByMac(in.mac);
    }
    in.ip      = ui->editIp->text().trimmed();
    in.mask    = ui->editMask->text().trimmed();
    in.gateway = ui->editGateway->text().trimmed();
    in.dns1    = ui->editDNSServer->text().trimmed();
    in.dns2    = ui->editBackupDNS->text().trimmed();
    in.ssidRaw = ui->editSsid->text().trimmed();

    // 校验失败直接终止（不持久化、不启动）
    ConnectionBuilder::Result r = ConnectionBuilder::build(in);
    if (!r.ok) {
        onLogMessage(r.error, 2);
        applyStateUI(m_sessionManager->state());   // 结束"等待网卡"展示（若正处于其中）
        return;
    }
    if (!r.warning.isEmpty())
        onLogMessage(r.warning, 1);

    saveConfig();
    ui->textLog->clear();

    AuthConfig config = getCurrentConfig();
    const QStringList ssids = ConnectionBuilder::parseSsidList(in.ssidRaw);
    m_sessionManager->startConnection(config, r.needStaticIp ? r.ipConfig : StaticIpConfig{},
                                      ConnectMode::Auto, ssids);
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

    // 用户已点「取消」（cancelPendingAutoConnect）：本链作废，迟到的单发回调直接结束
    if (!m_autoConnectPending)
        return;

    // 已在连接中（用户已手动连接，或某次尝试已启动成功）——整个流程结束
    if (m_sessionManager->state() != AppConnectionState::Disconnected) {
        m_autoConnectPending = false;
        return;
    }

    // 登录早期最常见的网络未就绪信号：Npcap 尚未把网卡枚举出来（count==0），
    // 属暂时性，值得重试。MAC 由用户「查询」/手动填写，不作为未就绪判据。
    bool networkNotReady = ui->comboInterface->count() == 0;

    if (networkNotReady) {
        if (attempt >= AUTO_CONNECT_RETRY_COUNT) {
            onLogMessage(QStringLiteral("自动连接失败：网卡在约 %1 秒内未就绪，已放弃。请点击\"连接\"或\"刷新网卡\"手动重试。")
                             .arg(AUTO_CONNECT_RETRY_COUNT * AUTO_CONNECT_RETRY_INTERVAL / 1000), 1);
            m_autoConnectPending = false;
            applyStateUI(m_sessionManager->state());   // 结束等待态展示（恢复连接按钮）
            return;
        }
        onLogMessage(QStringLiteral("网络尚未就绪，%1 秒后自动重试 (%2/%3) ...")
                         .arg(AUTO_CONNECT_RETRY_INTERVAL / 1000)
                         .arg(attempt + 1).arg(AUTO_CONNECT_RETRY_COUNT), 0);
        // 等待期展示"等待中"并亮「取消」按钮（用户要求所有等待阶段都可取消）：
        // 这是 MainWindow 自己的就绪重试链，SessionManager 尚未启动会话，故直接以
        // 等待态文案渲染一次（纯展示，不改 SessionManager 状态）
        applyStateUI(AppConnectionState::WaitingForNetwork);
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

// 取消"启动期自动连接重试链"（等待网卡就绪的那条链）：清标志、复位等待态展示。
void MainWindow::cancelPendingAutoConnect()
{
    if (!m_autoConnectPending)
        return;
    m_autoConnectPending = false;
    onLogMessage(QStringLiteral("已取消自动连接等待"), 0);
    applyStateUI(m_sessionManager->state());   // 复位为"未连接"（连接按钮恢复可用）
}

void MainWindow::on_btnDisconnect_clicked()
{
    // 等待态（等待网线/校园 Wi-Fi、认证失败后的重试等待）里本按钮显示为「取消」：
    // 取消等待 = 结束重试排程/就绪监听并回到未连接，不再自动连接（直到用户再点连接）
    cancelPendingAutoConnect();

    // 手动点"连接"后正在等待网卡枚举：取消这次续接（枚举完成回调见 enumerateInterfaces）
    if (m_connectAfterEnumeration) {
        m_connectAfterEnumeration = false;
        onLogMessage(QStringLiteral("已取消连接等待"), 0);
        applyStateUI(m_sessionManager->state());
    }

    if (m_sessionManager->state() == AppConnectionState::Disconnected)
        return;

    m_sessionManager->stopConnection(/*logoutWifi=*/true, /*userInitiated=*/true);
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
        // 等待态展示：断开按钮改文案为「取消」（点击即结束等待，而非断开会话）。
        // 空串 = 保持默认「断开」。
        QString cancelButtonText;
    };

    static const StateInfo kDisconnected = {
        QStringLiteral("未连接"), QStringLiteral("点击下方按钮开始认证"),
        QStringLiteral(" (未连接)"), QStringLiteral("disconnected"), false, QString() };
    // 等待网络/等待重试：可取消的等待（用户要求所有等待阶段都亮「取消」按钮）
    static const StateInfo kWaitingForNetwork = {
        QStringLiteral("等待网络..."),
        QStringLiteral("正在等待网线插入或校园 Wi-Fi 连接，将自动认证（点「取消」结束等待）"),
        QStringLiteral(" (等待网络...)"), QStringLiteral("connecting"), true,
        QStringLiteral("取消") };
    static const StateInfo kSettingNetwork = {
        QStringLiteral("正在配置网络..."), QStringLiteral("正在设置静态IP及DNS"),
        QStringLiteral(" (配置网络中...)"), QStringLiteral("connecting"), true, QString() };
    static const StateInfo kAuthenticating = {
        QStringLiteral("正在认证..."), QStringLiteral("正在发送802.1X认证包"),
        QStringLiteral(" (认证中...)"), QStringLiteral("connecting"), true, QString() };
    static const StateInfo kConnected = {
        QStringLiteral("已连接"), QStringLiteral("校园网已连接，可以上网"),
        QStringLiteral(" (已连接)"), QStringLiteral("connected"), true, QString() };
    // 无线 Portal 认证中（探测/门户/登录/上线确认——细化文案来自日志）
    static const StateInfo kWiFiConnecting = {
        QStringLiteral("正在认证..."), QStringLiteral("正在连接无线校园网（门户认证）"),
        QStringLiteral(" (无线认证中...)"), QStringLiteral("connecting"), true, QString() };

    const StateInfo* info = nullptr;
    switch (state) {
    case AppConnectionState::Disconnected:     info = &kDisconnected;     break;
    case AppConnectionState::WaitingForNetwork: info = &kWaitingForNetwork; break;
    case AppConnectionState::SettingNetwork:   info = &kSettingNetwork;   break;
    case AppConnectionState::Authenticating:   info = &kAuthenticating;   break;
    case AppConnectionState::WiFiConnecting:   info = &kWiFiConnecting;   break;
    case AppConnectionState::Connected:        info = &kConnected;        break;
    default:
        return;  // 防御：枚举越界直接忽略（状态由 SessionManager 内部状态机产生）
    }

    // 按钮状态（等待态：连接禁用、断开=「取消」可用）
    ui->btnConnect->setEnabled(!info->connected);
    ui->btnDisconnect->setEnabled(info->connected);
    m_actionConnect->setEnabled(!info->connected);
    m_actionDisconnect->setEnabled(info->connected);
    const bool cancelMode = !info->cancelButtonText.isEmpty();
    const QString disconnectText = cancelMode ? info->cancelButtonText : QStringLiteral("断开");
    ui->btnDisconnect->setText(disconnectText);
    m_actionDisconnect->setText(cancelMode ? QStringLiteral("取消等待") : QStringLiteral("断开"));

    // 标签
    ui->label_status->setText(info->text);
    ui->labelStatusText->setText(info->text);
    ui->labelStatusHint->setText(info->hint);
    m_trayIcon->setToolTip(QStringLiteral("SCUT 校园网认证") + info->traySuffix);

    // 样式（头部状态胶囊）
    ui->label_status->setProperty("state", info->styleProp);
    ui->label_status->style()->unpolish(ui->label_status);
    ui->label_status->style()->polish(ui->label_status);

    // 自绘状态指示器（连接中带旋转动画；等待态保持灰环，不转）
    updateStatusIcon(state);
}

void MainWindow::updateStatusIcon(AppConnectionState state)
{
    m_statusState = state;
    ui->labelStatusIcon->setPixmap(makeStatusIcon(state, m_statusAngle));

    if (state == AppConnectionState::SettingNetwork
        || state == AppConnectionState::Authenticating
        || state == AppConnectionState::WiFiConnecting) {
        if (!m_statusTimer->isActive())
            m_statusTimer->start();
    } else {
        m_statusTimer->stop();
    }
}

void MainWindow::updateConnectModeLabel(AppConnectionState state)
{
    // "当前连接模式"：以 SessionManager 后端与实时链路为准（wlanapi 关联状态只反映
    // 是否连接了热点，不代表认证，故以认证状态机的后端为准）。
    QString mode;
    switch (state) {
    case AppConnectionState::Connected:
        if (m_sessionManager->activeBackend() == ActiveBackend::PortalWifi) {
            const WlanMedia::WlanInfo wlan = WlanMedia::currentWifiConnection();
            mode = wlan.connected
                       ? QStringLiteral("无线（%1）").arg(wlan.ssid)
                       : QStringLiteral("无线");
        } else {
            mode = QStringLiteral("有线");
        }
        break;
    case AppConnectionState::Disconnected:
        mode = QStringLiteral("未连接");
        break;
    case AppConnectionState::WaitingForNetwork:
        // 等待期后端尚未定（会话未开始），显示"等待网络"而不是误报"有线"
        mode = QStringLiteral("等待网络");
        break;
    default:
        // SettingNetwork / Authenticating / WiFiConnecting：后端已定，直接按后端显示
        mode = (m_sessionManager->activeBackend() == ActiveBackend::PortalWifi)
                   ? QStringLiteral("无线")
                   : QStringLiteral("有线");
        break;
    }
    ui->labelWifiStatus->setText(QStringLiteral("当前连接模式：%1").arg(mode));
}

void MainWindow::onStateChanged(AppConnectionState state)
{
    applyStateUI(state);
    updateConnectModeLabel(state);
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
    // 刷新：保留刷新前的选择（同一实现见 enumerateInterfaces；QPointer 守卫保证窗口
    // 销毁后回调安全失效）
    enumerateInterfaces(ui->comboInterface->currentData().toString(),
                        ui->comboInterface->currentText());
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
    // 复用 collectCurrentCfg：原先这里另手抓 7 个控件（其余字段用默认构造值），
    // 与 collectCurrentCfg 是两份必须同步维护的映射——新增配置项时极易漏改一处
    // （默认构造的 AppConfig 还会把 manualMask 默认值等悄悄带进来）
    AuthConfig config = ConfigManager::toAuthConfig(collectCurrentCfg());
    ConfigManager::resolveAuthConfig(config);
    return config;
}
