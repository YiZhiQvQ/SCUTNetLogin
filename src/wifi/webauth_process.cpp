#include "wifi/webauth_process.h"

#include "core/constants.h"
#include "wifi/wlan_media.h"

#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMutexLocker>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QRandomGenerator>
#include <QSslConfiguration>
#include <QSslSocket>
#include <QTimer>
#include <QUrl>
#include <QUrlQuery>
#include <functional>
#include <utility>

namespace {

// 服务端要求 wlan_user_ip 等参数按 base64 上传（loadConfig 实测）
QString b64(const QString& s)
{
    return QString::fromLatin1(s.toUtf8().toBase64());
}

// JSONP 回调名：任意随机名（drNNNN，浏览器 JSONP 惯例）——回调缺失或 =jsonpReturn
// 时服务器返回空体（实测）；v 为防缓存随机参数。多处接口共用，防参数漂移。
QString makeJsonpCallback()
{
    return QStringLiteral("dr") + QString::number(QRandomGenerator::global()->bounded(100000, 999999));
}

int makeV()
{
    return QRandomGenerator::global()->bounded(500, 10000);
}

// 登录响应判定枚举 → 可读名称（调试输出用）
QString verdictName(PortalParser::Verdict v)
{
    switch (v) {
    case PortalParser::Verdict::Success: return QStringLiteral("Success");
    case PortalParser::Verdict::Failure: return QStringLiteral("Failure");
    case PortalParser::Verdict::Unknown: return QStringLiteral("Unknown");
    }
    return QStringLiteral("?");
}

} // namespace

// ============================================================================
// 构造 / 析构 / 配置
// ============================================================================

WebAuthProcess::WebAuthProcess(QObject* parent)
    : QObject(parent)
{
    // 门户 host 用默认校域名兜底（发现门户时会被 fetchPortalPage 更新为实际值）。
    // 保证在"尚未发现门户"（首次直接判定在线）时 unbind/状态查询仍有合法地址。
    m_portalOrigin = QStringLiteral("https://") + QLatin1String(EPORTAL_DEFAULT_HOST);
    m_eportalPort  = EPORTAL_HTTPS_PORT;
}

WebAuthProcess::~WebAuthProcess()
{
    // 线程退出路径的兜底：abort 未完成请求，避免回调进入半死亡对象
    for (QNetworkReply* r : std::as_const(m_pendingReplies))
        r->abort();
}

void WebAuthProcess::setConfig(const AuthConfig& config)
{
    QMutexLocker lock(&m_mutex);
    m_config = config;
}

void WebAuthProcess::setDebugLogEnabled(bool on)
{
    m_debugLog.store(on);
}

void WebAuthProcess::debugLog(const QString& message)
{
    if (m_debugLog.load())
        deferLog(QStringLiteral("[调试] ") + message, 0);
}

// ============================================================================
// 信号缓冲（持锁 append，解锁 flush —— 与 EapProcess/UdpProcess 同惯例）
// ============================================================================

void WebAuthProcess::deferState(WifiAuthState s, const QString& msg, bool retryable)
{
    QMutexLocker lock(&m_mutex);
    m_pending.append({ PendingSignal::Kind::State, s, msg, retryable, 0 });
}

void WebAuthProcess::deferLog(const QString& msg, int level)
{
    QMutexLocker lock(&m_mutex);
    m_pending.append({ PendingSignal::Kind::Log, WifiAuthState::Idle, msg, true, level });
}

void WebAuthProcess::deferOnline()
{
    QMutexLocker lock(&m_mutex);
    m_pending.append({ PendingSignal::Kind::Online, WifiAuthState::Idle, QString(), true, 0 });
}

void WebAuthProcess::flushPending()
{
    // 注意：flush 必须在释放锁之后调用（DeferredSignalQueue 约定）
    m_pending.flush([this](const PendingSignal& sig) {
        switch (sig.kind) {
        case PendingSignal::Kind::State:
            emit stateChanged(sig.state, sig.message, sig.retryable);
            break;
        case PendingSignal::Kind::Log:
            emit logMessage(sig.message, sig.level);
            break;
        case PendingSignal::Kind::Online:
            emit online();
            break;
        }
    });
}

bool WebAuthProcess::staleGen(int gen) const
{
    QMutexLocker lock(&m_mutex);
    return gen != m_startGeneration || !m_running;
}

quint32 WebAuthProcess::wifiIpInt() const
{
    // 权威：startWifiAuth 已从 Wi-Fi 接口写入 m_config.localIp；v46ip 兜底（首轮
    // 探测时 m_vars 尚未解析，用 v46ip 会把 ip=0 传给查询）
    const QHostAddress ip(QByteArray(reinterpret_cast<const char*>(m_config.localIp), 4));
    quint32 v = ip.isNull() ? 0 : ip.toIPv4Address();
    if (v == 0) {
        const QHostAddress v46(m_vars.v46ip);
        v = v46.isNull() ? 0 : v46.toIPv4Address();
    }
    return v;
}

QString WebAuthProcess::wifiIpString() const
{
    const quint32 v = wifiIpInt();
    return (v == 0) ? QString() : QHostAddress(v).toString();
}

QString WebAuthProcess::wifiMacHex() const
{
    // 接口未取到时 m_config.localMac 为全零 → "000000000000"（协议约定空 MAC 值）
    return QString::fromLatin1(
        QByteArray(reinterpret_cast<const char*>(m_config.localMac), 6).toHex().toUpper());
}

QUrl WebAuthProcess::portalUrl(const QByteArray& path) const
{
    // <origin>:<port><path> —— 门户各 API（loadConfig/login/unbind…）共用骨架
    return QUrl(m_portalOrigin + QStringLiteral(":") + QString::number(m_eportalPort)
                + QLatin1String(path));
}

void WebAuthProcess::teardown()
{
    // stop()/stopSession()/checkNow() 的公共尾部：中止在途请求、停两个定时器
    for (QNetworkReply* r : std::as_const(m_pendingReplies))
        r->abort();
    m_pendingReplies.clear();
    if (m_pollTimer)    m_pollTimer->stop();
    if (m_confirmTimer) m_confirmTimer->stop();
}

// ============================================================================
// 启动 / 停止 / 立即重探
// ============================================================================

void WebAuthProcess::start()
{
    {
        QMutexLocker lock(&m_mutex);
        ++m_startGeneration;
        m_running = true;
        m_pending.clear();
        m_confirmAttempts = 0;
        m_onlineNotified = false;   // 新会话：需重新宣告在线（避免跨轮询沿用旧标记）
        m_probeIdx = 0;             // 校区域名候选探测：新会话清零
        m_probeSawUsable = false;
        m_domainConfirmed = false;
        m_triedAlternate = false;
        // 每次会话以默认域名为基址重来（跨校区重连不残留上轮发现的域名）；
        // 正确域名由 302 / online_list 探测 / 失败换域 重新确定
        m_portalOrigin = QStringLiteral("https://") + QLatin1String(EPORTAL_DEFAULT_HOST);
        m_eportalPort = EPORTAL_HTTPS_PORT;
    }

    // 首次启动时在工作线程内创建网络管理器与定时器（线程亲和）
    if (!m_nam) {
        m_nam = new QNetworkAccessManager(this);

        m_pollTimer = new QTimer(this);
        m_pollTimer->setInterval(WIFI_RECHECK_INTERVAL_MS);
        connect(m_pollTimer, &QTimer::timeout, this, [this]() {
            const int gen = m_startGeneration;
            if (staleGen(gen))
                return;
            m_pollTimer->stop();
            beginCycle();          // 在线期轮询：未认证会自动转入重新登录
        });

        m_confirmTimer = new QTimer(this);
        m_confirmTimer->setSingleShot(true);
        connect(m_confirmTimer, &QTimer::timeout, this, [this]() {
            const int gen = m_startGeneration;
            if (staleGen(gen))
                return;
            confirmOnline();
        });
    }

    debugLog(QStringLiteral("无线门户认证启动，正在探测在线状态..."));
    beginCycle();
}

void WebAuthProcess::stop()
{
    {
        QMutexLocker lock(&m_mutex);
        ++m_startGeneration;
        m_running = false;
    }
    teardown();

    deferLog(QStringLiteral("正在注销无线连接..."), 0);
    flushPending();

    // ① 执行"解绑下线"（mac/unbind）——即为"登出注销"的真实动作（浏览器
    //    成功页的"注销/解绑"即此接口，参数见 2026-09-03 F12 抓包）。它直接解绑
    //    本机会话，比 portal/logout 更彻底（后者会被门户 Auto-Login 抢回）。
    //    失败仅记日志；【不】立即复查 online_list——会话回收有延迟，早查会误报
    //    "仍在"。【不】做物理断开（即使系统/用户自行管理 Wi-Fi）。
    //    解绑走异步请求而非嵌套 QEventLoop：嵌套事件泵会让已排队的 start() 在解绑
    //    等待期间执行（旧周期的 Stopped 将覆盖新周期），异步 + 代数比较则自然丢弃。
    sendUnbindRequest();
}

void WebAuthProcess::sendUnbindRequest()
{
    if (!m_nam) {
        // 防御：正常时序下 stop 只在 start 之后被排队（m_nam 已建）。若无网络管理器
        // 就直接结束（停止态无需解绑），避免空转。
        deferState(WifiAuthState::Stopped, QStringLiteral("无线已断开"));
        flushPending();
        return;
    }

    const int gen = m_startGeneration;   // stop() 已递增
    QUrl unbindUrl = portalUrl(EPORTAL_UNBIND_PATH);
    const QHostAddress ip(QByteArray(reinterpret_cast<const char*>(m_config.localIp), 4));
    QUrlQuery q;
    q.addQueryItem(QStringLiteral("user_account"),   m_config.username);
    q.addQueryItem(QStringLiteral("wlan_user_mac"),  QStringLiteral("000000000000"));
    q.addQueryItem(QStringLiteral("wlan_user_ip"),   QString::number(ip.isNull() ? 0 : ip.toIPv4Address()));
    q.addQueryItem(QStringLiteral("jsVersion"),      QLatin1String(EPORTAL_JS_VERSION));
    q.addQueryItem(QStringLiteral("v"),              QString::number(makeV()));
    q.addQueryItem(QStringLiteral("lang"),           QStringLiteral("zh"));
    q.addQueryItem(QStringLiteral("callback"),       makeJsonpCallback());
    unbindUrl.setQuery(q);

    QNetworkRequest req = makeRequest(unbindUrl, true);
    req.setTransferTimeout(WIFI_LOGOUT_TIMEOUT_MS);
    QNetworkReply* rep = m_nam->get(req);
    m_pendingReplies.append(rep);
    connect(rep, &QNetworkReply::finished, this, [this, rep, gen]() {
        m_pendingReplies.removeAll(rep);
        const int status = rep->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const QString errStr = rep->errorString();
        rep->deleteLater();
        // 注意：不能用 staleGen()（含 !m_running，stop 已置 false，回调必被丢弃）。
        // 解绑期间若有排队 start() 插入新周期，代数已再递增——静默让位即可。
        if (gen != m_startGeneration)
            return;

        // 注销结果以解绑请求本身为准：HTTP 200 = 服务器受理解绑，随即 AC 收回会话、
        // 实测网络即刻下线。不能用 error()==NoError 判定成功——请求尚在飞行中时
        // 那也是 NoError；以 HTTP 状态码判定。
        if (status == 200) {
            debugLog(QStringLiteral("解绑/注销请求已发送（HTTP %1）").arg(status));
            deferLog(QStringLiteral("已注销（解绑下线，在线会话已回收）"), 0);
        } else {
            deferLog(errStr.isEmpty()
                         ? QStringLiteral("解绑/注销请求失败（HTTP %1）").arg(status)
                         : QStringLiteral("解绑/注销请求失败（HTTP %1，%2）").arg(status).arg(errStr), 1);
        }
        deferState(WifiAuthState::Stopped, QStringLiteral("无线已断开"));
        flushPending();
    });
}

void WebAuthProcess::stopSession()
{
    // 与 stop() 的差异：不发送 mac/unbind、不发射 Stopped。用途：
    // 退出程序且未勾选"退出时注销无线连接"（SessionManager 析构）——
    // 门户会话保持在线（这是用户的选择），只终止本进程的轮询/请求。
    {
        QMutexLocker lock(&m_mutex);
        ++m_startGeneration;
        m_running = false;
    }
    teardown();
}

void WebAuthProcess::checkNow()
{
    {
        QMutexLocker lock(&m_mutex);
        if (!m_running)
            return;
        ++m_startGeneration;   // 丢弃旧回调（含进行中的登录/确认）
        m_running = true;
        m_probeIdx = 0;        // 校区域名候选探测：重探测也清零
        m_probeSawUsable = false;
        m_domainConfirmed = false;
        m_triedAlternate = false;
    }
    teardown();
    beginCycle();
}

// ============================================================================
// 网络辅助
// ============================================================================

QNetworkRequest WebAuthProcess::makeRequest(const QUrl& url, bool ignoreTls) const
{
    QNetworkRequest req(url);
    req.setHeader(QNetworkRequest::UserAgentHeader, QString::fromUtf8(EPORTAL_UA));
    // 门户各接口（loadConfig/login/online_list/unbind…）校验 Referer（浏览器 F12 抓包
    // 均带 Referer: https://s2.scut.edu.cn/）；缺失会被拒，故统一附上门户 origin 作 Referer。
    if (!m_portalOrigin.isEmpty())
        req.setRawHeader("Referer", (m_portalOrigin + QLatin1Char('/')).toUtf8());
    req.setTransferTimeout(PORTAL_FETCH_TIMEOUT_MS);
    if (ignoreTls) {
        // 门户证书为自签（s2.scut.edu.cn），仅对这些请求忽略校验；
        // 不修改全局默认配置，不影响其它域名的证书校验
        QSslConfiguration ssl = QSslConfiguration::defaultConfiguration();
        ssl.setPeerVerifyMode(QSslSocket::VerifyNone);
        req.setSslConfiguration(ssl);
    }
    return req;
}

void WebAuthProcess::sendJsonpGet(const QUrl& url, bool ignoreTls, int timeoutMs,
                                  const std::function<void(const QByteArray&, const QString&)>& onDone)
{
    QNetworkRequest req = makeRequest(url, ignoreTls);
    req.setTransferTimeout(timeoutMs);
    // 手动跟随重定向：我们需要记录每一跳 Location，禁止 QNAM 自动跟随
    // （Qt 6.11 以 attribute 形式设置；枚举值真值见 QtNetwork/qnetworkrequest.h）
    req.setAttribute(QNetworkRequest::RedirectPolicyAttribute,
                     QVariant::fromValue(QNetworkRequest::ManualRedirectPolicy));
    QNetworkReply* reply = m_nam->get(req);
    m_pendingReplies.append(reply);
    const int gen = m_startGeneration;
    connect(reply, &QNetworkReply::finished, this, [this, reply, onDone, gen]() {
        m_pendingReplies.removeAll(reply);
        const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const QByteArray body = reply->readAll();
        // Location/Refresh 提取（302 重定向目标；ManualRedirectPolicy 下不自动跟随）
        QString location;
        const QVariant loc = reply->header(QNetworkRequest::LocationHeader);
        if (loc.isValid())
            location = loc.toString();
        if (location.isEmpty())
            location = reply->rawHeader("Location");
        const QNetworkReply::NetworkError err = reply->error();
        reply->deleteLater();
        if (staleGen(gen))
            return;                       // 会话已切换/停止：丢弃
        if (err == QNetworkReply::NoError || status != 0) {
            onDone(body, location);       // 业务/HTTP 层结果（含 3xx/4xx/5xx 体）
        } else {
            // 传输层失败 → 空体。此处【不】写入 UI 日志：探测网关（如已认证后网关
            // 80 拒绝连接）必然触发该错误，属于预期流程的前奏，反复打印会误导用户。
            // 真正的失败由调用方依据"门户是否确认"来陈述；这里仅留 qWarning 供诊断。
            qWarning().noquote() << "webauth request failed:" << reply->errorString()
                                 << static_cast<int>(err);
            onDone(QByteArray(), QString());
        }
    });
}

// ============================================================================
// 状态机：探测 → 门户 → 登录 → 上线确认
// ============================================================================

void WebAuthProcess::beginCycle()
{
    const int gen = m_startGeneration;
    if (staleGen(gen))
        return;

    deferState(WifiAuthState::Probing);
    flushPending();

    // ① 主探测：目标是 Wi-Fi 默认网关（属 Wi-Fi 子网，路由天然走 Wi-Fi，避免被
    //    USB 共享等其它上行带偏——connecttest 走默认路由会被其它上行误判为在线）。
    //    网关 302 → 未认证（进门户）；无 302 → 门户确认在线；连接异常 → 交上层重试。
    probeGateway();
}

void WebAuthProcess::probeGateway()
{
    const int gen = m_startGeneration;
    if (staleGen(gen))
        return;

    const QHostAddress gw = WlanMedia::wifiDefaultGateway();
    if (gw.isNull()) {
        deferLog(QStringLiteral("未取到 Wi-Fi 网关，无法探测认证状态（即将重试）"), 1);
        deferState(WifiAuthState::Failed,
                   QStringLiteral("未取到 Wi-Fi 网关信息，请确认已连接校园 Wi-Fi"), true);
        flushPending();
        return;
    }
    m_gatewayIp = gw.toString();
    debugLog(QStringLiteral("探测网关 %1").arg(m_gatewayIp));

    // ② 网关探测：未认证时网关 80 端口稳定返回 302 → 门户入口
    sendJsonpGet(QUrl(QStringLiteral("http://") + m_gatewayIp + QLatin1Char('/')), false, 6000,
                 [this, gen](const QByteArray& body, const QString& location) {
        if (staleGen(gen))
            return;
        // 302 Location 即门户入口（实测：https://s2.scut.edu.cn/a79.htm?wlanacip=…）
        if (!location.isEmpty()) {
            debugLog(QStringLiteral("网关 302 重定向 → %1").arg(location));
            const QUrl entry(location);
            if (entry.isValid()) {
                m_portalFetchRetries = 0;   // 新一轮门户发现：重置瞬态重试计数
                m_domainConfirmed = true;   // AC 直指的门户 = 当前 zone 的可靠域名，无需再探测/换域
                fetchPortalPage(entry);
                return;
            }
        }
        debugLog(QStringLiteral("网关无 302（body=%1 B，location 为空），用 online_list 确认在线状态").arg(body.size()));
        // 网关【无 302】（200/refused/空体）→ 不做任何"放行/在线"推断，一律交由
        // 门户 online_list 权威确认。仅当 Wi-Fi 明确未关联时才直接判"未连接"。
        if (!WlanMedia::currentWifiConnection().connected) {
            deferLog(QStringLiteral("未连接到的校园 Wi-Fi，请重新接入后重试"), 1);
            deferState(WifiAuthState::Failed,
                       QStringLiteral("未连接校园 Wi-Fi，请重新接入后重试"), true);
            flushPending();
            return;
        }
        queryOnlineStatus();
    });
}

void WebAuthProcess::queryOnlineStatus()
{
    const int gen = m_startGeneration;
    if (staleGen(gen))
        return;

    // 网关无 302（已认证放行 / 网关不指向门户）时，无法单靠 302 得知校区域名。
    // 逐个用候选域名（EPORTAL_HOST_CANDIDATES）查 online_list —— 哪个返回 result:1 且
    // 是本机会话，哪个就是当前 zone 的正确域名（对应"已在线门户显示已成功登录"现象）。
    m_probeIdx = 0;
    m_probeSawUsable = false;
    probeCandidate(gen);
}

void WebAuthProcess::probeCandidate(int gen)
{
    if (staleGen(gen))
        return;

    // 所有候选都探测完：
    //   · 至少一个可达（有可解析响应）但无本机会话 → 未登录，走页面登录（基址用默认）；
    //   · 全部无法解析（网络错）→ 无法确认，明确失败（不猜测）。
    if (m_probeIdx >= static_cast<int>(EPORTAL_HOST_CANDIDATES.size())) {
        if (m_probeSawUsable) {
            debugLog(QStringLiteral("候选校区域名均未发现本机会话，按未登录处理"));
            const QUrl entry(m_portalOrigin + QLatin1String(PORTAL_ENTRY_PATH) + m_gatewayIp);
            fetchPortalPage(entry);
        } else {
            deferLog(QStringLiteral("无法向门户确认在线状态（查询无响应）"), 1);
            deferState(WifiAuthState::Failed,
                       QStringLiteral("无法确认在线状态，请稍后重试"), true);
            flushPending();
        }
        return;
    }

    const QString origin = QStringLiteral("https://")
                           + QLatin1String(EPORTAL_HOST_CANDIDATES[m_probeIdx]);
    const QUrl url = PortalParser::buildOnlineListUrl(
        origin, m_eportalPort, wifiIpInt(), wifiMacHex(),
        QLatin1String(EPORTAL_JS_VERSION), makeJsonpCallback(), makeV());

    sendJsonpGet(url, true, PORTAL_FETCH_TIMEOUT_MS, [this, gen, origin](const QByteArray& body, const QString&) {
        if (staleGen(gen))
            return;
        const QJsonObject json = PortalParser::extractJsonp(body);
        if (!json.isEmpty())
            m_probeSawUsable = true;   // 至少一个候选可达（即便未登录）
        const QJsonArray list = json.value(QStringLiteral("list")).toArray();
        if (json.value(QStringLiteral("result")).toInt(-1) == 1 && !list.isEmpty()
            && PortalParser::isOwnSession(list.first().toObject(),
                                          wifiIpString(), m_config.username, wifiMacHex())) {
            // 该候选门户"认识"本机会话 → 当前 zone 的正确域名
            m_portalOrigin = origin;
            m_domainConfirmed = true;
            debugLog(QStringLiteral("online_list 命中校区域名 %1，认定当前 zone 在线").arg(origin));
            finishOnline();
            return;
        }
        // 本候选未命中 → 探测下一候选
        ++m_probeIdx;
        probeCandidate(gen);
    });
}

void WebAuthProcess::fetchPortalPage(const QUrl& url)
{
    const int gen = m_startGeneration;
    if (staleGen(gen))
        return;

    deferState(WifiAuthState::FetchingPortal);
    debugLog(QStringLiteral("发现认证门户: ") + url.toString());
    flushPending();

    // ④ 门户页：自签证书 → 仅此请求忽略校验。
    //    允许门户在 3 跳内继续重定向（各校区/AC 部署差异，禁止硬编码入口）
    m_portalOrigin = QStringLiteral("%1://%2").arg(url.scheme(), url.host());
    // eportal API 端口：HTTPS 页面用 802（实测 enableHttps=1）
    m_eportalPort = (url.scheme().compare(QStringLiteral("https"), Qt::CaseInsensitive) == 0)
                        ? EPORTAL_HTTPS_PORT : EPORTAL_HTTP_PORT;

    fetchPortalRedirect(url, 0);
}

void WebAuthProcess::fetchPortalRedirect(const QUrl& u, int depth)
{
    const int gen = m_startGeneration;
    if (staleGen(gen))
        return;

    sendJsonpGet(u, true, PORTAL_FETCH_TIMEOUT_MS,
                 [this, gen, depth, u](const QByteArray& body, const QString& location) {
        if (staleGen(gen))
            return;
        if (!location.isEmpty() && depth < PORTAL_MAX_REDIRECTS) {
            const QUrl next(location);
            if (next.isValid() && next != u) {
                // 成员函数重入：302 异步延续不捕获自身 std::function（递归
                // std::function 按引用自捕获，栈帧销毁后回调触发 UB）
                fetchPortalRedirect(next, depth + 1);
                return;
            }
        }
        // 区分"网络抓取失败"（空体 = 认证域不可达/多网卡路由或 DNS 抖动）与
        // "解析失败"（有页面但没有关键变量）。多网卡并行时系统解析器可能
        // 瞬态超时（实测），对空体做 2 次 1.5s 间隔重试再判失败。
        if (body.isEmpty()) {
            if (m_portalFetchRetries < 2) {
                ++m_portalFetchRetries;
                debugLog(QStringLiteral("门户页抓取失败，%1 秒后重试（%2/2）...")
                             .arg(QString::number(WIFI_RETRY_DELAY_MS / 1000.0, 'f', 1))
                             .arg(m_portalFetchRetries));
                // 重新入 fetchPortalPage：重试时重新归一化 host/port（与旧行为一致，
                // 同时刷新 origin——门户域在竞态重定向中已变化的情况）
                QTimer::singleShot(WIFI_RETRY_DELAY_MS, this, [this, gen, u]() {
                    if (staleGen(gen))
                        return;
                    fetchPortalPage(u);
                });
                return;
            }
            m_portalFetchRetries = 0;
            deferLog(QStringLiteral("门户页抓取失败（认证域不可达或被拦截），请确认 Wi-Fi 已联网"), 1);
            deferState(WifiAuthState::Failed,
                       QStringLiteral("未能连接认证门户，请确认 Wi-Fi 已联网后重试"), true);
            flushPending();
            return;
        }
        m_portalFetchRetries = 0;
        // wlanacip 从 302 入口 URL 的 query 提取（parse 内部处理）
        m_vars = PortalParser::parse(body, u);
        if (!m_vars.isValid()) {
            deferLog(QStringLiteral("门户页解析失败（可能页面结构变化）"), 1);
            deferState(WifiAuthState::Failed, QStringLiteral("门户页面解析失败，请稍后重试"), true);
            flushPending();
            return;
        }
        debugLog(QStringLiteral("门户解析 OK: 入口=%1 v4serip=%2 v46ip=%3 wlanacip=%4 端口=%5 登录字段=%6/%7 成功页=%8")
                     .arg(u.toString(), m_vars.v4serip, m_vars.v46ip, m_vars.wlanacip,
                          QString::number(m_vars.authLoginPort),
                          m_vars.authUserField, m_vars.authPassField, m_vars.authSuccess));
        fetchLoadConfig();
    });
}

void WebAuthProcess::fetchLoadConfig()
{
    const int gen = m_startGeneration;
    if (staleGen(gen))
        return;

    // ⑤ 动态配置：page_index / login_method / en_md5（各校区可能不同，禁止硬编码）
    QUrl url = portalUrl(EPORTAL_LOADCONFIG_PATH);
    QUrlQuery q;
    q.addQueryItem(QStringLiteral("program_index"),    QLatin1String(EPORTAL_PORTAL_NAME));
    q.addQueryItem(QStringLiteral("wlan_vlan_id"),     m_vars.vlanid.isEmpty() ? QStringLiteral("0") : m_vars.vlanid);
    q.addQueryItem(QStringLiteral("wlan_user_ip"),     b64(m_vars.v46ip));
    q.addQueryItem(QStringLiteral("wlan_user_ipv6"),   b64(QString()));
    q.addQueryItem(QStringLiteral("wlan_user_ssid"),   m_config.wifiSsid);
    q.addQueryItem(QStringLiteral("wlan_ac_ip"),       b64(m_vars.wlanacip));
    q.addQueryItem(QStringLiteral("wlan_ap_mac"),      QStringLiteral("000000000000"));
    q.addQueryItem(QStringLiteral("gw_id"),            QStringLiteral("000000000000"));
    q.addQueryItem(QStringLiteral("callback"),         makeJsonpCallback());
    url.setQuery(q);
    debugLog(QStringLiteral("loadConfig 请求: %1").arg(url.toString()));

    sendJsonpGet(url, true, PORTAL_FETCH_TIMEOUT_MS, [this, gen](const QByteArray& body, const QString&) {
        if (staleGen(gen))
            return;
        // 空体（网络抖/瞬断）→ 重试 2 次再采用默认值，抗多网卡 DNS/瞬时抖动
        if (body.isEmpty() && m_loadConfigRetries < 2) {
            ++m_loadConfigRetries;
            debugLog(QStringLiteral("门户配置获取失败，%1 秒后重试（%2/2）...")
                         .arg(QString::number(WIFI_RETRY_DELAY_MS / 1000.0, 'f', 1))
                         .arg(m_loadConfigRetries));
            QTimer::singleShot(WIFI_RETRY_DELAY_MS, this, [this, gen]() {
                if (!staleGen(gen))
                    fetchLoadConfig();
            });
            return;
        }
        m_loadConfigRetries = 0;
        const QJsonObject json = PortalParser::extractJsonp(body);
        const QJsonObject data = json.value(QStringLiteral("data")).toObject();
        if (json.value(QStringLiteral("code")).toInt() == 1 && !data.isEmpty()) {
            m_loginMethod = data.value(QStringLiteral("login_method")).toString();
            m_enMd5       = data.value(QStringLiteral("en_md5")).toInt() == 1;
            debugLog(QStringLiteral("门户配置: login_method=%1 en_md5=%2")
                         .arg(m_loginMethod, QString::number(m_enMd5)));
        } else {
            // 配置接口异常（重试后仍不可用）：不强行造"默认登录方式"（实测会引入
            // login_method 不一致）；仅保持 login_method 为空→登录默认用 "1"，
            // en_md5 保持默认 false（明文），继续尝试登录，交由后续结果判定。
            deferLog(QStringLiteral("门户配置获取失败（重试后），按默认参数继续登录"), 1);
        }
        sendLogin();
    });
}

void WebAuthProcess::sendLogin()
{
    const int gen = m_startGeneration;
    if (staleGen(gen))
        return;

    deferState(WifiAuthState::LoggingIn);
    debugLog(QStringLiteral("正在向门户提交账号..."));
    flushPending();

    // 登录前先查在线：服务器对"已在线账号"的再登录会返回空体（实测），且多端
    // 账号策略各异。若 online_list 已显示本机在线会话，则直接判定上线、不再重复登录。
    {
        const QUrl chk = PortalParser::buildOnlineListUrl(
            m_portalOrigin, m_eportalPort, wifiIpInt(), wifiMacHex(),
            QLatin1String(EPORTAL_JS_VERSION), makeJsonpCallback(), makeV());
        // 预检用短超时：失败/超时视为"未在线"，直接走登录，不阻塞主流程
        sendJsonpGet(chk, true, WIFI_PRELOGIN_TIMEOUT_MS, [this, gen](const QByteArray& body, const QString&) {
            if (staleGen(gen))
                return;
            const QJsonObject json = PortalParser::extractJsonp(body);
            const QJsonArray list = json.value(QStringLiteral("list")).toArray();
            if (json.value(QStringLiteral("result")).toInt(-1) == 1 && !list.isEmpty()
                && PortalParser::isOwnSession(list.first().toObject(),
                                              wifiIpString(), m_config.username, wifiMacHex())) {
                // 账号已在线（本机会话命中）→ 无需重复登录
                debugLog(QStringLiteral("检测到已处于在线状态，无需重复登录"));
                finishOnline();
                return;
            }
            // 未在线（或查询失败/超时/仅他机会话）→ 继续正常登录流程
            sendLoginBody();
        });
        return;
    }
}

void WebAuthProcess::sendLoginBody()
{
    const int gen = m_startGeneration;
    if (staleGen(gen))
        return;

    // ⑥ 登录：GET + JSONP 式 query（实测服务器仅回 JSONP）。仅走 portal 入口
    //   （/eportal/portal/login，:802）——精确复刻浏览器 F12 抓包（2026-09-03）：
    //   login_method=1 + user_account/user_password + wlan_user_mac=000000000000 +
    //   wlan_ac_ip 等。注意：本部署 wlan_user_mac 必须传全零（与浏览器一致；
    //   传真实 MAC 会被拒）。另一端点 /drcom/login 不稳定（返回空体），不使用（见 docs）。
    QUrl url = portalUrl(EPORTAL_LOGIN_PATH_PORTAL);

    QUrlQuery q;
    q.addQueryItem(QStringLiteral("login_method"), m_loginMethod.isEmpty()
                                                       ? QStringLiteral("1") : m_loginMethod);
    q.addQueryItem(QStringLiteral("user_account"),  m_config.username);
    q.addQueryItem(QStringLiteral("user_password"), m_config.password);
    q.addQueryItem(QStringLiteral("wlan_user_ip"),   m_vars.v46ip);
    q.addQueryItem(QStringLiteral("wlan_user_ipv6"), QString());
    q.addQueryItem(QStringLiteral("wlan_user_mac"),  QStringLiteral("000000000000"));
    q.addQueryItem(QStringLiteral("wlan_ac_ip"),     m_vars.wlanacip);
    q.addQueryItem(QStringLiteral("wlan_ac_name"),   QString());
    q.addQueryItem(QStringLiteral("jsVersion"),     QLatin1String(EPORTAL_JS_VERSION));
    q.addQueryItem(QStringLiteral("terminal_type"), QStringLiteral("1"));
    q.addQueryItem(QStringLiteral("lang"),          QStringLiteral("zh-cn"));
    // 实测（2026-09-03）：登录接口若 callback 缺失或 =jsonpReturn 会返回【空体】；
    // 任意随机名（drNNNN，浏览器 JSONP 惯例）会回显 "drNNNN({...})"。
    q.addQueryItem(QStringLiteral("callback"),       makeJsonpCallback());
    q.addQueryItem(QStringLiteral("v"),              QString::number(makeV()));
    url.setQuery(q);

    // 调试：登录请求参数（【绝不】输出 user_password）
    debugLog(QStringLiteral("登录请求: 端口=%1 login_method=%2 账号=%3 wlan_user_ip=%4 wlan_ac_ip=%5")
                 .arg(QString::number(m_eportalPort),
                      m_loginMethod.isEmpty() ? QStringLiteral("1") : m_loginMethod,
                      m_config.username, m_vars.v46ip, m_vars.wlanacip));

    sendJsonpGet(url, /*ignoreTls=*/true, PORTAL_LOGIN_TIMEOUT_MS,
                 [this, gen](const QByteArray& body, const QString&) {
        if (staleGen(gen))
            return;
        const PortalParser::VerdictResult r = PortalParser::classify(body);
        debugLog(QStringLiteral("登录响应判定: verdict=%1 retryable=%2 msg=%3")
                     .arg(verdictName(r.verdict), QString::number(r.retryable), r.message));
        switch (r.verdict) {
        case PortalParser::Verdict::Success:
            m_confirmAttempts = 0;
            confirmOnline();
            return;
        case PortalParser::Verdict::Failure:
            // 默认(未证实)域名登录失败且可重试（如错区"Radius超时"等暂时性现象）→
            // 换另一候选校区域名重来一次，以免"校区不同登不上"被误报为登录失败。
            // 已证实域名(302/探测命中)或硬性错误(凭证/账户)不换，直接按失败处理。
            if (r.retryable && !m_domainConfirmed && !m_triedAlternate) {
                tryAlternateDomain();
                return;
            }
            // 失败仅由 deferState 携带 message 输出一次（SessionManager 会显示该文案），
            // 不再额外 deferLog 同一句，避免"门户认证失败: X"与"X"重复刷屏。
            deferState(WifiAuthState::Failed,
                       r.message.isEmpty() ? QStringLiteral("无线认证失败") : r.message, r.retryable);
            flushPending();
            return;
        case PortalParser::Verdict::Unknown:
            break;
        }
        deferLog(QStringLiteral("登录响应无法解析，稍后重试"), 1);
        deferState(WifiAuthState::Failed, QStringLiteral("门户登录响应异常，请稍后重试"), true);
        flushPending();
    });
}

void WebAuthProcess::tryAlternateDomain()
{
    const int gen = m_startGeneration;
    if (staleGen(gen))
        return;

    // 换当前 host 之外的另一候选校区域名（共两个，取不同者）。m_triedAlternate 保证至多重来一次。
    const QString currentHost = QUrl(m_portalOrigin).host();
    QString altHost;
    for (const char* c : EPORTAL_HOST_CANDIDATES) {
        if (QLatin1String(c) != currentHost) {
            altHost = QString::fromLatin1(c);
            break;
        }
    }
    if (altHost.isEmpty()) {
        // 没有另一候选（或已换过）→ 按失败处理
        deferState(WifiAuthState::Failed, QStringLiteral("认证失败"), true);
        flushPending();
        return;
    }

    m_triedAlternate = true;
    m_portalOrigin = QStringLiteral("https://") + altHost;
    debugLog(QStringLiteral("域名登录失败，切换候选校区域名 %1 重试").arg(m_portalOrigin));
    // 重新抓取该域名的门户页 → parse → loadConfig → login。此处【不】置 m_domainConfirmed：
    // 若该域也失败且可重试，因 m_triedAlternate 已置位而不再换，回归正常失败处理。
    const QUrl entry(m_portalOrigin + QLatin1String(PORTAL_ENTRY_PATH) + m_gatewayIp);
    fetchPortalPage(entry);
}

void WebAuthProcess::confirmOnline()
{
    const int gen = m_startGeneration;
    if (staleGen(gen))
        return;

    // ⑦ 上线确认：登录 result:1 ≠ 立即放行（实测授权延迟可达数十秒），
    //    官方成功页正是轮询 online_list 才跳转成功页。在线列表接口：
    //    参数 user_account 用空串（按当前 IP/MAC 查询），IP 为整数型。
    const QUrl url = PortalParser::buildOnlineListUrl(
        m_portalOrigin, m_eportalPort, wifiIpInt(), wifiMacHex(),
        QLatin1String(EPORTAL_JS_VERSION), makeJsonpCallback(), makeV());

    sendJsonpGet(url, true, PORTAL_FETCH_TIMEOUT_MS, [this, gen](const QByteArray& body, const QString&) {
        if (staleGen(gen))
            return;
        const QJsonObject json = PortalParser::extractJsonp(body);
        const int result = json.value(QStringLiteral("result")).toInt(-1);
        const QJsonArray list = json.value(QStringLiteral("list")).toArray();
        debugLog(QStringLiteral("online_list 查询: result=%1 会话数=%2 尝试=%3")
                     .arg(result).arg(list.size()).arg(m_confirmAttempts));
        if ((result == 1) && !list.isEmpty()) {
            const QJsonObject session = list.first().toObject();
            // 归属校验：列表非空但非本机会话（多端共享网关/同网段）→ 视为未放行，继续轮询
            if (PortalParser::isOwnSession(session,
                                           wifiIpString(), m_config.username, wifiMacHex())) {
                debugLog(QStringLiteral("门户确认上线（会话 %1，账号 %2）")
                             .arg(session.value(QStringLiteral("online_session")).toInt())
                             .arg(session.value(QStringLiteral("user_account")).toString()));
                finishOnline();
                return;
            }
            debugLog(QStringLiteral("在线列表仅含其它设备会话，继续等待..."));
        }
        ++m_confirmAttempts;
        if (m_confirmAttempts < WIFI_CONFIRM_TIMEOUT_MS / WIFI_CONFIRM_POLL_MS) {
            debugLog(QStringLiteral("等待上线确认（%1/%2）...")
                         .arg(m_confirmAttempts)
                         .arg(WIFI_CONFIRM_TIMEOUT_MS / WIFI_CONFIRM_POLL_MS));
            m_confirmTimer->start(WIFI_CONFIRM_POLL_MS);
            return;
        }
        // 确认轮询超时：登录已受理但未见在线记录 —— 不武断判在线，交给上层
        // （Failed(retryable) → 调度重试；避免"假在线"误导断开/二段逻辑）
        deferLog(QStringLiteral("上线确认超时（登录已受理但未见会话记录）"), 1);
        deferState(WifiAuthState::Failed,
                   QStringLiteral("登录已受理但未确认上线，将自动重试"), true);
        flushPending();
    });
}

void WebAuthProcess::finishOnline()
{
    const int gen = m_startGeneration;
    if (staleGen(gen))
        return;

    // 仅"首次上线"打印确认日志并发射 Online 信号；此后 60 秒在线轮询命中
    // 在线时静默续跑（只重启轮询），避免每轮重复打印"确认在线/已认证"刷屏
    if (!m_onlineNotified) {
        m_onlineNotified = true;
        // 上线即一条清晰的成功文案（与有线 onEapSuccess 的"认证成功，可以上网了！"一致）；
        // 具体会话/账号细节走调试日志（debugLog），不污染用户视线。
        deferState(WifiAuthState::Online, QStringLiteral("认证成功，可以上网了！"));
        deferOnline();
        flushPending();
    }
    if (m_pollTimer) {
        m_pollTimer->stop();
        m_pollTimer->start();
    }
}
