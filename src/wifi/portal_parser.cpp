#include "wifi/portal_parser.h"

#include "core/constants.h"

#include <QHash>
#include <QRegularExpression>
#include <QUrlQuery>
#include <windows.h>

#if !defined(CP_GB18030)
#define CP_GB18030 54936   // GB18030 代码页（当前 Windows SDK 的 winnls.h 未定义，本地兜底）
#endif

namespace PortalParser {

namespace {

// 整页一次扫描，提取形如 name='value' / name="value" / name=value 的 JS 变量。
// （页面为 GBK，但变量值全为 ASCII；按字节匹配，不依赖编码。
//  值可与双/单引号包裹、可无引号；值域 [^'";,] 后跟可选闭合引号 + 分号/逗号/空白。）
//
// 为什么整页一次而不是"每个变量单独扫一遍"：门户页可达上百 KB，逐个变量提取要
// 重复做 20+ 次整页 QString 转换 + 20+ 次正则编译与全文扫描（每轮认证各一次）。
// 语义与逐个提取一致：同名取【首次出现】的那一次赋值。
QHash<QByteArray, QString> extractQuotedVars(const QByteArray& page)
{
    static const QRegularExpression re(
        QStringLiteral(R"(\b([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*'?"?([^'";,]*)(?:'?"?)?[;,\s])"));
    QHash<QByteArray, QString> vars;
    auto it = re.globalMatch(QString::fromLatin1(page, page.size()));
    while (it.hasNext()) {
        const QRegularExpressionMatch m = it.next();
        const QByteArray key = m.captured(1).toLatin1();
        if (!vars.contains(key))
            vars.insert(key, m.captured(2).trimmed());
    }
    return vars;
}

// 从 JSONP 原始字节中抽取 msga 值的原始字节（GBK 字节直接内嵌于 JSON 字符串——
// 严格 UTF-8 解析会将其打为 U+FFFD，故按字节抽取先于 JSON 解析；值内可按 \uXXXX
// 或 \" 转义，模式兼容）
QByteArray extractRawMsgaValue(const QByteArray& body)
{
    static const QRegularExpression re(QStringLiteral("\"msga\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\""));
    const QRegularExpressionMatch m = re.match(QString::fromLatin1(body));
    return m.hasMatch() ? m.captured(1).toLatin1() : QByteArray();
}

// 按 Windows 代码页解码。CP_GB18030 兼容 GBK/GB2312（含 4 字节扩展）且与系统区域
// 设置无关；CP_ACP 则显式依赖本机区域设置（仅在 GB18030 解码失败时兜底）。
QString decodeWindowsCodePage(UINT codePage, const QByteArray& raw)
{
    if (raw.isEmpty())
        return QString();
    const int len = MultiByteToWideChar(codePage, 0, raw.constData(), raw.size(), nullptr, 0);
    if (len <= 0)
        return QString();
    QString out;
    out.resize(len);
    if (MultiByteToWideChar(codePage, 0, raw.constData(), raw.size(),
                            reinterpret_cast<wchar_t*>(out.data()), len) <= 0)
        return QString();
    return out;
}

// 解码错误文案：UTF-8（现代部署）→ GBK/GB2312（实测 msga 直接内嵌 GBK 字节，
// 用 CP_GB18030 超集）→ 系统 ANSI → Latin-1
QString decodeErrorText(const QByteArray& raw)
{
    if (raw.isEmpty())
        return QString();
    const QString utf8 = QString::fromUtf8(raw);
    if (!utf8.contains(QChar::ReplacementCharacter))
        return utf8;
    const QString gb = decodeWindowsCodePage(CP_GB18030, raw);
    if (!gb.isEmpty())
        return gb;
    const QString sys = decodeWindowsCodePage(CP_ACP, raw);
    if (!sys.isEmpty())
        return sys;
    return QString::fromLatin1(raw);
}

} // namespace

PortalVars parse(const QByteArray& page, const QUrl& pageUrl)
{
    const QHash<QByteArray, QString> vars = extractQuotedVars(page);
    auto var = [&vars](const char* name) { return vars.value(QByteArray(name)); };

    PortalVars v;
    v.v4serip     = var("v4serip");
    v.mip         = var("mip");
    v.ipm         = var("ipm");
    v.ss1         = var("ss1");
    v.ss2         = var("ss2");
    v.ss3         = var("ss3");
    v.ss4         = var("ss4");
    v.ss5         = var("ss5");
    v.ss6         = var("ss6");
    v.v46ip       = var("v46ip");
    v.vlanid      = var("vlanid");
    v.gno         = var("Gno");
    v.v4serip     = v.v4serip.isEmpty() ? v.ss6 : v.v4serip;   // 兼容 v4serip 缺失的变体
    v.authLoginPath = var("authloginpath");
    v.authUserField = var("authuserfield");
    v.authPassField = var("authpassfield");
    v.authSuccess   = var("authsuccess");
    v.authFail      = var("authfail");
    v.charset       = var("charset");

    bool ok = false;
    const int port = var("authloginport").toInt(&ok);
    if (ok) v.authLoginPort = port;
    const qint64 t = var("timet").toLongLong(&ok);
    if (ok) v.timet = t;

    // wlanacip 优先从 302 终点 URL 的 query 提取（a79.htm?wlanacip=...）
    v.wlanacip = QUrlQuery(pageUrl).queryItemValue(QStringLiteral("wlanacip"),
                                                   QUrl::FullyDecoded);
    return v;
}

QString computeMip(const uint8_t ip[4])
{
    QString s;
    for (int i = 0; i < 4; ++i)
        s += QStringLiteral("%1").arg(ip[i], 3, 10, QLatin1Char('0'));
    return s;   // 10.197.183.251 → "010197183251"
}

QString computeIpm(const uint8_t ip[4])
{
    QString s;
    for (int i = 0; i < 4; ++i)
        s += QStringLiteral("%1").arg(ip[i], 2, 16, QLatin1Char('0')).toLower();
    return s;   // 192.168.53.229 → "c0a835e5"
}

QString computeSs3(const uint8_t ip[4])
{
    return computeIpm(ip);
}

QJsonObject extractJsonp(const QByteArray& body)
{
    const int start = body.indexOf('{');
    const int end   = body.lastIndexOf('}');
    if (start < 0 || end <= start)
        return {};
    const QByteArray json = body.mid(start, end - start + 1);

    QJsonDocument doc = QJsonDocument::fromJson(json);
    if (doc.isObject())
        return doc.object();

    // 兼容：服务器会把 GBK 字节直接装进 JSON 字符串（非法 UTF-8，整个文档被
    // 严格解析器拒绝）。将非 ASCII 字节替换为 '?' 后按宽松路径重解析——
    // 结构（result/hidn 等 ASCII 字段）得以完整保留，仅错误文案含占位符。
    QByteArray sanitized = json;
    for (char& c : sanitized) {
        if (static_cast<uchar>(c) >= 0x80)
            c = '?';
    }
    doc = QJsonDocument::fromJson(sanitized);
    return doc.isObject() ? doc.object() : QJsonObject();
}

VerdictResult classify(const QByteArray& jsonpBody)
{
    VerdictResult r;
    const QJsonObject json = extractJsonp(jsonpBody);
    if (json.isEmpty()) {
        r.verdict = Verdict::Unknown;    // 非 JSON（301/302、HTML 错误页等）
        r.message = QString::fromLatin1(jsonpBody.left(120));
        return r;
    }

    const QJsonValue res = json.value(QStringLiteral("result"));
    const bool success = res.toInt(-1) == 1
        || res.toString().compare(QStringLiteral("ok"), Qt::CaseInsensitive) == 0;
    if (success) {
        r.verdict  = Verdict::Success;
        return r;
    }

    // 失败：取服务器错误文案。msga 按原始字节抽取并 GB18030 解码——extractJsonp
    // 把非 ASCII 替换成了 '?'，直接用解析对象命中不了中文关键词，故按原始 GBK
    // 字节抽取。解码失败时回退解析对象中的（可能已打点的）值与 ASCII 错误宏
    // （"userid error2"）。诊断信息附带 hidn 错误码。
    const QJsonObject obj = json;
    QString msg;
    const QByteArray rawMsga = extractRawMsgaValue(jsonpBody);
    if (!rawMsga.isEmpty())
        msg = decodeErrorText(rawMsga);
    if (msg.isEmpty())
        msg = obj.value(QStringLiteral("msga")).toString();
    if (msg.isEmpty() && obj.value(QStringLiteral("msg")).isString())
        msg = obj.value(QStringLiteral("msg")).toString();

    r.verdict  = Verdict::Failure;
    r.message  = msg;
    if (!obj.value(QStringLiteral("hidn")).isUndefined())
        r.message += QStringLiteral(" (code=%1)").arg(obj.value(QStringLiteral("hidn")).toInt(-1));
    r.retryable = !(msg.contains(QStringLiteral("密码"))
                    || msg.contains(QStringLiteral("账号"))
                    || msg.contains(QStringLiteral("停用"))
                    || msg.contains(QStringLiteral("欠费"))
                    || msg.contains(QStringLiteral("不可用"))
                    // ASCII 错误宏（实测部署："userid error2" = 账号/会话问题）
                    || msg.contains(QStringLiteral("userid"), Qt::CaseInsensitive));
    // 时段/网络类错误（"当前时段禁止使用"等）→ 可重试（夜间窗口由上层调度）
    return r;
}

QUrl buildOnlineListUrl(const QString& portalOrigin, int eportalPort,
                        quint32 ipInt, const QString& macHex,
                        const QString& jsVersion,
                        const QString& callback, int vRand)
{
    QUrl url(portalOrigin + QStringLiteral(":") + QString::number(eportalPort)
             + QLatin1String(EPORTAL_ONLINE_LIST_PATH));
    QUrlQuery q;
    q.addQueryItem(QStringLiteral("user_account"),   QString());
    q.addQueryItem(QStringLiteral("user_password"),  QLatin1String(EPORTAL_PORTAL_LOGOUT_PASSWORD));
    q.addQueryItem(QStringLiteral("wlan_user_mac"),  macHex);
    q.addQueryItem(QStringLiteral("wlan_user_ip"),   QString::number(ipInt));
    q.addQueryItem(QStringLiteral("curr_user_ip"),   QString::number(ipInt));
    q.addQueryItem(QStringLiteral("jsVersion"),      jsVersion);
    q.addQueryItem(QStringLiteral("callback"),       callback);
    q.addQueryItem(QStringLiteral("v"),              QString::number(vRand));
    q.addQueryItem(QStringLiteral("lang"),           QStringLiteral("zh"));
    url.setQuery(q);
    return url;
}

bool isOwnSession(const QJsonObject& session, const QString& localIp,
                  const QString& username, const QString& localMacHex)
{
    // ① 服务器归属标记（实抓为字符串 "1"）。JSON 里同一语义可能被序列化成数字或布尔，
    //    而 toString() 不会转换数字——三种形态都接受，避免因后端改类型而静默漏判。
    const QJsonValue owner = session.value(QStringLiteral("is_owner_ip"));
    if (owner.toString() == QLatin1String("1") || owner.toInt(-1) == 1 || owner.toBool(false))
        return true;
    // ② online_ip 命中本机无线 IP（点分十进制字符串比较）
    const QString onlineIp = session.value(QStringLiteral("online_ip")).toString();
    if (!onlineIp.isEmpty() && !localIp.isEmpty() && onlineIp == localIp)
        return true;
    // ③ user_account 命中登录账号（后端存 "<账号>@wifi"，登录可无后缀）
    const QString account = session.value(QStringLiteral("user_account")).toString();
    if (!account.isEmpty() && !username.isEmpty()) {
        const QString suffixed = username + QLatin1String(EPORTAL_ACCOUNT_SUFFIX);
        if (account == username || account == suffixed)
            return true;
    }
    // ④ online_mac 命中本机接口 MAC（localMacHex 全零=接口未取到，不参与比较）
    const QString mac = session.value(QStringLiteral("online_mac")).toString();
    if (!mac.isEmpty() && localMacHex != QStringLiteral("000000000000"))
        return mac.compare(localMacHex, Qt::CaseInsensitive) == 0;
    return false;
}

QJsonObject findOwnSession(const QJsonArray& list, const QString& localIp,
                           const QString& username, const QString& localMacHex)
{
    for (const QJsonValue& v : list) {
        const QJsonObject session = v.toObject();
        if (isOwnSession(session, localIp, username, localMacHex))
            return session;
    }
    return QJsonObject();   // 空对象 = 列表中没有本机会话
}

} // namespace PortalParser
