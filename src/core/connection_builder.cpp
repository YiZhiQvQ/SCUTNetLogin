#include "core/connection_builder.h"
#include <QRegularExpression>

namespace ConnectionBuilder {

namespace {

// IPv4 格式严格校验：4 段十进制、各段 0-255（四段齐全，拒绝 "192.168.1" 这类
// 被部分解析器接受的不完整形式）。纯校验层：合法 IP 才会交给 netsh。
bool isValidIPv4(const QString& s)
{
    static const QRegularExpression re(QStringLiteral(R"(^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$)"));
    const QRegularExpressionMatch m = re.match(s);
    if (!m.hasMatch())
        return false;
    for (int i = 1; i <= 4; ++i) {
        const int octet = m.captured(i).toInt();
        if (octet < 0 || octet > 255)
            return false;
    }
    return true;
}

} // namespace

Result build(const Input& in)
{
    Result r;

    // 1. 回环网卡拒绝（认证前先拦截）
    if (in.displayText.contains(QStringLiteral("Loopback"), Qt::CaseInsensitive)
        || in.pcapName.contains(QStringLiteral("Loopback"), Qt::CaseInsensitive)) {
        r.error = QStringLiteral("错误：当前选中的是虚拟回环网卡，无法用于认证！");
        return r;
    }

    // 2. 空凭证校验（避免发出空用户名/空密码的认证包，服务器端必然拒绝）
    if (in.username.trimmed().isEmpty() || in.password.isEmpty()) {
        r.error = QStringLiteral("用户名或密码不能为空，请检查认证配置");
        return r;
    }

    // 3. 静态 IP 配置分支
    if (in.autoSetNetwork) {
        if (in.mac.isEmpty()) {
            r.error = QStringLiteral("无法获取网卡MAC地址，静态IP配置失败。请手动填写MAC地址或取消静态IP配置。");
            return r;
        }
        if (in.adapterName.isEmpty()) {
            r.error = QStringLiteral("未找到MAC地址 %1 对应的网络适配器，无法配置静态IP。").arg(in.mac);
            return r;
        }

        QStringList missing;
        if (in.ip.isEmpty())      missing << QStringLiteral("IPv4地址");
        if (in.mask.isEmpty())    missing << QStringLiteral("子网掩码");
        if (in.gateway.isEmpty()) missing << QStringLiteral("默认网关");
        if (in.dns1.isEmpty())    missing << QStringLiteral("主DNS");
        if (!missing.isEmpty()) {
            r.error = QStringLiteral("静态IP配置不完整，缺少: %1。请完善配置后重试。")
                          .arg(missing.join(QStringLiteral(", ")));
            return r;
        }

        // 4. IPv4 格式校验（netsh 对非法地址的报错晦涩难懂，前置拦截）
        QStringList invalid;
        if (!isValidIPv4(in.ip))      invalid << QStringLiteral("IPv4地址");
        if (!isValidIPv4(in.mask))    invalid << QStringLiteral("子网掩码");
        if (!isValidIPv4(in.gateway)) invalid << QStringLiteral("默认网关");
        if (!isValidIPv4(in.dns1))    invalid << QStringLiteral("主DNS");
        if (!in.dns2.isEmpty() && !isValidIPv4(in.dns2))
            invalid << QStringLiteral("备用DNS");
        if (!invalid.isEmpty()) {
            r.error = QStringLiteral("静态IP参数格式无效: %1。请输入合法的 IPv4 地址（如 192.168.1.100）。")
                          .arg(invalid.join(QStringLiteral(", ")));
            return r;
        }

        r.needStaticIp = true;
        r.ipConfig.adapterName = in.adapterName;
        r.ipConfig.ip      = in.ip;
        r.ipConfig.mask    = in.mask;
        r.ipConfig.gateway = in.gateway;
        r.ipConfig.dns1    = in.dns1;
        r.ipConfig.dns2    = in.dns2;
        r.ipConfig.mac     = in.mac;
    }

    r.ok = true;
    return r;
}

// ============================================================================
// 无线接入后端决策（纯函数）
// ============================================================================

QStringList parseSsidList(const QString& raw)
{
    QStringList result;
    // 兼容逗号（半角/全角）、顿号、分号、空格分隔
    static const QRegularExpression sep(QStringLiteral(R"([,，、;；\s]+)"));
    for (const QString& part : raw.split(sep, Qt::SkipEmptyParts)) {
        const QString s = part.trimmed();
        if (!s.isEmpty())
            result << s;
    }
    return result;
}

bool ssidMatch(const QString& currentSsid, const QStringList& whitelist)
{
    if (currentSsid.isEmpty())
        return false;
    if (whitelist.isEmpty())
        return true;    // 空白名单 = 任意
    return whitelist.contains(currentSsid);
}

BackendDecision resolveAuthBackend(ConnectMode mode, bool ethernetLinkUp,
                                   const QString& currentSsid, const QStringList& whitelist)
{
    switch (mode) {
    case ConnectMode::Wired:
        // 强制有线：链路必须 Up；未知链路状态时先按 Up 走有线（由后续 EAP 失败兜底）
        if (!ethernetLinkUp)
            return { AuthBackend::None, QStringLiteral("已选择有线方式，但以太网网卡未检测到链路，请检查网线连接。") };
        return { AuthBackend::WiredEap, QString() };

    case ConnectMode::Wireless:
        if (!ssidMatch(currentSsid, whitelist))
            return { AuthBackend::None,
                     currentSsid.isEmpty()
                         ? QStringLiteral("已选择无线方式，但当前未连接到校园 Wi-Fi。")
                         : QStringLiteral("已选择无线方式，但当前 SSID（%1）不在允许列表，请连接指定的校园 Wi-Fi。")
                               .arg(currentSsid) };
        return { AuthBackend::PortalWifi, QString() };

    case ConnectMode::Auto:
        break;
    }
    // Auto（及未来新增模式的默认）：有线优先，其次无线
    if (ethernetLinkUp)
        return { AuthBackend::WiredEap, QString() };
    if (ssidMatch(currentSsid, whitelist))
        return { AuthBackend::PortalWifi, QString() };
    if (currentSsid.isEmpty())
        return { AuthBackend::None, QStringLiteral("未检测到有线网络连接，也未连接到校园 Wi-Fi。") };
    return { AuthBackend::None,
             QStringLiteral("当前 SSID（%1）不在允许列表，连接 scut-student 后方可自动认证。").arg(currentSsid) };
}

} // namespace ConnectionBuilder
