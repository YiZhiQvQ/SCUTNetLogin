#include "config/config_manager.h"
#include "config/credential.h"
#include "core/byte_utils.h"
#include "core/constants.h"
#include "network/network.h"
#include <QSettings>
#include <QCoreApplication>
#include <QHostAddress>
#include <QHostInfo>
#include <QNetworkInterface>

namespace ConfigManager {

QString defaultPath()
{
    return QCoreApplication::applicationDirPath() + QStringLiteral("/config.ini");
}

AppConfig load(const QString& configPath)
{
    QSettings settings(configPath, QSettings::IniFormat);
    // 【不】显式 beginGroup("General")：Qt 6.11 对显式组名转义为 [%General]，
    // 与写入时的无组默认形式 [General] 不匹配。保持无组读写。
    AppConfig cfg;

    cfg.username      = settings.value("username", "").toString();
    cfg.host          = settings.value("host",     DEFAULT_HOST).toString();
    cfg.dns           = settings.value("dns",      DEFAULT_DNS).toString();
    cfg.backupDns     = settings.value("backupDns", "").toString();
    cfg.interfaceName = settings.value("interface", "").toString();
    cfg.manualMac     = settings.value("manualMac", "").toString();
    cfg.manualIp      = settings.value("manualIp", "").toString();
    cfg.manualMask    = settings.value("manualMask", "255.255.255.0").toString();
    cfg.manualGateway = settings.value("manualGateway", "").toString();
    cfg.autoSetNetwork = settings.value("autoSetNetwork", true).toBool();
    cfg.autoStart      = settings.value("autoStart", true).toBool();
    cfg.autoConnect    = settings.value("autoConnect", true).toBool();
    cfg.connectMode    = settings.value("connectMode", QString::fromLatin1(PORTAL_DEFAULT_MODE)).toString();
    cfg.wifiSsids      = settings.value("wifiSsids",  QString::fromLatin1(PORTAL_DEFAULT_SSID)).toString();
    cfg.logoutOnExit   = settings.value("logoutOnExit", false).toBool();

    // 密码：优先按 DPAPI 密文解密；失败（非 DPAPI 密文（Base64 明文）/ 数据损坏 /
    // 非当前用户加密）则回退为直接 Base64 解码，兼容旧明文凭据。
    const QByteArray pwdBase64 = settings.value("password", "").toByteArray();
    if (!pwdBase64.isEmpty()) {
        QString pwd = Credential::decryptPassword(pwdBase64);
        if (pwd.isEmpty())
            pwd = QString::fromUtf8(QByteArray::fromBase64(pwdBase64));
        cfg.password     = pwd;
        cfg.savePassword = !pwd.isEmpty();
    }

    return cfg;
}

void save(const QString& configPath, const AppConfig& cfg)
{
    QSettings settings(configPath, QSettings::IniFormat);
    // 与 load 相同：不显式 beginGroup（见 load 内注释，避免 [%General] 转义破坏旧配置兼容）

    settings.setValue("username",  cfg.username);
    settings.setValue("host",      cfg.host);
    settings.setValue("dns",       cfg.dns);
    settings.setValue("interface", cfg.interfaceName);
    settings.setValue("manualMac",     cfg.manualMac);
    settings.setValue("manualIp",      cfg.manualIp);
    settings.setValue("manualMask",    cfg.manualMask);
    settings.setValue("manualGateway", cfg.manualGateway);
    settings.setValue("backupDns",     cfg.backupDns);
    settings.setValue("autoSetNetwork", cfg.autoSetNetwork);
    settings.setValue("autoStart",      cfg.autoStart);
    settings.setValue("autoConnect",    cfg.autoConnect);
    settings.setValue("connectMode",    cfg.connectMode);
    settings.setValue("wifiSsids",      cfg.wifiSsids);
    settings.setValue("logoutOnExit",   cfg.logoutOnExit);

    if (cfg.savePassword)
        settings.setValue("password", Credential::encryptPassword(cfg.password));
    else
        settings.remove("password");
}

AuthConfig toAuthConfig(const AppConfig& cfg)
{
    AuthConfig config;
    config.username      = cfg.username;
    config.password      = cfg.password;
    config.host          = cfg.host;
    config.dnsServer     = cfg.dns;
    config.interfaceName = cfg.interfaceName;

    // MAC
    QString macStr = ByteUtils::normalizeMac(cfg.manualMac);
    if (!macStr.isEmpty()) {
        QByteArray bytes = QByteArray::fromHex(macStr.toLatin1());
        if (bytes.size() == 6)
            memcpy(config.localMac, bytes.constData(), 6);
    }

    // IP
    QHostAddress addr(cfg.manualIp);
    if (addr.protocol() == QAbstractSocket::IPv4Protocol)
        ByteUtils::ipv4ToBytes(addr, config.localIp);

    return config;
}

void resolveAuthConfig(AuthConfig& config)
{
    // 本机主机名
    config.hostname = QHostInfo::localHostName();

    // 本机 IP 回退：UI 未填时从网卡自动获取
    // 注意：config.interfaceName 是 pcap 设备名 (\Device\NPF_{GUID})，
    // 必须通过 Network::findInterface() 转换为 Qt 接口名后查询，不能直接
    // 传给 QNetworkInterface::interfaceFromName()（后者期望 Windows GUID 格式）
    if (ByteUtils::isIpZero(config.localIp) && !config.interfaceName.isEmpty()) {
        QNetworkInterface iface = Network::findInterface(config.interfaceName);
        if (iface.isValid()) {
            for (const auto& entry : iface.addressEntries()) {
                if (entry.ip().protocol() == QAbstractSocket::IPv4Protocol
                    && entry.ip().toIPv4Address() != 0) {
                    ByteUtils::ipv4ToBytes(entry.ip(), config.localIp);
                    break;
                }
            }
        }
    }
}

ConnectMode connectModeFromString(const QString& s)
{
    if (s.compare(QStringLiteral("wireless"), Qt::CaseInsensitive) == 0)
        return ConnectMode::Wireless;
    if (s.compare(QStringLiteral("wired"), Qt::CaseInsensitive) == 0)
        return ConnectMode::Wired;
    return ConnectMode::Auto;    // "auto" / 未知 / 空串 → 自动（有线优先）
}

QString connectModeToString(ConnectMode m)
{
    switch (m) {
    case ConnectMode::Wireless: return QStringLiteral("wireless");
    case ConnectMode::Wired:    return QStringLiteral("wired");
    case ConnectMode::Auto:     break;
    }
    return QStringLiteral("auto");
}

} // namespace ConfigManager
