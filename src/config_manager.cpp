#include "config_manager.h"
#include "constants.h"
#include "network.h"
#include <QSettings>
#include <QCoreApplication>
#include <QHostAddress>

namespace ConfigManager {

QString defaultPath()
{
    return QCoreApplication::applicationDirPath() + QStringLiteral("/config.ini");
}

AppConfig load(const QString& configPath)
{
    QSettings settings(configPath, QSettings::IniFormat);
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
    cfg.autoSetNetwork = settings.value("autoSetNetwork", false).toBool();
    cfg.autoStart      = settings.value("autoStart", false).toBool();
    cfg.autoConnect    = settings.value("autoConnect", false).toBool();

    QByteArray pwdBase64 = settings.value("password", "").toByteArray();
    if (!pwdBase64.isEmpty()) {
        cfg.password     = QString::fromUtf8(QByteArray::fromBase64(pwdBase64));
        cfg.savePassword = true;
    }

    return cfg;
}

void save(const QString& configPath, const AppConfig& cfg)
{
    QSettings settings(configPath, QSettings::IniFormat);

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

    if (cfg.savePassword)
        settings.setValue("password", cfg.password.toUtf8().toBase64());
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
    QString macStr = Network::normalizeMac(cfg.manualMac);
    if (!macStr.isEmpty()) {
        QByteArray bytes = QByteArray::fromHex(macStr.toLatin1());
        if (bytes.size() == 6)
            memcpy(config.localMac, bytes.constData(), 6);
    }

    // IP
    QHostAddress addr(cfg.manualIp);
    if (addr.protocol() == QAbstractSocket::IPv4Protocol)
        Network::ipv4ToBytes(addr, config.localIp);

    return config;
}

} // namespace ConfigManager
