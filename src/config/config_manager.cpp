#include "config/config_manager.h"
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

void resolveAuthConfig(AuthConfig& config)
{
    // 本机主机名
    config.hostname = QHostInfo::localHostName();

    // DNS 服务器 IP（解析失败则回退默认值）
    QHostAddress srvAddr(config.dnsServer);
    if (srvAddr.protocol() == QAbstractSocket::IPv4Protocol)
        Network::ipv4ToBytes(srvAddr, config.serverIp);
    else
        memcpy(config.serverIp, DEFAULT_SERVER_IP.data(), DEFAULT_SERVER_IP.size());

    // 本机 IP 回退：UI 未填时从网卡自动获取
    // 注意：config.interfaceName 是 pcap 设备名 (\Device\NPF_{GUID})，
    // 必须通过 Network::findInterface() 转换为 Qt 接口名后查询，不能直接
    // 传给 QNetworkInterface::interfaceFromName()（后者期望 Windows GUID 格式）
    if (Network::isIpZero(config.localIp) && !config.interfaceName.isEmpty()) {
        QNetworkInterface iface = Network::findInterface(config.interfaceName);
        if (iface.isValid()) {
            for (const auto& entry : iface.addressEntries()) {
                if (entry.ip().protocol() == QAbstractSocket::IPv4Protocol
                    && entry.ip().toIPv4Address() != 0) {
                    Network::ipv4ToBytes(entry.ip(), config.localIp);
                    break;
                }
            }
        }
    }
}

} // namespace ConfigManager
