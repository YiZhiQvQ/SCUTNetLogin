#include "network/network_worker.h"
#include "network/network.h"
#include "core/constants.h"
#include <QProcess>
#include <QCoreApplication>
#include <QDir>
#include <QThread>
#include <windows.h>

// ============================================================================
// 构造 / 析构
// ============================================================================

NetworkWorker::NetworkWorker(QObject* parent)
    : QObject(parent) {}

NetworkWorker::~NetworkWorker() = default;

// ============================================================================
// 静态 IP 设置 / DHCP 恢复
// ============================================================================

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

// ============================================================================
// 开机自启 (Task Scheduler)
// ============================================================================

void NetworkWorker::doSetAutoStart(bool enable)
{
    QString taskName = QStringLiteral("SCUTNetLogin_AutoStart");
    QString appPath = QDir::toNativeSeparators(QCoreApplication::applicationFilePath());

    QProcess proc;
    proc.setCreateProcessArgumentsModifier([](QProcess::CreateProcessArguments* cpa) {
        cpa->flags |= CREATE_NO_WINDOW;
    });

    if (enable) {
        proc.start(QStringLiteral("schtasks"), {
            QStringLiteral("/create"), QStringLiteral("/tn"), taskName,
            QStringLiteral("/tr"), QStringLiteral("\"") + appPath + QStringLiteral("\" --silent"),
            QStringLiteral("/sc"), QStringLiteral("onlogon"),
            QStringLiteral("/rl"), QStringLiteral("highest"),
            QStringLiteral("/f")
        });
    } else {
        proc.start(QStringLiteral("schtasks"),
                   {QStringLiteral("/delete"), QStringLiteral("/tn"), taskName,
                    QStringLiteral("/f")});
    }
    proc.waitForFinished(15000);

    if (proc.exitCode() != 0) {
        QString err = QString::fromLocal8Bit(proc.readAllStandardError());
        if (!err.isEmpty())
            qWarning() << "schtasks error:" << err;
    }
}
