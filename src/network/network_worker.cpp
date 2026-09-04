#include "network/network_worker.h"
#include "network/network.h"
#include "core/constants.h"
#include <QProcess>
#include <QCoreApplication>
#include <QDir>
#include <QRegularExpression>
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

    // 先查询现有任务「实际指向的命令行」，再决定要不要动手。
    // 原实现只在勾选状态变化时才触发，一旦 config 已是 autoStart=true 但任务仍指向别的 exe
    // （例如从开发版换装到 Program Files），就永远不重建，开机自启形同虚设。这里改成核对
    // 「任务真实目标 vs 当前 exe」，且仅在真正失配时才 /create 或 /delete —— 既修复错指向，
    // 又不像早期实现那样每次保存都增删任务、制造"系统找不到指定的文件"告警。
    QString taskCommand, taskArgs;
    bool taskFound = false;
    {
        QProcess q;
        q.setCreateProcessArgumentsModifier([](QProcess::CreateProcessArguments* cpa) {
            cpa->flags |= CREATE_NO_WINDOW;
        });
        q.setProgram(QStringLiteral("schtasks"));
        q.setNativeArguments(QStringLiteral("/query /tn \"%1\" /xml").arg(taskName));
        q.start();
        if (q.waitForFinished(NETSH_TIMEOUT) && q.exitCode() == 0) {
            QByteArray out = q.readAllStandardOutput();
            // schtasks /query /xml 的编码不稳定：有的版本输出 UTF-16LE（字符间穿插 0x00），
            // 有的输出单字节 ASCII。按内容探测而非盲目相信 XML 的 encoding 声明。
            QString xml;
            if (out.size() >= 2 && quint8(out[0]) == 0xFF && quint8(out[1]) == 0xFE)
                xml = QString::fromUtf16(reinterpret_cast<const char16_t*>(out.constData() + 2),
                                         (out.size() - 2) / 2);
            else if (out.contains('\0'))
                xml = QString::fromUtf16(reinterpret_cast<const char16_t*>(out.constData()), out.size() / 2);
            else
                xml = QString::fromUtf8(out);

            QRegularExpression reCmd(QStringLiteral("(?s)<Command>(.*?)</Command>"));
            QRegularExpression reArgs(QStringLiteral("(?s)<Arguments>(.*?)</Arguments>"));
            QRegularExpressionMatch m = reCmd.match(xml);
            if (m.hasMatch()) taskCommand = m.captured(1).trimmed();
            m = reArgs.match(xml);
            if (m.hasMatch()) taskArgs = m.captured(1).trimmed();
            taskFound = true;
        }
    }

    // 执行 schtasks，统一超时/失败处理。
    auto runSchTasks = [&](const QString& native) -> bool {
        QProcess proc;
        proc.setCreateProcessArgumentsModifier([](QProcess::CreateProcessArguments* cpa) {
            cpa->flags |= CREATE_NO_WINDOW;
        });
        proc.setProgram(QStringLiteral("schtasks"));
        proc.setNativeArguments(native);
        proc.start();
        if (!proc.waitForFinished(NETSH_TIMEOUT)) {
            proc.kill();
            proc.waitForFinished(2000);
            emit autoStartDone(false, QStringLiteral("schtasks 命令超时"));
            return false;
        }
        if (proc.exitCode() != 0) {
            QString err = QString::fromLocal8Bit(proc.readAllStandardError()).trimmed();
            if (err.isEmpty())
                err = QString::fromLocal8Bit(proc.readAllStandardOutput()).trimmed();
            emit autoStartDone(false, err.isEmpty() ? QStringLiteral("schtasks 执行失败") : err);
            return false;
        }
        return true;
    };

    if (enable) {
        // taskCommand 来自 schtasks 的 <Command>，含空格的路径必然带外层双引号，先剥掉再比。
        QString clean = taskCommand;
        if (clean.size() >= 2 && clean.startsWith(QLatin1Char('"')) && clean.endsWith(QLatin1Char('"')))
            clean = clean.mid(1, clean.size() - 2);
        const bool alreadyCorrect = taskFound
            && QDir::fromNativeSeparators(clean)
                   .compare(QDir::fromNativeSeparators(appPath), Qt::CaseInsensitive) == 0
            && taskArgs.split(QLatin1Char(' '), Qt::SkipEmptyParts)
                   .contains(QStringLiteral("--silent"));
        if (alreadyCorrect) {
            emit autoStartDone(true, QString());
            return;
        }

        // 重要：schtasks 的 /tr 值含路径 + "--silent"，若走 QProcess::start(program, QStringList)，
        // Qt 会自动对含空格的参数加引号并转义内部引号，导致 schtasks 收到双反斜杠转义的引号，
        // 无法解析路径 → /create 失败。因此全部改用 setNativeArguments 手工拼接命令行。
        // schtasks 官方文档对含空格的 /tr 路径要求【两套引号】：外层双引号给 CMD.EXE，内层单引号
        // '...' 给 schtasks.exe 解析路径。单引号是字面字符，不与双引号争夺语义，彻底避免
        // "\\\"C:\\...\\exe\\\"" 这类反斜杠转义地狱。/rl highest 需管理员权限创建（本程序以
        // 管理员运行），确保成功。
        const QString native =
            QStringLiteral("/create /tn \"%1\" /tr \"'%2' --silent\" /sc onlogon /rl highest /f")
                .arg(taskName, appPath);
        qWarning().noquote() << "[AutoStart] create:" << native;
        if (runSchTasks(native))
            emit autoStartDone(true, QString());
    } else {
        if (!taskFound) {   // 任务本就不存在：视为成功，不为"系统找不到指定的文件"报错
            emit autoStartDone(true, QString());
            return;
        }
        const QString native = QStringLiteral("/delete /tn \"%1\" /f").arg(taskName);
        qWarning().noquote() << "[AutoStart] delete:" << native;
        if (runSchTasks(native))
            emit autoStartDone(true, QString());
    }
}
