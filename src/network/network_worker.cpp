#include "network/network_worker.h"
#include "network/network.h"
#include "core/constants.h"
#include <QProcess>
#include <QCoreApplication>
#include <QFile>
#include <QDir>
#include <QRegularExpression>
#include <QStringList>
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
                                   const QString& dns1, const QString& dns2,
                                   int generation)
{
    QString error;
    bool ok = Network::setStaticIp(adapter, ip, mask, gw, dns1, dns2, &error);
    QThread::msleep(IP_SETTLE_WAIT);
    if (ok)
        emit staticIpDone(generation);
    else
        emit staticIpFailed(error, generation);
}

void NetworkWorker::doPurgeStaleConfig(const QString& keepAdapter, const QString& campusGateway,
                                     const QStringList& campusDns)
{
    QStringList report;
    const bool clean = Network::purgeStaleCampusIpConfig(campusGateway, campusDns,
                                                         keepAdapter, &report);
    emit purgeDone(clean, report.join(QStringLiteral("; ")));
}

void NetworkWorker::doSetDhcp(const QString& adapter)
{
    // 结果必须回传：这是"退出前务必恢复 DHCP"承诺的最后一环，
    // 失败静默会让机器留在静态 IP 上且无人知晓
    QString error;
    const bool ok = Network::setDhcp(adapter, &error);
    emit dhcpDone(ok, error);
}

// ============================================================================
// 开机自启 (Task Scheduler)
// ============================================================================

// 构造自启动任务的 XML 定义。
//
// 【为什么不能用 schtasks /create /sc onlogon /rl highest】
// 该命令生成的默认设置里包含三条会"杀死"本程序的项：
//   · StopIfGoingOnBatteries = true    → 切到电池时**直接终止进程**
//   · DisallowStartIfOnBatteries = true → 电池下不启动
//   · StopOnIdleEnd = true              → 系统结束空闲即终止
// 另外默认 ExecutionTimeLimit = PT72H，长期挂机的客户端跑满 72 小时也会被杀。
//
// 实测后果（2026-11-26 18:35）：拔掉扩展坞/电源切到电池的瞬间，任务计划把正在
// 在线的进程杀掉，用户看到"软件自己退了"。因为不是崩溃，WER/事件日志里查不到
// 任何 Application Error（这正是当时排查最迷惑的地方）。
// 因此改为写 XML 后 /create /xml，显式关掉上述全部项。
static QString buildAutoStartTaskXml(const QString& appPath)
{
    auto esc = [](QString s) {
        s.replace(QLatin1Char('&'), QStringLiteral("&amp;"));
        s.replace(QLatin1Char('<'), QStringLiteral("&lt;"));
        s.replace(QLatin1Char('>'), QStringLiteral("&gt;"));
        s.replace(QLatin1Char('"'), QStringLiteral("&quot;"));
        return s;
    };

    return QStringLiteral(
               "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n"
               "<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\n"
               "  <RegistrationInfo>\n"
               "    <Description>SCUT 校园网认证 — 登录时静默启动</Description>\n"
               "  </RegistrationInfo>\n"
               "  <Triggers>\n"
               "    <LogonTrigger>\n"
               "      <Enabled>true</Enabled>\n"
               "    </LogonTrigger>\n"
               "  </Triggers>\n"
               "  <Principals>\n"
               "    <Principal id=\"Author\">\n"
               "      <LogonType>InteractiveToken</LogonType>\n"
               "      <RunLevel>HighestAvailable</RunLevel>\n"
               "    </Principal>\n"
               "  </Principals>\n"
               // 元素顺序严格照抄 Windows 自身导出任务的顺序（<Settings> 是 schema 有序序列，
               // 顺序错了 /create /xml 会直接失败）。顺序取自本机真实任务导出结果：
               //   DisallowStartIfOnBatteries → StopIfGoingOnBatteries → ExecutionTimeLimit
               //   → MultipleInstancesPolicy → StartWhenAvailable → IdleSettings
               // 只保留必要的项，未知位置的元素一律不写，避免 schema 校验失败。
               "  <Settings>\n"
               "    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\n"
               "    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\n"
               "    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>\n"
               "    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\n"
               "    <StartWhenAvailable>true</StartWhenAvailable>\n"
               "    <IdleSettings>\n"
               "      <StopOnIdleEnd>false</StopOnIdleEnd>\n"
               "      <RestartOnIdle>false</RestartOnIdle>\n"
               "    </IdleSettings>\n"
               "  </Settings>\n"
               "  <Actions Context=\"Author\">\n"
               "    <Exec>\n"
               "      <Command>%1</Command>\n"
               "      <Arguments>--silent</Arguments>\n"
               "    </Exec>\n"
               "  </Actions>\n"
               "</Task>\n")
        .arg(esc(appPath));
}

void NetworkWorker::doSetAutoStart(bool enable)
{
    QString taskName = QStringLiteral("SCUTNetLogin_AutoStart");
    QString appPath = QDir::toNativeSeparators(QCoreApplication::applicationFilePath());

    // 先查询现有任务「实际指向的命令行」，再决定要不要动手。核对「任务真实目标 vs
    // 当前 exe」，仅在真正失配（任务不存在 / 指向别的 exe / 缺 --silent）时才
    // /create 或 /delete——修正错指向，也不在每次保存时增删任务、制造无谓告警。
    QString taskCommand, taskArgs;
    QString taskXml;          // 原始 XML：用于判断旧任务的电源设置是否需要迁移
    bool taskFound = false;
    {
        QProcess q;
        q.setCreateProcessArgumentsModifier([](QProcess::CreateProcessArguments* cpa) {
            cpa->flags |= CREATE_NO_WINDOW;
        });
        q.setProgram(Network::systemExecutable(QStringLiteral("schtasks.exe")));
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
            taskXml = xml;
            taskFound = true;
        }
    }

    // 执行 schtasks，统一超时/失败处理。
    auto runSchTasks = [&](const QString& native) -> bool {
        QProcess proc;
        proc.setCreateProcessArgumentsModifier([](QProcess::CreateProcessArguments* cpa) {
            cpa->flags |= CREATE_NO_WINDOW;
        });
        proc.setProgram(Network::systemExecutable(QStringLiteral("schtasks.exe")));
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
        // 除了"指向本 exe + 带 --silent"，还必须确认电源相关设置是安全的。
        // 旧版本创建的任务带 StopIfGoingOnBatteries=true（切电池即杀进程），
        // 若不校验这一项，存量机器永远不会被迁移到新模板。
        const bool alreadyCorrect = taskFound
            && QDir::fromNativeSeparators(clean)
                   .compare(QDir::fromNativeSeparators(appPath), Qt::CaseInsensitive) == 0
            && taskArgs.split(QLatin1Char(' '), Qt::SkipEmptyParts)
                   .contains(QStringLiteral("--silent"))
            && !taskXml.contains(QRegularExpression(
                   QStringLiteral("<StopIfGoingOnBatteries>\\s*true\\s*</StopIfGoingOnBatteries>"),
                   QRegularExpression::CaseInsensitiveOption))
            && !taskXml.contains(QRegularExpression(
                   QStringLiteral("<DisallowStartIfOnBatteries>\\s*true\\s*</DisallowStartIfOnBatteries>"),
                   QRegularExpression::CaseInsensitiveOption))
            && !taskXml.contains(QRegularExpression(
                   QStringLiteral("<StopOnIdleEnd>\\s*true\\s*</StopOnIdleEnd>"),
                   QRegularExpression::CaseInsensitiveOption));
        if (alreadyCorrect) {
            // 任务已正确指向当前 exe 并带 --silent：无变更，静默返回（不打印
            // "设置成功"——该消息仅在实际创建/变更时才有意义，避免每次点连接都刷屏）
            return;
        }

        // 用 XML 定义替代 /sc onlogon /rl highest 的默认模板（见 buildAutoStartTaskXml
        // 上方的说明：默认模板会在切到电池时终止进程）。
        // XML 必须写文件再 /create /xml：schtasks 不接受命令行内联 XML。
        // 编码用 UTF-16LE + BOM，与 Task Scheduler 自身导出的格式一致，避免中文描述乱码。
        const QString xml = buildAutoStartTaskXml(appPath);
        const QString xmlPath = QDir::temp().filePath(QStringLiteral("SCUTNetLogin_AutoStart.xml"));
        {
            QFile f(xmlPath);
            if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
                emit autoStartDone(false, QStringLiteral("无法写入任务定义文件: %1").arg(xmlPath));
                return;
            }
            QByteArray utf16;
            utf16.append('\xFF');
            utf16.append('\xFE');
            const QString bom = xml;
            utf16.append(reinterpret_cast<const char*>(bom.utf16()),
                         bom.size() * 2);
            f.write(utf16);
            f.close();
        }

        const QString native =
            QStringLiteral("/create /tn \"%1\" /xml \"%2\" /f").arg(taskName, xmlPath);
        qWarning().noquote() << "[AutoStart] create(xml):" << native;
        const bool ok = runSchTasks(native);
        QFile::remove(xmlPath);
        if (ok)
            emit autoStartDone(true, QString());
    } else {
        if (!taskFound) {   // 任务本就不存在：本就符合"未启用"目标，静默返回
            return;
        }
        const QString native = QStringLiteral("/delete /tn \"%1\" /f").arg(taskName);
        qWarning().noquote() << "[AutoStart] delete:" << native;
        if (runSchTasks(native))
            emit autoStartDone(true, QString());
    }
}
