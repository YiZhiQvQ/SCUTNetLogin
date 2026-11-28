#define _WIN32_WINNT 0x0601

#include "network/network.h"
#include "network/network_internal.h"
#include "core/byte_utils.h"
#include "core/constants.h"
#include <winsock2.h>
#include <windows.h>
// 顺序要求：netioapi.h（由 iphlpapi.h 末尾包含）的主体声明在 #ifdef _WS2IPDEF_ 内，
// 而 winsock2.h 只带 ws2def.h —— 缺 ws2ipdef.h 会让 NotifyIpInterfaceChange /
// MIB_IPFORWARD_TABLE2 等全部"未声明的标识符"
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <ifdef.h>
#include <QProcess>
#include <QRegularExpression>
#include <QNetworkInterface>
#include <QSet>
#include <QElapsedTimer>
#include <QMetaObject>
#include <QtEndian>
#include <vector>
#include <algorithm>
#include <QDebug>
#include <QThread>
#include <pcap.h>

namespace Network {

using Internal::RawWin32Adapter;   // 定义见 network_internal.h



// ============================================================================
// adapterNameByMac — 通过 MAC 地址查找适配器名（用于 netsh）
// ============================================================================


// netsh 退出码非 0 但实际已达目标的情形（幂等调用必然命中）。
// 实测中文 Windows 的原文是「DHCP 已在此接口上启用。」——注意不是"已启用"；
// 只匹配英文 "already" 会漏掉，从而把正常状态误报成失败。
static bool isBenignNetshMessage(const QString& text)
{
    return text.contains(QStringLiteral("already"), Qt::CaseInsensitive)
           || text.contains(QStringLiteral("DHCP is already"))
           || text.contains(QStringLiteral("已在此接口"))
           || text.contains(QStringLiteral("已启用"));
}

// 执行 netsh 并把"已在目标状态"视为成功
static bool runNetshTolerant(const QStringList& args, QString* errorMsg)
{
    QString detail;
    if (runNetsh(args, &detail))
        return true;
    if (isBenignNetshMessage(detail))
        return true;
    if (errorMsg)
        *errorMsg = detail;
    return false;
}

bool purgeStaleCampusIpConfig(const QString& campusGateway, const QStringList& campusDns,
                              const QString& keepAdapter, QStringList* report)
{
    auto note = [report](const QString& s) {
        if (report)
            *report << s;
        qWarning().noquote() << "[自愈]" << s;
    };

    bool clean = true;
    const auto adapters = Internal::enumerateWin32Adapters();
    const QString keepName = keepAdapter.isEmpty() ? QString() : netshAdapterName(keepAdapter);

    // 统一用"已在目标状态也算成功"的封装：中文 Windows 返回
    // 「DHCP 已在此接口上启用。」且退出码为 1，若按失败处理会把正常状态
    // 误报成"清理失败"，并在 UI 上闪一条红色错误（曾经真的这么报过）。
    auto setDhcpOn = [&](const QString& name, const QString& tag) {
        QString err;
        const QStringList addrArgs = { QStringLiteral("interface"), QStringLiteral("ipv4"),
                                       QStringLiteral("set"), QStringLiteral("address"),
                                       QStringLiteral("name=%1").arg(name),
                                       QStringLiteral("source=dhcp") };
        if (!runNetshTolerant(addrArgs, &err)) {
            clean = false;
            note(QStringLiteral("%1 地址恢复 DHCP 失败(%2): %3").arg(tag, name, err));
        }
        QString dnsErr;
        const QStringList dnsArgs = { QStringLiteral("interface"), QStringLiteral("ipv4"),
                                      QStringLiteral("set"), QStringLiteral("dnsservers"),
                                      QStringLiteral("name=%1").arg(name),
                                      QStringLiteral("source=dhcp") };
        if (!runNetshTolerant(dnsArgs, &dnsErr)) {
            note(QStringLiteral("%1 DNS 恢复 DHCP 未成功(%2): %3").arg(tag, name, dnsErr));
        }
    };

    // 判定"这块网卡的当前配置里有没有校园网痕迹"：
    //   · 网关命中 campusGateway；或
    //   · DNS 命中 campusDns 中的任意一个；或
    //   · 地址落在校园静态 IP 所属网段（调用方通过 keepAdapter 之外的 IP 无法判断，
    //     因此退化为"有网关且有 DNS"——校园静态 IP 必然同时带这两项）。
    // 只清有痕迹的接口，绝不动用户自己的其它网络配置（如热点、公司网络）。
    auto hasCampusTrace = [&](const RawWin32Adapter& ra) {
        if (!campusGateway.isEmpty()
            && std::any_of(ra.gateways.begin(), ra.gateways.end(),
                           [&](const QString& g) { return g == campusGateway; }))
            return true;
        for (const QString& d : ra.dns) {
            if (campusDns.contains(d))
                return true;
        }
        // 网关 + DNS 同时存在但没有可用判据（campusDns 为空）时不动，避免误伤
        return false;
    };

    for (const auto& ra : adapters) {
        const QString name = ra.friendlyName.isEmpty() ? QString::number(ra.ifIndex)
                                                       : ra.friendlyName;

        if (ra.ifType == IF_TYPE_SOFTWARE_LOOPBACK) {
            // 环回上的网关是破坏性最大的一项：它会生成 metric=1 的默认路由，
            // 优先级高于手机热点，把全部流量送进黑洞。环回接口本就不该有任何网关/
            // DNS，因此无条件清理（这不是"用户的配置"）。
            if (!ra.gateways.isEmpty() || !ra.dns.isEmpty()) {
                setDhcpOn(name, QStringLiteral("环回接口"));
                note(QStringLiteral("环回接口存在网关%1/DNS%2，已清除")
                         .arg(ra.gateways.join(QLatin1Char('+')),
                              ra.dns.join(QLatin1Char('+'))));
            }
            // 环回上的持久默认路由必须显式删除，否则重启后依旧生效
            QString routeErr;
            const QStringList routeArgs = { QStringLiteral("interface"), QStringLiteral("ipv4"),
                                            QStringLiteral("delete"), QStringLiteral("route"),
                                            QStringLiteral("prefix=0.0.0.0/0"),
                                            QStringLiteral("interface=%1").arg(name),
                                            QStringLiteral("store=persistent") };
            if (runNetsh(routeArgs, &routeErr))
                note(QStringLiteral("已删除环回接口上的持久默认路由"));
            continue;
        }

        // 明确保留的接口（通常是当前在用的有线网卡）不动
        if (!keepName.isEmpty()
            && (ra.friendlyName.compare(keepName, Qt::CaseInsensitive) == 0
                || ra.guid.compare(keepAdapter, Qt::CaseInsensitive) == 0)) {
            continue;
        }

        // WAN Miniport / Teredo / 内核调试口等：绝不该带任何 IP 配置，
        // 出现过就说明历史路径写错了目标（本次故障的根源之一），一律清掉。
        if (isUselessNetshTarget(ra.guid)) {
            if (!ra.ipv4.isEmpty() || !ra.gateways.isEmpty() || !ra.dns.isEmpty()) {
                setDhcpOn(name, QStringLiteral("无效接口"));
                note(QStringLiteral("已清理无效接口残留: %1 [%2]").arg(name, ra.description));
            }
            continue;
        }

        // 其它真实网卡：只有确实挂着校园配置才动手（关键——否则会清掉用户自己的设置）
        if (hasCampusTrace(ra)) {
            setDhcpOn(name, QStringLiteral("校园配置残留"));
            note(QStringLiteral("已清除校园配置残留: %1 网关[%2] DNS[%3]")
                     .arg(name, ra.gateways.join(QLatin1Char('+')),
                          ra.dns.join(QLatin1Char('+'))));
        }
    }

    return clean;
}
QString dumpIpConfigSnapshot()
{
    QStringList out;

    // ① IPv4 默认路由（含持久路由）—— 残留的校园网关会在这里原形毕露
    PMIB_IPFORWARD_TABLE2 fwd = nullptr;
    if (GetIpForwardTable2(AF_INET, &fwd) == NO_ERROR && fwd) {
        for (ULONG i = 0; i < fwd->NumEntries; ++i) {
            const MIB_IPFORWARD_ROW2& row = fwd->Table[i];
            if (row.DestinationPrefix.PrefixLength != 0)
                continue;
            if (row.DestinationPrefix.Prefix.si_family != AF_INET)
                continue;
            const auto* nh = reinterpret_cast<const sockaddr_in*>(&row.NextHop);
            if (!nh || nh->sin_addr.S_un.S_addr == 0)
                continue;
            char nhBuf[INET_ADDRSTRLEN] = {};
            inet_ntop(AF_INET, &nh->sin_addr, nhBuf, sizeof(nhBuf));
            out << QStringLiteral("[路由] 默认路由 网关=%1 接口LUID=%2 度量=%3")
                       .arg(QString::fromLatin1(nhBuf))
                       .arg(static_cast<qulonglong>(row.InterfaceLuid.Value))
                       .arg(row.Metric);
        }
        FreeMibTable(fwd);
    } else {
        out << QStringLiteral("[路由] GetIpForwardTable2 失败，无法枚举默认路由");
    }

    // ② 每块网卡的 IPv4 地址与 DNS —— 静态残留 / 校园 DNS 挂在错误接口上一眼可见
    //
    // 复用 Internal::enumerateWin32Adapters()，不再在这里重复一遍 GetAdaptersAddresses 与
    // unicast/DNS 提取。此前这段与枚举函数各写一份，历史上正是"改了一处漏了另一处"
    // 的直接来源（GAA_FLAG_INCLUDE_GATEWAYS 那次就漏了这个快照路径）。
    for (const auto& ra : Internal::enumerateWin32Adapters()) {
        const QString name = ra.friendlyName.isEmpty() ? QStringLiteral("(无)")
                                                       : ra.friendlyName;
        out << QStringLiteral("[网卡] %1 (idx=%2) IP=[%3] DNS=[%4]")
                   .arg(name)
                   .arg(ra.ifIndex)
                   .arg(ra.ipv4.join(QLatin1Char(',')))
                   .arg(ra.dns.join(QLatin1Char(',')));
    }

    return out.join(QLatin1Char('\n'));
}

// ============================================================================
// listInterfaces — 枚举可用 Npcap 网卡
// ============================================================================

QList<InterfaceEntry> listInterfaces()
{
    // 构建 Wi-Fi GUID 集合（Win32 IfType，精确可靠）
    const auto win32Adapters = Internal::enumerateWin32Adapters();
    QSet<QString> wifiGuids;
    for (const auto& ra : win32Adapters) {
        if (ra.ifType == IF_TYPE_IEEE80211)
            wifiGuids.insert(ra.guid.toUpper());
    }

    QList<InterfaceEntry> result;
    QList<InterfaceEntry> wireless;
    static const QRegularExpression guidRe(R"(\\Device\\NPF_\{([A-Fa-f0-9\-]+)\})");

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) != -1) {
        static const QStringList wifiKeys = {"Wireless", "Wi-Fi", "WiFi", "802.11", "WLAN", "无线"};
        for (pcap_if_t* dev = alldevs; dev != nullptr; dev = dev->next) {
            if (dev->flags & PCAP_IF_LOOPBACK)
                continue;
            const QString desc = dev->description ? QString::fromLocal8Bit(dev->description) : QString();
            const QString name = QString::fromUtf8(dev->name);
            if (desc.contains(QStringLiteral("Loopback"), Qt::CaseInsensitive)
                || name.contains(QStringLiteral("Loopback"), Qt::CaseInsensitive))
                continue;

            // 优先通过 Win32 IfType 检测 Wi-Fi，回退到字符串匹配
            bool isWireless = false;
            auto match = guidRe.match(name);
            if (match.hasMatch()) {
                const QString guid = QStringLiteral("{") + match.captured(1) + QStringLiteral("}");
                isWireless = wifiGuids.contains(guid.toUpper());
            }
            if (!isWireless) {
                for (const QString& key : wifiKeys) {
                    if (desc.contains(key, Qt::CaseInsensitive)
                        || name.contains(key, Qt::CaseInsensitive)) {
                        isWireless = true;
                        break;
                    }
                }
            }

            const QString displayName = desc.isEmpty() ? name : desc;
            if (isWireless)
                wireless.append({displayName, name, true});
            else
                result.append({displayName, name, false});
        }
        pcap_freealldevs(alldevs);
    } else {
        // 枚举失败（如 Npcap 未安装）：记录原因，返回空列表由 UI 提示
        qWarning().noquote() << "pcap_findalldevs failed:" << errbuf;
    }

    // Wi-Fi 网卡排到列表末尾，加前缀区分
    for (const auto& w : wireless)
        result.append({QStringLiteral("[Wi-Fi] ") + w.displayName, w.pcapName, true});

    return result;
}

// ============================================================================
// netsh 命令执行
// ============================================================================

// 控制台程序输出编码容错：先按 UTF-8 解，出现替换字符再退回系统本地代码页
// （中文 Windows 为 GBK/936）。netsh / route / schtasks 在不同版本下不一致，
// 硬编码任何一种都会在某些机器上解成乱码——而乱码会直接破坏"按文本判定状态"的逻辑。
static QString decodeConsoleText(const QByteArray& raw)
{
    if (raw.isEmpty())
        return QString();

    const QString asUtf8 = QString::fromUtf8(raw);
    if (!asUtf8.contains(QChar::ReplacementCharacter))
        return asUtf8;

    const QString asLocal = QString::fromLocal8Bit(raw);
    // 本地代码页解码结果里若仍有替换字符，取两者中"更干净"的一个
    if (asLocal.contains(QChar::ReplacementCharacter))
        return asUtf8;
    return asLocal;
}

bool runNetsh(const QStringList& args, QString* errorMsg)
{
    QProcess proc;
    proc.setCreateProcessArgumentsModifier([](QProcess::CreateProcessArguments* cpa) {
        cpa->flags |= CREATE_NO_WINDOW;
    });
    proc.start(systemExecutable(QStringLiteral("netsh.exe")), args);
    if (!proc.waitForStarted(NETSH_TIMEOUT)) {
        if (errorMsg)
            *errorMsg = QStringLiteral("netsh 无法启动: %1").arg(args.join(QLatin1Char(' ')));
        return false;
    }
    if (!proc.waitForFinished(NETSH_TIMEOUT)) {
        // 显式终止挂起的 netsh（QProcess 析构也会杀，但显式 kill 保证
        // 错误信息可读且不依赖析构时序）
        proc.kill();
        proc.waitForFinished(NETSH_KILL_WAIT_MS);
        if (errorMsg) {
            *errorMsg = QString("netsh 命令超时 (%1 秒): %2")
                            .arg(NETSH_TIMEOUT / 1000)
                            .arg(args.join(' '));
        }
        return false;
    }

    // netsh 把大部分错误写到 **stdout**（而非 stderr），原先只读 stderr 会让
    // "文件名、目录名或卷标语法不正确" 这类关键提示变成空字符串。
    // 编码也必须容错：本机实测 netsh 的本地化文本是 **UTF-8**，而按 GBK 解会把
    // "已在此接口上启用 DHCP" 解成乱码，进而让上面的幂等判定失配、
    // 把正常情况误报成"清理失败"。
    const QString outText = decodeConsoleText(proc.readAllStandardOutput()).trimmed();
    const QString errText = decodeConsoleText(proc.readAllStandardError()).trimmed();

    if (proc.exitCode() != 0) {
        if (errorMsg) {
            QString detail = errText.isEmpty() ? outText : errText;
            *errorMsg = QString("netsh 失败 (exit=%1): %2\n%3")
                            .arg(proc.exitCode())
                            .arg(args.join(' '), detail);
        }
        return false;
    }

    // 退出码 0 也未必真的生效（历史坑：name= 为空时 netsh 静默成功）。这里只负责把
    // 输出透传给调用方做二次校验，判定逻辑放在 setStaticIp/setDhcp 里。
    if (errorMsg && !outText.isEmpty())
        *errorMsg = outText;
    return true;
}

// 逐字段核对网卡当前 IPv4 配置：静态 IP 必须地址/掩码/网关都对上；DHCP 必须
// DHCP 已启用且没有残留的静态网关与 DNS。
//
// 【为什么不再解析 netsh 文本】
// 原实现读 "netsh interface ipv4 show config" 的本地化文本再逐行取值。这条路有三个
// 结构性缺陷，且已经实际造成误判（日志：地址读出空串被判失败，但同一毫秒的 Win32
// 快照里该网卡明明已是 10.40.16.57）：
//   ① 文本标签随系统语言变化（"IP Address" / "IP 地址" / 其他语言版本）；
//   ② 无地址时 netsh 直接不输出该行，与"读取失败"无法区分；
//   ③ netsh set 返回后配置是否已提交到协议栈取决于时序，文本层可能滞后。
// 因此改为直接查 Win32 结构化数据（GetAdaptersAddresses），与语言无关、无文本滞后，
// 并带退避重试等待地址/DNS/网关状态稳定。
// 该 LUID 对应的接口上，是否存在"默认路由 → gw"。
// 网关生效的最终判据：只要路由表里有这条 0.0.0.0/0，网关就一定在工作。
// 单纯依赖适配器的 FirstGatewayAddress 不够稳（它受 GAA flags 与过渡态影响）。
static bool hasDefaultRouteVia(const IF_LUID& luid, const QString& gw)
{
    if (gw.isEmpty())
        return false;
    PMIB_IPFORWARD_TABLE2 fwd = nullptr;
    if (GetIpForwardTable2(AF_INET, &fwd) != NO_ERROR || !fwd)
        return false;

    bool found = false;
    for (ULONG i = 0; i < fwd->NumEntries && !found; ++i) {
        const MIB_IPFORWARD_ROW2& row = fwd->Table[i];
        if (row.DestinationPrefix.PrefixLength != 0)
            continue;                                   // 只看默认路由
        if (row.DestinationPrefix.Prefix.si_family != AF_INET)
            continue;
        if (row.InterfaceLuid.Value != luid.Value)
            continue;
        const auto* nh = reinterpret_cast<const sockaddr_in*>(&row.NextHop);
        if (!nh)
            continue;
        char ipb[INET_ADDRSTRLEN] = {};
        inet_ntop(AF_INET, &nh->sin_addr, ipb, sizeof(ipb));
        if (QString::fromLatin1(ipb) == gw)
            found = true;
    }
    FreeMibTable(fwd);
    return found;
}

static bool verifyIpv4ConfigImpl(const QString& netshName, bool expectStatic,
                             const QString& ip, const QString& mask,
                             const QString& gw, const QString& dns1,
                             QString* detail)
{
    // mask 参数保留但不再参与校验：GetAdaptersAddresses 给的是前缀长度而不是点分掩码，
    // 换算出来只是同义反复（掩码错则地址/前缀必然对不上，已由地址项覆盖）。
    Q_UNUSED(mask);

    // 目标网卡 -> LUID（GUID/LUID 名/友好名/ifIndex 都能换算）
    const auto adapters = Internal::enumerateWin32Adapters();
    const RawWin32Adapter* target = nullptr;
    for (const auto& ra : adapters) {
        if (ra.friendlyName.compare(netshName, Qt::CaseInsensitive) == 0
            || ra.luidName.compare(netshName, Qt::CaseInsensitive) == 0
            || ra.guid.compare(netshName, Qt::CaseInsensitive) == 0) {
            target = &ra;
            break;
        }
    }
    if (!target) {
        if (detail)
            *detail = QStringLiteral("回读失败: 找不到网卡[%1]").arg(netshName);
        return false;
    }

    // 退避重试：netsh 返回后配置仍在提交中，等 DHCP/地址状态稳定（最多约 1.5 秒）
    QStringList bad;
    for (int attempt = 0; attempt < 10; ++attempt) {
        if (attempt > 0)
            QThread::msleep(IP_VERIFY_RETRY_MS);

        // 每轮重新枚举（配置在变，不能用缓存）
        const auto snapshotNow = Internal::enumerateWin32Adapters();
        const RawWin32Adapter* cur = nullptr;
        for (const auto& ra : snapshotNow) {
            if (ra.ifIndex == target->ifIndex) { cur = &ra; break; }
        }
        if (!cur) {
            bad = { QStringLiteral("网卡消失") };
            continue;
        }

        bad.clear();
        if (expectStatic) {
            if (!ip.isEmpty() && !cur->ipv4.contains(ip)) {
                bad << QStringLiteral("地址实际为[%1] 期望[%2]")
                           .arg(cur->ipv4.join(QLatin1Char(',')), ip);
            }
            if (!gw.isEmpty()) {
                // 网关有两个可信来源，任一命中即算生效：
                //   ① 适配器自身的 FirstGatewayAddress（需 GAA_FLAG_INCLUDE_GATEWAYS）；
                //   ② 路由表里该接口上指向该网关的默认路由。
                // ②是最终判据——只要默认路由在，网关就是生效的。实测出现过适配器
                // 网关为空、但路由表明确有该默认路由的情况（见 .hang.log 快照）。
                const bool gwOnAdapter = cur->gateways.contains(gw);
                if (!gwOnAdapter && !hasDefaultRouteVia(cur->luid, gw)) {
                    bad << QStringLiteral("网关实际为[%1] 期望[%2]")
                               .arg(cur->gateways.join(QLatin1Char(',')), gw);
                }
            }
            if (!dns1.isEmpty() && !cur->dns.contains(dns1)) {
                bad << QStringLiteral("DNS 实际为[%1] 期望含[%2]")
                           .arg(cur->dns.join(QLatin1Char(',')), dns1);
            }
        } else {
            // 期望 DHCP：校园网关/DNS 不能残留
            const bool gwStillThere = cur->gateways.contains(gw)
                                      || (!gw.isEmpty() && hasDefaultRouteVia(cur->luid, gw));
            if (!gw.isEmpty() && gwStillThere)
                bad << QStringLiteral("仍残留网关[%1]").arg(gw);
            if (!dns1.isEmpty() && cur->dns.contains(dns1))
                bad << QStringLiteral("仍残留 DNS[%1]").arg(dns1);
        }

        if (bad.isEmpty())
            return true;   // 已满足期望：不必再等
    }

    if (!bad.isEmpty() && detail)
        *detail = QStringLiteral("%1回读不符: %2")
                      .arg(expectStatic ? QStringLiteral("静态IP ") : QStringLiteral("DHCP "))
                      .arg(bad.join(QStringLiteral("; ")));
    return bad.isEmpty();
}

// 读取网卡驱动注册表里的省电相关键，判断是否存在与 Npcap 冲突的风险。
//
// 背景（实测故障）：Realtek PCIe GbE 的 "Power Saving Mode" 与 "Green Ethernet"
// 开启时，网卡会在链路空闲时进入低功耗、关断部分收发通路。Npcap 是内核级过滤驱动，
// 其 pcap_activate 在这种情况下会**永久阻塞在内核态**，导致：
//   · EAP 线程无法返回，整个连接流程停摆；
//   · 进程无法被终止 —— TerminateProcess 返回 ERROR_ACCESS_DENIED，
//     任务管理器"结束任务"无任何反应，最终只能重启系统。
// 因此这里主动检测并提示用户，把"事后无从下手"变成"事前可规避"。

bool verifyIpv4ConfigPublic(const QString& anyAdapterForm, bool expectStatic,
                            const QString& ip, const QString& mask,
                            const QString& gw, const QString& dns1,
                            QString* detail)
{
    // 入参可能是 {GUID} / pcap 名 / LUID 名 / 友好名：统一解析成 netsh 侧名字后校验
    return verifyIpv4ConfigImpl(netshAdapterName(anyAdapterForm), expectStatic,
                                ip, mask, gw, dns1, detail);
}

// 静态 IP / DHCP 两个入口的公共骨架：解析目标 → 拒绝无效目标 → 逐条执行 netsh →
// 回读校验 → 汇总错误。原实现里 setStaticIp 与 setDhcp 各写一遍这五步（约 45 行 x 2），
// 任何一处改动都必须同步另一处，是典型的"改一处漏一处"来源。
static bool applyIpv4Config(const QString& winName,
                            const QVector<QStringList>& addressDnsCommands,
                            bool expectStatic,
                            const QString& ip, const QString& mask,
                            const QString& gw, const QString& dns1,
                            const QString& actionLabel,
                            QString* errorMsg)
{
    const QString target = netshAdapterName(winName);
    // 目标为空或指向环回/WAN Miniport：绝不能写。写错会把网关/DNS 挂到假接口上，
    // 在路由表里留下持久默认路由，离开校园网后依然无法上网。
    if (target.isEmpty() || isUselessNetshTarget(winName)) {
        if (errorMsg) {
            *errorMsg = QStringLiteral("拒绝向无效目标[%1]%2（解析结果[%3]）")
                            .arg(winName, actionLabel, target);
        }
        return false;
    }

    QStringList errors;
    bool ok = true;
    for (const QStringList& cmd : addressDnsCommands) {
        // 命令模板里的 {target} 占位符在调用处替换（各命令参数位置不同）
        QStringList resolved;
        resolved.reserve(cmd.size());
        for (const QString& arg : cmd) {
            resolved << (arg == QLatin1String("{target}") ? target : arg);
        }
        QString err;
        if (!runNetshTolerant(resolved, &err)) {
            qWarning().noquote() << err;
            errors << err;
            ok = false;
        }
    }

    if (ok) {
        QString detail;
        if (!verifyIpv4ConfigImpl(target, expectStatic, ip, mask, gw, dns1, &detail)) {
            errors << detail;
            ok = false;
        }
    }
    if (!ok && errorMsg)
        *errorMsg = errors.join(QLatin1Char('\n'));
    return ok;
}
// 两个入口都必须先把标识转成 netsh 认识的名称：传进来的可能是 {GUID}
// （adapterNameByMac 的历史返回值）或 pcap 设备名。
bool setStaticIp(const QString& winName, const QString& ip, const QString& mask,
                 const QString& gw, const QString& dns1, const QString& dns2,
                 QString* errorMsg)
{
    // 命令模板里的 {target} 由 applyIpv4Config 解析成 netsh 目标名后替换。
    QVector<QStringList> commands = {
        { "interface", "ip", "set", "address", "{target}", "static", ip, mask, gw },
        { "interface", "ip", "set", "dns",     "{target}", "static", dns1 },
    };
    // 备用 DNS 为可选：为空时不再追加（否则 netsh 会收到空参数）
    if (!dns2.isEmpty())
        commands.append({ "interface", "ip", "add", "dns", "{target}", dns2 });

    return applyIpv4Config(winName, commands, /*expectStatic=*/true,
                           ip, mask, gw, dns1,
                           QStringLiteral("写入静态IP"), errorMsg);
}

bool setDhcp(const QString& winName, QString* errorMsg)
{
    const QVector<QStringList> commands = {
        { "interface", "ip", "set", "address", "{target}", "dhcp" },
        { "interface", "ip", "set", "dns",     "{target}", "dhcp" },
    };
    return applyIpv4Config(winName, commands, /*expectStatic=*/false,
                           QString(), QString(), QString(), QString(),
                           QStringLiteral("恢复 DHCP"), errorMsg);
}

} // namespace Network