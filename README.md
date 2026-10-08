# SCUTNetLogin

[![Platform](https://img.shields.io/badge/platform-Windows%20x64-blue)](https://github.com/YiZhiQvQ/SCUTNetLogin)
[![Qt](https://img.shields.io/badge/Qt-6.11.0-green)](https://www.qt.io/)
[![License](https://img.shields.io/badge/license-MIT-orange)](LICENSE)

华南理工大学校园网认证客户端。支持**有线 802.1X（DrCOM）**与**无线 Web Portal（Dr.COM eportal）**两种接入方式，自动选择、断线重连、托盘后台运行。

---

## 功能特性

- **双模式自动接入** — 网线已插入走有线 802.1X（EAP-MD5，Ruijie/H3C/DrCOM 变体）；否则命中 SSID 白名单的 Wi-Fi 走无线 Portal 自动登录，无需手动选择
- **断线自动重连** — 被服务器踢下线后自动重试；夜间 0:00–6:00 断网时段等待至 6:01 再连（有线/无线一致）
- **可取消的等待** — 等待网线/校园 Wi-Fi、以及认证失败后的自动重试期间显示「等待网络...」，按钮变为「取消」，点一下即结束等待（不再自动重连，直到再次点「连接」）
- **系统托盘后台运行** — 最小化到托盘，支持开机自启（Windows 计划任务）
- **静态 IP 支持** — 认证前配置静态 IP/DNS；有线认证失败、断开或退出程序都会恢复 DHCP（无线基于 DHCP，自动忽略）
- **DrCOM UDP 心跳保活** — 可选，默认关闭，仅有线
- **Fluent 风格界面** — 圆角卡片布局、自绘状态指示器（断开=灰环 / 连接中=蓝色旋转 / 已连接=绿色对勾）
- **日志持久化** — 按日轮转写入 `log/SCUTNetLogin_YYYY-MM-DD.log`

## 环境要求

- Windows 10 / 11 x64
- [Npcap](https://npcap.com/)（安装时勾选 **Support raw 802.1X traffic**）— WinPcap 不支持
- 管理员权限（发送原始 802.1X 以太网帧需要）

## 快速开始

1. 以**管理员身份**运行程序
2. 填写校园网账号（学号）与密码，点击**连接**

连接方式全自动：有线优先，无线兜底。

首次使用建议在「设置」中确认：

- **无线网络名称** — SSID 白名单，默认 `scut-student`，多个用逗号分隔，留空=任意 Wi-Fi
- **网卡** — 选择用于认证的有线网卡，程序自动检测 IP/掩码/网关/MAC
- 按需开启**静态 IP**、**开机自启动**、**DrCOM UDP 心跳保活**

### 界面

主界面分两个标签页：

| 标签页 | 内容 |
|--------|------|
| **连接** | 状态指示器 + 状态文案 + 当前连接模式；账号 / 密码（回车即连接）；连接 / 断开；底部运行日志（一键复制 / 清空） |
| **设置** | 有线网络（网卡刷新、MAC、静态 IP/DNS、认证服务器）；无线网络（SSID 白名单、退出时注销）；自动化（开机自启动、启动后自动连接）；保存配置 |

## 注意事项

- **无线「断开」= 解绑下线**：校园门户的 Auto-Login cookie 会在页面加载时立即抢回登录，因此断开按钮执行门户 `mac/unbind` 解绑下线，不做物理断链（Wi-Fi 连接交给系统/用户管理）。重连请点「连接」或重新接入 Wi-Fi。
- **心跳超时不断线**：部分校区的 DrCOM 服务器不回复 UDP 心跳包但网络实际正常，因此心跳超时仅被静默忽略，断线检测只依赖 EAP 层失败（认证被拒、服务器踢线）。这也是 UDP 保活**默认关闭**的原因——有线认证只需 802.1X，EAP 成功即已放行交换机端口；关闭时程序完全不启动 UDP 线程。
- **夜间断网与待机**：0:00–6:00 被拒后程序等待至 6:01 重连（6:00 整点仍会被服务端拒绝）。若电脑**睡眠**过夜，唤醒后按墙钟时间重新检查排程（已过 6:01 立即重连）；若**关机**过夜，请配合「开机自启动」（`--silent` + schtasks）使用。
- **有线认证的时机**：静态 IP 配置、网卡与本机 IP/MAC 都在**真正发起有线认证的时刻**才确定。因此「先启动程序、后插网线」时，首次自动认证就会带上正确的静态 IP 与地址，不需要手动再点一次「连接」。
- **未勾选「启动后自动连接」时不检测网卡**：启动阶段不做任何网卡枚举/自动填充；首次切到「设置」页、点「刷新」或点「连接」时才检测（点「连接」会在检测完成后自动继续）。Wi-Fi 侧启动期同样不做任何探测。
- **无线认证细节**：程序自动跟随校园网网关重定向（AC 302 → 门户 a79.htm → Dr.COM eportal）模拟浏览器登录，并轮询官方 `online_list` 接口确认上线后才判定「已连接」。各校区门户地址/参数会自动动态发现，无需手工配置。

## 配置项

| 配置项 | 说明 |
|--------|------|
| 账号 / 密码 | 校园网统一认证账号和密码（有/无线通用） |
| 记住密码 | 密码经 Windows DPAPI 加密后保存在程序目录下的 `config.ini` |
| 无线网络名称 | SSID 白名单，逗号分隔，留空=任意（默认 `scut-student`） |
| 网卡 / MAC | 认证用有线网卡；MAC 留空时在需要静态 IP 的连接中自动补取（离线可用，不要求已插网线） |
| IPv4 / 掩码 / 网关 / DNS | 静态 IP 参数，勾选「连接时配置静态IP」时必填；DNS 默认 `202.38.193.33`。是否真的写入网卡由认证时刻决定（有线失败即恢复 DHCP） |
| 认证服务器 | 默认 `s.scut.edu.cn`，**仅 DrCOM 心跳启用时生效**（有线认证走二层 EAPOL，与服务器地址无关），关闭时置灰 |
| DrCOM UDP 心跳保活 | **默认关闭**。SCUT 现行网络由 802.1X/RADIUS 维持会话；仅当某校区网络确实依赖 UDP 保活时才勾选。开启后下次连接生效，取消勾选立即停止 |
| 开机自启动 | 通过 Windows 计划任务（`schtasks`）实现 |
| 启动后自动连接 | 打开程序自动发起认证；**未勾选时启动阶段不检测网卡/Wi-Fi**，首次需要时（设置页/刷新/连接）才检测 |
| 退出时注销无线连接 | 勾选后关闭程序对无线执行注销下线；默认不勾选（保持在线） |

## 常见错误

| 错误信息 | 含义 |
|----------|------|
| `userid error 1` | 账号不存在 |
| `userid error 2/3` | 用户名或密码错误 |
| `userid error 4/9` | 账号已欠费或过期 |
| `ErrCode=5` | 账号已被停用 |
| `ErrCode=11` | 不允许进行 RADIUS 认证 |
| `ErrCode=16` | 当前时段禁止上网（夜间断网，程序将自动等待到 6:01 重连） |
| `ErrCode=30/63` | 流量 / 时长已用尽 |
| `flowover` | 流量用完 |
| `In use` | 账号已在其他设备登录 |
| `AdminReset` | 管理员已重置连接 |
| `Mac, IP, NASip, PORT` | 当前 IP/MAC 地址不允许登录 |
| 打开网卡失败 | Npcap 未安装或网卡被其他程序占用 |
| 无线: 未取到 Wi-Fi 网关 / 未连接校园 Wi-Fi | 未连接白名单内 Wi-Fi，或 Wi-Fi 未获得 DHCP 地址 |
| 无线: 门户页面解析失败 | 门户结构变化（罕见），等待自动重试或检查网络 |
| 无线: 当前时段禁止使用（code=-5） | 校园网 0:00–6:00 断网时段，程序会等待到 6:01 自动重试 |
| 等待网络... | 正在等待网线插入或校园 Wi-Fi 连接（此时按钮为「取消」，可结束等待） |

## 命令行参数

| 参数 | 说明 |
|------|------|
| `--silent` / `-s` / `--minimized` | 静默启动：不显示窗口，直接最小化到托盘并自动连接 |

用于开机自启场景（配合 `schtasks`）。

## 配置文件

配置保存在程序同目录下的 `config.ini`，密码经 DPAPI 加密（非明文 / Base64 原文）：

```ini
[General]
username=你的学号
password=<Base64(DPAPI密文)>
host=s.scut.edu.cn
dns=202.38.193.33
interface=\Device\NPF_{GUID}
manualMac=
manualIp=
manualMask=255.255.255.0
manualGateway=
backupDns=
autoSetNetwork=false
autoStart=false
autoConnect=false
logoutOnExit=false
wifiSsids=scut-student
```

> `connectMode`（auto/wired/wireless）为历史遗留键：模式切换功能已移除，程序恒按「自动（有线优先）」运行，旧值仅向后兼容保留。

## 构建

**Visual Studio 2022 + Qt VS Tools**（推荐）：在 Qt VS Tools 中打开 `SCUTNetLogin.pro` 生成工程后构建（`.sln`/`.vcxproj` 由工具生成，不入库）。

> ⚠️ 管理员清单（requireAdministrator + Common-Controls）由 `src/app.rc` 嵌入 `src/app.manifest`。VS 路径会让 linker 自动生成 manifest，需在生成工程的 **RC 预处理定义**中加上 `NO_EMBED_MANIFEST`，否则报 `CVT1100: MANIFEST 资源重复`（重新生成 `.vcxproj` 后需重新添加）。

**qmake 备选**：`qmake SCUTNetLogin.pro && nmake release`

- Qt 6.11.0 (msvc2022_64)，C++17，MSVC v143
- 依赖：Npcap SDK（`C:\npcap-sdk\`）；单元测试无需 Npcap SDK

### 安装包

自包含安装器 `release\SCUTNetLogin-Setup.exe`（内嵌 exe + Qt/VC 运行库 + 安装/卸载 + 快捷方式 + Npcap 检测）：

```powershell
# 先 build Release，再：
powershell -File tools\installer\build_installer.ps1
```

> 安装器本体为 `tools\installer\Installer.cs`（C# WinForms，用系统自带 `csc` 编译，零外部依赖）。运行时依赖由脚本收集进内嵌 zip；部署目录带 `qt.conf`（`Prefix=.`、`Plugins=plugins`）保证离线环境插件路径解析正确。

### 单元测试

协议纯函数（封包构造 / 帧解析 / 校验和 / 加解密 / 字节工具 / 连接校验 / 服务器通知解析 / 配置回环 / 无线门户解析与接入后端决策）有 QtTest 回归护栏；无线侧覆盖 a79.htm 变量解析、`online_list` 查询构造、GBK 错误文案分类（密码错误→不可重试）、会话归属校验、SSID 白名单。用例见 `tests/tst_packets.cpp`，夹具 `tests/wifi_fixtures.h` 为实测抓取的真实协议响应样本。

```
cd tests
qmake tst_packets.pro && nmake release
.\release\tst_packets.exe
```

## 项目结构

```
src/
├── main.cpp                    # 入口：管理员权限检查、单实例、静默启动
├── app.rc / app.manifest       # 管理员清单（requireAdministrator）经 .rc 嵌入
├── ui/                         # 布局、系统托盘、网卡列表、配置（mainwindow）
├── core/                       # 连接编排与共享纯逻辑
│   ├── session_manager         # 状态机、线程管理、自动重连（编排层）
│   ├── connection_builder      # 连接前校验 + 接入后端决策（纯逻辑）
│   ├── byte_utils              # 字节工具纯函数（MAC/IP 归一化等）
│   ├── deferred_signals.h      # 工作线程"持锁缓冲信号、解锁统一发射"共享队列
│   ├── protocol.h              # 协议结构体 + AuthConfig/AuthState/ConnectMode
│   └── constants.h             # 全部协议常量、魔数、偏移量（单一事实来源）
├── config/                     # config.ini 读写（ConfigManager）+ DPAPI（credential）
├── eap/                        # 有线 802.1X：EAPOL 握手、帧构造/解析、服务器通知解析
├── udp/                        # DrCOM UDP 心跳：包构造 + 校验和（有线）
├── wifi/                       # 无线 Portal：认证工作线程、门户解析（纯函数）、wlanapi 封装
├── network/                    # 网卡枚举、适配器查找、netsh 封装、有线链路检测
└── log/                        # 日志文件持久化（按日轮转）
res/                            # style.qss、resources.qrc、图标
tools/installer/                # 安装包：Installer.cs + 构建脚本
tests/                          # 协议纯函数回归测试（QtTest，夹具为实测样本）
docs/                           # 无线认证协议文档 + 实施方案（实测逆向记录）
```

## License

MIT
