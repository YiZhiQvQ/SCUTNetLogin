# SCUTNetLogin — 华南理工大学校园网认证客户端

[![Platform](https://img.shields.io/badge/platform-Windows%20x64-blue)](https://github.com/YiZhiQvQ/SCUTNetLogin)
[![Qt](https://img.shields.io/badge/Qt-6.11.0-green)](https://www.qt.io/)
[![License](https://img.shields.io/badge/license-MIT-orange)](LICENSE)

华南理工大学（SCUT）校园网认证客户端：**有线 802.1X（DrCOM）+ 无线 Web Portal（DrCOM eportal）**，支持 DrCOM 会话保持、系统托盘后台运行、断线自动重连、夜间断网自动恢复。

---

## 功能特性

- **802.1X EAP-MD5 认证**（Ruijie/H3C/DrCOM 私有扩展）
- **无线 Web Portal 认证**（scut-student 等校园 Wi-Fi）：自动识别门户、模拟浏览器登录、上线确认（`online_list` 官方接口轮询），校园网 0:00 强制登出后晨间自动再登
- **自动连接（有线优先）**：网线插入→有线 802.1X；未插网线且当前 Wi-Fi 命中白名单→无线 Portal；无需手动选择（无线 SSID 白名单可配置，默认 `scut-student`，留空=任一 Wi-Fi）
- **DrCOM UDP 心跳保活**（MiscAlive → MiscInfo → Alive 协议，仅有线）
- **静态 IP 自动配置**：认证前设置静态 IP/DNS，断开后恢复 DHCP（无线 Portal 场景自动忽略，Portal 基于 DHCP 地址）
- **断线自动重连**：被服务器踢下线后自动重试（夜间 0:00-6:00 等待至 6:00，其余时段每 5 分钟重试）
- **系统托盘后台运行**：最小化到托盘，开机自启动
- **日志持久化**：按日轮转写入 `log/SCUTNetLogin_YYYY-MM-DD.log`
- **现代 Fluent 风格界面**：圆角卡片布局、分段式标签、自绘状态指示器（断开=灰环 / 连接中=蓝色旋转动画 / 已连接=绿色对勾）、账号密码直连无需切换标签页

---

## 界面概览

主界面分「连接」与「设置」两个标签页：

- **连接**：顶部状态指示器 + 状态文案 + 当前连接模式；账号 / 密码（回车即连接）；主按钮「连接」与「断开」；底部深色运行日志（一键复制 / 清空）
- **设置**：有线网络配置（网卡刷新、MAC、静态 IP/DNS、认证服务器）、无线网络配置（无线网络名称白名单、退出时注销无线连接）、自动化（开机自启动 / 启动后自动连接）、保存配置

---

## 环境要求

- Windows 10 / 11 x64
- [Npcap](https://npcap.com/)（安装时勾选 **"Support raw 802.1X traffic"**）
- 管理员权限（发送原始 802.1X 以太网帧需要）

> WinPcap 不支持，必须安装 Npcap。

---

## 使用说明

1. **以管理员身份运行**程序
2. 填写校园网账号（学号）和密码
3. 在「设置」中确认「无线网络名称」白名单包含当前校园 Wi-Fi（默认 `scut-student`，多个用逗号分隔，留空=任意）
4. **有线**：选择对应的网卡，程序自动检测 IP/掩码/网关/MAC；如需静态 IP 勾选「连接时配置静态IP，断开时恢复DHCP」
5. 点击**连接**——连接方式**自动**：网线插入走有线 802.1X；未插网线且 Wi-Fi 命中白名单走无线 Portal（无线基于 DHCP 地址，自动忽略静态 IP 配置）
连接成功后程序可最小化到系统托盘后台运行。被服务器夜间强制踢下线后会自动等待到早上 6:00 重连（有线/无线一致）。

> **关于无线认证**：程序自动跟随校园网网关重定向（AC 302 → 门户 a79.htm → Dr.COM eportal），模拟浏览器登录并轮询官方 `online_list` 接口确认上线后才判定"已连接"。各校区门户地址/参数不同会自动动态发现，无需手工配置。已知限制：学校门户的"注销"可能被门户自动登录（Auto-Login cookie）立即抢回，因此断开按钮执行 **门户 mac/unbind 解绑下线**（不做物理断链，Wi-Fi 连接交给系统/用户自行管理）；重连请点「连接」或重新接入 Wi-Fi。

> **关于夜间重连与待机**："6:00 自动重试"是程序运行中的定时排程。若电脑**睡眠/待机**过夜，
> 唤醒后程序会立即用墙钟重新检查排程——已过 6:00 则马上重连、仍在夜间则重排到 6:00。
> 若电脑**关机**过夜，请配合「开机自启动」（+ schtasks 静默启动即自动连接）使用。

> **关于心跳超时**：部分校区/网络的 DrCOM 服务器**不回复** UDP 心跳包，但网络连接实际正常。
> 因此本程序**不会**因为心跳超时触发断连或自动重连——心跳超时仅被静默忽略，
> 断线检测只依赖 EAP 层失败（认证被拒、服务器踢线）。这是有意设计，避免学校服务器
> 不响应心跳导致频繁误断线。

---

## 配置项

| 配置项 | 说明 |
|--------|------|
| 账号 / 密码 | 校园网统一认证账号和密码（有/无线通用） |
| 记住密码 | 密码经 Windows DPAPI 加密后保存在程序目录下的 `config.ini` |
| 无线网络名称 | SSID 白名单（逗号分隔，留空=任意；默认 `scut-student`；连接方式固定为自动：有线优先、无线兜底；位于设置页） |
| 网卡 | 选择用于认证的有线网卡，点击刷新重新扫描 |
| MAC 地址 | 留空自动获取 |
| IPv4 地址 / 子网掩码 / 默认网关 | 静态 IP 参数（勾选静态 IP 时必填） |
| 主 DNS / 备用 DNS | 默认 `202.38.193.33` |
| 认证服务器 | 默认 `s.scut.edu.cn` |
| 连接时配置静态IP | 认证前设置静态 IP/DNS，断开后恢复 DHCP |
| 开机自启动 | 通过 Windows 计划任务实现（`schtasks`） |
| 启动后自动连接 | 打开程序自动发起认证 |
| 退出时注销无线连接 | 勾选后关闭程序会对无线执行注销下线；不勾选则保持在线（默认） |

---

## 常见错误

| 错误信息 | 含义 |
|----------|------|
| `userid error 1` | 账号不存在 |
| `userid error 2/3` | 用户名或密码错误 |
| `userid error 4/9` | 账号已欠费或过期 |
| `ErrCode=5` | 账号已被停用 |
| `ErrCode=11` | 不允许进行 RADIUS 认证 |
| `ErrCode=16` | 当前时段禁止上网（夜间断网，程序将自动等待到 6:00 重连） |
| `ErrCode=30/63` | 流量 / 时长已用尽 |
| `flowover` | 流量用完 |
| `In use` | 账号已在其他设备登录 |
| `AdminReset` | 管理员已重置连接 |
| `Mac, IP, NASip, PORT` | 当前 IP/MAC 地址不允许登录 |
| 打开网卡失败 | Npcap 未安装或网卡被其他程序占用 |
| 无线: 未取到 Wi-Fi 网关 / 未连接校园 Wi-Fi | 未连接白名单内 Wi-Fi，或 Wi-Fi 未获得 DHCP 地址 |
| 无线: 门户页面解析失败 | 门户结构变化（罕见），等待自动重试或检查网络 |
| 无线: 当前时段禁止使用（code=-5） | 校园网 0:00-6:00 断网时段，程序会等待到 6:00 自动重试 |

---

## 命令行参数

| 参数 | 说明 |
|------|------|
| `--silent` / `-s` / `--minimized` | 静默启动，不显示窗口，直接最小化到托盘 |

用于开机自启场景（配合 `schtasks`）。

---

## 配置文件

配置保存在程序同目录下的 `config.ini`：

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

> `connectMode`（auto/wired/wireless）为历史遗留键：模式切换功能已移除，程序恒按"自动（有线优先）"运行，旧值仅向后兼容保留。

---

## 构建

- **Visual Studio 2022** + Qt VS Tools（推荐）。仓库不含 `.sln`/`.vcxproj`（由 Qt VS Tools 从 `.pro` 生成，不入库）：在 Qt VS Tools 中直接打开 `SCUTNetLogin.pro` 生成工程后构建
  > ⚠️ 管理员清单（requireAdministrator + Common-Controls）由 `src/app.rc` 嵌入 `src/app.manifest`；qmake 路径默认嵌入。VS/Qt VS Tools 路径会让 linker 自动生成 manifest，需在生成工程的 **RC 预处理定义**里加上 `NO_EMBED_MANIFEST` 以避免 `CVT1100: MANIFEST 资源重复`（若重新生成 `.vcxproj` 需重新加上）。
- **qmake** 备选：`qmake SCUTNetLogin.pro && nmake release`
- Qt 6.11.0 (msvc2022_64)，C++17，MSVC v143
- 依赖：Npcap SDK (`C:\npcap-sdk\`)；单元测试无需 Npcap SDK

### 安装包

自包含安装器 `release\SCUTNetLogin-Setup.exe`（免提权打包，内嵌 exe + Qt/VC 运行库 + 安装/卸载 + 快捷方式 + Npcap 检测）：

```powershell
# 先 build Release，再：
powershell -File tools\installer\build_installer.ps1
```

> 说明：安装器本体是 `tools\installer\Installer.cs`（C# WinForms，用系统自带 `csc` 编译，零外部依赖）。
> 运行时依赖（`Qt6*.dll` + `plugins\` + VC 运行库）由脚本手动收集进内嵌 zip；
> 部署目录带 `qt.conf`（`Prefix=.`，`Plugins=plugins`）保证离线环境下插件路径解析正确。

### 单元测试

协议纯函数（封包构造 / 帧解析 / 校验和 / 加解密 / 字节工具 / 连接校验 / 服务器通知解析 /
配置回环 / 无线门户解析与接入后端决策）有 QtTest 回归护栏，无线侧覆盖 a79.htm 变量解析、
online_list 查询构造、GBK 错误文案分类（密码错误→不可重试）、会话归属校验、SSID 白名单；
全量测试用例见 `tests/tst_packets.cpp`（夹具 `tests/wifi_fixtures.h` 为实测抓取的真实协议响应样本）：

```
cd tests
qmake tst_packets.pro && nmake release
.\release\tst_packets.exe
```

---



## 项目结构

```
src/
├── main.cpp              # 入口：管理员权限检查、单实例、静默启动
├── app.rc / app.manifest # 管理员清单（requireAdministrator）经 .rc 嵌入
├── ui/                   # UI：布局、系统托盘、网卡列表、配置（mainwindow.cpp/h/ui）
├── core/                 # 连接编排与共享纯逻辑
│   ├── session_manager.cpp/h   # 状态机、线程管理、自动重连（编排层）
│   ├── connection_builder.cpp/h # 连接前校验 + 接入后端决策（纯逻辑，无 pcap/UI 依赖）
│   ├── byte_utils.cpp/h        # 字节工具纯函数（MAC/IP 归一化等）
│   ├── deferred_signals.h      # 工作线程"持锁缓冲信号、解锁统一发射"共享队列
│   ├── protocol.h              # 协议结构体 + AuthConfig/AuthState/ConnectMode + StaticIpConfig
│   ├── constants.h             # 所有协议常量、魔数、偏移量（含无线 Portal 常量）
│   └── log_level.h             # 日志级别常量
├── config/               # config.ini 读写（ConfigManager，含 ToAuthConfig）+ DPAPI（credential）
├── eap/                  # 有线 802.1X
│   ├── eap_process.cpp/h           # EAPOL 握手（pcap 原始套接字）
│   ├── eapol_packet.cpp/h          # EAPOL 帧构造 + EAP 帧解析（纯数据，无 I/O）
│   └── notification_parser.cpp/h   # 服务器通知解析（纯函数，数据驱动查表）
├── udp/                  # DrCOM UDP 心跳（有线）
│   ├── udp_process.cpp/h
│   └── drcom_packet.cpp/h          # 包构造 + 校验和（纯数据）
├── wifi/                 # 无线 Portal 认证（Dr.COM eportal）
│   ├── webauth_process.cpp/h       # 无线认证工作线程：探测→门户→登录→上线确认→轮询
│   ├── portal_parser.cpp/h         # 门户解析/查询构造/响应判定/归属校验（纯函数）
│   └── wlan_media.cpp/h            # wlanapi/iphlpapi：Wi-Fi 接口查询、默认网关
├── network/              # 通用网络：网卡枚举、适配器查找、netsh 封装、有线链路检测
│   ├── network.cpp/h              # pcap/适配器/MAC/networks + ethernetLinkUp
│   └── network_worker.cpp/h       # 后台线程执行 netsh/schtasks
└── log/                  # 日志文件持久化（按日轮转，log_manager.cpp/h）

res/                     # 资源：style.qss（界面样式）、resources.qrc、SCUTnetwork.ico、check.svg
tools/installer/         # 安装包：Installer.cs + Installer.manifest + build_installer.ps1
tests/                   # 协议纯函数回归测试（QtTest：封包/解析/校验和/连接校验/
                         # 无线门户解析/查询构造/响应判定/后端决策），夹具为实测抓取样本
docs/                    # 无线认证协议文档 + 实施方案（实测逆向记录）
```

---

## License

MIT
