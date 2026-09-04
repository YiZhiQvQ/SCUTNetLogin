# SCUTNetLogin — 华南理工大学校园网有线认证客户端

[![Platform](https://img.shields.io/badge/platform-Windows%20x64-blue)](https://github.com/YiZhiQvQ/SCUTNetLogin)
[![Qt](https://img.shields.io/badge/Qt-6.11.0-green)](https://www.qt.io/)
[![License](https://img.shields.io/badge/license-MIT-orange)](LICENSE)

华南理工大学（SCUT）校园网有线 802.1X 认证客户端，支持 DrCOM 会话保持、系统托盘后台运行、断线自动重连。

---

## 功能特性

- **802.1X EAP-MD5 认证**（Ruijie/H3C/DrCOM 私有扩展）
- **DrCOM UDP 心跳保活**（MiscAlive → MiscInfo → Alive 协议）
- **静态 IP 自动配置**：认证前设置静态 IP/DNS，断开后恢复 DHCP
- **断线自动重连**：被服务器踢下线后自动重试（夜间 0:00-6:00 等待至 6:00，其余时段每 5 分钟重试）
- **系统托盘后台运行**：最小化到托盘，开机自启动
- **日志持久化**：按日轮转写入 `log/SCUTNetLogin_YYYY-MM-DD.log`
- **现代 Fluent 风格界面**：圆角卡片布局、分段式标签、自绘状态指示器（断开=灰环 / 连接中=蓝色旋转动画 / 已连接=绿色对勾）、账号密码直连无需切换标签页

---

## 界面概览

主界面分「连接」与「设置」两个分段式标签：

- **连接**：顶部状态指示器 + 状态文案；账号 / 密码（回车即连接）；主按钮「连接」与「断开」；底部深色运行日志（一键复制 / 清空）
- **设置**：网络与网卡配置（网卡刷新、MAC、静态 IP/DNS）、认证服务器、自动化（开机自启动 / 启动后自动连接）、保存配置

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
3. 选择对应的有线网卡，程序会自动检测 IP、子网掩码、网关、MAC
4. 如需静态 IP，勾选「连接时配置静态IP，断开时恢复DHCP」并填写网络参数
5. 点击**连接**

连接成功后程序可最小化到系统托盘后台运行。被服务器夜间强制踢下线后会自动等待到早上 6:00 重连。

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
| 账号 / 密码 | 校园网统一认证账号和密码 |
| 记住密码 | 密码经 Windows DPAPI 加密后保存在程序目录下的 `config.ini` |
| 网卡 | 选择用于认证的有线网卡，点击刷新重新扫描 |
| MAC 地址 | 留空自动获取 |
| IPv4 地址 / 子网掩码 / 默认网关 | 静态 IP 参数（勾选静态 IP 时必填） |
| 主 DNS / 备用 DNS | 默认 `202.38.193.33` |
| 认证服务器 | 默认 `s.scut.edu.cn` |
| 连接时配置静态IP | 认证前设置静态 IP/DNS，断开后恢复 DHCP |
| 开机自启动 | 通过 Windows 计划任务实现（`schtasks`） |
| 启动后自动连接 | 打开程序自动发起认证 |

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
```

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
配置回环）有 QtTest 回归护栏，全量测试用例见 `tests/tst_packets.cpp`：

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
├── mainwindow.cpp/h      # UI：布局、系统托盘、网卡列表、配置
├── session_manager.cpp/h # 连接编排：状态机、线程管理、自动重连
├── connection_builder.cpp/h # 连接前校验（纯逻辑，无 pcap/UI 依赖）
├── byte_utils.cpp/h      # 字节工具纯函数（MAC/IP 归一化等）
├── deferred_signals.h    # 工作线程"持锁缓冲信号、解锁统一发射"共享队列
├── credential.cpp/h      # 密码 DPAPI 加密/解密（CryptProtectData）
├── eap_process.cpp/h     # 802.1X EAPOL 握手（pcap 原始套接字）
├── notification_parser.cpp/h # 服务器通知解析（纯函数，数据驱动查表）
├── udp_process.cpp/h     # DrCOM UDP 心跳协议
├── network_worker.cpp/h  # netsh/schtasks 后台线程
├── network.cpp/h         # 网卡枚举、MAC/IP 工具、netsh 封装
├── config_manager.cpp/h  # config.ini 读写、AuthConfig 组装
├── eapol_packet.cpp/h    # EAPOL 帧构造 + EAP 帧解析（纯数据，无 I/O）
├── drcom_packet.cpp/h    # DrCOM UDP 包构造 + 校验和（纯数据）
├── log_manager.cpp/h     # 日志文件持久化（按日轮转）
├── protocol.h            # 协议结构体 + AuthConfig/AuthState + StaticIpConfig
└── constants.h           # 所有协议常量、魔数、偏移量

res/                     # 资源：style.qss（界面样式）、resources.qrc、SCUTnetwork.ico、check.svg
tools/installer/         # 安装包：Installer.cs + Installer.manifest + build_installer.ps1
tests/tst_packets.pro/cpp # 协议纯函数回归测试（QtTest）
```

---

## License

MIT
