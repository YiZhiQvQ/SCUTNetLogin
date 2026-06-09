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

---

## 配置项

| 配置项 | 说明 |
|--------|------|
| 账号 / 密码 | 校园网统一认证账号和密码 |
| 记住密码 | 密码以 Base64 保存在程序目录下的 `config.ini` |
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
password=<Base64>
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

- **Visual Studio 2022** + Qt VS Tools（推荐）
- **qmake** 备选：`qmake SCUTNetLogin.pro && nmake`
- Qt 6.11.0 (msvc2022_64)，C++17，MSVC v143
- 依赖：Npcap SDK (`C:\npcap-sdk\`)、OpenSSL (`C:\OpenSSL-Win64\`)

---

## 项目结构

```
src/
├── main.cpp              # 入口：管理员权限检查、单实例、静默启动
├── mainwindow.cpp/h      # UI：布局、系统托盘、网卡列表、配置
├── session_manager.cpp/h # 连接编排：状态机、线程管理、自动重连
├── eap_process.cpp/h     # 802.1X EAPOL 握手（pcap 原始套接字）
├── udp_process.cpp/h     # DrCOM UDP 心跳协议
├── network_worker.cpp/h  # netsh/schtasks 后台线程
├── network.cpp/h         # 网卡枚举、MAC/IP 工具、netsh 封装
├── config_manager.cpp/h  # config.ini 读写、AuthConfig 组装
├── eapol_packet.cpp/h    # EAPOL 帧构造（纯数据，无 I/O）
├── drcom_packet.cpp/h    # DrCOM UDP 包构造 + 校验和（纯数据）
├── log_manager.cpp/h     # 日志文件持久化（按日轮转）
├── protocol.h            # 协议结构体 + AuthConfig/AuthState/UdpState
└── constants.h           # 所有协议常量、魔数、偏移量
```

---

## License

MIT
