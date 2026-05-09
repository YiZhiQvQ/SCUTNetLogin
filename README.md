# SCUTNetLogin — 华南理工大学校园网有线认证客户端

[![Platform](https://img.shields.io/badge/platform-Windows%20x64-blue)](https://github.com/TheJuneSky/SCUTnetwork)
[![Qt](https://img.shields.io/badge/Qt-6.11.0-green)](https://www.qt.io/)
[![License](https://img.shields.io/badge/license-MIT-orange)](LICENSE)

华南理工大学（SCUT）校园网有线认证客户端，支持 802.1X 认证和 DrCOM 会话保持，系统托盘后台运行。

---

## 使用说明

### 环境要求

- Windows 10 / 11 x64
- [Npcap](https://npcap.com/)（安装时勾选 **"Support raw 802.1X traffic"**）
- 管理员权限（发送原始以太网帧需要）

> 不支持 WinPcap，必须安装 Npcap。

### 安装

从 [Releases](https://github.com/TheJuneSky/SCUTnetwork/releases) 下载 `SCUTNetLogin_Setup.exe`，运行安装向导即可。桌面和开始菜单会自动创建快捷方式。

### 基本使用

1. **以管理员身份运行**程序
2. 在「设置」页填写校园网账号（学号）和密码
3. 选择对应的有线网卡（程序会自动检测 IP、子网掩码、网关、MAC）
4. 如需静态 IP，勾选「连接时配置静态IP，断开时恢复DHCP」并填写网络参数
5. 切换到「连接」页，点击**连接**

连接成功后程序可最小化到系统托盘后台运行。

### 命令行参数

```bash
SCUTNetLogin.exe --silent     # 静默启动，隐藏窗口，自动连接
SCUTNetLogin.exe -s           # 同上
```

### 配置项说明

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
| 开机自启动 | 通过 Windows 计划任务实现 |
| 启动后自动连接 | 打开程序自动发起认证 |

### 配置文件

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

### 常见错误

| 错误信息 | 含义 |
|----------|------|
| `userid error 1` | 账号不存在 |
| `userid error 2/3` | 用户名或密码错误 |
| `userid error 4` | 账号可能已欠费 |
| `ErrCode=5` | 账号已被停用 |
| `ErrCode=9` | 账号可能已过期 |
| `ErrCode=16` | 当前时段禁止上网 |
| `ErrCode=30/63` | 流量 / 时长已用尽 |
| `flowover` | 流量用完 |
| `In use` | 账号已在其他设备登录 |
| 打开网卡失败 | Npcap 未安装或网卡被其他程序占用 |

---

## 从源码构建

### 依赖

| 依赖 | 版本 / 说明 |
|------|-------------|
| Visual Studio 2022 | MSVC v143 工具链 |
| Qt | 6.11.0（msvc2022_64） |
| [Npcap SDK](https://npcap.com/#download) | 安装到 `C:/npcap-sdk/` |

### 构建

```bash
# 1. 生成 VS 解决方案
qmake -tp vc SCUTNetLogin.pro -spec win32-msvc CONFIG+=release

# 2. 打开 SCUTNetLogin.sln，Visual Studio 中选择 Release | x64 生成

# 3. 部署 Qt 依赖
windeployqt --release --no-compiler-runtime release/SCUTNetLogin.exe
```

### 项目结构

```
SCUTnetwork/
├── src/
│   ├── main.cpp              # 入口，命令行解析
│   ├── mainwindow.h/cpp      # 主窗口、状态管理
│   ├── mainwindow.ui         # Qt Designer 布局
│   ├── eap_process.h/cpp     # 802.1X/EAPOL 认证
│   ├── udp_process.h/cpp     # DrCOM UDP 心跳
│   ├── network.h/cpp         # 网卡查找、netsh 操作
│   ├── protocol.h            # 协议结构体定义
│   ├── constants.h           # 协议常量与配置默认值
│   └── app.rc                # 应用图标资源
├── res/
│   ├── resources.qrc         # Qt 资源索引
│   ├── style.qss             # 全局样式表
│   ├── SCUTnetwork.ico       # 应用图标
│   └── check.svg             # 复选框图标
├── SCUTNetLogin.pro          # qmake 项目文件
└── README.md
```

## 开源协议

MIT License
