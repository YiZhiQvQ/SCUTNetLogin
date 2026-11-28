# 架构说明

面向贡献者与维护者的架构速览。协议细节见 `docs/wifi_auth_logic.md`，构建方式见 `README.md`。

## 进程与线程模型

单进程，主线程跑 Qt 事件循环（UI）；四个长生命周期工作线程由 `SessionManager` 持有：

| 线程 | 对象 | 职责 | 启动时机 |
|---|---|---|---|
| `m_eapThread` | `EapProcess` | 有线 802.1X EAPOL 握手（Npcap 原始套接字） | 首次有线认证（惰性） |
| `m_udpThread` | `UdpProcess` | DrCOM UDP 心跳会话 | 仅在 `drcomHeartbeat` 开启且首次有线认证 |
| `m_networkThread` | `NetworkWorker` | `netsh` / `schtasks` 等阻塞系统调用 | 构造时立即启动 |
| `m_wifiThread` | `WebAuthProcess` | 无线 Portal 认证（HTTPS 登录 + 在线确认轮询） | 首次无线认证（惰性） |

另有**一个独立的 std::thread**：`HangWatch`（`core/watchdog.cpp`）。它不依赖 Qt 事件循环，
主线程每 2 秒心跳一次；超过 15 秒无心跳即判定卡死，写入 `.hang.log`。

### 为什么要独立看门狗线程

本程序的卡死发生在**内核态**（`pcap_activate` / `pcap_next_ex` 在网卡被电源管理挂起或
驱动异常时阻塞）。此时 Qt 的定时器、信号、日志定时器全部停摆，界面不更新、日志停在
最后一行，事后完全无法定位。只有独立线程能在这个状态下继续执行并记录现场。

## 跨线程通信约定

- **一律使用 `QMetaObject::invokeMethod(..., Qt::QueuedConnection)`**，禁止跨线程直调。
- 工作线程在持锁期间**只缓冲信号、不 emit**：用 `DeferredSignalQueue`（`core/deferred_signals.h`），
  解锁后统一按产生顺序发出。若将来把连接改为 `DirectConnection`，持锁 emit 会造成重入死锁。
- **锁的划分**：`EapProcess` 有两把锁——`m_mutex`（会话状态，被 pcap 轮询整轮持有）与
  `m_configMutex`（配置快照）。配置读写**绝不能**等 `m_mutex`，否则 pcap 一卡住主线程就死等
  （这是 2026-11-29 那次"界面无响应且关不掉"的直接原因）。
- **代次防护**：凡是"异步完成后要回来改状态"的路径，都必须捕获发起时的代数
  （`m_startGeneration` / `m_ipSetupGeneration`），回调时发现代数不符即丢弃。

## 状态机

`AppConnectionState`（`core/session_manager.h`）管理应用级流程：

```
Disconnected -> WaitingForNetwork   没有可用后端，或已排程重试（UI 亮「取消」）
            -> SettingNetwork       可选，仅有线且启用静态 IP
            -> Authenticating       有线 EAP 握手
            -> WiFiConnecting       无线 Portal（探测/登录/确认）
            -> Connected
```

不变式：`WaitingForNetwork` 等价于"自动就绪监听或重试排程正在运行"。
进入它的路径只有 `startAutoWait()` 与 `scheduleNextRetry()`；离开它的路径只有
"启动会话"或 `stopConnection()`（用户取消）。

`AuthState`（`core/protocol.h`）是 EAP 层状态机，由收到的 EAP 帧驱动：
`Idle -> SendingStart -> SendingIdentity -> SendingMD5Challenge -> Authenticated`。

## 静态 IP 生命周期

这是历史上最容易出错的一处，因此单独说明。涉及四个状态标志：

| 标志 | 含义 |
|---|---|
| `m_ipCfg` | 用户**意图**（`ip` 非空 = 勾选了静态 IP；`adapterName` 可为空，认证时刻才解析） |
| `m_wasStaticIpSet` | 是否**真的写入过**静态 IP（与意图分离，否则恢复 DHCP 会找不到目标） |
| `m_staticIpAdapter` | 实际被写入静态 IP 的网卡（与 `m_ipCfg.adapterName` 分离） |
| `m_staticIpPending` | 写入请求在途（丢弃错序的 DHCP 回执） |

规则：

1. **每一条放弃路径**都必须调用 `restoreDhcp()`（认证失败、后端未决定、无线回退、
   用户断开/取消/退出、析构安全网）。漏掉任何一条，静态 IP 就会残留在用户机器上。
2. 析构里用 `BlockingQueuedConnection` 兜底恢复一次，确保进程被强杀前的最后机会。
3. 恢复失败时触发 `purgeStaleCampusIpConfig()` 自愈，而不是静默失败。
4. 写入与恢复都**回读校验**（`verifyIpv4ConfigImpl`），只信读回来的结构化数据，
   不信 netsh 的退出码。

## 链路监视

主路径是 `NotifyIpInterfaceChange`（系统回调，零轮询）；`LinkMonitor` 包装它并转成 Qt 信号。
注册失败时退化为 2 秒轮询（`LINK_POLL_INTERVAL_MS`）。注册成功时仍保留 20 秒低频复核
（`LINK_RESYNC_INTERVAL_MS`）作为漏事件保险。

## EAP 轮询频率

`m_pollTimer` 的频率随会话阶段自适应（`core/constants.h`）：

| 阶段 | 间隔 | 理由 |
|---|---|---|
| 握手期 | 20 ms | 需要尽快响应交换机，实测 1–2 秒完成认证 |
| 稳态（已认证） | 200 ms | 仍需轮询——交换机定期发 EAP-Request/Identity 探活，不回应会被踢；但不需要 50 Hz |

切到稳态的时机是收到 `EAP-Success`；任何 `EAP-Request` 到达时立即切回 20 ms。

> 注意：稳态轮询**不是空转**。`handleEapRequest` 对已认证状态下的 Identity 请求会静默回应，
> 这是维持在线状态的必要机制。不要因为"看起来没做事"就把它停掉。

## 模块划分

| 目录 | 职责 | 是否有单元测试 |
|---|---|---|
| `core/` | 状态机、连接决策、纯逻辑、看门狗 | `connection_builder` / `retry_policy` / `byte_utils` / `deferred_signals` 有 |
| `eap/` | EAPOL 帧构造解析、握手、服务器通知解析 | `eapol_packet` / `notification_parser` 有 |
| `udp/` | DrCOM 包构造、校验和、心跳 | `drcom_packet` 有 |
| `wifi/` | Portal 解析（纯）、认证工作线程、wlanapi 封装 | `portal_parser` 有 |
| `network/` | 适配器枚举、netsh 封装、链路检测、诊断 | 无（依赖系统 API） |
| `config/` | INI 读写、DPAPI 加解密 | 有 |
| `ui/` | 仅布局与用户交互 | 无 |
| `log/` | 按日轮转的文件日志 | 无 |

## 已知的可测试性缺口

涉及系统调用的模块（`eap_process` / `udp_process` / `webauth_process` / `network` /
`session_manager`）目前**没有自动化测试**，因为它们直接调用 Win32 / Npcap API 且不可注入。

近期的严重 Bug 全部落在这个盲区（网卡名映射、网关标志位、跨线程锁、pcap 阻塞、注册表值类型）。
补测需要先引入三个最小注入口：netsh 执行、时钟、适配器快照。

在此之前，这些模块靠 `docs/manual_test_checklist.md` 的手工清单把关。

## 编码约定

- `.ps1` / `.bat` 脚本一律**纯 ASCII**。Windows PowerShell 5.1 会把无 BOM 的 UTF-8 按
  GBK 读取，中文注释会吞掉后面的引号导致语法错误（`tools/build_installer.ps1` 顶部有同样的警告）。
- 所有时间常量放 `core/constants.h`，不要散落在调用处。
- 跨模块的字符串比较注意大小写与花括号差异：`GetAdaptersAddresses` 的 `AdapterName`
  **不带**花括号，注册表 `NetCfgInstanceId` **带**花括号。
- Qt 6 的 `QNetworkInterface::name()` 返回 `ethernet_32774` 这类 LUID 名，**不是 GUID 也不是
  友好名**。需要 GUID 时用 `ConvertInterfaceLuidToGuid`。