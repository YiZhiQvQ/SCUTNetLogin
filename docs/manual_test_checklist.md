# 手工验证清单

以下场景依赖真实网卡 / 交换机 / 校园网环境，无法自动化测试。发版前按此清单逐项确认。

## 1. 有线认证基础流程

- [ ] 插好网线 → 启动程序 → 点「连接」→ 日志出现「认证成功，可以上网了！」
- [ ] 认证成功后 `ipconfig` 能看到静态 IP（若开了静态 IP）
- [ ] 点「断开」→ 网卡恢复 DHCP（`netsh interface ipv4 show config name=以太网` 显示 `DHCP enabled: Yes`）
- [ ] 断开后能正常访问外网（说明路由/DNS 已还回去）

## 2. 静态 IP 相关

- [ ] 开启「连接时配置静态IP」→ 连接 → 回读校验通过，日志**没有**「回读不符」
- [ ] 认证失败后静态 IP 被恢复（不残留）
- [ ] 程序退出后静态 IP 被恢复（检查 `netsh` 输出）
- [ ] 循环环回接口无网关：`netsh interface ipv4 show config name="Loopback Pseudo-Interface 1"` 不应有 Default Gateway

## 3. 夜间与重试

- [ ] 0:00 后断开 → 日志「当前时段禁止上网，将在明早 6:01 自动重试」→ UI 显示「等待网络...」+「取消」
- [ ] 点「取消」→ 等待结束，不再自动重连
- [ ] 合盖/睡眠过夜 → 唤醒后若已过 6:01 应立即重连（不依赖单调时钟）

## 4. 链路切换

- [ ] 有线在线时拔网线 → 日志「有线网线已拔出，正在断开有线...」→ 断开
- [ ] 插回网线 → 自动重新认证（不需手动点连接）
- [ ] 有线连续失败 2 次且 Wi-Fi 已连 → 自动回退无线

## 5. 无线 Portal

- [ ] 连上 `scut-student` → 启动程序 → 自动无线认证成功
- [ ] 点「断开」→ 执行 `mac/unbind` 解绑（不是物理断链）
- [ ] 退出程序时若未勾选「退出时注销无线连接」→ 门户会话保持在线

## 6. 开机自启与电源

- [ ] 勾选「开机自启动」→ 保存 → `schtasks /query /tn "SCUTNetLogin_AutoStart" /xml` 中
      `StopIfGoingOnBatteries=false`、`DisallowStartIfOnBatteries=false`、
      `StopOnIdleEnd=false`、`ExecutionTimeLimit=PT0S`
- [ ] **拔掉电源切到电池 → 进程不退出**（这是 1.6 修复的关键项）
- [ ] 重新登录 Windows → 程序自动静默启动并连接

## 7. 卡死与诊断

- [ ] 正常使用数天，`log/` 下**不应**出现 `.hang.log`
- [ ] 若出现 `.hang.log`，检查「当前阶段」字段：
  - 停在 `pcap_activate` / `pcap_next_ex` → 网卡省电冲突，运行 `tools/close-nic-powersaving.ps1`
  - 停在 `设置静态IP` / `恢复 DHCP` → netsh 阻塞
  - 停在 `启动认证线程` / `投递认证配置` → 线程或锁问题
- [ ] 卡死后**任务管理器能结束进程**（1.7 之后应可以；若不能，说明 pcap 仍在内核阻塞）

## 8. 网卡省电检测

- [ ] 故意开启网卡 Power Saving Mode → 连接时日志应出现告警提示
- [ ] 运行 `tools/close-nic-powersaving.ps1`（管理员）→ 回读全部 `Disabled`

## 9. 异常输入

- [ ] 密码错误 → 日志「认证被拒绝」且**不再**自动重试（永久性错误）
- [ ] 拔掉网线后点「连接」→ 进入「等待网络...」，插线后自动继续
- [ ] 未安装 Npcap → 明确的错误提示，不是崩溃
- [ ] 配置文件损坏 → 程序仍能启动（回退默认值）

## 10. 构建产物

- [ ] `SCUTNetLogin.exe` 属性页显示 `FileVersion = 1.8.0`
- [ ] 安装包能正常安装 / 卸载，快捷方式可用
- [ ] 安装后首次启动会检测 Npcap，缺失时有提示