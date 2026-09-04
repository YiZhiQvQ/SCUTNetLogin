#ifndef CONNECTION_BUILDER_H
#define CONNECTION_BUILDER_H

#include <QString>
#include <QStringList>
#include "core/protocol.h"

// ============================================================================
// 连接编排 — 从 MainWindow::on_btnConnect_clicked 下沉的可测纯逻辑
//
// 负责"点击连接"时的校验与组装：
//   1. 回环网卡拒绝
//   2. MAC 可用性检查
//   3. netsh 适配器名非空检查（适配器名由调用方用 Network::adapterNameByMac 预解析）
//   4. 静态 IP 字段完整性校验
//   5. StaticIpConfig 组装
//
// 所有 UI 读写（编辑框、下拉框、按钮禁用）仍留在 MainWindow 槽中；本模块
// 不含 pcap / Qt Widgets / Network 依赖，可被单元测试直接编译。
// ============================================================================

namespace ConnectionBuilder {

// 输入：由 UI 槽从窗体控件收集（不含任何 UI 依赖，可直接构造）
struct Input {
    QString pcapName;            // Npcap 设备名（\\Device\\NPF_...）
    QString displayText;         // 下拉框显示名
    QString username;            // 认证用户名（须非空）
    QString password;            // 认证密码（须非空）
    QString mac;                 // 网卡 MAC（已自动探测，可能为空）
    bool    autoSetNetwork = false;   // 是否启用静态 IP 配置
    QString adapterName;         // netsh 适配器名（调用方预解析，可为空）
    QString ip;
    QString mask;
    QString gateway;
    QString dns1;
    QString dns2;
    // 无线模块（追加于末尾，默认值保证既有聚合初始化兼容）
    QString connectMode = QStringLiteral("auto");        // auto / wired / wireless
    QString ssidRaw     = QStringLiteral("scut-student"); // SSID 白名单原文（逗号分隔）
};

// 结果：ok=false 时 error 为可显示的终止原因
struct Result {
    bool ok = false;
    QString error;
    bool needStaticIp = false;
    StaticIpConfig ipConfig;     // 仅 needStaticIp 时有效
};

// 校验并组装连接参数。ok=false 时 error 含用户可读原因（供 UI 直接显示）。
Result build(const Input& in);

// ============================================================================
// 无线接入后端决策 — 纯函数（SessionManager 现场取以太网链路/SSID 后调用）
// ============================================================================

// 认证后端
enum class AuthBackend {
    None,                       // 无可选后端（需要用户检查原因）
    WiredEap,                   // 有线 802.1X EAPOL
    PortalWifi                  // 无线 DrCOM Web Portal
};

struct BackendDecision {
    AuthBackend backend = AuthBackend::None;
    QString reason;             // backend==None 时为用户可读原因
};

// 解析 SSID 白名单：按逗号/顿号/空格切分，去空、逐项 trim。空串 → 空列表（= 任意 SSID）。
QStringList parseSsidList(const QString& raw);

// 当前 SSID 是否命中白名单（空白名单 = 任意；大小写敏感，SSID 有大小写语义）
bool ssidMatch(const QString& currentSsid, const QStringList& whitelist);

// 决策矩阵（详见 wifi_module_plan.md §3.5）：
//   Auto       + 有线链路Up          → WiredEap（有线优先）
//   Auto       + 链路Down + SSID命中  → PortalWifi
//   Auto       + 链路Down + SSID未中  → None
//   Wired      + 链路Down            → None（提示检查网线）
//   Wired      + 链路Up/未知         → WiredEap
//   Wireless   + SSID命中            → PortalWifi
//   Wireless   + SSID未中            → None（提示 SSID 不在白名单）
BackendDecision resolveAuthBackend(ConnectMode mode, bool ethernetLinkUp,
                                   const QString& currentSsid, const QStringList& whitelist);

} // namespace ConnectionBuilder

#endif // CONNECTION_BUILDER_H
