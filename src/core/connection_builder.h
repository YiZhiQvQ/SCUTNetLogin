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

} // namespace ConnectionBuilder

#endif // CONNECTION_BUILDER_H
