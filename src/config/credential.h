#ifndef CREDENTIAL_H
#define CREDENTIAL_H

#include <QByteArray>
#include <QString>

// ============================================================================
// 凭证加密 — 基于 Windows DPAPI（CryptProtectData / CryptUnprotectData）
//
// 用途：以 DPAPI 密文代替 Base64 明文存储密码。DPAPI 密文绑定当前 Windows
// 用户账户（CurrentUser 作用域），即使用户 A 拿到了用户 B 的 config.ini，
// 也无法在 B 的账户之外解密；本机登录用户可直接解密（与操作系统登录保护一致，
// 这是非交互桌面应用在 Windows 上成本最低的密码保护方式）。
//
// 兼容性：加密结果整体再做 Base64 编码后写入 config.ini（与字段形状一致的
// 常规写法）。非 DPAPI 密文（Base64 明文）无法通过 DPAPI 解密，ConfigManager::load
// 会回退为直接 Base64 解码，兼容旧明文凭据。
// ============================================================================

namespace Credential {

// 加密明文密码 → Base64(DPAPI 密文)。失败（罕见）返回空 QByteArray。
QByteArray encryptPassword(const QString& plain);

// 解密 Base64(DPAPI 密文) → 明文。解密失败（非 DPAPI 密文 / 非本用户 / 数据损坏）
// 返回空 QString，由调用方决定回退策略。
QString decryptPassword(const QByteArray& encoded);

} // namespace Credential

#endif // CREDENTIAL_H
