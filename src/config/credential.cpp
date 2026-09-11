#include "config/credential.h"
#include <windows.h>
#include <dpapi.h>

namespace Credential {

QByteArray encryptPassword(const QString& plain)
{
    if (plain.isEmpty())
        return {};

    QByteArray utf8 = plain.toUtf8();
    DATA_BLOB in;
    in.pbData = reinterpret_cast<BYTE*>(utf8.data());
    in.cbData = static_cast<DWORD>(utf8.size());

    DATA_BLOB out = {};
    // CRYPTPROTECT_UI_FORBIDDEN：禁止任何 UI 提示（静默保护，适配无界面/托盘场景）
    const BOOL ok = CryptProtectData(&in, L"SCUTNetLogin_password", nullptr, nullptr, nullptr,
                                     CRYPTPROTECT_UI_FORBIDDEN, &out);
    // 及时清除明文密码临时缓冲（QString 本身无法安全清零，至少不留副本）
    utf8.fill('\0');

    if (!ok)
        return {};

    QByteArray blob(reinterpret_cast<const char*>(out.pbData), static_cast<int>(out.cbData));
    LocalFree(out.pbData);
    return blob.toBase64();
}

QString decryptPassword(const QByteArray& encoded)
{
    const QByteArray blob = QByteArray::fromBase64(encoded);
    if (blob.isEmpty())
        return {};

    DATA_BLOB in;
    in.pbData = reinterpret_cast<BYTE*>(const_cast<char*>(blob.constData()));
    in.cbData = static_cast<DWORD>(blob.size());

    DATA_BLOB out = {};
    if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr,
                            CRYPTPROTECT_UI_FORBIDDEN, &out))
        return {};

    const QString result = QString::fromUtf8(
        reinterpret_cast<const char*>(out.pbData), static_cast<int>(out.cbData));
    LocalFree(out.pbData);
    return result;
}

} // namespace Credential
