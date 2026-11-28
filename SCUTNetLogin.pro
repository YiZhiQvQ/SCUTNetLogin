QT += core gui network widgets svg

CONFIG += c++17

TARGET = SCUTNetLogin
TEMPLATE = app

# ============================================================================
# 版本号单点定义
# 改版本只改这一处：这里拆成三个整数宏供 app.rc 的 VERSIONINFO 使用，
# 同时以 APP_VERSION 字符串形式供 main.cpp 设置 QApplication::applicationVersion()。
# ============================================================================
VERSION = 1.8.0
APP_VERSION_PARTS = $$split(VERSION, ".")
# 数值宏（供 app.rc 的 VERSIONINFO 与 main.cpp 用）
DEFINES += APP_VERSION_MAJOR=$$member(APP_VERSION_PARTS, 0)
DEFINES += APP_VERSION_MINOR=$$member(APP_VERSION_PARTS, 1)
DEFINES += APP_VERSION_PATCH=$$member(APP_VERSION_PARTS, 2)
# 字符串版本。注意两处使用方的引号需求不同：
#   · app.rc 的 VERSIONINFO VALUE 语法需要**带引号**的字面量
#   · main.cpp 用 QStringLiteral(APP_VERSION) 需要**不带引号**的宏值
# 因此分别定义：APP_VERSION_QUOTED 给 rc，APP_VERSION 给 C++。
# 注意：不能直接写 APP_VERSION=$$VERSION（=1.8.0 在 C++ 里是非法数字字面量）。
# C++ 侧的版本字符串由主程序自行组合三段整数宏得到。

# 版本号作为三段整数传入，供 rc 拼装字符串（避开 rc 不支持字符串化的限制，
# 也避免 DEFINES 里的引号被 qmake 再转义一轮变成 ""1.8.0""）
DEFINES += APP_VER_MAJOR=$$member(APP_VERSION_PARTS, 0)
DEFINES += APP_VER_MINOR=$$member(APP_VERSION_PARTS, 1)
DEFINES += APP_VER_PATCH=$$member(APP_VERSION_PARTS, 2)

INCLUDEPATH += src

# Npcap
INCLUDEPATH += "C:/npcap-sdk/Include"
LIBS += -L"C:/npcap-sdk/Lib/x64" -lwpcap -lPacket -lws2_32 -liphlpapi
# DPAPI（密码加密，CryptProtectData/CryptUnprotectData）
LIBS += -lcrypt32
# 管理员权限检查（main.cpp: OpenProcessToken / GetTokenInformation）
LIBS += -ladvapi32
# WLAN API（无线 SSID 查询与接口枚举，Windows SDK 自带；仅 src/wifi/wlan_media.cpp）
LIBS += -lwlanapi
# 管理员权限清单：不再用 QMAKE_LFLAGS /MANIFESTUAC（其引号会被 linker 剥掉，
# 生成无引号的畸形 manifest，导致 SxS "并行配置不正确" 启动失败）。
# 改用 .rc 嵌入 src/app.manifest 标准模板（见 app.rc）。
# 同时必须禁用 qmake/linker 的自动 manifest 嵌入，否则 .rc 的 RT_MANIFEST 与
# linker 自动生成的 manifest 冲突（CVT1100: MANIFEST 资源重复）。
# msvc-desktop.conf 默认启用 embed_manifest_exe，需显式关闭，
# 让 .rc 里嵌入的 app.manifest 成为唯一清单。
CONFIG -= embed_manifest_exe

SOURCES += \
    src/main.cpp \
    src/ui/mainwindow.cpp \
    src/core/session_manager.cpp \
    src/core/connection_builder.cpp \
    src/core/retry_policy.cpp \
    src/core/watchdog.cpp \
    src/core/byte_utils.cpp \
    src/config/config_manager.cpp \
    src/config/credential.cpp \
    src/network/network_worker.cpp \
    src/eap/eap_process.cpp \
    src/eap/notification_parser.cpp \
    src/udp/udp_process.cpp \
    src/network/network.cpp \
    src/network/network_adapter.cpp \
    src/network/network_link.cpp \
    src/udp/drcom_packet.cpp \
    src/eap/eapol_packet.cpp \
    src/log/log_manager.cpp \
    src/wifi/portal_parser.cpp \
    src/wifi/webauth_process.cpp \
    src/wifi/wlan_media.cpp

HEADERS += \
    src/ui/mainwindow.h \
    src/core/session_manager.h \
    src/core/connection_builder.h \
    src/core/retry_policy.h \
    src/core/watchdog.h \
    src/core/byte_utils.h \
    src/config/config_manager.h \
    src/config/credential.h \
    src/network/network_worker.h \
    src/eap/eap_process.h \
    src/eap/notification_parser.h \
    src/udp/udp_process.h \
    src/core/protocol.h \
    src/core/log_level.h \
    src/network/network.h \
    src/network/network_internal.h \
    src/core/constants.h \
    src/udp/drcom_packet.h \
    src/eap/eapol_packet.h \
    src/log/log_manager.h \
    src/wifi/portal_parser.h \
    src/wifi/webauth_process.h \
    src/wifi/wlan_media.h

FORMS += src/ui/mainwindow.ui

RESOURCES += res/resources.qrc

RC_FILE = src/app.rc

# 警告级别：Qt mkspec 默认只给 /W3，这里提到 /W4。
# 已实测：全量重建（38 个 TU，含 Qt 头）在此级别下零警告，故设为默认以拦住新增问题。
# 若接入第三方头文件后出现大量噪音，可对特定 TU 单独降级，而不是整体退回 /W3。
QMAKE_CXXFLAGS_WARN_ON = -W4
QMAKE_CXXFLAGS_WARN_OFF =
