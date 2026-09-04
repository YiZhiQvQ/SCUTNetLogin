QT += core gui network widgets svg

CONFIG += c++17

TARGET = SCUTNetLogin
TEMPLATE = app

INCLUDEPATH += src

# Npcap
INCLUDEPATH += "C:/npcap-sdk/Include"
LIBS += -L"C:/npcap-sdk/Lib/x64" -lwpcap -lPacket -lws2_32 -liphlpapi
# DPAPI（密码加密，CryptProtectData/CryptUnprotectData）
LIBS += -lcrypt32
# 管理员权限检查（main.cpp: OpenProcessToken / GetTokenInformation）
LIBS += -ladvapi32
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
    src/core/byte_utils.cpp \
    src/config/config_manager.cpp \
    src/config/credential.cpp \
    src/network/network_worker.cpp \
    src/eap/eap_process.cpp \
    src/eap/notification_parser.cpp \
    src/udp/udp_process.cpp \
    src/network/network.cpp \
    src/udp/drcom_packet.cpp \
    src/eap/eapol_packet.cpp \
    src/log/log_manager.cpp

HEADERS += \
    src/ui/mainwindow.h \
    src/core/session_manager.h \
    src/core/connection_builder.h \
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
    src/core/constants.h \
    src/udp/drcom_packet.h \
    src/eap/eapol_packet.h \
    src/log/log_manager.h

FORMS += src/ui/mainwindow.ui

RESOURCES += res/resources.qrc

RC_FILE = src/app.rc
