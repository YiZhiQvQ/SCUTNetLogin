# ============================================================================
# 单元测试 — 协议封包 / 校验和 / 加解密 / 字节工具
# 覆盖 EapolPacket、DrcomPacket、ByteUtils（均为纯函数，无 pcap/网络 I/O 依赖）
#
# 构建（需先进入 VS 开发者命令行环境）：
#   cd tests
#   qmake tst_packets.pro
#   nmake          (Debug)
#   nmake release  (Release)
# 运行：
#   .\release\tst_packets.exe    或  .\debug\tst_packets.exe
# ============================================================================

QT += core network testlib

CONFIG += c++17 console
CONFIG -= app_bundle

# htons/ntohs（协议头网络字节序）
LIBS += -lws2_32
# Credential（DPAPI）与 ConfigManager 测试
LIBS += -lcrypt32

TARGET = tst_packets
TEMPLATE = app

INCLUDEPATH += ../src

SOURCES += \
    tst_packets.cpp \
    ../src/eap/eapol_packet.cpp \
    ../src/eap/notification_parser.cpp \
    ../src/udp/drcom_packet.cpp \
    ../src/core/byte_utils.cpp \
    ../src/core/connection_builder.cpp \
    ../src/config/config_manager.cpp \
    ../src/config/credential.cpp

HEADERS += \
    ../src/eap/eapol_packet.h \
    ../src/eap/notification_parser.h \
    ../src/udp/drcom_packet.h \
    ../src/core/byte_utils.h \
    ../src/core/connection_builder.h \
    ../src/core/protocol.h \
    ../src/core/constants.h \
    ../src/core/deferred_signals.h \
    ../src/config/config_manager.h \
    ../src/config/credential.h
