QT += core gui network widgets svg

CONFIG += c++17

TARGET = SCUTNetLogin
TEMPLATE = app

INCLUDEPATH += src

# Npcap
INCLUDEPATH += "C:/npcap-sdk/Include"
LIBS += -L"C:/npcap-sdk/Lib/x64" -lwpcap -lPacket -lws2_32 -liphlpapi
QMAKE_LFLAGS += /MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\"

SOURCES += \
    src/main.cpp \
    src/ui/mainwindow.cpp \
    src/core/session_manager.cpp \
    src/config/config_manager.cpp \
    src/network/network_worker.cpp \
    src/eap/eap_process.cpp \
    src/udp/udp_process.cpp \
    src/network/network.cpp \
    src/udp/drcom_packet.cpp \
    src/eap/eapol_packet.cpp \
    src/log/log_manager.cpp

HEADERS += \
    src/ui/mainwindow.h \
    src/core/session_manager.h \
    src/config/config_manager.h \
    src/network/network_worker.h \
    src/eap/eap_process.h \
    src/udp/udp_process.h \
    src/core/protocol.h \
    src/network/network.h \
    src/core/constants.h \
    src/udp/drcom_packet.h \
    src/eap/eapol_packet.h \
    src/log/log_manager.h

FORMS += src/ui/mainwindow.ui

RESOURCES += res/resources.qrc

RC_FILE = src/app.rc
