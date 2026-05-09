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
    src/mainwindow.cpp \
    src/eap_process.cpp \
    src/udp_process.cpp \
    src/network.cpp

HEADERS += \
    src/mainwindow.h \
    src/eap_process.h \
    src/udp_process.h \
    src/protocol.h \
    src/network.h \
    src/constants.h

FORMS += src/mainwindow.ui

RESOURCES += res/resources.qrc

RC_FILE = src/app.rc
