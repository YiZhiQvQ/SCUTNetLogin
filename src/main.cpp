#include "ui/mainwindow.h"
#include <QApplication>
#include <QMessageBox>
#include <QSharedMemory>
#include <QIcon>
#include <QFile>
#include <QCommandLineParser>
#include <windows.h>

bool isRunningAsAdmin() {
    BOOL isElevated = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD dwSize;
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
            isElevated = elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }
    return isElevated != FALSE;
}

int main(int argc, char* argv[]) {
    QApplication a(argc, argv);
    a.setApplicationName("SCUTNetLogin");
    a.setOrganizationName("SCUTNetLogin");   // QSettings 默认构造（UI 几何记忆）用；不影响 config.ini
    a.setApplicationDisplayName("SCUT 校园网认证");

    // 载入图标
    a.setWindowIcon(QIcon(":/SCUTnetwork.ico"));

    // 解析命令行参数（QCommandLineParser 处理 Unicode 参数更健壮）
    QCommandLineParser parser;
    parser.setApplicationDescription(QStringLiteral("SCUT 校园网认证客户端"));
    parser.addHelpOption();
    parser.addOptions({
        { QStringLiteral("silent"),    QStringLiteral("静默启动：不显示窗口，最小化到托盘") },
        { QStringLiteral("minimized"), QStringLiteral("同 --silent") },
        { QStringLiteral("s"),         QStringLiteral("同 --silent") },
    });
    parser.process(a);

    const bool silentMode = parser.isSet(QStringLiteral("silent"))
                            || parser.isSet(QStringLiteral("minimized"))
                            || parser.isSet(QStringLiteral("s"));

    // 单实例检查
    QSharedMemory shared("SCUTNetLogin_SingleInstance");
    if (!shared.create(1)) {
        if (silentMode) {
            // 静默模式：已有实例在运行，直接退出即可
            return 0;
        }
        QMessageBox::warning(nullptr, "提示",
            "程序已经在运行中！\n请检查右下角系统托盘是否已有该程序的图标。");
        return 0;
    }

    // 检查管理员权限
    if (!isRunningAsAdmin()) {
        QMessageBox::critical(nullptr, "错误",
            "本程序需要管理员权限才能发送802.1X认证包。\n"
            "请右键点击程序，选择\"以管理员身份运行\"。");
        return -1;
    }

    MainWindow w;

    // 加载全局样式表
    QFile styleFile(":/style.qss");
    if (styleFile.open(QFile::ReadOnly | QFile::Text)) {
        a.setStyleSheet(QString::fromUtf8(styleFile.readAll()));
        styleFile.close();
    }

    if (silentMode) {
        // 静默启动：不显示窗口，直接最小化到托盘并自动连接
        w.setSilentStartup();
    } else {
        w.show();
    }

    return a.exec();
}
