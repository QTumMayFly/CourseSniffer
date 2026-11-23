#include "ui/MainWindow.h"
#include "ui/DemoPackets.h"
#include "ui/StreamDialog.h"
#include "ui/LiveVerification.h"
#include "ui/GuidedRecording.h"
#include <QApplication>
#include <QCommandLineParser>
#include <QDir>
#include <QFileInfo>
#include <QTimer>
#include <QTextStream>

int main(int argc, char* argv[]) {
    QApplication application(argc, argv);
    QCoreApplication::setApplicationName(QStringLiteral("CourseSniffer"));
    QCoreApplication::setApplicationVersion(QStringLiteral("1.1.0"));
    QCoreApplication::setOrganizationName(QStringLiteral("CourseSniffer"));
    QCommandLineParser parser;
    parser.setApplicationDescription(QStringLiteral("课程实验 1A 网络嗅探器"));
    parser.addHelpOption(); parser.addVersionOption();
    QCommandLineOption demo(QStringLiteral("demo"), QStringLiteral("加载明确标注的内置演示数据。"));
    QCommandLineOption demoPcap(QStringLiteral("demo-pcap"), QStringLiteral("加载指定 PCAP 作为演示数据。"), QStringLiteral("file"));
    QCommandLineOption smoke(QStringLiteral("smoke-test"), QStringLiteral("显示窗口并自动结束界面启动检查。"));
    QCommandLineOption screenshot(QStringLiteral("screenshot"), QStringLiteral("保存主窗口截图并退出。"), QStringLiteral("path"));
    QCommandLineOption streamScreenshot(QStringLiteral("stream-screenshot"), QStringLiteral("保存首条 TCP 连接内容窗口截图并退出。"), QStringLiteral("path"));
    QCommandLineOption captureProof(QStringLiteral("capture-proof"), QStringLiteral("执行实际回环抓包验证并保存日志和窗口截图。"), QStringLiteral("directory"));
    QCommandLineOption demoScript(QStringLiteral("demo-script"), QStringLiteral("实际验证使用的 demo/run_demo.py 路径。"), QStringLiteral("path"));
    QCommandLineOption proofInterface(QStringLiteral("proof-interface"), QStringLiteral("实际验证使用的回环接口。"), QStringLiteral("name"), QStringLiteral("lo0"));
    QCommandLineOption recordDemo(QStringLiteral("record-demo"),
        QStringLiteral("在真实抓包和离线协议样例之间明确标注并自动录制演示 MP4。"), QStringLiteral("movie.mp4"));
    QCommandLineOption samplePcap(QStringLiteral("sample-pcap"),
        QStringLiteral("录制中展示 DNS、ARP 时使用的固定 PCAP 样例。"), QStringLiteral("file"));
    parser.addOptions({demo, demoPcap, smoke, screenshot, streamScreenshot, captureProof,
                       demoScript, proofInterface, recordDemo, samplePcap});
    parser.process(application);
    if (parser.isSet(captureProof) && (!parser.isSet(demoScript) || parser.isSet(demo) || parser.isSet(demoPcap) || parser.isSet(smoke) || parser.isSet(screenshot) || parser.isSet(streamScreenshot))) {
        QTextStream(stderr) << "实际验证需要 --demo-script，并使用独立的实际抓包会话。\n";
        return 2;
    }
    if (parser.isSet(recordDemo) && (!parser.isSet(demoScript) || !parser.isSet(samplePcap) ||
        parser.isSet(captureProof) || parser.isSet(demo) || parser.isSet(demoPcap) ||
        parser.isSet(smoke) || parser.isSet(screenshot) || parser.isSet(streamScreenshot))) {
        QTextStream(stderr) << "录制真实操作需要 --demo-script 与 --sample-pcap，并使用独立抓包会话。\n";
        return 2;
    }
    if (parser.isSet(captureProof) || parser.isSet(recordDemo)) application.setQuitOnLastWindowClosed(false);
    sniffer::MainWindow window;
    if (parser.isSet(demoPcap)) {
        QString error;
        auto records = sniffer::readDemoPcap(parser.value(demoPcap), &error);
        if (records.empty() && !error.isEmpty()) { QTextStream(stderr) << error << '\n'; return 2; }
        window.loadDemoPackets(std::move(records), QFileInfo(parser.value(demoPcap)).fileName());
        if (!error.isEmpty()) QTextStream(stderr) << error << '\n';
    } else if (parser.isSet(demo) || parser.isSet(streamScreenshot)) window.loadDemoPackets(sniffer::builtInDemoPackets());
    window.show();
    if (parser.isSet(recordDemo)) {
        sniffer::startGuidedRecording(window, QFileInfo(parser.value(recordDemo)).absoluteFilePath(),
            QFileInfo(parser.value(demoScript)).absoluteFilePath(),
            QFileInfo(parser.value(samplePcap)).absoluteFilePath());
    } else if (parser.isSet(captureProof)) {
        sniffer::startLiveVerification(window, QDir(parser.value(captureProof)).absolutePath(),
                                      QFileInfo(parser.value(demoScript)).absoluteFilePath(), parser.value(proofInterface));
    } else if (parser.isSet(screenshot) || parser.isSet(streamScreenshot)) {
        const bool stream = parser.isSet(streamScreenshot);
        const QString path = parser.value(stream ? streamScreenshot : screenshot);
        QTimer::singleShot(700, &application, [&application, &window, path, stream]() {
            QWidget* target = &window;
            if (stream) {
                target = window.showFirstStream();
                if (!target) { QTextStream(stderr) << "没有可显示的 TCP 连接。\n"; application.exit(2); return; }
            }
            QTimer::singleShot(200, &application, [&application, target, path]() {
                QDir().mkpath(QFileInfo(path).absolutePath());
                const bool saved = target->grab().save(path);
                if (!saved) QTextStream(stderr) << "截图保存失败。\n";
                application.exit(saved ? 0 : 2);
            });
        });
    } else if (parser.isSet(smoke)) QTimer::singleShot(400, &application, &QCoreApplication::quit);
    return application.exec();
}
