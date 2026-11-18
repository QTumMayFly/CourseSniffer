#include <QtTest>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QProcess>
#include <QTableView>
#include "capture/CaptureWorker.h"
#include "ui/MainWindow.h"
#include "ui/DemoPackets.h"
#include "ui/StreamDialog.h"
#include "core/PacketParser.h"
#include <set>

#ifndef SNIFFER_SOURCE_DIR
#define SNIFFER_SOURCE_DIR "."
#endif

using namespace sniffer;

namespace {
struct CaptureObservation {
    int started = 0;
    int stopped = 0;
    QStringList errors;
    QObject receiver;
};

void observeCapture(CaptureWorker* worker, CaptureObservation& observation) {
    // 观察对象属于测试线程，计数和错误列表仅由该线程访问。
    QObject::connect(worker, &CaptureWorker::captureStarted, &observation.receiver,
        [&observation](const QString&, int) { ++observation.started; }, Qt::QueuedConnection);
    QObject::connect(worker, &CaptureWorker::captureStopped, &observation.receiver,
        [&observation](const CaptureSummary&) { ++observation.stopped; }, Qt::QueuedConnection);
    QObject::connect(worker, &CaptureWorker::captureError, &observation.receiver,
        [&observation](const QString& error) { observation.errors.push_back(error); }, Qt::QueuedConnection);
}

bool stopCaptureThread(CaptureWorker* worker, std::unique_ptr<QThread>& thread) {
    QMetaObject::invokeMethod(worker, [worker]() {
        worker->stopCapture();
        QThread::currentThread()->quit();
    }, Qt::QueuedConnection);
    QElapsedTimer timer;
    timer.start();
    while (!thread->wait(0) && timer.elapsed() < 3000) QTest::qWait(5);
    if (!thread->wait(0)) {
        // 保留仍运行的线程对象，外部测试时限负责终止这个失败进程。
        thread.release();
        QTest::qFail("抓包工作线程未在三秒内退出，等待外部测试时限终止进程。", __FILE__, __LINE__);
        for (;;) QTest::qWait(100);
    }
    return true;
}
}

class GuiTests : public QObject {
    Q_OBJECT
private slots:
    void queueCapacityAndDrain() {
        CaptureQueue queue;
        for (std::size_t index = 0; index < CaptureQueue::MaxPackets; ++index) {
            RawPacket packet; packet.id = index + 1; packet.bytes = {0};
            QVERIFY(queue.push(std::move(packet)));
        }
        RawPacket extra; extra.bytes = {0};
        QVERIFY(!queue.push(std::move(extra)));
        QCOMPARE(queue.size(), CaptureQueue::MaxPackets);
        QCOMPARE(queue.byteCount(), CaptureQueue::MaxPackets);
        const auto batch = queue.take(512);
        QCOMPARE(batch.size(), std::size_t(512));
        QCOMPARE(batch.front().id, std::uint64_t(1));
        QCOMPARE(batch.back().id, std::uint64_t(512));
        QCOMPARE(queue.size(), CaptureQueue::MaxPackets - 512);
        queue.clear();
        QVERIFY(queue.empty());
        QCOMPARE(queue.byteCount(), std::size_t(0));
        RawPacket large; large.bytes.resize(CaptureQueue::MaxBytes + 1);
        QVERIFY(!queue.push(std::move(large)));
    }

    void demoProtocolLabelsAndFilters() {
        MainWindow window;
        window.loadDemoPackets(builtInDemoPackets());
        QCOMPARE(window.packetModel()->rowCount(), 16);
        QVERIFY(!window.captureBusy());
        QString error;
        QVERIFY(window.proxyModel()->setExpression(QStringLiteral("http"), &error));
        QCOMPARE(window.proxyModel()->rowCount(), 4);
        QVERIFY(window.proxyModel()->setExpression(QStringLiteral("ipv6 and (udp or icmp6)"), &error));
        QCOMPARE(window.proxyModel()->rowCount(), 2);
        QVERIFY(!window.proxyModel()->setExpression(QStringLiteral("tcp and ("), &error));
        QVERIFY(!error.isEmpty());
        QCOMPARE(window.proxyModel()->rowCount(), 2);
        QVERIFY(window.proxyModel()->setExpression(QString(), &error));
        QCOMPARE(window.proxyModel()->rowCount(), 16);
        auto* description = window.findChild<QLabel*>(QStringLiteral("sessionDescription"));
        QVERIFY(description);
        QVERIFY(description->text().contains(QStringLiteral("演示数据")));
        const auto* icmp = window.packetModel()->packetAt(13);
        QVERIFY(icmp && !icmp->hasPorts);
        QCOMPARE(window.packetModel()->data(window.packetModel()->index(13, PacketTableModel::Source)).toString(),
                 QString::fromStdString(icmp->source.text));
    }

    void controlsApplyFilterAndShowStream() {
        MainWindow window;
        window.loadDemoPackets(builtInDemoPackets());
        window.show();
        auto* input = window.findChild<QLineEdit*>(QStringLiteral("filterEdit"));
        auto* button = window.findChild<QPushButton*>(QStringLiteral("applyFilterButton"));
        auto* trace = window.findChild<QPushButton*>(QStringLiteral("traceButton"));
        auto* table = window.findChild<QTableView*>(QStringLiteral("packetTable"));
        QVERIFY(input && button && trace && table);
        input->setText(QStringLiteral("http and ipv4"));
        QTest::mouseClick(button, Qt::LeftButton);
        QCOMPARE(window.proxyModel()->rowCount(), 4);
        table->selectRow(0);
        QVERIFY(trace->isEnabled());
        QTest::mouseClick(trace, Qt::LeftButton);
        auto* dialog = window.findChild<StreamDialog*>();
        QVERIFY(dialog);
        QVERIFY(dialog->isVisible());
        dialog->close();
        input->setText(QStringLiteral("http or"));
        QTest::mouseClick(button, Qt::LeftButton);
        QCOMPARE(window.proxyModel()->rowCount(), 4);
        auto* error = window.findChild<QLabel*>(QStringLiteral("filterStatus"));
        QVERIFY(error && error->text().contains(QStringLiteral("字符")));
        window.close();
    }

    void unavailableInterfaceCompletesStop() {
        qRegisterMetaType<CaptureSummary>();
        auto queue = std::make_shared<CaptureQueue>();
        auto thread = std::make_unique<QThread>();
        auto* worker = new CaptureWorker(queue);
        worker->moveToThread(thread.get());
        connect(thread.get(), &QThread::finished, worker, &QObject::deleteLater);
        CaptureObservation observation;
        observeCapture(worker, observation);
        thread->start();
        const bool invoked = QMetaObject::invokeMethod(worker, "startCapture", Qt::QueuedConnection,
                                         Q_ARG(QString, QStringLiteral("coursesniffer_missing_interface")));
        QElapsedTimer waitTimer;
        waitTimer.start();
        while (observation.stopped == 0 && waitTimer.elapsed() < 3000) QTest::qWait(5);
        const bool completed = observation.stopped == 1;
        const int errors = observation.errors.size();
        const bool threadFinished = stopCaptureThread(worker, thread);
        QVERIFY(threadFinished);
        QVERIFY(invoked);
        QVERIFY(completed);
        QCOMPARE(errors, 1);
        QCOMPARE(observation.stopped, 1);
        QVERIFY(queue->empty());
    }

    void idleLiveCaptureStop() {
        if (qEnvironmentVariableIntValue("COURSESNIFFER_LIVE_TEST") != 1)
            QSKIP("实时抓包检查通过 COURSESNIFFER_LIVE_TEST=1 启用。");
        QString enumerationError;
        const auto interfaces = CaptureWorker::enumerate(&enumerationError);
        QString loopback;
        for (const auto& interface : interfaces)
            if (interface.name == QStringLiteral("lo0") || interface.name == QStringLiteral("lo")) loopback = interface.name;
        QVERIFY2(!loopback.isEmpty(), qPrintable(enumerationError.isEmpty() ? QStringLiteral("回环接口不可用") : enumerationError));
        qRegisterMetaType<CaptureSummary>();
        auto queue = std::make_shared<CaptureQueue>();
        auto thread = std::make_unique<QThread>();
        auto* worker = new CaptureWorker(queue);
        worker->moveToThread(thread.get());
        connect(thread.get(), &QThread::finished, worker, &QObject::deleteLater);
        CaptureObservation observation;
        observeCapture(worker, observation);
        QString failure;
        thread->start();
        for (int attempt = 0; attempt < 10; ++attempt) {
            queue->clear();
            QMetaObject::invokeMethod(worker, "startCapture", Qt::QueuedConnection, Q_ARG(QString, loopback));
            QElapsedTimer timer;
            timer.start();
            while (observation.started <= attempt && observation.errors.isEmpty() && timer.elapsed() < 3000) QTest::qWait(5);
            if (!observation.errors.isEmpty()) { failure = observation.errors.first(); break; }
            if (observation.started != attempt + 1) { failure = QStringLiteral("启动接口超时"); break; }
            timer.restart();
            QMetaObject::invokeMethod(worker, "stopCapture", Qt::QueuedConnection);
            while (observation.stopped <= attempt && timer.elapsed() < 1000) QTest::qWait(5);
            if (observation.stopped != attempt + 1 || timer.elapsed() >= 1000) {
                failure = QStringLiteral("空闲接口停止超过一秒");
                break;
            }
        }
        const bool threadFinished = stopCaptureThread(worker, thread);
        QVERIFY(threadFinished);
        QVERIFY2(failure.isEmpty(), qPrintable(failure));
        QCOMPARE(observation.started, 10);
        QCOMPARE(observation.stopped, 10);
    }

    void liveLoopbackTraffic() {
        if (qEnvironmentVariableIntValue("COURSESNIFFER_LIVE_TEST") != 1)
            QSKIP("本机通信抓包检查通过 COURSESNIFFER_LIVE_TEST=1 启用。");
        const auto interfaces = CaptureWorker::enumerate();
        QString loopback;
        for (const auto& interface : interfaces)
            if (interface.name == QStringLiteral("lo0") || interface.name == QStringLiteral("lo")) loopback = interface.name;
        QVERIFY2(!loopback.isEmpty(), "回环接口不可用");
        qRegisterMetaType<CaptureSummary>();
        auto queue = std::make_shared<CaptureQueue>();
        auto thread = std::make_unique<QThread>();
        auto* worker = new CaptureWorker(queue);
        worker->moveToThread(thread.get());
        connect(thread.get(), &QThread::finished, worker, &QObject::deleteLater);
        CaptureObservation observation;
        observeCapture(worker, observation);
        std::vector<RawPacket> captured;
        auto drain = [&]() {
            auto batch = queue->take(512);
            for (auto& packet : batch) captured.push_back(std::move(packet));
        };
        QString failure;
        QProcess process;
        process.setProcessChannelMode(QProcess::MergedChannels);
        thread->start();
        QMetaObject::invokeMethod(worker, "startCapture", Qt::QueuedConnection, Q_ARG(QString, loopback));
        QElapsedTimer timer;
        timer.start();
        while (observation.started == 0 && observation.errors.isEmpty() && timer.elapsed() < 3000) { QTest::qWait(5); drain(); }
        if (!observation.errors.isEmpty()) failure = observation.errors.first();
        else if (observation.started == 0) failure = QStringLiteral("启动回环接口超时");
        if (failure.isEmpty()) {
            const QString python = qEnvironmentVariable("COURSESNIFFER_PYTHON", QStringLiteral("python3"));
            const QString script = QString::fromUtf8(SNIFFER_SOURCE_DIR) + QStringLiteral("/demo/run_demo.py");
            process.start(python, {script, QStringLiteral("--repeat"), QStringLiteral("1")});
            timer.restart();
            while (process.state() != QProcess::NotRunning && timer.elapsed() < 20000 && observation.errors.isEmpty()) {
                QTest::qWait(5); drain();
            }
            if (!observation.errors.isEmpty()) failure = observation.errors.first();
            else if (process.state() != QProcess::NotRunning) failure = QStringLiteral("演示通信执行超时");
            else if (process.error() == QProcess::FailedToStart)
                failure = QStringLiteral("无法启动 Python：%1").arg(process.errorString());
            else if (process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0)
                failure = QStringLiteral("演示通信失败：%1").arg(QString::fromUtf8(process.readAllStandardOutput()));
            if (failure.isEmpty()) {
                timer.restart();
                while (timer.elapsed() < 300) { QTest::qWait(5); drain(); }
            }
        }
        if (process.state() != QProcess::NotRunning) {
            process.terminate();
            if (!process.waitForFinished(2000)) { process.kill(); process.waitForFinished(2000); }
        }
        const bool threadFinished = stopCaptureThread(worker, thread);
        while (!queue->empty()) drain();
        QVERIFY(threadFinished);
        QVERIFY2(failure.isEmpty(), qPrintable(failure));
        QVERIFY(!captured.empty());
        TcpTracker tracker;
        std::set<std::uint64_t> connections;
        bool ipv4 = false, ipv6 = false, tcp = false, udp4 = false, udp6 = false;
        for (auto& raw : captured) {
            auto packet = PacketParser::parse(std::move(raw));
            ipv4 = ipv4 || packet.has(Protocol::Ipv4);
            ipv6 = ipv6 || packet.has(Protocol::Ipv6);
            tcp = tcp || packet.has(Protocol::Tcp);
            if (packet.has(Protocol::Udp) && (packet.source.port == 9999 || packet.destination.port == 9999)) {
                udp4 = udp4 || packet.has(Protocol::Ipv4);
                udp6 = udp6 || packet.has(Protocol::Ipv6);
            }
            const auto update = tracker.ingest(packet);
            if (update.connectionId) connections.insert(update.connectionId);
        }
        bool http4 = false, http6 = false;
        for (auto id : connections) {
            auto view = tracker.trace(id);
            if (!view || !view->connection.http) continue;
            bool request = false, response = false, body = false;
            for (std::size_t direction = 0; direction < 2; ++direction) {
                const auto& message = view->connection.httpMessages[direction];
                if (message) {
                    request = request || (message->method == "GET" && message->target.rfind("/lab", 0) == 0);
                    response = response || message->statusCode == 200;
                }
                body = body || streamText(view->directions[direction]).find("CourseSniffer EX1A") != std::string::npos;
            }
            if (request && response && body) {
                http4 = http4 || view->connection.a.family == 4;
                http6 = http6 || view->connection.a.family == 6;
            }
        }
        QVERIFY(ipv4);
        QVERIFY(ipv6);
        QVERIFY(tcp);
        QVERIFY(udp4);
        QVERIFY(udp6);
        QVERIFY2(http4, "IPv4 HTTP 请求、响应和正文需要出现在同一连接中");
        QVERIFY2(http6, "IPv6 HTTP 请求、响应和正文需要出现在同一连接中");
    }
};

QTEST_MAIN(GuiTests)
#include "test_gui.moc"
