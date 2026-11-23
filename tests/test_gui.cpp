#include <QtTest>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QProcess>
#include <QTableView>
#include <QTreeWidget>
#include <QTreeWidgetItemIterator>
#include "capture/CaptureWorker.h"
#include "ui/MainWindow.h"
#include "ui/DemoPackets.h"
#include "ui/StreamDialog.h"
#include "core/PacketParser.h"
#include <algorithm>
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
    CaptureSummary summary;
    QObject receiver;
};

void observeCapture(CaptureWorker* worker, CaptureObservation& observation) {
    // 观察对象属于测试线程，计数和错误列表仅由该线程访问。
    QObject::connect(worker, &CaptureWorker::captureStarted, &observation.receiver,
        [&observation](const QString&, int) { ++observation.started; }, Qt::QueuedConnection);
    QObject::connect(worker, &CaptureWorker::captureStopped, &observation.receiver,
        [&observation](const CaptureSummary& summary) { ++observation.stopped; observation.summary = summary; }, Qt::QueuedConnection);
    QObject::connect(worker, &CaptureWorker::captureModeChanged, &observation.receiver,
        [&observation](const CaptureSummary& summary) { observation.summary = summary; }, Qt::QueuedConnection);
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
    QCoreApplication::processEvents();
    return true;
}

bool hasField(const PacketRecord& packet, const std::string& layer, const std::string& name,
              const std::string& value) {
    return std::any_of(packet.fields.begin(), packet.fields.end(), [&](const Field& field) {
        return field.layer == layer && field.name == name && field.value == value;
    });
}

bool treeHasValue(QTreeWidget* tree, const QString& name, const QString& value) {
    for (QTreeWidgetItemIterator item(tree); *item; ++item)
        if ((*item)->text(0) == name && (*item)->text(1) == value) return true;
    return false;
}
}

class GuiTests : public QObject {
    Q_OBJECT
private slots:
    void captureModePolicy() {
        NetworkInterface flagged;
        flagged.name = QStringLiteral("en0");
        flagged.flags = PCAP_IF_LOOPBACK | PCAP_IF_UP;
        QVERIFY(flagged.isLoopback());
        QVERIFY(!requestsPromiscuousMode(flagged.flags));
        NetworkInterface unflagged;
        unflagged.name = QStringLiteral("lo0");
        unflagged.flags = PCAP_IF_UP;
        QVERIFY(!unflagged.isLoopback());
        QVERIFY(requestsPromiscuousMode(unflagged.flags));
        QCOMPARE(captureSetupAction(true, 0), CaptureSetupAction::Continue);
        QCOMPARE(captureSetupAction(true, PCAP_WARNING), CaptureSetupAction::Continue);
        QCOMPARE(captureSetupAction(true, PCAP_WARNING_PROMISC_NOTSUP), CaptureSetupAction::RetryOrdinary);
        QCOMPARE(captureSetupAction(true, PCAP_ERROR_PROMISC_PERM_DENIED), CaptureSetupAction::RetryOrdinary);
        QCOMPARE(captureSetupAction(true, PCAP_ERROR_PERM_DENIED), CaptureSetupAction::Fail);
        QCOMPARE(captureSetupAction(true, PCAP_ERROR_NO_SUCH_DEVICE), CaptureSetupAction::Fail);
        QCOMPARE(captureSetupAction(false, PCAP_ERROR_PROMISC_PERM_DENIED), CaptureSetupAction::Fail);
        QCOMPARE(captureSetupAction(false, PCAP_WARNING), CaptureSetupAction::Continue);
        QCOMPARE(captureSetupAction(false, 0), CaptureSetupAction::Continue);
    }

    void captureModeWarningsRemainVisible() {
        MainWindow window;
        CaptureSummary summary;
        summary.interfaceName = QStringLiteral("en0");
        summary.interfaceFlagsKnown = true;
        summary.interfaceFlags = PCAP_IF_UP;
        summary.promiscuousRequested = true;
        summary.finalPromiscuousRequest = false;
        summary.ordinaryFallback = true;
        summary.activationAttempted = true;
        summary.captureActivated = true;
        summary.activationResult = 0;
        summary.reason = QStringLiteral("捕获已停止");
        summary.warnings = {QStringLiteral("混杂模式权限不足，已请求普通模式。"),
                            QStringLiteral("接口返回捕获缓冲区警告。")};
        summary.warning = summary.warnings.join('\n');
        summary.apiResults = {QStringLiteral("pcap_activate() 返回 -11"),
                              QStringLiteral("pcap_set_promisc(0) 返回 0"),
                              QStringLiteral("pcap_activate() 返回 0")};
        int finished = 0;
        CaptureSummary finishedSummary;
        connect(&window, &MainWindow::sessionFinished, &window, [&](const CaptureSummary& result) {
            ++finished;
            finishedSummary = result;
        });
        QVERIFY(QMetaObject::invokeMethod(&window, "onCaptureStopped", Qt::DirectConnection,
                                         Q_ARG(sniffer::CaptureSummary, summary)));
        auto* mode = window.findChild<QLabel*>(QStringLiteral("captureMode"));
        QVERIFY(mode);
        QVERIFY(mode->text().contains(QStringLiteral("请求：混杂模式")));
        QVERIFY(mode->text().contains(QStringLiteral("普通模式回退")));
        QVERIFY(mode->text().contains(QStringLiteral("普通模式请求获 API 接受")));
        for (const auto& warning : summary.warnings) QVERIFY(mode->text().contains(warning));
        for (const auto& result : summary.apiResults) QVERIFY(mode->toolTip().contains(result));
        QCOMPARE(window.lastCaptureSummary().warnings, summary.warnings);
        QCOMPARE(finishedSummary.apiResults, summary.apiResults);
        QCOMPARE(finished, 1);
        QVERIFY(!window.captureBusy());
        QVERIFY(!window.captureHasError());
        summary.error = true;
        QVERIFY(QMetaObject::invokeMethod(&window, "onCaptureModeChanged", Qt::DirectConnection,
                                         Q_ARG(sniffer::CaptureSummary, summary)));
        QVERIFY(window.captureHasError());
    }

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
        QCOMPARE(window.packetModel()->rowCount(), 22);
        QVERIFY(!window.captureBusy());
        QString error;
        QVERIFY(window.proxyModel()->setExpression(QStringLiteral("http"), &error));
        QCOMPARE(window.proxyModel()->rowCount(), 4);
        QVERIFY(window.proxyModel()->setExpression(QStringLiteral("ipv6 and (udp or icmp6)"), &error));
        QCOMPARE(window.proxyModel()->rowCount(), 4);
        QVERIFY(!window.proxyModel()->setExpression(QStringLiteral("tcp and ("), &error));
        QVERIFY(!error.isEmpty());
        QCOMPARE(window.proxyModel()->rowCount(), 4);
        QVERIFY(window.proxyModel()->setExpression(QString(), &error));
        QCOMPARE(window.proxyModel()->rowCount(), 22);
        auto* description = window.findChild<QLabel*>(QStringLiteral("sessionDescription"));
        QVERIFY(description);
        QVERIFY(description->text().contains(QStringLiteral("演示数据")));
        const auto* icmp = window.packetModel()->packetAt(13);
        QVERIFY(icmp && !icmp->hasPorts);
        QCOMPARE(window.packetModel()->data(window.packetModel()->index(13, PacketTableModel::Source)).toString(),
                 QString::fromStdString(icmp->source.text));
        QVERIFY(!window.startCaptureOnInterface(QStringLiteral("coursesniffer_missing_interface")));
        QVERIFY(!window.startCaptureOnInterface(QStringLiteral("lo0")));
    }

    void dnsAndArpFiltersAndFields() {
        MainWindow window;
        QVERIFY(!window.startCaptureOnInterface(QStringLiteral("coursesniffer_missing_interface")));
        window.loadDemoPackets(builtInDemoPackets());
        auto* table = window.findChild<QTableView*>(QStringLiteral("packetTable"));
        auto* details = window.findChild<QTreeWidget*>(QStringLiteral("packetDetails"));
        QVERIFY(table && details);
        QString error;
        QVERIFY2(window.proxyModel()->setExpression(QStringLiteral("dns and udp.port == 53"), &error), qPrintable(error));
        QCOMPARE(window.proxyModel()->rowCount(), 4);
        for (int row = 0; row < 4; ++row) {
            const auto index = window.proxyModel()->mapToSource(window.proxyModel()->index(row, 0));
            const auto* packet = window.packetModel()->packetAt(index.row());
            QVERIFY(packet && packet->has(Protocol::Dns) && !packet->malformed);
            QCOMPARE(packet->protocolName(), std::string("DNS"));
            QVERIFY(hasField(*packet, "DNS Question 1", "QNAME", "example.test."));
            QVERIFY(hasField(*packet, "DNS Question 1", "QTYPE", row < 2 ? "A (1)" : "AAAA (28)"));
            if (row % 2 == 1)
                QVERIFY(hasField(*packet, "DNS Answer 1", "RDATA", row < 2 ? "192.0.2.123" : "2001:db8::123"));
        }
        table->selectRow(1);
        QVERIFY(treeHasValue(details, QStringLiteral("QNAME"), QStringLiteral("example.test.")));
        QVERIFY(treeHasValue(details, QStringLiteral("RDATA"), QStringLiteral("192.0.2.123")));
        QVERIFY(window.proxyModel()->setExpression(QStringLiteral("dns and ipv6"), &error));
        QCOMPARE(window.proxyModel()->rowCount(), 2);
        table->selectRow(1);
        QVERIFY(treeHasValue(details, QStringLiteral("RDATA"), QStringLiteral("2001:db8::123")));
        QVERIFY(window.proxyModel()->setExpression(QStringLiteral("arp"), &error));
        QCOMPARE(window.proxyModel()->rowCount(), 2);
        table->selectRow(0);
        QVERIFY(treeHasValue(details, QStringLiteral("Sender IP"), QStringLiteral("192.0.2.123")));
        QVERIFY(treeHasValue(details, QStringLiteral("Target IP"), QStringLiteral("192.0.2.1")));
        QVERIFY(treeHasValue(details, QStringLiteral("Opcode"), QStringLiteral("1")));
        const auto index = window.proxyModel()->mapToSource(window.proxyModel()->index(0, 0));
        const auto* arp = window.packetModel()->packetAt(index.row());
        QVERIFY(arp && arp->has(Protocol::Arp) && !arp->hasPorts && !arp->malformed);
        QCOMPARE(window.packetModel()->data(window.packetModel()->index(index.row(), PacketTableModel::Source)).toString(),
                 QStringLiteral("192.0.2.123"));
        QVERIFY(window.proxyModel()->setExpression(QStringLiteral("ip.addr == 127.0.0.1 and tcp.port == 8080"), &error));
        QCOMPARE(window.proxyModel()->rowCount(), 12);
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
            if (interface.isLoopback()) { loopback = interface.name; break; }
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
        QVERIFY(observation.summary.interfaceFlagsKnown);
        QVERIFY((observation.summary.interfaceFlags & PCAP_IF_LOOPBACK) != 0);
        QVERIFY(!observation.summary.promiscuousRequested);
        QVERIFY(!observation.summary.finalPromiscuousRequest);
        QVERIFY(!observation.summary.ordinaryFallback);
    }

    void livePhysicalInterfaceMode() {
        if (qEnvironmentVariableIntValue("COURSESNIFFER_LIVE_TEST") != 1)
            QSKIP("物理接口捕获模式检查通过 COURSESNIFFER_LIVE_TEST=1 启用。");
        QString enumerationError;
        const auto interfaces = CaptureWorker::enumerate(&enumerationError);
        const QString requested = qEnvironmentVariable("COURSESNIFFER_INTERFACE");
        auto selected = interfaces.cend();
        if (!requested.isEmpty()) {
            selected = std::find_if(interfaces.cbegin(), interfaces.cend(), [&](const NetworkInterface& item) {
                return item.name == requested;
            });
        } else {
            selected = std::find_if(interfaces.cbegin(), interfaces.cend(), [](const NetworkInterface& item) {
                return item.name == QStringLiteral("en0") && !item.isLoopback();
            });
            if (selected == interfaces.cend())
                selected = std::find_if(interfaces.cbegin(), interfaces.cend(), [](const NetworkInterface& item) {
                    return !item.isLoopback() && !item.addresses.isEmpty();
                });
        }
        QVERIFY2(selected != interfaces.cend(), qPrintable(enumerationError.isEmpty()
            ? QStringLiteral("指定的非回环接口不可用；可通过 COURSESNIFFER_INTERFACE 选择接口。") : enumerationError));
        QVERIFY2(!selected->isLoopback(), "物理接口模式检查需要选择非回环接口。");
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
                                                       Q_ARG(QString, selected->name));
        QElapsedTimer timer;
        timer.start();
        while (observation.started == 0 && observation.errors.isEmpty() && timer.elapsed() < 3000) QTest::qWait(5);
        const bool threadFinished = stopCaptureThread(worker, thread);
        while (!queue->empty()) queue->take(512);
        qInfo().noquote() << QStringLiteral("接口 %1：%2").arg(selected->name, captureModeDescription(observation.summary));
        for (const auto& result : observation.summary.apiResults) qInfo().noquote() << result;
        for (const auto& warning : observation.summary.warnings) qInfo().noquote() << warning;
        QVERIFY(threadFinished);
        QVERIFY(invoked);
        QVERIFY2(observation.errors.isEmpty(), qPrintable(observation.errors.join('\n')));
        QCOMPARE(observation.started, 1);
        QCOMPARE(observation.stopped, 1);
        QVERIFY(observation.summary.interfaceFlagsKnown);
        QCOMPARE(observation.summary.interfaceFlags, selected->flags);
        QVERIFY((observation.summary.interfaceFlags & PCAP_IF_LOOPBACK) == 0);
        QVERIFY(observation.summary.promiscuousRequested);
        QVERIFY(observation.summary.activationAttempted);
        QVERIFY(observation.summary.captureActivated);
        QVERIFY(observation.summary.activationResult >= 0);
        QCOMPARE(observation.summary.finalPromiscuousRequest, !observation.summary.ordinaryFallback);
        QVERIFY(!observation.summary.apiResults.isEmpty());
        QVERIFY(!observation.summary.error);
    }

    void liveLoopbackTraffic() {
        if (qEnvironmentVariableIntValue("COURSESNIFFER_LIVE_TEST") != 1)
            QSKIP("本机通信抓包检查通过 COURSESNIFFER_LIVE_TEST=1 启用。");
        const auto interfaces = CaptureWorker::enumerate();
        QString loopback;
        for (const auto& interface : interfaces)
            if (interface.isLoopback()) { loopback = interface.name; break; }
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
            process.start(python, {script, QStringLiteral("--repeat"), QStringLiteral("1"), QStringLiteral("--dns")});
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
        QVERIFY(observation.summary.interfaceFlagsKnown);
        QVERIFY((observation.summary.interfaceFlags & PCAP_IF_LOOPBACK) != 0);
        QVERIFY(!observation.summary.promiscuousRequested);
        QVERIFY(!observation.summary.finalPromiscuousRequest);
        QVERIFY(!observation.summary.error);
        TcpTracker tracker;
        std::set<std::uint64_t> connections;
        std::set<std::pair<int, int>> dnsQuestions;
        std::set<std::pair<int, int>> dnsAnswers;
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
            if (packet.has(Protocol::Dns) && hasField(packet, "DNS Question 1", "QNAME", "example.test.")) {
                const int family = packet.has(Protocol::Ipv6) ? 6 : 4;
                for (int type : {1, 28}) {
                    const std::string typeName = type == 1 ? "A (1)" : "AAAA (28)";
                    if (!hasField(packet, "DNS Question 1", "QTYPE", typeName)) continue;
                    if (hasField(packet, "DNS", "QR", "0 (Query)")) dnsQuestions.emplace(family, type);
                    const std::string address = type == 1 ? "192.0.2.123" : "2001:db8::123";
                    if (hasField(packet, "DNS", "QR", "1 (Response)") &&
                        hasField(packet, "DNS Answer 1", "NAME", "example.test.") &&
                        hasField(packet, "DNS Answer 1", "TYPE", typeName) &&
                        hasField(packet, "DNS Answer 1", "RDATA", address)) dnsAnswers.emplace(family, type);
                }
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
        for (int family : {4, 6}) {
            for (int type : {1, 28}) {
                QVERIFY2(dnsQuestions.count({family, type}) == 1,
                         qPrintable(QStringLiteral("IPv%1 缺少 example.test 的 DNS %2 查询。").arg(family).arg(type == 1 ? "A" : "AAAA")));
                QVERIFY2(dnsAnswers.count({family, type}) == 1,
                         qPrintable(QStringLiteral("IPv%1 缺少 example.test 的 DNS %2 回答。").arg(family).arg(type == 1 ? "A" : "AAAA")));
            }
        }
    }
};

QTEST_MAIN(GuiTests)
#include "test_gui.moc"
