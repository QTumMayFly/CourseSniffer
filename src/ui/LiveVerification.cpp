#include "LiveVerification.h"
#include "MainWindow.h"
#include "StreamDialog.h"
#include <QApplication>
#include <QDateTime>
#include <QDir>
#include <QEvent>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcess>
#include <QPointer>
#include <QSaveFile>
#include <QSysInfo>
#include <QTableView>
#include <QTextStream>
#include <QTimer>
#include <pcap/pcap.h>
#include <unistd.h>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <set>

namespace sniffer {
namespace {
class LiveVerification final : public QObject {
public:
    LiveVerification(MainWindow& window, QString directory, QString script, QString interfaceName)
        : QObject(qApp), window_(window), directory_(std::move(directory)),
          script_(std::move(script)), interface_(std::move(interfaceName)) {
        window_.setVerificationActive(true);
        qApp->installEventFilter(this);
        deadline_.setSingleShot(true);
        stopDeadline_.setSingleShot(true);
        connect(&deadline_, &QTimer::timeout, this, [this]() {
            failures_ << QStringLiteral("实际界面捕获验证超过四十五秒。");
            requestStop(true);
        });
        connect(&stopDeadline_, &QTimer::timeout, this, [this]() {
            if (finished_) return;
            if (window_.captureBusy()) {
                failures_ << QStringLiteral("捕获工作线程在停止请求后三秒内未完成，验证进程将以失败状态结束。");
                forceExit_ = true;
            }
            finish();
        });
        connect(&window_, &MainWindow::verificationCloseRequested, this, [this]() {
            failures_ << QStringLiteral("实际界面验证完成之前收到关闭窗口请求。");
            requestStop(true);
        });
        connect(&window_, &MainWindow::sessionStarted, this, [this](const QString&, int) {
            if (finished_ || stopping_) return;
            process_.setProcessChannelMode(QProcess::MergedChannels);
            process_.start(qEnvironmentVariable("COURSESNIFFER_PYTHON", QStringLiteral("python3")),
                           {script_, QStringLiteral("--repeat"), QStringLiteral("1")});
        });
        connect(&process_, &QProcess::errorOccurred, this, [this](QProcess::ProcessError error) {
            if (error == QProcess::FailedToStart && !finished_) {
                failures_ << QStringLiteral("演示通信进程无法启动：%1").arg(process_.errorString());
                requestStop(true);
            }
        });
        connect(&process_, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), this,
                [this](int code, QProcess::ExitStatus status) {
            if (finished_) return;
            trafficPassed_ = code == 0 && status == QProcess::NormalExit;
            if (!trafficPassed_) failures_ << QStringLiteral("演示通信进程执行失败。");
            QTimer::singleShot(600, this, [this]() { requestStop(); });
        });
        connect(&window_, &MainWindow::sessionFinished, this, [this](const CaptureSummary&) { finish(); });
    }

    void begin() {
        if (finished_) return;
        if (!QDir().mkpath(directory_)) {
            QTextStream(stderr) << "无法创建验证结果目录。\n";
            saved_ = true;
            qApp->exit(2);
            return;
        }
        deadline_.start(45000);
        if (!QFileInfo(script_).isFile()) {
            failures_ << QStringLiteral("演示通信脚本不存在。");
            finish();
        } else if (!window_.startCaptureOnInterface(interface_)) {
            failures_ << QStringLiteral("无法启动指定接口：%1").arg(interface_);
            requestStop(true);
        }
    }

private:
    bool eventFilter(QObject* object, QEvent* event) override {
        if (object == qApp && event->type() == QEvent::Quit && !saved_) {
            failures_ << QStringLiteral("实际界面验证完成之前收到退出程序请求。");
            requestStop(true);
            return true;
        }
        return QObject::eventFilter(object, event);
    }
    bool writeFile(const QString& name, const QByteArray& bytes) {
        if (!QDir().mkpath(directory_)) return false;
        QSaveFile output(QDir(directory_).filePath(name));
        return output.open(QIODevice::WriteOnly) && output.write(bytes) == bytes.size() && output.commit();
    }
    void stopTraffic() {
        if (process_.state() != QProcess::NotRunning) {
            process_.terminate();
            if (!process_.waitForFinished(1000)) {
                process_.kill();
                if (!process_.waitForFinished(1000) && process_.state() != QProcess::NotRunning) {
                    failures_ << QStringLiteral("演示通信进程在结束请求后仍未退出。");
                    forceExit_ = true;
                }
            }
        }
    }
    void requestStop(bool abortTraffic = false) {
        if (saved_) return;
        stopping_ = true;
        if (abortTraffic) stopTraffic();
        if (finished_) return;
        if (!window_.captureBusy()) { finish(); return; }
        window_.requestCaptureStop();
        if (!stopDeadline_.isActive()) stopDeadline_.start(3000);
    }
    void finish() {
        if (finished_) return;
        finished_ = true;
        deadline_.stop();
        stopDeadline_.stop();
        stopTraffic();
        const auto summary = window_.lastCaptureSummary();
        if (summary.error || window_.captureHasError()) failures_ << summary.reason;
        if (!summary.captureActivated) failures_ << QStringLiteral("捕获接口尚未成功激活。");
        if (!trafficPassed_) failures_ << QStringLiteral("HTTP 与 UDP 演示通信尚未完成成功验证。");
        const std::pair<const char*, Protocol> protocols[] = {
            {"ipv4", Protocol::Ipv4}, {"ipv6", Protocol::Ipv6}, {"tcp", Protocol::Tcp},
            {"udp", Protocol::Udp}, {"http", Protocol::Http}, {"dns", Protocol::Dns},
            {"arp", Protocol::Arp}, {"icmp", Protocol::Icmp}, {"icmp6", Protocol::Icmp6}
        };
        QJsonObject counts;
        for (const auto& item : protocols) {
            int count = 0;
            for (int row = 0; row < window_.packetModel()->rowCount(); ++row)
                if (window_.packetModel()->packetAt(row)->has(item.second)) ++count;
            counts[QString::fromLatin1(item.first)] = count;
        }
        std::array<std::array<bool, 2>, 2> udp{};
        std::array<std::uint64_t, 2> httpConnections{};
        std::set<std::uint64_t> connections;
        for (int row = 0; row < window_.packetModel()->rowCount(); ++row) {
            const auto* packet = window_.packetModel()->packetAt(row);
            if (packet->connectionId) connections.insert(packet->connectionId);
            if (!packet->has(Protocol::Udp) || !packet->hasPorts || packet->malformed || packet->truncated) continue;
            const std::size_t family = packet->has(Protocol::Ipv6) ? 1 : 0;
            const std::string address = family ? "::1" : "127.0.0.1";
            if (packet->source.text != address || packet->destination.text != address) continue;
            const auto payload = packet->payload();
            const std::string content(payload.begin(), payload.end());
            const std::string expected = family ? "CourseSniffer IPv6 UDP 1" : "CourseSniffer IPv4 UDP 1";
            if (packet->destination.port == 9999 && content == expected) udp[family][0] = true;
            if (packet->source.port == 9999 && content == "echo: " + expected) udp[family][1] = true;
        }
        for (const auto id : connections) {
            const auto view = window_.traceConnection(id);
            if (!view || !view->connection.http ||
                (view->connection.a.port != 8080 && view->connection.b.port != 8080)) continue;
            const std::size_t family = view->connection.a.family == 6 ? 1 : 0;
            const std::string address = family ? "::1" : "127.0.0.1";
            if (view->connection.a.text != address || view->connection.b.text != address) continue;
            for (std::size_t direction = 0; direction < 2; ++direction) {
                const auto& request = view->connection.httpMessages[direction];
                const auto& response = view->connection.httpMessages[1 - direction];
                if (request && response && request->method == "GET" && request->target.rfind("/lab", 0) == 0 &&
                    response->statusCode == 200 &&
                    streamText(view->directions[1 - direction]).find("CourseSniffer EX1A") != std::string::npos)
                    httpConnections[family] = id;
            }
        }
        QJsonObject demonstrationChecks;
        for (std::size_t family = 0; family < 2; ++family) {
            const QString label = family ? QStringLiteral("IPv6") : QStringLiteral("IPv4");
            demonstrationChecks[label] = QJsonObject{{"udp_request", udp[family][0]},
                {"udp_response", udp[family][1]}, {"http_connection_id", static_cast<qint64>(httpConnections[family])}};
            if (!udp[family][0] || !udp[family][1])
                failures_ << QStringLiteral("%1 捕获记录缺少 UDP 9999 演示请求或对应回应内容。").arg(label);
            if (!httpConnections[family])
                failures_ << QStringLiteral("%1 捕获记录缺少同一连接中的 /lab 请求、200 响应和演示正文。").arg(label);
        }
        verifiedConnection_ = httpConnections[0] ? httpConnections[0] : httpConnections[1];
        QJsonObject filters;
        for (const auto* expression : {"http and tcp.port==8080", "ip.addr==127.0.0.1", "ip.addr==::1"}) {
            QString error;
            const bool accepted = window_.proxyModel()->setExpression(QString::fromLatin1(expression), &error);
            filters[QString::fromLatin1(expression)] = accepted ? window_.proxyModel()->rowCount() : -1;
            if (!accepted || window_.proxyModel()->rowCount() == 0)
                failures_ << QStringLiteral("实际数据过滤检查未通过：%1").arg(QString::fromLatin1(expression));
        }
        window_.proxyModel()->setExpression(QString());
        report_ = {{"application_version", QCoreApplication::applicationVersion()},
            {"created_utc", QDateTime::currentDateTimeUtc().toString(Qt::ISODate)},
            {"platform", QSysInfo::prettyProductName()}, {"architecture", QSysInfo::currentCpuArchitecture()},
            {"qt_version", QString::fromLatin1(qVersion())}, {"libpcap_version", QString::fromLatin1(pcap_lib_version())},
            {"effective_uid", static_cast<int>(geteuid())}, {"data_source", "live-libpcap"},
            {"interface_name", interface_}, {"capture_mode", captureModeDescription(summary)},
            {"promiscuous_requested", summary.promiscuousRequested}, {"ordinary_fallback", summary.ordinaryFallback},
            {"activation_result", summary.activationResult}, {"capture_activated", summary.captureActivated},
            {"api_results", QJsonArray::fromStringList(summary.apiResults)},
            {"warnings", QJsonArray::fromStringList(summary.warnings)},
            {"packet_count", window_.packetModel()->rowCount()}, {"protocol_counts", counts},
            {"filter_match_counts", filters}, {"traffic_passed", trafficPassed_},
            {"demonstration_checks", demonstrationChecks},
            {"screenshot_connection_id", static_cast<qint64>(verifiedConnection_)},
            {"capture_finished", !window_.captureBusy()}};
        if (!writeFile(QStringLiteral("demo_traffic.txt"), process_.isOpen() ? process_.readAll() : QByteArray()))
            failures_ << QStringLiteral("演示通信日志保存失败。");
        if (forceExit_) { saveAndExit(); return; }
        QTimer::singleShot(250, this, [this]() {
            for (int row = 0; row < window_.packetModel()->rowCount(); ++row) {
                const auto* packet = window_.packetModel()->packetAt(row);
                if (packet->connectionId != verifiedConnection_ || !packet->has(Protocol::Http)) continue;
                if (auto* table = window_.findChild<QTableView*>(QStringLiteral("packetTable"))) {
                    const auto index = window_.proxyModel()->mapFromSource(window_.packetModel()->index(row, 0));
                    table->selectRow(index.row());
                    table->scrollTo(index);
                }
                break;
            }
            if (!window_.grab().save(QDir(directory_).filePath(QStringLiteral("main_window_live.png"))))
                failures_ << QStringLiteral("实际抓包窗口截图保存失败。");
            QPointer<StreamDialog> stream = verifiedConnection_ ? window_.showConnection(verifiedConnection_) : nullptr;
            if (!stream) {
                failures_ << QStringLiteral("实际数据未形成可展示的 TCP 连接。");
                saveAndExit();
                return;
            }
            QTimer::singleShot(150, this, [this, stream]() {
                if (!stream || !stream->isVisible())
                    failures_ << QStringLiteral("TCP 内容窗口在截图完成之前关闭。");
                else if (!stream->grab().save(QDir(directory_).filePath(QStringLiteral("tcp_stream_live.png"))))
                    failures_ << QStringLiteral("实际 TCP 内容窗口截图保存失败。");
                saveAndExit();
            });
        });
    }
    void saveAndExit() {
        if (saved_) return;
        saved_ = true;
        failures_.removeDuplicates();
        const QString log = failures_.isEmpty() ? QStringLiteral("实际界面抓包验证通过。") : failures_.join('\n');
        if (!writeFile(QStringLiteral("verification_log.txt"), log.toUtf8() + '\n'))
            failures_ << QStringLiteral("验证结果日志保存失败。");
        report_["failures"] = QJsonArray::fromStringList(failures_);
        report_["passed"] = failures_.isEmpty();
        report_["forced_process_exit"] = forceExit_;
        const bool saved = writeFile(QStringLiteral("capture_proof.json"), QJsonDocument(report_).toJson());
        QTextStream output(failures_.isEmpty() && saved ? stdout : stderr);
        output << (failures_.isEmpty() && saved ? "实际界面抓包验证通过。\n" : "实际界面抓包验证未通过。\n");
        for (const auto& failure : failures_) output << failure << '\n';
        if (!saved) output << "JSON 验证记录保存失败。\n";
        output.flush();
        if (forceExit_) {
            std::fflush(nullptr);
            std::_Exit(2);
        }
        qApp->exit(failures_.isEmpty() && saved ? 0 : 2);
    }
    MainWindow& window_;
    QString directory_, script_, interface_;
    QProcess process_;
    QTimer deadline_;
    QTimer stopDeadline_;
    QStringList failures_;
    QJsonObject report_;
    bool trafficPassed_ = false;
    bool finished_ = false;
    bool stopping_ = false;
    bool saved_ = false;
    bool forceExit_ = false;
    std::uint64_t verifiedConnection_ = 0;
};
}

void startLiveVerification(MainWindow& window, const QString& directory,
                           const QString& demoScript, const QString& interfaceName) {
    auto* verification = new LiveVerification(window, directory, demoScript, interfaceName);
    QTimer::singleShot(0, verification, [verification]() { verification->begin(); });
}
}
