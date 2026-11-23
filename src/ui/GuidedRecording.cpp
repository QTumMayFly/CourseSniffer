#include "GuidedRecording.h"
#include "MainWindow.h"
#include "StreamDialog.h"
#include "DemoPackets.h"
#include "core/PacketRecord.h"

#include <QAbstractItemView>
#include <QApplication>
#include <QBuffer>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QFont>
#include <QImage>
#include <QJsonArray>
#include <QSysInfo>
#include <QMetaObject>
#include <QPixmap>
#include <QColor>
#include <QStringList>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QPainter>
#include <QPointer>
#include <QProcess>
#include <QSaveFile>
#include <QTabWidget>
#include <QTableView>
#include <QTextStream>
#include <QTimer>
#include <QVector>

#include <algorithm>
#include <cstdint>
#include <utility>

namespace sniffer {
namespace {
constexpr int FrameWidth = 1440;
constexpr int FrameHeight = 1000;
constexpr int FrameRate = 8;
constexpr int FrameIntervalMs = 1000 / FrameRate;
constexpr int CaptureAreaHeight = 866;

struct CaptionCue {
    int frame = 0;
    QString text;
};

QString subtitleTime(int frames) {
    const qint64 millis = static_cast<qint64>(frames) * 1000 / FrameRate;
    const qint64 hours = millis / 3600000;
    const qint64 minutes = (millis / 60000) % 60;
    const qint64 seconds = (millis / 1000) % 60;
    const qint64 remainder = millis % 1000;
    return QStringLiteral("%1:%2:%3,%4")
        .arg(hours, 2, 10, QLatin1Char('0'))
        .arg(minutes, 2, 10, QLatin1Char('0'))
        .arg(seconds, 2, 10, QLatin1Char('0'))
        .arg(remainder, 3, 10, QLatin1Char('0'));
}

class GuidedRecording final : public QObject {
public:
    GuidedRecording(MainWindow& window, QString moviePath, QString script, QString pcap)
        : QObject(qApp), window_(window), moviePath_(std::move(moviePath)),
          script_(std::move(script)), pcap_(std::move(pcap)) {
        const QFileInfo movie(moviePath_);
        const QDir parent(movie.absolutePath());
        const QString stem = movie.completeBaseName();
        partialMovie_ = parent.filePath(stem + QStringLiteral(".recording.mp4"));
        subtitlePath_ = parent.filePath(stem + QStringLiteral(".srt"));
        manifestPath_ = parent.filePath(stem + QStringLiteral(".proof.json"));
        ffmpegLog_ = parent.filePath(stem + QStringLiteral(".ffmpeg.log"));
        trafficLog_ = parent.filePath(stem + QStringLiteral(".traffic.log"));

        frameTimer_.setInterval(FrameIntervalMs);
        connect(&frameTimer_, &QTimer::timeout, this, [this]() { recordFrame(); });
        connect(&window_, &MainWindow::sessionStarted, this, [this](const QString&, int) {
            if (!captureRequested_ || ending_ || aborting_ || activated_) return;
            activated_ = true;
            caption(QStringLiteral("libpcap 已打开本机 lo0 回环接口。现在捕获真实 IPv4、IPv6、TCP 和 UDP 报文。"));
            QTimer::singleShot(2800, this, [this]() { launchTraffic(); });
        });
        connect(&window_, &MainWindow::sessionFinished, this, [this](const CaptureSummary& summary) {
            if (!captureRequested_ || ending_ || aborting_) return;
            if (!summary.captureActivated || summary.error || window_.captureHasError()) {
                fail(QStringLiteral("本机实时抓包失败：%1").arg(summary.reason));
                return;
            }
            if (!trafficPassed_) {
                fail(QStringLiteral("本机通信尚未通过检查。"));
                return;
            }
            livePacketCount_ = window_.packetModel()->rowCount();
            int ipv4 = 0, ipv6 = 0, tcp = 0, udp = 0, http = 0;
            for (int i = 0; i < livePacketCount_; ++i) {
                const auto* packet = window_.packetModel()->packetAt(i);
                ipv4 += packet->has(Protocol::Ipv4);
                ipv6 += packet->has(Protocol::Ipv6);
                tcp += packet->has(Protocol::Tcp);
                udp += packet->has(Protocol::Udp);
                http += packet->has(Protocol::Http);
            }
            liveProtocols_ = QJsonObject{{"ipv4", ipv4}, {"ipv6", ipv6}, {"tcp", tcp},
                                         {"udp", udp}, {"http", http}};
            if (ipv4 == 0 || ipv6 == 0 || tcp == 0 || udp == 0 || http == 0) {
                fail(QStringLiteral("真实抓包缺少 IPv4、IPv6、TCP、UDP 或 HTTP 数据，详见验证记录。"));
                return;
            }
            if (!findBidirectionalHttpStream()) {
                fail(QStringLiteral("实际抓包未形成可追踪的 HTTP 双向内容。"));
                return;
            }
            window_.setVerificationActive(false);
            caption(QStringLiteral("停止捕获后，真实数据包保留在列表中。可以逐层检查协议字段及原始十六进制内容。"));
            selectPacket(Protocol::Tcp, 0);
            QTimer::singleShot(6500, this, [this]() { showTcpFilter(); });
        });
        connect(&window_, &MainWindow::verificationCloseRequested, this, [this]() {
            fail(QStringLiteral("演示录制过程中收到关闭窗口请求。"));
        });
        connect(&traffic_, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), this,
                [this](int status, QProcess::ExitStatus exitStatus) {
            trafficOutput_ += traffic_.readAll();
            if (ending_ || aborting_) return;
            trafficPassed_ = status == 0 && exitStatus == QProcess::NormalExit;
            if (!trafficPassed_) {
                fail(QStringLiteral("演示通信脚本执行失败，详见 traffic.log。"));
                return;
            }
            caption(QStringLiteral("HTTP 请求与响应、双向 UDP 回声通信已经产生，继续捕获以展示协议识别结果。"));
            QTimer::singleShot(3700, this, [this]() {
                if (ending_ || aborting_) return;
                caption(QStringLiteral("点击停止抓包，完成当前实际捕获会话。"));
                window_.requestCaptureStop();
            });
        });
        connect(&traffic_, &QProcess::readyRead, this, [this]() { trafficOutput_ += traffic_.readAll(); });
        connect(&traffic_, &QProcess::errorOccurred, this, [this](QProcess::ProcessError error) {
            if (error == QProcess::FailedToStart && !ending_)
                fail(QStringLiteral("无法启动实际通信脚本：%1").arg(traffic_.errorString()));
        });
        connect(&encoder_, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), this,
                [this](int exitCode, QProcess::ExitStatus exitStatus) {
            encoderFinished(exitCode, exitStatus);
        });
        connect(&encoder_, &QProcess::errorOccurred, this, [this](QProcess::ProcessError error) {
            if (error == QProcess::FailedToStart)
                fail(QStringLiteral("视频编码器启动失败：%1").arg(encoder_.errorString()));
        });
    }

    void begin() {
        if (!QDir().mkpath(QFileInfo(moviePath_).absolutePath())) {
            fail(QStringLiteral("无法创建视频输出目录。"));
            return;
        }
        if (!QFileInfo(script_).isFile() || !QFileInfo(pcap_).isFile()) {
            fail(QStringLiteral("演示通信脚本或 PCAP 样例文件不存在。"));
            return;
        }
        if (QFileInfo(moviePath_).absoluteFilePath() == QFileInfo(partialMovie_).absoluteFilePath()) {
            fail(QStringLiteral("视频输出路径无效。"));
            return;
        }
        window_.resize(1320, 900);
        window_.raise();
        window_.activateWindow();
        window_.setVerificationActive(true);
        encoder_.setProcessChannelMode(QProcess::SeparateChannels);
        encoder_.setStandardErrorFile(ffmpegLog_, QIODevice::Truncate);
        encoder_.setStandardOutputFile(QProcess::nullDevice());
        const QString executable = qEnvironmentVariable("COURSESNIFFER_FFMPEG", QStringLiteral("ffmpeg"));
        encoder_.start(executable, {QStringLiteral("-hide_banner"), QStringLiteral("-loglevel"), QStringLiteral("error"),
            QStringLiteral("-y"), QStringLiteral("-f"), QStringLiteral("image2pipe"),
            QStringLiteral("-framerate"), QString::number(FrameRate),
            QStringLiteral("-vcodec"), QStringLiteral("mjpeg"), QStringLiteral("-i"), QStringLiteral("pipe:0"),
            QStringLiteral("-an"), QStringLiteral("-c:v"), QStringLiteral("libx264"),
            QStringLiteral("-preset"), QStringLiteral("veryfast"), QStringLiteral("-crf"), QStringLiteral("20"),
            QStringLiteral("-pix_fmt"), QStringLiteral("yuv420p"), QStringLiteral("-movflags"),
            QStringLiteral("+faststart"), partialMovie_});
        if (!encoder_.waitForStarted(5000)) {
            fail(QStringLiteral("无法运行 ffmpeg，请安装 Homebrew ffmpeg。"));
            return;
        }
        caption(QStringLiteral("软件与系统安全 · 实验 1A：CourseSniffer 网络嗅探器。演示包含真实抓包与协议分析。"));
        frameTimer_.start();
        QTimer::singleShot(5500, this, [this]() {
            if (ending_ || aborting_) return;
            captureRequested_ = true;
            caption(QStringLiteral("选择本机 lo0 回环接口，启动 libpcap 实时抓包。"));
            if (!window_.startCaptureOnInterface(QStringLiteral("lo0"))) {
                fail(QStringLiteral("无法选择或启动 lo0 接口，请检查 Mac 抓包权限。"));
            }
        });
        QTimer::singleShot(220000, this, [this]() {
            if (!ending_ && !aborting_) fail(QStringLiteral("演示超过预设运行上限。"));
        });
    }

private:
    void caption(const QString& value) {
        if (currentCaption_ == value) return;
        currentCaption_ = value;
        captions_.push_back(CaptionCue{frameCount_, value});
        QTextStream(stdout) << "演示步骤：" << value << '\n';
    }

    void recordFrame() {
        if (ending_) return;
        if (!window_.isVisible()) {
            fail(QStringLiteral("程序主窗口已关闭，录制提前终止。"));
            return;
        }
        if (encoder_.state() != QProcess::Running) {
            fail(QStringLiteral("ffmpeg 录制进程提前退出。"));
            return;
        }
        if (encoder_.bytesToWrite() > 8 * 1024 * 1024) {
            fail(QStringLiteral("视频编码速度不足，录制缓冲超过上限。"));
            return;
        }
        QImage image(FrameWidth, FrameHeight, QImage::Format_RGB32);
        image.fill(QColor(QStringLiteral("#E9EFF5")));
        QPainter painter(&image);
        painter.setRenderHint(QPainter::SmoothPixmapTransform);
        const QPixmap mainWindow = window_.grab();
        if (!mainWindow.isNull()) {
            const QPixmap scaled = mainWindow.scaled(FrameWidth, CaptureAreaHeight, Qt::KeepAspectRatio, Qt::SmoothTransformation);
            const QPoint topLeft((FrameWidth - scaled.width()) / 2,
                                 (CaptureAreaHeight - scaled.height()) / 2);
            painter.drawPixmap(topLeft, scaled);
        }
        if (stream_ && stream_->isVisible()) {
            const QPixmap popup = stream_->grab();
            if (!popup.isNull()) {
                const QPixmap scaled = popup.scaled(FrameWidth - 160, CaptureAreaHeight - 70,
                    Qt::KeepAspectRatio, Qt::SmoothTransformation);
                const QRect backdrop((FrameWidth - scaled.width()) / 2 - 12,
                    (CaptureAreaHeight - scaled.height()) / 2 - 12,
                    scaled.width() + 24, scaled.height() + 24);
                painter.fillRect(backdrop, QColor(25, 38, 54, 180));
                painter.drawPixmap(backdrop.topLeft() + QPoint(12, 12), scaled);
            }
        }
        painter.fillRect(QRect(0, CaptureAreaHeight, FrameWidth, FrameHeight - CaptureAreaHeight),
                         QColor(QStringLiteral("#152638")));
        painter.setPen(QColor(QStringLiteral("#91C6E8")));
        QFont labelFont(QStringLiteral("PingFang SC")); labelFont.setPixelSize(18); labelFont.setBold(true);
        painter.setFont(labelFont);
        painter.drawText(QRect(32, CaptureAreaHeight + 12, FrameWidth - 64, 26),
                         Qt::AlignLeft | Qt::AlignVCenter,
                         offline_ ? QStringLiteral("固定 PCAP 样例 · 离线协议分析")
                                  : QStringLiteral("真实 libpcap 捕获 · macOS lo0"));
        painter.setPen(Qt::white);
        QFont captionFont(QStringLiteral("PingFang SC")); captionFont.setPixelSize(27);
        painter.setFont(captionFont);
        painter.drawText(QRect(32, CaptureAreaHeight + 42, FrameWidth - 64, 85),
                         Qt::AlignLeft | Qt::AlignVCenter | Qt::TextWordWrap, currentCaption_);
        painter.end();
        QByteArray encoded;
        QBuffer bytes(&encoded);
        if (!bytes.open(QIODevice::WriteOnly) || !image.save(&bytes, "JPEG", 87)) {
            fail(QStringLiteral("GUI 画面无法编码为 JPEG 帧。"));
            return;
        }
        if (encoder_.write(encoded) != encoded.size()) {
            fail(QStringLiteral("写入视频编码器失败。"));
            return;
        }
        ++frameCount_;
    }

    void launchTraffic() {
        if (ending_ || aborting_ || !activated_) return;
        caption(QStringLiteral("运行本地 HTTP 与 UDP 服务，自动发送 IPv4、IPv6 请求及回应。"));
        traffic_.setProcessChannelMode(QProcess::MergedChannels);
        traffic_.start(qEnvironmentVariable("COURSESNIFFER_PYTHON", QStringLiteral("python3")),
                       {script_, QStringLiteral("--repeat"), QStringLiteral("3")});
    }

    bool findBidirectionalHttpStream() {
        for (int row = 0; row < window_.packetModel()->rowCount(); ++row) {
            const auto* packet = window_.packetModel()->packetAt(row);
            if (!packet || !packet->has(Protocol::Http) || !packet->connectionId ||
                !packet->has(Protocol::Ipv4)) continue;
            const auto view = window_.traceConnection(packet->connectionId);
            if (!view) continue;
            if (view->directions[0].uniqueBytes == 0 || view->directions[1].uniqueBytes == 0) continue;
            if (!view->connection.http) continue;
            streamId_ = packet->connectionId;
            return true;
        }
        return false;
    }

    bool filterTo(const QString& expression) {
        auto* input = window_.findChild<QLineEdit*>(QStringLiteral("filterEdit"));
        if (!input) { fail(QStringLiteral("未找到过滤输入框。")); return false; }
        input->setText(expression);
        if (!QMetaObject::invokeMethod(&window_, "applyFilter", Qt::DirectConnection)) {
            fail(QStringLiteral("无法调用协议过滤操作。")); return false;
        }
        if (window_.proxyModel()->expression() != expression) {
            fail(QStringLiteral("过滤表达式未被接受：%1").arg(expression)); return false;
        }
        return true;
    }

    bool selectPacket(Protocol protocol, std::uint64_t connectionId) {
        auto* table = window_.findChild<QTableView*>(QStringLiteral("packetTable"));
        if (!table) { fail(QStringLiteral("未找到数据包列表。")); return false; }
        const auto* source = window_.packetModel();
        auto* proxy = window_.proxyModel();
        for (int row = 0; row < source->rowCount(); ++row) {
            const auto* packet = source->packetAt(row);
            if (!packet || !packet->has(protocol) || (connectionId && packet->connectionId != connectionId)) continue;
            const QModelIndex index = proxy->mapFromSource(source->index(row, 0));
            if (!index.isValid()) continue;
            table->setCurrentIndex(index);
            table->selectRow(index.row());
            table->scrollTo(index, QAbstractItemView::PositionAtCenter);
            QMetaObject::invokeMethod(&window_, "showSelectedPacket", Qt::DirectConnection);
            return true;
        }
        fail(QStringLiteral("当前过滤结果缺少需要展示的协议数据包。"));
        return false;
    }

    void showTcpFilter() {
        if (ending_ || aborting_) return;
        caption(QStringLiteral("协议过滤支持地址、端口与逻辑运算，示例：ip.addr == 127.0.0.1 and tcp。"));
        if (!filterTo(QStringLiteral("ip.addr == 127.0.0.1 and tcp")) ||
            !selectPacket(Protocol::Tcp, 0)) return;
        QTimer::singleShot(6700, this, [this]() { showHttpFilter(); });
    }
    void showHttpFilter() {
        if (ending_ || aborting_) return;
        caption(QStringLiteral("HTTP 与 TCP 端口条件联合筛选；字段树展示请求头和传输层信息。"));
        if (!filterTo(QStringLiteral("http and tcp.port == 8080")) ||
            !selectPacket(Protocol::Http, streamId_)) return;
        QTimer::singleShot(7500, this, [this]() { showIpv6Filter(); });
    }
    void showIpv6Filter() {
        if (ending_ || aborting_) return;
        caption(QStringLiteral("IPv6 条件与括号组合：ipv6 and (tcp or udp)。可以分析 IPv6 的传输层协议。"));
        if (!filterTo(QStringLiteral("ipv6 and (tcp or udp)")) ||
            !selectPacket(Protocol::Udp, 0)) return;
        QTimer::singleShot(6500, this, [this]() { showUdpFilter(); });
    }
    void showUdpFilter() {
        if (ending_ || aborting_) return;
        caption(QStringLiteral("UDP 数据包独立解析：源端口、目的端口、长度，以及原始负载字节。"));
        if (!filterTo(QStringLiteral("udp and ip.addr == 127.0.0.1")) ||
            !selectPacket(Protocol::Udp, 0)) return;
        QTimer::singleShot(6500, this, [this]() { showStream(); });
    }
    void showStream() {
        if (ending_ || aborting_) return;
        caption(QStringLiteral("按 IP 地址与端口关联 TCP 连接，查看真实 HTTP 请求与响应的两个方向。"));
        if (!filterTo(QStringLiteral("http")) || !selectPacket(Protocol::Http, streamId_)) return;
        stream_ = window_.showConnection(streamId_);
        if (!stream_) { fail(QStringLiteral("无法打开实际 TCP 流内容窗口。")); return; }
        stream_->raise();
        QTimer::singleShot(8500, this, [this]() {
            if (ending_ || aborting_) return;
            if (!stream_) { fail(QStringLiteral("TCP 内容窗口提前关闭。")); return; }
            auto* directions = stream_->findChild<QTabWidget*>(QStringLiteral("streamDirections"));
            if (!directions || directions->count() < 2) {
                fail(QStringLiteral("TCP 双向内容标签页缺失。")); return;
            }
            directions->setCurrentIndex(1);
            caption(QStringLiteral("另一方向展示对应的 HTTP 200 响应；TCP 数据按序号整理并识别重传与缺口。"));
            QTimer::singleShot(8500, this, [this]() { showOfflineProtocols(); });
        });
    }
    void showOfflineProtocols() {
        if (ending_ || aborting_) return;
        if (stream_) stream_->close();
        stream_.clear();
        caption(QStringLiteral("协议分析补充展示：接下来读取明确标注的固定 PCAP 样例，检查 DNS 与 ARP 字段。"));
        QTimer::singleShot(2500, this, [this]() {
            if (ending_ || aborting_) return;
            QString error;
            auto records = readDemoPcap(pcap_, &error);
            if (records.empty() || !error.isEmpty()) {
                fail(QStringLiteral("无法读取离线协议样例：%1").arg(error)); return;
            }
            offline_ = true;
            offlinePacketCount_ = static_cast<int>(records.size());
            window_.loadDemoPackets(std::move(records), QStringLiteral("离线协议样例 protocol_examples.pcap"));
            caption(QStringLiteral("DNS 查询与响应解析：事务编号、标志位、查询域名、查询类型及资源记录。"));
            if (!filterTo(QStringLiteral("dns")) || !selectPacket(Protocol::Dns, 0)) return;
            QTimer::singleShot(7800, this, [this]() { showArp(); });
        });
    }
    void showArp() {
        if (ending_ || aborting_) return;
        caption(QStringLiteral("ARP 解析以太网硬件地址与 IPv4 地址，区分地址解析请求和响应。"));
        if (!filterTo(QStringLiteral("arp")) || !selectPacket(Protocol::Arp, 0)) return;
        QTimer::singleShot(8200, this, [this]() { endPresentation(); });
    }
    void endPresentation() {
        if (ending_ || aborting_) return;
        caption(QStringLiteral("演示完成：实时 NPS 抓包、NPA 分层解析、逻辑过滤、TCP 双向流追踪。"));
        QTimer::singleShot(6000, this, [this]() { finish(); });
    }

    void fail(const QString& message) {
        if (ending_ || aborting_) return;
        aborting_ = true;
        failures_ << message;
        QTextStream(stderr) << "录制失败：" << message << '\n';
        caption(QStringLiteral("录制检查未通过：%1").arg(message));
        if (traffic_.state() != QProcess::NotRunning) traffic_.kill();
        if (captureRequested_ && window_.captureBusy()) window_.requestCaptureStop();
        // 留下错误画面并给工作线程有限的退出时间；视频结果标记为失败。
        QTimer::singleShot(1800, this, [this]() { finish(); });
    }

    void saveSrt() {
        QString text;
        QTextStream output(&text);
        int sequence = 0;
        for (int index = 0; index < captions_.size(); ++index) {
            const auto& cue = captions_.at(index);
            const int end = index + 1 < captions_.size() ? captions_.at(index + 1).frame : frameCount_;
            if (end <= cue.frame) continue;
            output << ++sequence << '\n' << subtitleTime(cue.frame) << " --> " << subtitleTime(end)
                   << '\n' << cue.text << "\n\n";
        }
        output.flush();
        const QByteArray subtitleBytes = text.toUtf8();
        QSaveFile subtitles(subtitlePath_);
        if (!subtitles.open(QIODevice::WriteOnly) || subtitles.write(subtitleBytes) != subtitleBytes.size() ||
            !subtitles.commit()) failures_ << QStringLiteral("无法保存 SRT 字幕。 ");
    }

    void finish() {
        if (ending_) return;
        ending_ = true;
        frameTimer_.stop();
        if (traffic_.state() != QProcess::NotRunning) traffic_.kill();
        trafficOutput_ += traffic_.readAll();
        QFile log(trafficLog_);
        if (log.open(QIODevice::WriteOnly | QIODevice::Truncate)) log.write(trafficOutput_);
        else failures_ << QStringLiteral("通信日志保存失败。 ");
        saveSrt();
        if (encoder_.state() == QProcess::Running || encoder_.state() == QProcess::Starting) {
            encoder_.closeWriteChannel();
        } else {
            encoderFinished(-1, QProcess::CrashExit);
        }
    }

    void encoderFinished(int exitCode, QProcess::ExitStatus exitStatus) {
        if (reported_) return;
        if (!ending_) {
            failures_ << QStringLiteral("视频编码器提前退出。 ");
            ending_ = true;
            frameTimer_.stop();
            saveSrt();
        }
        reported_ = true;
        if (exitCode != 0 || exitStatus != QProcess::NormalExit)
            failures_ << QStringLiteral("ffmpeg 编码失败，请检查 .ffmpeg.log。 ");
        const QFileInfo partial(partialMovie_);
        if (!partial.exists() || partial.size() < 100000)
            failures_ << QStringLiteral("未生成有效长度的视频文件。 ");
        if (failures_.isEmpty()) {
            if (QFile::exists(moviePath_) && !QFile::remove(moviePath_))
                failures_ << QStringLiteral("无法替换先前生成的视频文件。 ");
            else if (!QFile::rename(partialMovie_, moviePath_))
                failures_ << QStringLiteral("无法将录制结果移动到指定路径。 ");
        }
        QJsonObject proof{
            {"recorded_at_utc", QDateTime::currentDateTimeUtc().toString(Qt::ISODate)},
            {"application_version", QCoreApplication::applicationVersion()},
            {"platform", QSysInfo::prettyProductName()},
            {"capture_interface", QStringLiteral("lo0")},
            {"live_source", QStringLiteral("live-libpcap")},
            {"offline_sample", pcap_},
            {"live_packets", livePacketCount_}, {"live_protocol_counts", liveProtocols_},
            {"offline_sample_packets", offlinePacketCount_},
            {"traffic_script_passed", trafficPassed_},
            {"capture_activated", activated_},
            {"tcp_stream_id", static_cast<qint64>(streamId_)},
            {"video_frames", frameCount_}, {"video_fps", FrameRate},
            {"video_width", FrameWidth}, {"video_height", FrameHeight},
            {"video_file", moviePath_}, {"subtitle_file", subtitlePath_}
        };
        proof[QStringLiteral("passed")] = failures_.isEmpty();
        QJsonArray errors;
        for (const auto& failure : failures_) errors.append(failure);
        proof[QStringLiteral("failures")] = errors;
        QSaveFile result(manifestPath_);
        bool saved = result.open(QIODevice::WriteOnly);
        const QByteArray json = QJsonDocument(proof).toJson(QJsonDocument::Indented);
        if (saved) saved = result.write(json) == json.size() && result.commit();
        if (!saved) failures_ << QStringLiteral("验证记录写入失败。 ");
        QTextStream output(failures_.isEmpty() ? stdout : stderr);
        output << (failures_.isEmpty() ? QStringLiteral("实际操作视频已生成：") : QStringLiteral("录制未通过检查："))
               << (failures_.isEmpty() ? moviePath_ : manifestPath_) << '\n';
        for (const auto& failure : failures_) output << failure << '\n';
        output.flush();
        window_.setVerificationActive(false);
        qApp->exit(failures_.isEmpty() ? 0 : 2);
    }

    MainWindow& window_;
    QString moviePath_, script_, pcap_, partialMovie_, subtitlePath_, manifestPath_, ffmpegLog_, trafficLog_;
    QProcess encoder_, traffic_;
    QTimer frameTimer_;
    QPointer<StreamDialog> stream_;
    QByteArray trafficOutput_;
    QVector<CaptionCue> captions_;
    QString currentCaption_;
    QStringList failures_;
    QJsonObject liveProtocols_;
    std::uint64_t streamId_ = 0;
    int frameCount_ = 0;
    int livePacketCount_ = 0;
    int offlinePacketCount_ = 0;
    bool captureRequested_ = false;
    bool activated_ = false;
    bool trafficPassed_ = false;
    bool offline_ = false;
    bool ending_ = false;
    bool aborting_ = false;
    bool reported_ = false;
};
} // namespace

void startGuidedRecording(MainWindow& window, const QString& moviePath,
                          const QString& trafficScript, const QString& protocolPcap) {
    auto* recorder = new GuidedRecording(window, moviePath, trafficScript, protocolPcap);
    QTimer::singleShot(0, recorder, [recorder]() { recorder->begin(); });
}
} // namespace sniffer
