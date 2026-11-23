#include "CaptureWorker.h"
#include <QTimer>
#include <QThread>
#include <QStringList>
#include <pcap/pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <cstring>
#include <algorithm>

namespace sniffer {

QString captureModeDescription(const CaptureSummary& summary) {
    if (!summary.interfaceFlagsKnown) return QStringLiteral("捕获模式：接口标志尚未取得");
    const QString requested = summary.promiscuousRequested ? QStringLiteral("混杂模式") : QStringLiteral("普通模式（回环接口）");
    QString result;
    if (!summary.captureActivated) {
        result = summary.activationAttempted
            ? QStringLiteral("激活返回 %1，捕获未启动").arg(summary.activationResult)
            : QStringLiteral("配置尚未完成");
    } else {
        const QString configured = summary.finalPromiscuousRequest ? QStringLiteral("混杂请求获 API 接受") : QStringLiteral("普通模式请求获 API 接受");
        result = QStringLiteral("%1 · 激活返回 %2").arg(configured).arg(summary.activationResult);
    }
    if (summary.ordinaryFallback) result = QStringLiteral("普通模式回退 · ") + result;
    return QStringLiteral("请求：%1 · %2。实际可见流量取决于接口和网络环境。").arg(requested, result);
}

bool CaptureQueue::push(RawPacket packet) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (packets_.size() >= MaxPackets || packet.bytes.size() > MaxBytes - bytes_) return false;
    bytes_ += packet.bytes.size();
    packets_.push_back(std::move(packet));
    return true;
}

std::vector<RawPacket> CaptureQueue::take(std::size_t maximum) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<RawPacket> result;
    result.reserve(std::min(maximum, packets_.size()));
    while (!packets_.empty() && result.size() < maximum) {
        bytes_ -= packets_.front().bytes.size();
        result.push_back(std::move(packets_.front()));
        packets_.pop_front();
    }
    return result;
}

bool CaptureQueue::empty() const { std::lock_guard<std::mutex> lock(mutex_); return packets_.empty(); }
std::size_t CaptureQueue::size() const { std::lock_guard<std::mutex> lock(mutex_); return packets_.size(); }
std::size_t CaptureQueue::byteCount() const { std::lock_guard<std::mutex> lock(mutex_); return bytes_; }
void CaptureQueue::clear() { std::lock_guard<std::mutex> lock(mutex_); packets_.clear(); bytes_ = 0; }

CaptureWorker::CaptureWorker(std::shared_ptr<CaptureQueue> queue, QObject* parent)
    : QObject(parent), queue_(std::move(queue)) {}

CaptureWorker::~CaptureWorker() {
    if (timer_) timer_->stop();
    if (handle_) pcap_close(handle_);
}

QList<NetworkInterface> CaptureWorker::enumerate(QString* error) {
    char buffer[PCAP_ERRBUF_SIZE]{};
    pcap_if_t* devices = nullptr;
    QList<NetworkInterface> result;
    if (pcap_findalldevs(&devices, buffer) != 0) {
        if (error) *error = QString::fromLocal8Bit(buffer);
        return result;
    }
    for (auto* device = devices; device; device = device->next) {
        if (!device->name) continue;
        NetworkInterface item;
        item.name = QString::fromLocal8Bit(device->name);
        item.description = device->description ? QString::fromLocal8Bit(device->description) : QString();
        item.flags = device->flags;
        QStringList addresses;
        for (auto* address = device->addresses; address; address = address->next) {
            if (!address->addr) continue;
            const int family = address->addr->sa_family;
            if (family != AF_INET && family != AF_INET6) continue;
            char host[NI_MAXHOST]{};
            const socklen_t length = family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
            if (getnameinfo(address->addr, length, host, sizeof(host), nullptr, 0, NI_NUMERICHOST) == 0)
                addresses << QString::fromLatin1(host);
        }
        addresses.removeDuplicates();
        item.addresses = addresses.join(QStringLiteral("，"));
        result.push_back(std::move(item));
    }
    pcap_freealldevs(devices);
    if (error) error->clear();
    return result;
}

void CaptureWorker::startCapture(const QString& interfaceName) {
    Q_ASSERT(QThread::currentThread() == thread());
    if (active_ || handle_) return;
    interfaceName_ = interfaceName;
    summary_ = CaptureSummary{};
    summary_.interfaceName = interfaceName;
    stopReason_.clear();
    active_ = true;
    QString enumerationError;
    const auto devices = enumerate(&enumerationError);
    if (!enumerationError.isEmpty()) { fail(QStringLiteral("枚举网络接口"), enumerationError); return; }
    const auto device = std::find_if(devices.begin(), devices.end(), [&](const NetworkInterface& item) { return item.name == interfaceName; });
    if (device == devices.end()) { fail(QStringLiteral("查找网络接口"), QStringLiteral("所选接口未出现在 libpcap 接口列表中。")); return; }
    summary_.interfaceFlags = device->flags;
    summary_.interfaceFlagsKnown = true;
    summary_.promiscuousRequested = requestsPromiscuousMode(device->flags);
    emit captureModeChanged(summary_);
    auto action = activateAttempt(summary_.promiscuousRequested);
    if (action == CaptureSetupAction::RetryOrdinary) {
        summary_.ordinaryFallback = true;
        if (handle_) { pcap_close(handle_); handle_ = nullptr; }
        summary_.captureActivated = false;
        addWarning(QStringLiteral("混杂请求需要普通模式回退，使用新的抓包句柄重新配置。"));
        action = activateAttempt(false);
    }
    if (action != CaptureSetupAction::Continue) return;
    char error[PCAP_ERRBUF_SIZE]{};
    linkType_ = pcap_datalink(handle_);
    if (linkType_ < 0) {
        fail(QStringLiteral("读取链路类型"), QString::fromLocal8Bit(pcap_geterr(handle_)));
        return;
    }
    const int nonblocking = pcap_setnonblock(handle_, 1, error);
    recordApiResult(QStringLiteral("pcap_setnonblock(1)"), nonblocking, QString::fromLocal8Bit(error));
    if (nonblocking < 0) {
        fail(QStringLiteral("启用非阻塞读取"), QString::fromLocal8Bit(error));
        return;
    }
    if (!timer_) {
        timer_ = new QTimer(this);
        timer_->setInterval(20);
        connect(timer_, &QTimer::timeout, this, &CaptureWorker::readBatch);
    }
    timer_->start();
    emit captureModeChanged(summary_);
    emit captureStarted(interfaceName_, linkType_);
}

QString CaptureWorker::resultDetail(int status) const {
    if (status == 0) return QStringLiteral("调用成功");
    QStringList detail;
    const char* generic = pcap_statustostr(status);
    if (generic && *generic) detail << QString::fromLocal8Bit(generic);
    if (handle_) {
        const QString specific = QString::fromLocal8Bit(pcap_geterr(handle_)).trimmed();
        if (!specific.isEmpty() && !detail.contains(specific)) detail << specific;
    }
    return detail.join(QStringLiteral("；"));
}

void CaptureWorker::recordApiResult(const QString& operation, int result, const QString& detail) {
    const QString information = detail.trimmed().isEmpty() ? resultDetail(result) : detail.trimmed();
    const QString message = QStringLiteral("%1 返回 %2：%3").arg(operation).arg(result).arg(information);
    summary_.apiResults << message;
    if (result > 0) addWarning(message);
}

void CaptureWorker::addWarning(const QString& message) {
    summary_.warnings << message;
    summary_.warning = summary_.warnings.join('\n');
    emit captureWarning(message);
    emit captureModeChanged(summary_);
}

CaptureSetupAction CaptureWorker::activateAttempt(bool promiscuous) {
    char error[PCAP_ERRBUF_SIZE]{};
    summary_.finalPromiscuousRequest = promiscuous;
    summary_.activationAttempted = false;
    summary_.captureActivated = false;
    handle_ = pcap_create(interfaceName_.toLocal8Bit().constData(), error);
    if (!handle_) { fail(QStringLiteral("打开接口"), QString::fromLocal8Bit(error)); return CaptureSetupAction::Fail; }
    const int snapshot = pcap_set_snaplen(handle_, 65535);
    recordApiResult(QStringLiteral("pcap_set_snaplen(65535)"), snapshot);
    if (snapshot < 0) { fail(QStringLiteral("配置捕获长度"), resultDetail(snapshot)); return CaptureSetupAction::Fail; }
    const int mode = pcap_set_promisc(handle_, promiscuous ? 1 : 0);
    recordApiResult(QStringLiteral("pcap_set_promisc(%1)").arg(promiscuous ? 1 : 0), mode);
    const auto modeAction = captureSetupAction(promiscuous, mode);
    if (modeAction == CaptureSetupAction::RetryOrdinary) {
        if (mode < 0) addWarning(QStringLiteral("混杂模式设置返回 %1：%2").arg(mode).arg(resultDetail(mode)));
        return modeAction;
    }
    if (modeAction == CaptureSetupAction::Fail) { fail(QStringLiteral("配置捕获模式"), resultDetail(mode)); return modeAction; }
    const int timeout = pcap_set_timeout(handle_, 100);
    recordApiResult(QStringLiteral("pcap_set_timeout(100)"), timeout);
    if (timeout < 0) { fail(QStringLiteral("配置读取超时"), resultDetail(timeout)); return CaptureSetupAction::Fail; }
    const int activation = pcap_activate(handle_);
    summary_.activationAttempted = true;
    summary_.activationResult = activation;
    recordApiResult(QStringLiteral("pcap_activate()"), activation);
    const auto action = captureSetupAction(promiscuous, activation);
    if (action == CaptureSetupAction::RetryOrdinary) {
        if (activation < 0) addWarning(QStringLiteral("混杂模式激活返回 %1：%2").arg(activation).arg(resultDetail(activation)));
        return action;
    }
    if (action == CaptureSetupAction::Fail) { fail(QStringLiteral("激活抓包接口"), resultDetail(activation)); return action; }
    summary_.captureActivated = true;
    return CaptureSetupAction::Continue;
}

void CaptureWorker::readBatch() {
    if (!active_ || !handle_) return;
    const int result = pcap_dispatch(handle_, 256, &CaptureWorker::packetCallback,
                                     reinterpret_cast<unsigned char*>(this));
    if (result == PCAP_ERROR) {
        fail(QStringLiteral("读取网络数据"), QString::fromLocal8Bit(pcap_geterr(handle_)));
        return;
    }
    if (!stopReason_.isEmpty()) finish(stopReason_);
}

void CaptureWorker::packetCallback(unsigned char* user, const pcap_pkthdr* header,
                                   const unsigned char* bytes) {
    auto* worker = reinterpret_cast<CaptureWorker*>(user);
    // C 回调始终收纳或记录数据包，句柄在本批读取结束之后关闭。
    try {
        worker->receivePacket(header, bytes);
    } catch (const std::exception&) {
        ++worker->summary_.applicationDropped;
        worker->summary_.error = true;
        worker->stopReason_ = QStringLiteral("数据包缓存分配失败，捕获已结束");
    }
}

void CaptureWorker::receivePacket(const pcap_pkthdr* header, const unsigned char* bytes) {
    ++summary_.received;
    if (!stopReason_.isEmpty()) { ++summary_.applicationDropped; return; }
    if (summary_.accepted >= MaxSessionPackets ||
        header->caplen > MaxSessionBytes - summary_.acceptedBytes) {
        ++summary_.applicationDropped;
        stopReason_ = QStringLiteral("已达到本次会话容量上限");
        return;
    }
    RawPacket packet;
    packet.id = summary_.accepted + 1;
    packet.timestampMicros = static_cast<std::int64_t>(header->ts.tv_sec) * 1000000 + header->ts.tv_usec;
    packet.wireLength = header->len;
    packet.linkType = linkType_;
    packet.bytes.assign(bytes, bytes + header->caplen);
    if (!queue_->push(std::move(packet))) {
        ++summary_.applicationDropped;
        stopReason_ = QStringLiteral("待处理队列已达到容量上限");
        return;
    }
    ++summary_.accepted;
    summary_.acceptedBytes += header->caplen;
    if (summary_.accepted >= MaxSessionPackets || summary_.acceptedBytes >= MaxSessionBytes)
        stopReason_ = QStringLiteral("已达到本次会话容量上限");
}

void CaptureWorker::fail(const QString& operation, const QString& message) {
    const QString detail = QStringLiteral("%1失败 · %2\n%3").arg(operation, interfaceName_, message);
    summary_.error = true;
    emit captureModeChanged(summary_);
    emit captureError(detail);
    finish(detail);
}

void CaptureWorker::finish(const QString& reason) {
    if (!active_ && !handle_) return;
    if (timer_) timer_->stop();
    if (handle_) {
        pcap_stat statistics{};
        if (pcap_stats(handle_, &statistics) == 0) {
            summary_.statisticsAvailable = true;
            summary_.interfaceReceived = statistics.ps_recv;
            summary_.interfaceDropped = statistics.ps_drop;
            summary_.driverDropped = statistics.ps_ifdrop;
        }
        pcap_close(handle_);
        handle_ = nullptr;
    }
    active_ = false;
    summary_.reason = reason;
    emit captureStopped(summary_);
}

void CaptureWorker::stopCapture() {
    Q_ASSERT(QThread::currentThread() == thread());
    finish(QStringLiteral("捕获已停止"));
}

} // namespace sniffer
