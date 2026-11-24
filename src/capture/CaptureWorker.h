#pragma once

#include "core/PacketRecord.h"
#include "CaptureModePolicy.h"
#include <QObject>
#include <QString>
#include <QList>
#include <QMetaType>
#include <QStringList>
#include <deque>
#include <memory>
#include <mutex>

class QTimer;
struct pcap;
struct pcap_pkthdr;

namespace sniffer {

struct NetworkInterface {
    QString name;
    QString description;
    QString addresses;
    quint32 flags = 0;
    bool isLoopback() const { return (flags & PCAP_IF_LOOPBACK) != 0; }
};

struct CaptureSummary {
    quint64 received = 0;
    quint64 accepted = 0;
    quint64 applicationDropped = 0;
    quint64 acceptedBytes = 0;
    bool statisticsAvailable = false;
    quint64 interfaceReceived = 0;
    quint64 interfaceDropped = 0;
    quint64 driverDropped = 0;
    QString reason;
    QString warning;
    QStringList warnings;
    QStringList apiResults;
    QString interfaceName;
    quint32 interfaceFlags = 0;
    bool interfaceFlagsKnown = false;
    bool promiscuousRequested = false;
    bool finalPromiscuousRequest = false;
    bool ordinaryFallback = false;
    bool activationAttempted = false;
    bool captureActivated = false;
    bool error = false;
    int activationResult = 0;
};

QString captureModeDescription(const CaptureSummary& summary);

class CaptureQueue {
public:
    static constexpr std::size_t MaxPackets = 2048;
    static constexpr std::size_t MaxBytes = 8U * 1024U * 1024U;
    bool push(RawPacket packet);
    std::vector<RawPacket> take(std::size_t maximum = 512);
    bool empty() const;
    std::size_t size() const;
    std::size_t byteCount() const;
    void clear();
private:
    mutable std::mutex mutex_;
    std::deque<RawPacket> packets_;
    std::size_t bytes_ = 0;
};

class CaptureWorker : public QObject {
    Q_OBJECT
public:
    static constexpr quint64 MaxSessionPackets = 10000;
    static constexpr quint64 MaxSessionBytes = 64U * 1024U * 1024U;
    explicit CaptureWorker(std::shared_ptr<CaptureQueue> queue, QObject* parent = nullptr);
    ~CaptureWorker() override;
    static QList<NetworkInterface> enumerate(QString* error = nullptr);
public slots:
    void startCapture(const QString& interfaceName, const QString& captureFilter = QString());
    void stopCapture();
signals:
    void captureStarted(const QString& interfaceName, int linkType);
    void captureStopped(const sniffer::CaptureSummary& summary);
    void captureError(const QString& message);
    void captureWarning(const QString& message);
    void captureModeChanged(const sniffer::CaptureSummary& summary);
private slots:
    void readBatch();
private:
    static void packetCallback(unsigned char* user, const pcap_pkthdr* header, const unsigned char* bytes);
    void receivePacket(const pcap_pkthdr* header, const unsigned char* bytes);
    void fail(const QString& operation, const QString& message);
    void finish(const QString& reason);
    CaptureSetupAction activateAttempt(bool promiscuous);
    void recordApiResult(const QString& operation, int result, const QString& detail = {});
    void addWarning(const QString& message);
    QString resultDetail(int status) const;
    std::shared_ptr<CaptureQueue> queue_;
    pcap* handle_ = nullptr;
    QTimer* timer_ = nullptr;
    QString interfaceName_;
    int linkType_ = 0;
    bool active_ = false;
    QString stopReason_;
    CaptureSummary summary_;
};
}

Q_DECLARE_METATYPE(sniffer::CaptureSummary)
