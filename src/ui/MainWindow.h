#pragma once

#include "capture/CaptureWorker.h"
#include "core/TcpTracker.h"
#include "PacketTableModel.h"
#include <QMainWindow>
#include <QThread>

class QComboBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QTableView;
class QTreeWidget;
class QPlainTextEdit;
class QTimer;
class QCloseEvent;

namespace sniffer {
class StreamDialog;
class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override;
    void loadDemoPackets(std::vector<RawPacket> packets, const QString& source = {});
    StreamDialog* showFirstStream();
    PacketTableModel* packetModel() const { return model_; }
    PacketFilterModel* proxyModel() const { return proxy_; }
    bool captureBusy() const;
signals:
    void requestStart(const QString& interfaceName);
    void requestStop();
protected:
    void closeEvent(QCloseEvent* event) override;
private slots:
    void startCapture();
    void stopCapture();
    void clearRecords();
    void applyFilter();
    void drainQueue();
    void showSelectedPacket();
    void traceSelected();
    void onCaptureStarted(const QString& interfaceName, int linkType);
    void onCaptureStopped(const sniffer::CaptureSummary& summary);
private:
    enum class State { Idle, Starting, Capturing, Stopping };
    void buildUi();
    void populateInterfaces();
    void processPackets(std::vector<RawPacket> packets);
    void resetSession();
    void updateControls();
    void updateCounts();
    void finishSession();
    const PacketRecord* selectedPacket() const;
    StreamDialog* showStream(std::uint64_t id);
    std::shared_ptr<CaptureQueue> queue_;
    QThread captureThread_;
    CaptureWorker* worker_ = nullptr;
    QTimer* displayTimer_ = nullptr;
    PacketTableModel* model_ = nullptr;
    PacketFilterModel* proxy_ = nullptr;
    TcpTracker tracker_;
    QComboBox* interfaces_ = nullptr;
    QPushButton* start_ = nullptr;
    QPushButton* stop_ = nullptr;
    QPushButton* clear_ = nullptr;
    QPushButton* trace_ = nullptr;
    QLineEdit* filter_ = nullptr;
    QLabel* filterError_ = nullptr;
    QLabel* sessionDescription_ = nullptr;
    QLabel* stateLabel_ = nullptr;
    QLabel* counts_ = nullptr;
    QLabel* statistics_ = nullptr;
    QTableView* table_ = nullptr;
    QTreeWidget* details_ = nullptr;
    QPlainTextEdit* rawBytes_ = nullptr;
    State state_ = State::Idle;
    bool workerFinished_ = true;
    bool closeRequested_ = false;
    bool captureError_ = false;
    bool demo_ = false;
    CaptureSummary lastSummary_;
};
}
