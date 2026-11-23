#include "MainWindow.h"
#include "StreamDialog.h"
#include "core/PacketParser.h"
#include <QApplication>
#include <QCloseEvent>
#include <QComboBox>
#include <QFontDatabase>
#include <QGroupBox>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QItemSelectionModel>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QScrollBar>
#include <QSplitter>
#include <QStatusBar>
#include <QStringList>
#include <QTableView>
#include <QTimer>
#include <QTreeWidget>
#include <QVBoxLayout>
#include <map>
#include <algorithm>

namespace sniffer {
namespace {
QString utf8(const std::string& text) { return QString::fromUtf8(text.data(), static_cast<int>(text.size())); }
QString sizeText(std::size_t bytes) {
    if (bytes >= 1024U * 1024U) return QStringLiteral("%1 MiB").arg(static_cast<double>(bytes) / (1024.0 * 1024.0), 0, 'f', 2);
    if (bytes >= 1024U) return QStringLiteral("%1 KiB").arg(static_cast<double>(bytes) / 1024.0, 0, 'f', 1);
    return QStringLiteral("%1 字节").arg(static_cast<qulonglong>(bytes));
}
QTreeWidgetItem* item(QTreeWidgetItem* parent, const QString& name, const QString& value) {
    return new QTreeWidgetItem(parent, {name, value});
}
}

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent), queue_(std::make_shared<CaptureQueue>()) {
    qRegisterMetaType<CaptureSummary>();
    buildUi();
    populateInterfaces();
    worker_ = new CaptureWorker(queue_);
    worker_->moveToThread(&captureThread_);
    connect(&captureThread_, &QThread::finished, worker_, &QObject::deleteLater);
    connect(this, &MainWindow::requestStart, worker_, &CaptureWorker::startCapture, Qt::QueuedConnection);
    connect(this, &MainWindow::requestStop, worker_, &CaptureWorker::stopCapture, Qt::QueuedConnection);
    connect(worker_, &CaptureWorker::captureStarted, this, &MainWindow::onCaptureStarted);
    connect(worker_, &CaptureWorker::captureStopped, this, &MainWindow::onCaptureStopped);
    connect(worker_, &CaptureWorker::captureModeChanged, this, &MainWindow::onCaptureModeChanged);
    connect(worker_, &CaptureWorker::captureError, this, [this](const QString& message) {
        captureError_ = true;
        sessionDescription_->setText(message);
        sessionDescription_->setStyleSheet(QStringLiteral("color: #A33A2B;"));
    });
    connect(worker_, &CaptureWorker::captureWarning, this, [this](const QString& message) {
        statusBar()->showMessage(message, 15000);
    });
    captureThread_.start();
    displayTimer_ = new QTimer(this);
    displayTimer_->setInterval(100);
    connect(displayTimer_, &QTimer::timeout, this, &MainWindow::drainQueue);
    displayTimer_->start();
    updateControls();
    updateCounts();
}

MainWindow::~MainWindow() {
    if (captureThread_.isRunning()) {
        QMetaObject::invokeMethod(worker_, "stopCapture", Qt::BlockingQueuedConnection);
        captureThread_.quit();
        captureThread_.wait();
    }
}

void MainWindow::buildUi() {
    setWindowTitle(QStringLiteral("CourseSniffer · 网络嗅探器"));
    setMinimumSize(1000, 720);
    resize(1360, 940);
    auto* central = new QWidget;
    auto* outer = new QVBoxLayout(central);
    outer->setContentsMargins(24, 20, 24, 14);
    outer->setSpacing(12);
    auto* titleRow = new QHBoxLayout;
    auto* title = new QLabel(QStringLiteral("网络嗅探器"));
    title->setObjectName(QStringLiteral("pageTitle"));
    titleRow->addWidget(title);
    auto* course = new QLabel(QStringLiteral("实验 1A"));
    course->setObjectName(QStringLiteral("courseLabel"));
    titleRow->addWidget(course);
    titleRow->addStretch();
    stateLabel_ = new QLabel(QStringLiteral("就绪"));
    stateLabel_->setObjectName(QStringLiteral("stateLabel"));
    stateLabel_->setAlignment(Qt::AlignCenter);
    stateLabel_->setMinimumWidth(90);
    titleRow->addWidget(stateLabel_);
    outer->addLayout(titleRow);
    sessionDescription_ = new QLabel(QStringLiteral("选择网络接口，捕获并查看本机通信。"));
    sessionDescription_->setObjectName(QStringLiteral("sessionDescription"));
    sessionDescription_->setWordWrap(true);
    sessionDescription_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    outer->addWidget(sessionDescription_);
    captureMode_ = new QLabel(QStringLiteral("捕获模式根据接口的回环标志自动选择。"));
    captureMode_->setObjectName(QStringLiteral("captureMode"));
    captureMode_->setWordWrap(true);
    captureMode_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    outer->addWidget(captureMode_);

    auto* toolbar = new QWidget;
    toolbar->setObjectName(QStringLiteral("toolbarCard"));
    auto* controls = new QHBoxLayout(toolbar);
    controls->setContentsMargins(14, 12, 14, 12);
    controls->setSpacing(10);
    controls->addWidget(new QLabel(QStringLiteral("网络接口")));
    interfaces_ = new QComboBox;
    interfaces_->setObjectName(QStringLiteral("interfaceCombo"));
    interfaces_->setMinimumWidth(210);
    interfaces_->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);
    controls->addWidget(interfaces_, 1);
    start_ = new QPushButton(QStringLiteral("开始抓包"));
    start_->setObjectName(QStringLiteral("startButton"));
    stop_ = new QPushButton(QStringLiteral("停止抓包"));
    stop_->setObjectName(QStringLiteral("stopButton"));
    clear_ = new QPushButton(QStringLiteral("清空记录"));
    clear_->setObjectName(QStringLiteral("clearButton"));
    controls->addWidget(start_); controls->addWidget(stop_); controls->addWidget(clear_);
    outer->addWidget(toolbar);

    auto* filterRow = new QHBoxLayout;
    filterRow->setSpacing(10);
    filterRow->addWidget(new QLabel(QStringLiteral("协议过滤")));
    filter_ = new QLineEdit;
    filter_->setObjectName(QStringLiteral("filterEdit"));
    filter_->setPlaceholderText(QStringLiteral("例如：tcp.port == 8080 or dns"));
    filter_->setMaxLength(1024);
    filter_->setClearButtonEnabled(true);
    filterRow->addWidget(filter_, 1);
    auto* apply = new QPushButton(QStringLiteral("应用过滤"));
    apply->setObjectName(QStringLiteral("applyFilterButton"));
    filterRow->addWidget(apply);
    trace_ = new QPushButton(QStringLiteral("追踪 TCP 流"));
    trace_->setObjectName(QStringLiteral("traceButton"));
    filterRow->addWidget(trace_);
    outer->addLayout(filterRow);
    filterError_ = new QLabel(QStringLiteral("支持 http、dns、arp、tcp、udp、ipv4、ipv6、icmp、icmp6；可组合 ip.addr == 127.0.0.1、tcp.port == 8080 和逻辑运算。"));
    filterError_->setObjectName(QStringLiteral("filterStatus"));
    filterError_->setWordWrap(true);
    outer->addWidget(filterError_);

    auto* vertical = new QSplitter(Qt::Vertical);
    vertical->setChildrenCollapsible(false);
    auto* packetGroup = new QGroupBox(QStringLiteral("数据包"));
    auto* packetLayout = new QVBoxLayout(packetGroup);
    packetLayout->setContentsMargins(0, 8, 0, 0);
    table_ = new QTableView;
    table_->setObjectName(QStringLiteral("packetTable"));
    model_ = new PacketTableModel(this);
    proxy_ = new PacketFilterModel(this);
    proxy_->setSourceModel(model_);
    table_->setModel(proxy_);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setAlternatingRowColors(true);
    table_->setShowGrid(false);
    table_->setSortingEnabled(true);
    table_->sortByColumn(PacketTableModel::Number, Qt::AscendingOrder);
    table_->verticalHeader()->hide();
    table_->verticalHeader()->setDefaultSectionSize(31);
    table_->horizontalHeader()->setHighlightSections(false);
    table_->horizontalHeader()->setStretchLastSection(true);
    table_->setColumnWidth(PacketTableModel::Number, 58);
    table_->setColumnWidth(PacketTableModel::Time, 135);
    table_->setColumnWidth(PacketTableModel::Source, 195);
    table_->setColumnWidth(PacketTableModel::Destination, 195);
    table_->setColumnWidth(PacketTableModel::ProtocolName, 92);
    table_->setColumnWidth(PacketTableModel::Length, 65);
    packetLayout->addWidget(table_);
    vertical->addWidget(packetGroup);
    auto* bottom = new QSplitter(Qt::Horizontal);
    bottom->setChildrenCollapsible(false);
    auto* detailsGroup = new QGroupBox(QStringLiteral("协议字段"));
    auto* detailsLayout = new QVBoxLayout(detailsGroup);
    detailsLayout->setContentsMargins(0, 8, 0, 0);
    details_ = new QTreeWidget;
    details_->setObjectName(QStringLiteral("packetDetails"));
    details_->setHeaderLabels({QStringLiteral("字段"), QStringLiteral("内容"), QStringLiteral("偏移"), QStringLiteral("字节")});
    details_->setColumnWidth(0, 175); details_->setColumnWidth(1, 280); details_->setColumnWidth(2, 55);
    details_->setAlternatingRowColors(true);
    details_->setUniformRowHeights(true);
    detailsLayout->addWidget(details_);
    bottom->addWidget(detailsGroup);
    auto* bytesGroup = new QGroupBox(QStringLiteral("原始字节"));
    auto* bytesLayout = new QVBoxLayout(bytesGroup);
    bytesLayout->setContentsMargins(0, 8, 0, 0);
    rawBytes_ = new QPlainTextEdit;
    rawBytes_->setObjectName(QStringLiteral("rawBytes"));
    rawBytes_->setReadOnly(true);
    rawBytes_->setLineWrapMode(QPlainTextEdit::NoWrap);
    rawBytes_->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    rawBytes_->setPlaceholderText(QStringLiteral("选中数据包后显示原始字节。"));
    bytesLayout->addWidget(rawBytes_);
    bottom->addWidget(bytesGroup);
    bottom->setSizes({660, 620});
    vertical->addWidget(bottom);
    vertical->setSizes({380, 300});
    outer->addWidget(vertical, 1);
    auto* footer = new QHBoxLayout;
    counts_ = new QLabel;
    counts_->setObjectName(QStringLiteral("packetCounts"));
    footer->addWidget(counts_);
    footer->addStretch();
    statistics_ = new QLabel(QStringLiteral("会话上限 10000 个数据包 / 64 MiB"));
    statistics_->setObjectName(QStringLiteral("captureStatistics"));
    footer->addWidget(statistics_);
    outer->addLayout(footer);
    setCentralWidget(central);
    statusBar()->setSizeGripEnabled(true);
    statusBar()->showMessage(QStringLiteral("协议详情与 TCP 内容以已捕获字节为依据。"));
    setStyleSheet(QStringLiteral(
        "QMainWindow { background: #F4F6F9; color: #243449; }"
        "QWidget { font-size: 13px; }"
        "QLabel#pageTitle { font-size: 26px; font-weight: 700; color: #1C3046; }"
        "QLabel#courseLabel { color: #63758A; padding: 5px 10px; background: #E7ECF3; border-radius: 5px; }"
        "QLabel#sessionDescription, QLabel#filterStatus, QLabel#captureMode { color: #63758A; }"
        "QLabel#packetCounts { color: #314C65; font-weight: 600; }"
        "QLabel#captureStatistics { color: #63758A; }"
        "QWidget#toolbarCard { background: white; border: 1px solid #DFE6EE; border-radius: 7px; }"
        "QPushButton { padding: 7px 15px; border: 1px solid #CDD7E3; border-radius: 5px; background: white; color: #30465D; }"
        "QPushButton:hover { background: #EDF3FA; border-color: #A9BFD6; }"
        "QPushButton:pressed { background: #DCE8F5; }"
        "QPushButton:disabled { color: #9BA9B9; background: #F4F6F8; border-color: #E0E5EA; }"
        "QPushButton#startButton { background: #246A9E; color: white; border-color: #246A9E; font-weight: 600; }"
        "QPushButton#startButton:disabled { background: #AABCCD; border-color: #AABCCD; }"
        "QLineEdit, QComboBox { min-height: 29px; padding: 2px 8px; border: 1px solid #CBD6E3; border-radius: 4px; background: white; color: #243449; }"
        "QLineEdit:focus, QComboBox:focus { border-color: #5384AE; }"
        "QGroupBox { border: none; font-weight: 600; color: #3B526B; margin-top: 14px; padding-top: 4px; }"
        "QGroupBox::title { subcontrol-origin: margin; subcontrol-position: top left; }"
        "QTableView, QTreeWidget, QPlainTextEdit { background: white; color: #243449; alternate-background-color: #F9FAFC; border: 1px solid #DFE6EE; border-radius: 4px; selection-background-color: #DCEBFA; selection-color: #193F63; }"
        "QHeaderView::section { background: #EDF1F6; color: #50647B; font-weight: 600; border: none; border-bottom: 1px solid #DAE2EB; padding: 8px 6px; }"
        "QTableView::item { padding: 3px 7px; border-bottom: 1px solid #F0F3F7; }"
        "QTreeWidget::item { padding: 3px 4px; }"
        "QSplitter::handle { background: #E7ECF2; }"
        "QStatusBar { color: #7A899B; background: #EEF2F6; }"
    ));
    connect(start_, &QPushButton::clicked, this, &MainWindow::startCapture);
    connect(stop_, &QPushButton::clicked, this, &MainWindow::stopCapture);
    connect(clear_, &QPushButton::clicked, this, &MainWindow::clearRecords);
    connect(apply, &QPushButton::clicked, this, &MainWindow::applyFilter);
    connect(filter_, &QLineEdit::returnPressed, this, &MainWindow::applyFilter);
    connect(trace_, &QPushButton::clicked, this, &MainWindow::traceSelected);
    connect(table_->selectionModel(), &QItemSelectionModel::currentRowChanged, this, &MainWindow::showSelectedPacket);
}

void MainWindow::populateInterfaces() {
    QString error;
    const auto interfaces = CaptureWorker::enumerate(&error);
    for (const auto& interface : interfaces) {
        QString label = interface.name;
        if (!interface.addresses.isEmpty()) label += QStringLiteral(" · ") + interface.addresses;
        interfaces_->addItem(label, interface.name);
        interfaces_->setItemData(interfaces_->count() - 1, interface.flags, Qt::UserRole + 1);
        const QString mode = interface.isLoopback() ? QStringLiteral("回环接口，请求普通模式") : QStringLiteral("非回环接口，请求混杂模式");
        interfaces_->setItemData(interfaces_->count() - 1, interface.description + '\n' + interface.addresses + '\n' + mode, Qt::ToolTipRole);
    }
    int preferred = interfaces_->findData(QStringLiteral("en0"));
    if (preferred < 0) preferred = interfaces_->findData(QStringLiteral("eth0"));
    if (preferred < 0) preferred = interfaces_->findData(QStringLiteral("lo0"));
    if (preferred >= 0) interfaces_->setCurrentIndex(preferred);
    if (interfaces_->count() == 0) {
        sessionDescription_->setText(error.isEmpty() ? QStringLiteral("当前没有可用的网络接口。") : QStringLiteral("枚举网络接口失败：%1").arg(error));
    }
}

bool MainWindow::captureBusy() const { return state_ != State::Idle; }

bool MainWindow::startCaptureOnInterface(const QString& interfaceName) {
    if (captureBusy() || model_->rowCount() != 0) return false;
    const int index = interfaces_->findData(interfaceName);
    if (index < 0) return false;
    interfaces_->setCurrentIndex(index);
    startCapture();
    return captureBusy();
}

void MainWindow::requestCaptureStop() { stopCapture(); }

void MainWindow::setVerificationActive(bool active) {
    verificationActive_ = active;
    filter_->setEnabled(!active);
    if (auto* apply = findChild<QPushButton*>(QStringLiteral("applyFilterButton"))) apply->setEnabled(!active);
    updateControls();
}

std::optional<StreamView> MainWindow::traceConnection(std::uint64_t connectionId) const {
    if (captureBusy()) return std::nullopt;
    return tracker_.trace(connectionId);
}

StreamDialog* MainWindow::showConnection(std::uint64_t connectionId) { return showStream(connectionId); }

void MainWindow::resetSession() {
    queue_->clear(); model_->clear(); tracker_.clear();
    details_->clear(); rawBytes_->clear();
    lastSummary_ = CaptureSummary{};
    captureError_ = false; demo_ = false;
    statistics_->setText(QStringLiteral("会话上限 10000 个数据包 / 64 MiB"));
    sessionDescription_->setStyleSheet(QString());
    captureMode_->setText(QStringLiteral("捕获模式根据接口的回环标志自动选择。"));
    captureMode_->setToolTip(QString());
    captureMode_->setStyleSheet(QString());
    updateCounts();
}

void MainWindow::startCapture() {
    if (captureBusy() || interfaces_->currentIndex() < 0) return;
    if (model_->rowCount() > 0) {
        QMessageBox confirmation(QMessageBox::Information, QStringLiteral("开始新会话"),
            QStringLiteral("开始新会话将清空当前记录。"), QMessageBox::Ok | QMessageBox::Cancel, this);
        confirmation.button(QMessageBox::Ok)->setText(QStringLiteral("开始新会话"));
        confirmation.button(QMessageBox::Cancel)->setText(QStringLiteral("保留当前记录"));
        confirmation.setDefaultButton(QMessageBox::Cancel);
        if (confirmation.exec() != QMessageBox::Ok) return;
    }
    resetSession();
    state_ = State::Starting; workerFinished_ = false;
    sessionDescription_->setText(QStringLiteral("正在打开网络接口 %1。 ").arg(interfaces_->currentData().toString()));
    updateControls();
    emit requestStart(interfaces_->currentData().toString());
}

void MainWindow::stopCapture() {
    if (state_ != State::Starting && state_ != State::Capturing) return;
    state_ = State::Stopping;
    updateControls();
    emit requestStop();
}

void MainWindow::clearRecords() {
    if (captureBusy()) return;
    resetSession();
    sessionDescription_->setText(QStringLiteral("选择网络接口，捕获并查看本机通信。"));
    updateControls();
}

void MainWindow::onCaptureStarted(const QString& interfaceName, int linkType) {
    if (state_ != State::Stopping) state_ = State::Capturing;
    sessionDescription_->setText(QStringLiteral("实时抓包 · 接口 %1 · 链路类型 %2").arg(interfaceName).arg(linkType));
    updateControls();
    emit sessionStarted(interfaceName, linkType);
}

void MainWindow::onCaptureStopped(const CaptureSummary& summary) {
    onCaptureModeChanged(summary);
    captureError_ = captureError_ || summary.error;
    if (captureError_) sessionDescription_->setStyleSheet(QStringLiteral("color: #A33A2B;"));
    workerFinished_ = true;
    state_ = State::Stopping;
    updateControls();
    drainQueue();
}

void MainWindow::onCaptureModeChanged(const CaptureSummary& summary) {
    lastSummary_ = summary;
    QString text = captureModeDescription(summary);
    if (!summary.warnings.isEmpty()) text += QStringLiteral("\n警告：") + summary.warnings.join(QStringLiteral("\n"));
    captureMode_->setText(text);
    captureMode_->setToolTip(summary.apiResults.join(QStringLiteral("\n")));
    captureMode_->setStyleSheet(summary.warnings.isEmpty() ? QString() : QStringLiteral("color: #8A5A18;"));
}

void MainWindow::processPackets(std::vector<RawPacket> packets) {
    if (packets.empty()) return;
    const bool wasAtBottom = table_->verticalScrollBar()->value() >= table_->verticalScrollBar()->maximum() - 2;
    std::vector<PacketRecord> parsed;
    std::vector<std::uint64_t> updates;
    parsed.reserve(packets.size());
    for (auto& raw : packets) {
        auto packet = PacketParser::parse(std::move(raw));
        const auto update = tracker_.ingest(packet);
        packet.connectionId = update.connectionId;
        updates.insert(updates.end(), update.httpPacketIds.begin(), update.httpPacketIds.end());
        parsed.push_back(std::move(packet));
    }
    model_->appendPackets(std::move(parsed));
    model_->markHttp(updates);
    if (!updates.empty()) proxy_->refresh();
    if (wasAtBottom && !table_->selectionModel()->hasSelection()) table_->scrollToBottom();
    updateCounts();
    const auto* selected = selectedPacket();
    if (selected && std::find(updates.begin(), updates.end(), selected->raw.id) != updates.end()) showSelectedPacket();
}

void MainWindow::drainQueue() {
    processPackets(queue_->take(512));
    if (state_ == State::Stopping && workerFinished_ && queue_->empty()) finishSession();
}

void MainWindow::finishSession() {
    state_ = State::Idle;
    QString information = lastSummary_.reason;
    if (lastSummary_.applicationDropped)
        information += QStringLiteral(" · 应用未收纳 %1 个数据包").arg(lastSummary_.applicationDropped);
    sessionDescription_->setText(information);
    if (lastSummary_.statisticsAvailable) {
        statistics_->setText(QStringLiteral("接口统计：接收 %1 · 丢弃 %2 · 驱动丢弃 %3")
            .arg(lastSummary_.interfaceReceived).arg(lastSummary_.interfaceDropped).arg(lastSummary_.driverDropped));
    } else statistics_->setText(QStringLiteral("接口统计不可用"));
    updateControls(); updateCounts(); showSelectedPacket();
    emit sessionFinished(lastSummary_);
    if (closeRequested_) QTimer::singleShot(0, this, &QWidget::close);
}

void MainWindow::applyFilter() {
    QString error;
    if (proxy_->setExpression(filter_->text(), &error)) {
        filterError_->setText(filter_->text().trimmed().isEmpty() ? QStringLiteral("当前显示全部记录。") : QStringLiteral("当前显示条件：%1").arg(proxy_->expression()));
        filterError_->setStyleSheet(QStringLiteral("color: #56728B;"));
    } else {
        filterError_->setText(error);
        filterError_->setStyleSheet(QStringLiteral("color: #A33A2B;"));
    }
    updateCounts(); showSelectedPacket();
}

const PacketRecord* MainWindow::selectedPacket() const {
    const QModelIndex index = table_->currentIndex();
    return index.isValid() ? model_->packetAt(proxy_->mapToSource(index).row()) : nullptr;
}

void MainWindow::showSelectedPacket() {
    details_->clear(); rawBytes_->clear();
    const auto* packet = selectedPacket();
    if (!packet) { updateControls(); return; }
    auto* frame = new QTreeWidgetItem(details_, {QStringLiteral("捕获记录"), QStringLiteral("数据包 %1").arg(packet->raw.id)});
    for (const auto& notice : packet->notices) item(frame, QStringLiteral("解析状态"), utf8(notice));
    std::map<std::string, QTreeWidgetItem*> layers;
    layers.emplace("Frame", frame);
    for (const auto& field : packet->fields) {
        auto found = layers.find(field.layer);
        if (found == layers.end()) {
            auto* layer = new QTreeWidgetItem(details_, {utf8(field.layer)});
            found = layers.emplace(field.layer, layer).first;
        }
        new QTreeWidgetItem(found->second, {utf8(field.name), utf8(field.value), QString::number(field.offset), QString::number(field.length)});
    }
    const auto* connection = tracker_.connection(packet->connectionId);
    if (connection) {
        auto* tcp = new QTreeWidgetItem(details_, {QStringLiteral("TCP 连接"), QStringLiteral("连接 %1").arg(connection->id)});
        item(tcp, QStringLiteral("端点 A"), utf8(connection->a.display()));
        item(tcp, QStringLiteral("端点 B"), utf8(connection->b.display()));
        item(tcp, QStringLiteral("关联数据包"), QString::number(connection->packetIds.size()));
        if (connection->midstream) item(tcp, QStringLiteral("捕获状态"), QStringLiteral("从连接中途开始捕获"));
        if (connection->http && packet->payloadLength) {
            const std::size_t direction = packet->source == connection->a ? 0 : 1;
            if (connection->httpMessages[direction]) {
                const auto& message = *connection->httpMessages[direction];
                auto* http = new QTreeWidgetItem(details_, {QStringLiteral("HTTP 关联头部"), utf8(message.startLine)});
                QStringList ids;
                for (auto id : connection->httpSourcePacketIds[direction]) ids << QString::number(id);
                item(http, QStringLiteral("来源数据包"), ids.join(QStringLiteral("，")));
                for (const auto& header : message.headers) item(http, utf8(header.first), utf8(header.second));
            }
        }
    }
    details_->expandAll();
    frame->setExpanded(!packet->notices.empty());
    rawBytes_->setPlainText(utf8(hexDump(packet->raw.bytes)));
    updateControls();
}

void MainWindow::updateCounts() {
    counts_->setText(QStringLiteral("已保留 %1 个数据包    当前显示 %2 个    %3")
        .arg(model_->rowCount()).arg(proxy_->rowCount()).arg(sizeText(model_->totalBytes())));
}

void MainWindow::updateControls() {
    const bool idle = state_ == State::Idle;
    interfaces_->setEnabled(idle && !verificationActive_);
    start_->setEnabled(idle && !verificationActive_ && interfaces_->count() > 0);
    stop_->setEnabled(!verificationActive_ && (state_ == State::Starting || state_ == State::Capturing));
    clear_->setEnabled(idle && !verificationActive_ && model_->rowCount() > 0);
    const auto* selected = selectedPacket();
    trace_->setEnabled(idle && !verificationActive_ && selected && selected->connectionId != 0);
    QString state;
    QString background = QStringLiteral("#E7EDF4");
    QString color = QStringLiteral("#557089");
    if (state_ == State::Starting) state = QStringLiteral("正在启动");
    else if (state_ == State::Capturing) { state = QStringLiteral("正在捕获"); background = QStringLiteral("#DFF1EA"); color = QStringLiteral("#167457"); }
    else if (state_ == State::Stopping) state = QStringLiteral("正在停止");
    else if (demo_) state = QStringLiteral("演示数据");
    else if (captureError_) { state = QStringLiteral("抓包失败"); background = QStringLiteral("#FAE7E3"); color = QStringLiteral("#A33A2B"); }
    else state = model_->rowCount() ? QStringLiteral("已停止") : QStringLiteral("就绪");
    stateLabel_->setText(state);
    stateLabel_->setStyleSheet(QStringLiteral("padding: 7px 14px; border-radius: 12px; background: %1; color: %2; font-weight: 600;").arg(background, color));
}

StreamDialog* MainWindow::showStream(std::uint64_t id) {
    if (captureBusy()) return nullptr;
    auto view = tracker_.trace(id);
    if (!view) return nullptr;
    auto* dialog = new StreamDialog(std::move(*view), this);
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->show();
    return dialog;
}

void MainWindow::traceSelected() {
    const auto* packet = selectedPacket();
    if (packet) showStream(packet->connectionId);
}

StreamDialog* MainWindow::showFirstStream() {
    for (int row = 0; row < model_->rowCount(); ++row) {
        const auto* packet = model_->packetAt(row);
        if (packet->connectionId) return showStream(packet->connectionId);
    }
    return nullptr;
}

void MainWindow::loadDemoPackets(std::vector<RawPacket> packets, const QString& source) {
    if (captureBusy()) return;
    resetSession();
    demo_ = true;
    captureMode_->setText(QStringLiteral("演示数据采用固定样例，捕获模式尚未请求。"));
    processPackets(std::move(packets));
    sessionDescription_->setText(source.isEmpty()
        ? QStringLiteral("演示数据 · 内置网络协议样例 · 实时抓包尚未启动")
        : QStringLiteral("演示数据 · %1 · 实时抓包尚未启动").arg(source));
    for (int row = 0; row < proxy_->rowCount(); ++row) {
        const auto* packet = model_->packetAt(proxy_->mapToSource(proxy_->index(row, 0)).row());
        if (packet && packet->has(Protocol::Http)) { table_->selectRow(row); break; }
    }
    if (!table_->currentIndex().isValid() && proxy_->rowCount()) table_->selectRow(0);
    updateControls(); updateCounts();
}

void MainWindow::closeEvent(QCloseEvent* event) {
    if (verificationActive_) {
        event->ignore();
        emit verificationCloseRequested();
        return;
    }
    if (captureBusy()) {
        closeRequested_ = true;
        stopCapture();
        event->ignore();
        return;
    }
    event->accept();
}

} // namespace sniffer
