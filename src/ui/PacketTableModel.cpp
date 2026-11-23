#include "PacketTableModel.h"
#include <QDateTime>
#include <QColor>
#include <QFont>
#include <QStringList>
#include <algorithm>
#include <limits>

namespace sniffer {

PacketTableModel::PacketTableModel(QObject* parent) : QAbstractTableModel(parent) {
    packets_.reserve(10000);
}

int PacketTableModel::rowCount(const QModelIndex& parent) const {
    return parent.isValid() ? 0 : static_cast<int>(packets_.size());
}

int PacketTableModel::columnCount(const QModelIndex& parent) const {
    return parent.isValid() ? 0 : ColumnCount;
}

const PacketRecord* PacketTableModel::packetAt(int row) const {
    return row >= 0 && static_cast<std::size_t>(row) < packets_.size() ? &packets_[static_cast<std::size_t>(row)] : nullptr;
}

QVariant PacketTableModel::data(const QModelIndex& index, int role) const {
    const auto* packet = packetAt(index.row());
    if (!index.isValid() || !packet || index.column() < 0 || index.column() >= ColumnCount) return {};
    if (role == Qt::UserRole) return QVariant::fromValue<qulonglong>(packet->raw.id);
    if (role == Qt::TextAlignmentRole) {
        if (index.column() == Number || index.column() == Length)
            return static_cast<int>(Qt::AlignRight | Qt::AlignVCenter);
        return static_cast<int>(Qt::AlignLeft | Qt::AlignVCenter);
    }
    if (role == Qt::ForegroundRole) {
        if (packet->malformed) return QColor(QStringLiteral("#A33A2B"));
        if (index.column() == ProtocolName) {
            if (packet->has(Protocol::Http)) return QColor(QStringLiteral("#087B67"));
            if (packet->has(Protocol::Dns)) return QColor(QStringLiteral("#7054A4"));
            if (packet->has(Protocol::Arp)) return QColor(QStringLiteral("#95651C"));
            if (packet->has(Protocol::Tcp)) return QColor(QStringLiteral("#315AA8"));
            if (packet->has(Protocol::Udp)) return QColor(QStringLiteral("#7857A3"));
        }
    }
    if (role == Qt::BackgroundRole && packet->has(Protocol::Http)) return QColor(QStringLiteral("#F0F9F5"));
    if (role == Qt::FontRole && index.column() == ProtocolName) { QFont font; font.setBold(true); return font; }
    if (role == Qt::ToolTipRole) {
        QStringList notices;
        for (const auto& notice : packet->notices) notices << QString::fromStdString(notice);
        return QStringLiteral("捕获长度：%1 字节\n原始长度：%2 字节\n%3")
            .arg(static_cast<qulonglong>(packet->raw.bytes.size())).arg(packet->raw.wireLength).arg(notices.join('\n'));
    }
    if (role == Qt::UserRole + 1) {
        if (index.column() == Number) return QVariant::fromValue<qulonglong>(packet->raw.id);
        if (index.column() == Time) return QVariant::fromValue<qlonglong>(packet->raw.timestampMicros);
        if (index.column() == Length) return packet->raw.wireLength;
        return data(index, Qt::DisplayRole);
    }
    if (role != Qt::DisplayRole) return {};
    switch (index.column()) {
    case Number: return QVariant::fromValue<qulonglong>(packet->raw.id);
    case Time: {
        const qint64 micros = packet->raw.timestampMicros;
        return QDateTime::fromMSecsSinceEpoch(micros / 1000).toString(QStringLiteral("HH:mm:ss")) +
               QStringLiteral(".%1").arg(static_cast<qulonglong>(micros >= 0 ? micros % 1000000 : 0), 6, 10, QLatin1Char('0'));
    }
    case Source: return QString::fromStdString(packet->hasPorts ? packet->source.display() : packet->source.text);
    case Destination: return QString::fromStdString(packet->hasPorts ? packet->destination.display() : packet->destination.text);
    case ProtocolName: return QString::fromStdString(packet->protocolName());
    case Length: return packet->raw.wireLength;
    case Summary:
        return packet->has(Protocol::Http)
            ? QStringLiteral("HTTP 数据 · 连接 %1 · %2").arg(packet->connectionId).arg(QString::fromStdString(packet->summary))
            : QString::fromStdString(packet->summary);
    default: return {};
    }
}

QVariant PacketTableModel::headerData(int section, Qt::Orientation orientation, int role) const {
    if (role != Qt::DisplayRole || orientation != Qt::Horizontal) return {};
    const QStringList labels{QStringLiteral("编号"), QStringLiteral("时间"), QStringLiteral("源地址与端口"),
        QStringLiteral("目标地址与端口"), QStringLiteral("协议"), QStringLiteral("长度"), QStringLiteral("摘要")};
    return section >= 0 && section < labels.size() ? labels[section] : QVariant();
}

void PacketTableModel::appendPackets(std::vector<PacketRecord> packets) {
    if (packets.empty()) return;
    const int start = rowCount();
    beginInsertRows({}, start, start + static_cast<int>(packets.size()) - 1);
    for (auto& packet : packets) {
        rowById_[packet.raw.id] = static_cast<int>(packets_.size());
        totalBytes_ += packet.raw.bytes.size();
        packets_.push_back(std::move(packet));
    }
    endInsertRows();
}

void PacketTableModel::markHttp(const std::vector<std::uint64_t>& ids) {
    int minimum = std::numeric_limits<int>::max();
    int maximum = -1;
    for (auto id : ids) {
        const auto found = rowById_.find(id);
        if (found == rowById_.end()) continue;
        auto& packet = packets_[static_cast<std::size_t>(found->second)];
        if (!packet.payloadLength || packet.has(Protocol::Http)) continue;
        packet.add(Protocol::Http);
        minimum = std::min(minimum, found->second);
        maximum = std::max(maximum, found->second);
    }
    if (maximum >= 0) emit dataChanged(index(minimum, 0), index(maximum, ColumnCount - 1));
}

void PacketTableModel::clear() {
    beginResetModel();
    packets_.clear(); rowById_.clear(); totalBytes_ = 0;
    endResetModel();
}

PacketFilterModel::PacketFilterModel(QObject* parent) : QSortFilterProxyModel(parent) {
    setDynamicSortFilter(true);
    setSortRole(Qt::UserRole + 1);
}

bool PacketFilterModel::setExpression(const QString& expression, QString* error) {
    FilterError failure;
    auto result = FilterParser::compile(expression.toUtf8().toStdString(), failure);
    if (!result) {
        if (error) *error = QStringLiteral("第 %1 个字符：%2")
            .arg(static_cast<qulonglong>(failure.position + 1)).arg(QString::fromStdString(failure.message));
        return false;
    }
    filter_ = std::move(*result);
    invalidateFilter();
    if (error) error->clear();
    return true;
}

QString PacketFilterModel::expression() const { return QString::fromStdString(filter_.expression()); }
void PacketFilterModel::refresh() { invalidateFilter(); }

bool PacketFilterModel::filterAcceptsRow(int row, const QModelIndex&) const {
    const auto* model = qobject_cast<const PacketTableModel*>(sourceModel());
    const auto* packet = model ? model->packetAt(row) : nullptr;
    return packet && filter_.matches(*packet);
}

} // namespace sniffer
