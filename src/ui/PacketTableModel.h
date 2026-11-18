#pragma once

#include "core/PacketRecord.h"
#include "core/FilterParser.h"
#include <QAbstractTableModel>
#include <QSortFilterProxyModel>
#include <unordered_map>

namespace sniffer {
class PacketTableModel : public QAbstractTableModel {
    Q_OBJECT
public:
    enum Column { Number, Time, Source, Destination, ProtocolName, Length, Summary, ColumnCount };
    explicit PacketTableModel(QObject* parent = nullptr);
    int rowCount(const QModelIndex& parent = {}) const override;
    int columnCount(const QModelIndex& parent = {}) const override;
    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
    const PacketRecord* packetAt(int row) const;
    void appendPackets(std::vector<PacketRecord> packets);
    void markHttp(const std::vector<std::uint64_t>& ids);
    void clear();
    std::size_t totalBytes() const { return totalBytes_; }
private:
    std::vector<PacketRecord> packets_;
    std::unordered_map<std::uint64_t, int> rowById_;
    std::size_t totalBytes_ = 0;
};

class PacketFilterModel : public QSortFilterProxyModel {
    Q_OBJECT
public:
    explicit PacketFilterModel(QObject* parent = nullptr);
    bool setExpression(const QString& expression, QString* error = nullptr);
    QString expression() const;
    void refresh();
protected:
    bool filterAcceptsRow(int row, const QModelIndex& parent) const override;
private:
    Filter filter_;
};
}
