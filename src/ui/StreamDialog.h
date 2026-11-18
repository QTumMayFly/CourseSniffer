#pragma once
#include "core/TcpTracker.h"
#include <QDialog>

namespace sniffer {
class StreamDialog : public QDialog {
    Q_OBJECT
public:
    explicit StreamDialog(StreamView view, QWidget* parent = nullptr);
};
}
