#pragma once
#include <QString>

namespace sniffer {
class MainWindow;
void startLiveVerification(MainWindow& window, const QString& directory,
                           const QString& demoScript, const QString& interfaceName);
}
