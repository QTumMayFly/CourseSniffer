#pragma once

#include <QString>

namespace sniffer {
class MainWindow;

// 在 Qt 窗口中执行实际抓包、过滤与流追踪，并记录连续窗口画面。
// 图像来自窗口当前内容；离线协议样例会在画面及字幕中单独标明。
void startGuidedRecording(MainWindow& window, const QString& moviePath,
                          const QString& trafficScript, const QString& protocolPcap);
} // namespace sniffer
