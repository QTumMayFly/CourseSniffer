#include "StreamDialog.h"
#include <QDialogButtonBox>
#include <QFontDatabase>
#include <QLabel>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QStringList>
#include <QTabWidget>
#include <QVBoxLayout>

namespace sniffer {
StreamDialog::StreamDialog(StreamView view, QWidget* parent) : QDialog(parent) {
    setWindowTitle(QStringLiteral("TCP 双向内容 · 连接 %1").arg(view.connection.id));
    resize(1080, 740);
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(22, 20, 22, 18);
    layout->setSpacing(12);
    auto* heading = new QLabel(QStringLiteral("TCP 双向内容"));
    QFont headingFont = heading->font(); headingFont.setPointSize(18); headingFont.setBold(true); heading->setFont(headingFont);
    layout->addWidget(heading);
    auto* endpoints = new QLabel(QStringLiteral("连接 %1    %2    ↔    %3")
        .arg(view.connection.id).arg(QString::fromStdString(view.connection.a.display()), QString::fromStdString(view.connection.b.display())));
    endpoints->setTextInteractionFlags(Qt::TextSelectableByMouse);
    layout->addWidget(endpoints);
    QStringList states;
    states << QStringLiteral("关联数据包 %1 个").arg(view.connection.packetIds.size());
    if (view.connection.midstream) states << QStringLiteral("从连接中途开始捕获");
    if (view.connection.boundaryUncertain) states << QStringLiteral("连接边界证据有限");
    if (view.connection.reset) states << QStringLiteral("已观察到 RST");
    else if (view.connection.closed) states << QStringLiteral("已观察到连接结束");
    auto* status = new QLabel(states.join(QStringLiteral(" · ")));
    status->setWordWrap(true);
    layout->addWidget(status);
    auto* directions = new QTabWidget;
    directions->setObjectName(QStringLiteral("streamDirections"));
    for (std::size_t i = 0; i < view.directions.size(); ++i) {
        const auto& direction = view.directions[i];
        auto* page = new QWidget;
        auto* pageLayout = new QVBoxLayout(page);
        auto* description = new QLabel(QStringLiteral("%1 → %2\n%3 字节 · %4")
            .arg(QString::fromStdString(direction.source.display()), QString::fromStdString(direction.destination.display()))
            .arg(direction.uniqueBytes).arg(QString::fromStdString(direction.status)));
        description->setWordWrap(true);
        description->setTextInteractionFlags(Qt::TextSelectableByMouse);
        pageLayout->addWidget(description);
        auto* formats = new QTabWidget;
        for (int hexadecimal = 0; hexadecimal < 2; ++hexadecimal) {
            auto* editor = new QPlainTextEdit;
            editor->setReadOnly(true);
            editor->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
            editor->setLineWrapMode(hexadecimal ? QPlainTextEdit::NoWrap : QPlainTextEdit::WidgetWidth);
            editor->setPlainText(QString::fromStdString(streamText(direction, hexadecimal != 0)));
            formats->addTab(editor, hexadecimal ? QStringLiteral("十六进制") : QStringLiteral("文本"));
        }
        pageLayout->addWidget(formats, 1);
        directions->addTab(page, i == 0 ? QStringLiteral("端点 A → 端点 B") : QStringLiteral("端点 B → 端点 A"));
    }
    layout->addWidget(directions, 1);
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close);
    buttons->button(QDialogButtonBox::Close)->setText(QStringLiteral("关闭窗口"));
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    layout->addWidget(buttons);
}
}
