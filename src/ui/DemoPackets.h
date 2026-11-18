#pragma once
#include "core/PacketRecord.h"
#include <QString>

namespace sniffer {
std::vector<RawPacket> builtInDemoPackets();
std::vector<RawPacket> readDemoPcap(const QString& path, QString* error = nullptr);
}
