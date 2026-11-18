#pragma once
#include "PacketRecord.h"

namespace sniffer {
class PacketParser {
public:
    static PacketRecord parse(RawPacket packet);
};
}
