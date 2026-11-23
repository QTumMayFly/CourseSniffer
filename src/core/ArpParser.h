#pragma once
#include "PacketRecord.h"

namespace sniffer {
class ArpParser {
public:
    static bool parse(PacketRecord& packet, std::size_t offset);
};
}
