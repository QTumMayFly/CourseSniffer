#pragma once
#include "PacketRecord.h"

namespace sniffer {
class DnsParser {
public:
    // 对 UDP 53 的完整候选负载进行结构校验，并保存有效 DNS 字段。
    static bool parse(PacketRecord& packet);
};
}
