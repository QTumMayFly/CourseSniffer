#include "ArpParser.h"

#include <algorithm>
#include <arpa/inet.h>
#include <iomanip>
#include <sstream>

namespace sniffer {
namespace {
std::string hexadecimal(std::uint16_t value) {
    std::ostringstream text;
    text << "0x" << std::hex << std::setfill('0') << std::setw(4) << value;
    return text.str();
}

std::string macAddress(const Bytes& bytes, std::size_t offset) {
    std::ostringstream text;
    for (std::size_t index = 0; index < 6; ++index) {
        if (index != 0) text << ':';
        text << std::hex << std::setfill('0') << std::setw(2)
             << static_cast<unsigned>(bytes[offset + index]);
    }
    return text.str();
}

void ipv4Address(Endpoint& endpoint, const Bytes& bytes, std::size_t offset) {
    endpoint = Endpoint{};
    endpoint.family = 4;
    std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(offset), 4, endpoint.address.begin());
    char text[INET_ADDRSTRLEN]{};
    const auto* result = inet_ntop(AF_INET, endpoint.address.data(), text, sizeof(text));
    endpoint.text = result ? result : "地址转换失败";
}
} // namespace

bool ArpParser::parse(PacketRecord& packet, std::size_t offset) {
    const auto& bytes = packet.raw.bytes;
    packet.add(Protocol::Arp);
    packet.summary = "ARP";
    const auto captured = [&](std::size_t count) {
        if (offset > bytes.size() || count > bytes.size() - offset) {
            packet.truncated = true;
            packet.notices.emplace_back("ARP 捕获内容不足。");
            return false;
        }
        return true;
    };
    if (!captured(8)) return false;
    const auto read16 = [&](std::size_t relative) {
        return static_cast<std::uint16_t>((static_cast<unsigned>(bytes[offset + relative]) << 8U)
                                          | bytes[offset + relative + 1]);
    };
    const auto field = [&](const std::string& name, const std::string& value,
                           std::size_t relative, std::size_t length) {
        packet.fields.push_back({"ARP", name, value, offset + relative, length});
    };
    const auto hardwareType = read16(0);
    const auto protocolType = read16(2);
    const auto hardwareLength = bytes[offset + 4];
    const auto protocolLength = bytes[offset + 5];
    const auto operation = read16(6);
    field("HTYPE", std::to_string(hardwareType), 0, 2);
    field("PTYPE", hexadecimal(protocolType), 2, 2);
    field("HLEN", std::to_string(hardwareLength), 4, 1);
    field("PLEN", std::to_string(protocolLength), 5, 1);
    field("Opcode", std::to_string(operation), 6, 2);

    if (hardwareLength == 0 || protocolLength == 0) {
        packet.malformed = true;
        packet.notices.emplace_back("ARP 地址长度不能为零。");
        return false;
    }
    if (hardwareType != 1 || protocolType != 0x0800) {
        packet.notices.emplace_back("ARP 地址格式尚未支持，保留 HTYPE、PTYPE 和原始字节。");
        captured(8U + 2U * static_cast<std::size_t>(hardwareLength)
                     + 2U * static_cast<std::size_t>(protocolLength));
        return false;
    }
    if (hardwareLength != 6 || protocolLength != 4) {
        packet.malformed = true;
        packet.notices.emplace_back("ARP 地址长度与 Ethernet/IPv4 格式不一致。");
        return false;
    }
    if (!captured(28)) return false;

    const auto senderMac = macAddress(bytes, offset + 8);
    const auto targetMac = macAddress(bytes, offset + 18);
    ipv4Address(packet.source, bytes, offset + 14);
    ipv4Address(packet.destination, bytes, offset + 24);
    packet.hasPorts = false;
    packet.payloadOffset = offset + 28;
    packet.payloadLength = 0;
    field("Sender MAC", senderMac, 8, 6);
    field("Sender IP", packet.source.text, 14, 4);
    field("Target MAC", targetMac, 18, 6);
    field("Target IP", packet.destination.text, 24, 4);
    if (operation == 1) {
        packet.summary = "ARP 请求：" + packet.source.text + " 查询 " + packet.destination.text;
    } else if (operation == 2) {
        packet.summary = "ARP 响应：" + packet.source.text + " 对应 " + senderMac;
    } else {
        packet.summary = "ARP Opcode " + std::to_string(operation) + "，发送方 " + packet.source.text;
        packet.notices.emplace_back("ARP 操作码尚未提供专门解释。");
    }
    return true;
}
} // namespace sniffer
