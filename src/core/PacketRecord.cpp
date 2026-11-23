#include "PacketRecord.h"

#include <algorithm>
#include <iomanip>
#include <sstream>
#include <tuple>

namespace sniffer {

bool Endpoint::operator<(const Endpoint& other) const {
    return std::tie(family, address, port) < std::tie(other.family, other.address, other.port);
}

bool Endpoint::operator==(const Endpoint& other) const {
    return family == other.family && address == other.address && port == other.port;
}

std::string Endpoint::display() const {
    if (family == 6) return "[" + text + "]:" + std::to_string(port);
    if (family == 4) return text + ":" + std::to_string(port);
    return text;
}

bool PacketRecord::has(Protocol protocol) const {
    return (protocols & static_cast<std::uint32_t>(protocol)) != 0;
}

void PacketRecord::add(Protocol protocol) {
    protocols |= static_cast<std::uint32_t>(protocol);
}

std::string PacketRecord::protocolName() const {
    if (has(Protocol::Dns)) return "DNS";
    if (has(Protocol::Arp)) return "ARP";
    if (has(Protocol::Http)) return "HTTP";
    if (has(Protocol::Tcp)) return "TCP";
    if (has(Protocol::Udp)) return "UDP";
    if (has(Protocol::Icmp6)) return "ICMPv6";
    if (has(Protocol::Icmp)) return "ICMP";
    if (has(Protocol::Ipv6)) return "IPv6";
    if (has(Protocol::Ipv4)) return "IPv4";
    if (raw.linkType == 1) return "Ethernet";
    if (raw.linkType == 0) return "Loopback";
    return "Unknown";
}

Bytes PacketRecord::payload() const {
    if (payloadOffset > raw.bytes.size()) return {};
    const auto length = std::min(payloadLength, raw.bytes.size() - payloadOffset);
    return Bytes(raw.bytes.begin() + static_cast<std::ptrdiff_t>(payloadOffset),
                 raw.bytes.begin() + static_cast<std::ptrdiff_t>(payloadOffset + length));
}

std::string printableText(const Bytes& data) {
    std::string result;
    result.reserve(data.size());
    for (const auto byte : data) {
        result.push_back((byte >= 32 && byte <= 126) || byte == '\r' || byte == '\n' || byte == '\t'
                             ? static_cast<char>(byte) : '.');
    }
    return result;
}

std::string hexDump(const Bytes& data, std::size_t limit) {
    std::ostringstream output;
    const auto count = std::min(data.size(), limit);
    for (std::size_t offset = 0; offset < count; offset += 16) {
        output << std::hex << std::setfill('0') << std::setw(8) << offset << "  ";
        for (std::size_t index = 0; index < 16; ++index) {
            if (offset + index < count) {
                output << std::setw(2) << static_cast<unsigned>(data[offset + index]) << ' ';
            } else {
                output << "   ";
            }
            if (index == 7) output << ' ';
        }
        output << " |";
        for (std::size_t index = offset; index < std::min(offset + 16, count); ++index) {
            const auto byte = data[index];
            output << (byte >= 32 && byte <= 126 ? static_cast<char>(byte) : '.');
        }
        output << "|\n";
    }
    if (count < data.size()) output << "内容达到显示上限。\n";
    return output.str();
}

} // namespace sniffer
