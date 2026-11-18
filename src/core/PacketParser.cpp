#include "PacketParser.h"

#include <algorithm>
#include <arpa/inet.h>
#include <cstring>
#include <iomanip>
#include <limits>
#include <sstream>
#include <utility>

namespace sniffer {
namespace {

std::string number(std::uint64_t value) { return std::to_string(value); }

std::string hexNumber(std::uint64_t value, int width) {
    std::ostringstream text;
    text << "0x" << std::hex << std::setfill('0') << std::setw(width) << value;
    return text.str();
}

class Decoder {
public:
    explicit Decoder(PacketRecord& packet) : packet_(packet), bytes_(packet.raw.bytes) {}

    void decode() {
        add("Frame", "Captured Length", number(bytes_.size()), 0, 0);
        add("Frame", "Original Length", number(packet_.raw.wireLength), 0, 0);
        add("Frame", "Link Type", number(static_cast<unsigned>(packet_.raw.linkType)), 0, 0);
        if (packet_.raw.wireLength > bytes_.size()) truncated("数据包捕获长度小于原始长度。");
        if (packet_.raw.linkType == 1) ethernet();
        else if (packet_.raw.linkType == 0) loopback();
        else {
            packet_.summary = "链路类型 " + std::to_string(packet_.raw.linkType);
            notice("当前解析器尚未支持该链路类型。");
        }
    }

private:
    PacketRecord& packet_;
    const Bytes& bytes_;

    void add(const std::string& layer, const std::string& name, std::string value,
             std::size_t offset, std::size_t length) {
        packet_.fields.push_back({layer, name, std::move(value), offset, length});
    }
    void notice(const std::string& message) {
        if (std::find(packet_.notices.begin(), packet_.notices.end(), message) == packet_.notices.end())
            packet_.notices.push_back(message);
    }
    void malformed(const std::string& message) { packet_.malformed = true; notice(message); }
    void truncated(const std::string& message) { packet_.truncated = true; notice(message); }

    bool captured(std::size_t offset, std::size_t count, const std::string& layer) {
        if (offset > bytes_.size() || count > bytes_.size() - offset) {
            truncated(layer + " 捕获内容不足。");
            return false;
        }
        return true;
    }

    bool require(std::size_t offset, std::size_t count, std::size_t declaredEnd,
                 const std::string& layer) {
        if (offset > declaredEnd || count > declaredEnd - offset) {
            malformed(layer + " 声明长度不足。");
            return false;
        }
        return captured(offset, count, layer);
    }

    std::uint16_t u16(std::size_t offset) const {
        return static_cast<std::uint16_t>((static_cast<unsigned>(bytes_[offset]) << 8U)
                                         | bytes_[offset + 1]);
    }
    std::uint32_t u32(std::size_t offset) const {
        return (static_cast<std::uint32_t>(bytes_[offset]) << 24U)
             | (static_cast<std::uint32_t>(bytes_[offset + 1]) << 16U)
             | (static_cast<std::uint32_t>(bytes_[offset + 2]) << 8U)
             | static_cast<std::uint32_t>(bytes_[offset + 3]);
    }

    std::string mac(std::size_t offset) const {
        std::ostringstream text;
        for (std::size_t index = 0; index < 6; ++index) {
            if (index) text << ':';
            text << std::hex << std::setfill('0') << std::setw(2)
                 << static_cast<unsigned>(bytes_[offset + index]);
        }
        return text.str();
    }

    void address(Endpoint& endpoint, int family, std::size_t offset) {
        endpoint.family = family;
        endpoint.address.fill(0);
        const std::size_t length = family == 4 ? 4 : 16;
        std::copy_n(bytes_.begin() + static_cast<std::ptrdiff_t>(offset), length, endpoint.address.begin());
        char buffer[INET6_ADDRSTRLEN]{};
        const auto* result = inet_ntop(family == 4 ? AF_INET : AF_INET6, endpoint.address.data(),
                                       buffer, sizeof(buffer));
        endpoint.text = result ? result : "地址转换失败";
    }

    void setPayload(std::size_t offset, std::size_t declaredEnd) {
        const auto capturedEnd = std::min(bytes_.size(), declaredEnd);
        packet_.payloadOffset = offset;
        packet_.payloadLength = offset <= capturedEnd ? capturedEnd - offset : 0;
    }

    void ethernet() {
        packet_.summary = "Ethernet";
        if (!captured(0, 14, "Ethernet")) return;
        packet_.source.text = mac(6);
        packet_.destination.text = mac(0);
        add("Ethernet", "Destination MAC", packet_.destination.text, 0, 6);
        add("Ethernet", "Source MAC", packet_.source.text, 6, 6);
        const auto type = u16(12);
        add("Ethernet", "EtherType", hexNumber(type, 4), 12, 2);
        packet_.networkOffset = 14;
        if (type == 0x0800) ipv4(14);
        else if (type == 0x86dd) ipv6(14);
        else {
            packet_.summary = "EtherType " + hexNumber(type, 4);
            notice("当前解析器尚未支持该 EtherType。");
        }
    }

    void loopback() {
        packet_.summary = "回环链路";
        if (!captured(0, 4, "DLT_NULL")) return;
        // DLT_NULL 的地址族字段采用捕获主机的字节序。
        std::uint32_t family = 0;
        std::memcpy(&family, bytes_.data(), sizeof(family));
        add("Loopback", "Address Family", number(family), 0, 4);
        packet_.networkOffset = 4;
        if (family == static_cast<std::uint32_t>(AF_INET)) ipv4(4);
        else if (family == static_cast<std::uint32_t>(AF_INET6) || family == 30 || family == 24 || family == 28)
            ipv6(4);
        else notice("当前解析器尚未支持该回环地址族。");
    }

    void ipv4(std::size_t offset) {
        packet_.add(Protocol::Ipv4);
        packet_.summary = "IPv4";
        if (!captured(offset, 20, "IPv4")) return;
        if ((bytes_[offset] >> 4U) != 4) { malformed("IPv4 版本字段无效。"); return; }
        const std::size_t headerLength = (bytes_[offset] & 0x0fU) * 4U;
        const std::size_t totalLength = u16(offset + 2);
        address(packet_.source, 4, offset + 12);
        address(packet_.destination, 4, offset + 16);
        add("IPv4", "Version", "4", offset, 1);
        add("IPv4", "Header Length", number(headerLength), offset, 1);
        add("IPv4", "Total Length", number(totalLength), offset + 2, 2);
        add("IPv4", "Identification", number(u16(offset + 4)), offset + 4, 2);
        const auto fragments = u16(offset + 6);
        add("IPv4", "Flags", hexNumber(fragments >> 13U, 1), offset + 6, 2);
        add("IPv4", "Fragment Offset", number((fragments & 0x1fffU) * 8U), offset + 6, 2);
        add("IPv4", "TTL", number(bytes_[offset + 8]), offset + 8, 1);
        add("IPv4", "Protocol", number(bytes_[offset + 9]), offset + 9, 1);
        add("IPv4", "Checksum", hexNumber(u16(offset + 10), 4), offset + 10, 2);
        add("IPv4", "Source Address", packet_.source.text, offset + 12, 4);
        add("IPv4", "Destination Address", packet_.destination.text, offset + 16, 4);
        if (headerLength < 20) { malformed("IPv4 IHL 小于最小头部长度。"); return; }
        if (totalLength < headerLength) { malformed("IPv4 总长度小于头部长度。"); return; }
        const auto declaredEnd = offset + totalLength;
        if (declaredEnd > bytes_.size()) truncated("IPv4 捕获内容未覆盖声明的总长度。");
        if (!require(offset, headerLength, declaredEnd, "IPv4 头部")) return;
        if (headerLength > 20) add("IPv4", "Options Length", number(headerLength - 20), offset + 20, headerLength - 20);
        packet_.transportOffset = offset + headerLength;
        setPayload(packet_.transportOffset, declaredEnd);
        packet_.fragmented = (fragments & 0x3fffU) != 0;
        if (packet_.fragmented) {
            packet_.summary = "IPv4 分片";
            notice("IPv4 分片保留网络层信息。");
            return;
        }
        transport(bytes_[offset + 9], packet_.transportOffset, declaredEnd, 4);
    }

    void ipv6(std::size_t offset) {
        packet_.add(Protocol::Ipv6);
        packet_.summary = "IPv6";
        if (!captured(offset, 40, "IPv6")) return;
        if ((bytes_[offset] >> 4U) != 6) { malformed("IPv6 版本字段无效。"); return; }
        address(packet_.source, 6, offset + 8);
        address(packet_.destination, 6, offset + 24);
        const auto payloadLength = u16(offset + 4);
        const std::size_t declaredEnd = offset + 40 + payloadLength;
        add("IPv6", "Version", "6", offset, 1);
        add("IPv6", "Traffic Class", number(((bytes_[offset] & 0x0fU) << 4U) | (bytes_[offset + 1] >> 4U)), offset, 2);
        add("IPv6", "Flow Label", number(u32(offset) & 0xfffffU), offset, 4);
        add("IPv6", "Payload Length", number(payloadLength), offset + 4, 2);
        add("IPv6", "Next Header", number(bytes_[offset + 6]), offset + 6, 1);
        add("IPv6", "Hop Limit", number(bytes_[offset + 7]), offset + 7, 1);
        add("IPv6", "Source Address", packet_.source.text, offset + 8, 16);
        add("IPv6", "Destination Address", packet_.destination.text, offset + 24, 16);
        if (declaredEnd > bytes_.size()) truncated("IPv6 捕获内容未覆盖声明的负载长度。");
        std::uint8_t next = bytes_[offset + 6];
        std::size_t cursor = offset + 40;
        std::size_t extensionCount = 0;
        while (next == 0 || next == 43 || next == 60) {
            if (extensionCount >= 8) { notice("IPv6 扩展头部超过数量限制。"); return; }
            if (!require(cursor, 2, declaredEnd, "IPv6 扩展头部")) return;
            const auto extensionLength = (static_cast<std::size_t>(bytes_[cursor + 1]) + 1U) * 8U;
            if (!require(cursor, extensionLength, declaredEnd, "IPv6 扩展头部")) return;
            const std::string name = next == 0 ? "Hop-by-Hop" : (next == 43 ? "Routing" : "Destination Options");
            add("IPv6 Extension", name + " Length", number(extensionLength), cursor + 1, 1);
            add("IPv6 Extension", "Next Header", number(bytes_[cursor]), cursor, 1);
            next = bytes_[cursor];
            cursor += extensionLength;
            ++extensionCount;
        }
        packet_.transportOffset = cursor;
        setPayload(cursor, declaredEnd);
        if (next == 44) {
            packet_.fragmented = true;
            packet_.summary = "IPv6 分片";
            if (!require(cursor, 8, declaredEnd, "IPv6 Fragment Header")) return;
            add("IPv6 Fragment", "Next Header", number(bytes_[cursor]), cursor, 1);
            add("IPv6 Fragment", "Fragment Offset", number(u16(cursor + 2) & 0xfff8U), cursor + 2, 2);
            add("IPv6 Fragment", "More Fragments", number(u16(cursor + 2) & 1U), cursor + 2, 2);
            add("IPv6 Fragment", "Identification", number(u32(cursor + 4)), cursor + 4, 4);
            setPayload(cursor + 8, declaredEnd);
            notice("IPv6 分片保留网络层信息。");
            return;
        }
        if (next == 50 || next == 51) { notice("当前解析器保留 IPv6 AH 或 ESP 的原始内容。"); return; }
        if (next == 59) { packet_.summary = "IPv6 No Next Header"; return; }
        transport(next, cursor, declaredEnd, 6);
    }

    void transport(std::uint8_t protocol, std::size_t offset, std::size_t end, int family) {
        if (protocol == 6) tcp(offset, end);
        else if (protocol == 17) udp(offset, end);
        else if (protocol == 1 && family == 4) icmp(offset, end, false);
        else if (protocol == 58 && family == 6) icmp(offset, end, true);
        else {
            packet_.summary = (family == 4 ? "IPv4 协议 " : "IPv6 Next Header ") + number(protocol);
            notice("当前解析器尚未支持该上层协议。");
        }
    }

    void ports(std::size_t offset) {
        packet_.source.port = u16(offset);
        packet_.destination.port = u16(offset + 2);
        packet_.hasPorts = true;
    }

    void tcp(std::size_t offset, std::size_t end) {
        if (!require(offset, 20, end, "TCP")) return;
        packet_.add(Protocol::Tcp);
        ports(offset);
        packet_.tcp.sequence = u32(offset + 4);
        packet_.tcp.acknowledgement = u32(offset + 8);
        packet_.tcp.flags = bytes_[offset + 13];
        packet_.tcp.window = u16(offset + 14);
        const std::size_t headerLength = (bytes_[offset + 12] >> 4U) * 4U;
        add("TCP", "Source Port", number(packet_.source.port), offset, 2);
        add("TCP", "Destination Port", number(packet_.destination.port), offset + 2, 2);
        add("TCP", "Seq", number(packet_.tcp.sequence), offset + 4, 4);
        add("TCP", "Ack", number(packet_.tcp.acknowledgement), offset + 8, 4);
        add("TCP", "Header Length", number(headerLength), offset + 12, 1);
        add("TCP", "Flags", hexNumber(packet_.tcp.flags, 2), offset + 13, 1);
        add("TCP", "Window", number(packet_.tcp.window), offset + 14, 2);
        add("TCP", "Checksum", hexNumber(u16(offset + 16), 4), offset + 16, 2);
        add("TCP", "Urgent Pointer", number(u16(offset + 18)), offset + 18, 2);
        if (headerLength < 20) { malformed("TCP Data Offset 小于最小头部长度。"); return; }
        if (!require(offset, headerLength, end, "TCP 头部")) return;
        if (headerLength > 20) add("TCP", "Options Length", number(headerLength - 20), offset + 20, headerLength - 20);
        packet_.hasTcp = true;
        setPayload(offset + headerLength, end);
        add("TCP", "Payload Length", number(packet_.payloadLength), packet_.payloadOffset, packet_.payloadLength);
        std::string flags;
        const std::pair<std::uint8_t, const char*> names[] = {
            {0x02, "SYN"}, {0x10, "ACK"}, {0x01, "FIN"}, {0x04, "RST"},
            {0x08, "PSH"}, {0x20, "URG"}, {0x40, "ECE"}, {0x80, "CWR"}
        };
        for (const auto& item : names) if ((packet_.tcp.flags & item.first) != 0) {
            if (!flags.empty()) flags += ' ';
            flags += item.second;
        }
        packet_.summary = number(packet_.source.port) + " → " + number(packet_.destination.port)
                        + " [" + flags + "] Seq " + number(packet_.tcp.sequence)
                        + " Ack " + number(packet_.tcp.acknowledgement)
                        + "，负载 " + number(packet_.payloadLength) + " 字节";
    }

    void udp(std::size_t offset, std::size_t end) {
        if (!require(offset, 8, end, "UDP")) return;
        packet_.add(Protocol::Udp);
        ports(offset);
        const auto length = u16(offset + 4);
        add("UDP", "Source Port", number(packet_.source.port), offset, 2);
        add("UDP", "Destination Port", number(packet_.destination.port), offset + 2, 2);
        add("UDP", "Length", number(length), offset + 4, 2);
        add("UDP", "Checksum", hexNumber(u16(offset + 6), 4), offset + 6, 2);
        packet_.payloadOffset = offset + 8;
        packet_.payloadLength = 0;
        if (length < 8) { malformed("UDP 长度小于头部长度。"); return; }
        if (length > end - offset) { malformed("UDP 长度超过 IP 声明的负载范围。"); return; }
        if (offset + length > bytes_.size()) truncated("UDP 捕获内容未覆盖声明的长度。");
        setPayload(offset + 8, offset + length);
        packet_.summary = number(packet_.source.port) + " → " + number(packet_.destination.port)
                        + "，负载 " + number(packet_.payloadLength) + " 字节";
    }

    void icmp(std::size_t offset, std::size_t end, bool ipv6) {
        const std::string layer = ipv6 ? "ICMPv6" : "ICMP";
        if (!require(offset, 4, end, layer)) return;
        packet_.add(ipv6 ? Protocol::Icmp6 : Protocol::Icmp);
        const auto type = bytes_[offset];
        add(layer, "Type", number(type), offset, 1);
        add(layer, "Code", number(bytes_[offset + 1]), offset + 1, 1);
        add(layer, "Checksum", hexNumber(u16(offset + 2), 4), offset + 2, 2);
        packet_.summary = layer + " Type " + number(type) + " Code " + number(bytes_[offset + 1]);
        const bool echo = ipv6 ? type == 128 || type == 129 : type == 8 || type == 0;
        if (echo) {
            if (!require(offset, 8, end, layer + " Echo")) return;
            add(layer, "Identifier", number(u16(offset + 4)), offset + 4, 2);
            add(layer, "Sequence", number(u16(offset + 6)), offset + 6, 2);
            packet_.summary += "，标识 " + number(u16(offset + 4)) + "，序号 " + number(u16(offset + 6));
        }
        setPayload(offset + (echo ? 8U : 4U), end);
    }
};

} // namespace

PacketRecord PacketParser::parse(RawPacket raw) {
    PacketRecord packet;
    packet.raw = std::move(raw);
    if (!packet.raw.wireLength)
        packet.raw.wireLength = static_cast<std::uint32_t>(std::min<std::size_t>(packet.raw.bytes.size(), std::numeric_limits<std::uint32_t>::max()));
    Decoder(packet).decode();
    return packet;
}

} // namespace sniffer
