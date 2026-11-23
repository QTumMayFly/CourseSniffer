#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace sniffer {

using Bytes = std::vector<std::uint8_t>;
enum class Protocol : std::uint32_t {
    Ipv4 = 1U, Ipv6 = 2U, Tcp = 4U, Udp = 8U,
    Icmp = 16U, Icmp6 = 32U, Http = 64U,
    Dns = 128U, Arp = 256U
};

struct RawPacket {
    std::uint64_t id = 0;
    std::int64_t timestampMicros = 0;
    std::uint32_t wireLength = 0;
    int linkType = 1;
    Bytes bytes;
};

struct Field {
    std::string layer;
    std::string name;
    std::string value;
    std::size_t offset = 0;
    std::size_t length = 0;
};

struct Endpoint {
    int family = 0; // 使用 4 或 6 表示网络地址族。
    std::array<std::uint8_t, 16> address{};
    std::uint16_t port = 0;
    std::string text;
    bool operator<(const Endpoint& other) const;
    bool operator==(const Endpoint& other) const;
    std::string display() const;
};

struct TcpInfo {
    std::uint32_t sequence = 0;
    std::uint32_t acknowledgement = 0;
    std::uint16_t window = 0;
    std::uint8_t flags = 0;
};

struct PacketRecord {
    RawPacket raw;
    std::uint32_t protocols = 0;
    Endpoint source;
    Endpoint destination;
    bool hasPorts = false;
    bool hasTcp = false;
    bool fragmented = false;
    bool malformed = false;
    bool truncated = false;
    TcpInfo tcp;
    std::size_t networkOffset = 0;
    std::size_t transportOffset = 0;
    std::size_t payloadOffset = 0;
    std::size_t payloadLength = 0;
    std::uint64_t connectionId = 0;
    std::string summary;
    std::vector<Field> fields;
    std::vector<std::string> notices;
    bool has(Protocol protocol) const;
    void add(Protocol protocol);
    std::string protocolName() const;
    Bytes payload() const;
};

std::string hexDump(const Bytes& data, std::size_t limit = 65535);
std::string printableText(const Bytes& data);

} // namespace sniffer
