#pragma once
#include "core/PacketRecord.h"
#include <cstring>
#include <utility>

namespace parserfixtures {
using sniffer::Bytes;
inline void put16(Bytes& bytes, std::size_t offset, std::uint16_t value) {
    bytes.at(offset) = static_cast<std::uint8_t>(value >> 8U);
    bytes.at(offset + 1) = static_cast<std::uint8_t>(value);
}
inline Bytes tcp(const Bytes& payload = {}) {
    Bytes bytes = {0xd4, 0x31, 0x1f, 0x90, 0x01, 0x02, 0x03, 0x04,
                   0x11, 0x22, 0x33, 0x44, 0x50, 0x18, 0x20, 0x00,
                   0xab, 0xcd, 0x00, 0x00};
    bytes.insert(bytes.end(), payload.begin(), payload.end());
    return bytes;
}
inline Bytes udp(const Bytes& payload = {}) {
    Bytes bytes = {0x22, 0xb8, 0x27, 0x0f, 0x00, 0x08, 0x12, 0x34};
    put16(bytes, 4, static_cast<std::uint16_t>(8 + payload.size()));
    bytes.insert(bytes.end(), payload.begin(), payload.end());
    return bytes;
}
inline Bytes ipv4(std::uint8_t protocol, const Bytes& payload) {
    Bytes bytes = {0x45, 0x00, 0x00, 0x14, 0x12, 0x34, 0x40, 0x00,
                   0x40, protocol, 0x00, 0x00, 0xc0, 0x00, 0x02, 0x01,
                   0xc6, 0x33, 0x64, 0x02};
    put16(bytes, 2, static_cast<std::uint16_t>(20 + payload.size()));
    bytes.insert(bytes.end(), payload.begin(), payload.end());
    return bytes;
}
inline Bytes ipv6(std::uint8_t next, const Bytes& payload) {
    Bytes bytes = {0x60, 0x00, 0x00, 0x00, 0x00, 0x00, next, 0x40,
                   0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                   0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02};
    put16(bytes, 4, static_cast<std::uint16_t>(payload.size()));
    bytes.insert(bytes.end(), payload.begin(), payload.end());
    return bytes;
}
inline Bytes ethernet(const Bytes& payload, std::uint16_t type = 0x0800) {
    Bytes bytes = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                   0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x00};
    put16(bytes, 12, type);
    bytes.insert(bytes.end(), payload.begin(), payload.end());
    return bytes;
}
inline Bytes loopback(const Bytes& payload, std::uint32_t family) {
    Bytes bytes(4);
    std::memcpy(bytes.data(), &family, 4);
    bytes.insert(bytes.end(), payload.begin(), payload.end());
    return bytes;
}
inline sniffer::RawPacket raw(Bytes bytes, int linkType = 1) {
    sniffer::RawPacket packet;
    packet.id = 7;
    packet.timestampMicros = 1700000000123456;
    packet.wireLength = static_cast<std::uint32_t>(bytes.size());
    packet.linkType = linkType;
    packet.bytes = std::move(bytes);
    return packet;
}
}
