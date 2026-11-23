#include "TestSupport.h"
#include "ParserFixtures.h"
#include "core/PacketParser.h"

#include <algorithm>
#include <limits>
#include <sys/socket.h>

namespace {
using namespace sniffer;
using namespace parserfixtures;

const Field& field(const PacketRecord& packet, const std::string& layer, const std::string& name) {
    const auto found = std::find_if(packet.fields.begin(), packet.fields.end(), [&](const Field& item) {
        return item.layer == layer && item.name == name;
    });
    if (found == packet.fields.end()) throw std::runtime_error("Missing field: " + layer + " " + name);
    return *found;
}

void checkBounds(const PacketRecord& packet) {
    for (const auto& item : packet.fields) {
        CHECK(item.offset <= packet.raw.bytes.size());
        CHECK(item.length <= packet.raw.bytes.size() - item.offset);
    }
    CHECK(packet.payload().size() <= packet.raw.bytes.size());
}
}

void runParserTests(TestSuite& suite) {
    suite.run("parser Ethernet IPv4 TCP fields and payload", [] {
        const auto packet = PacketParser::parse(raw(ethernet(ipv4(6, tcp({'h','e','l','l','o'})))));
        CHECK(packet.raw.id == 7);
        CHECK(packet.has(Protocol::Ipv4));
        CHECK(packet.has(Protocol::Tcp));
        CHECK(packet.hasTcp && packet.hasPorts);
        CHECK(!packet.malformed && !packet.truncated && !packet.fragmented);
        CHECK(packet.source.text == "192.0.2.1");
        CHECK(packet.destination.text == "198.51.100.2");
        CHECK(packet.source.port == 54321);
        CHECK(packet.destination.port == 8080);
        CHECK(packet.tcp.sequence == 0x01020304);
        CHECK(packet.tcp.acknowledgement == 0x11223344);
        CHECK(packet.tcp.window == 8192);
        CHECK(packet.tcp.flags == 0x18);
        CHECK(packet.networkOffset == 14 && packet.transportOffset == 34);
        CHECK(packet.payloadOffset == 54 && packet.payloadLength == 5);
        CHECK(packet.payload() == Bytes({'h','e','l','l','o'}));
        CHECK(field(packet, "Ethernet", "Source MAC").value == "aa:bb:cc:dd:ee:ff");
        CHECK(field(packet, "IPv4", "TTL").value == "64");
        CHECK(field(packet, "TCP", "Seq").offset == 38);
        CHECK(packet.protocolName() == "TCP");
        checkBounds(packet);
    });
    suite.run("parser loopback IPv4 uses four byte header", [] {
        const auto packet = PacketParser::parse(raw(loopback(ipv4(6, tcp({'x'})), AF_INET), 0));
        CHECK(packet.source.text == "192.0.2.1");
        CHECK(packet.networkOffset == 4 && packet.transportOffset == 24);
        CHECK(packet.payloadOffset == 44 && packet.payload() == Bytes({'x'}));
        CHECK(packet.hasTcp);
        checkBounds(packet);
    });
    suite.run("parser macOS and native loopback IPv6 families", [] {
        for (const auto family : {30U, static_cast<unsigned>(AF_INET6)}) {
            const auto packet = PacketParser::parse(raw(loopback(ipv6(17, udp({'a','b'})), family), 0));
            CHECK(packet.has(Protocol::Ipv6) && packet.has(Protocol::Udp));
            CHECK(packet.source.text == "2001:db8::1");
            CHECK(packet.destination.text == "2001:db8::2");
            CHECK(packet.source.port == 8888 && packet.destination.port == 9999);
            CHECK(packet.payloadOffset == 52);
            CHECK(packet.payload() == Bytes({'a','b'}));
            CHECK(packet.source.display() == "[2001:db8::1]:8888");
            checkBounds(packet);
        }
    });
    suite.run("parser IPv4 and TCP variable header lengths", [] {
        auto transport = tcp({'x','y'});
        transport[12] = 0x60;
        transport.insert(transport.begin() + 20, {1, 1, 1, 1});
        auto network = ipv4(6, transport);
        network[0] = 0x46;
        network.insert(network.begin() + 20, {1, 1, 1, 1});
        put16(network, 2, static_cast<std::uint16_t>(network.size()));
        const auto packet = PacketParser::parse(raw(ethernet(network)));
        CHECK(packet.transportOffset == 38);
        CHECK(packet.payloadOffset == 62);
        CHECK(packet.payload() == Bytes({'x','y'}));
        CHECK(field(packet, "IPv4", "Header Length").value == "24");
        CHECK(field(packet, "TCP", "Header Length").value == "24");
        checkBounds(packet);
    });
    suite.run("parser IPv6 TCP preserves transport offset and endpoints", [] {
        const auto packet = PacketParser::parse(raw(ethernet(ipv6(6, tcp({'G','E','T',' '})), 0x86dd)));
        CHECK(packet.has(Protocol::Ipv6) && packet.has(Protocol::Tcp));
        CHECK(packet.hasTcp && packet.hasPorts);
        CHECK(packet.source.family == 6 && packet.destination.family == 6);
        CHECK(packet.source.text == "2001:db8::1" && packet.destination.text == "2001:db8::2");
        CHECK(packet.source.port == 54321 && packet.destination.port == 8080);
        CHECK(packet.transportOffset == 54 && packet.payloadOffset == 74);
        CHECK(packet.payload() == Bytes({'G','E','T',' '}));
        CHECK(!packet.malformed && !packet.truncated);
        checkBounds(packet);
    });
    suite.run("parser IP length excludes Ethernet padding", [] {
        auto bytes = ethernet(ipv4(6, tcp({'a'})));
        bytes.insert(bytes.end(), 20, 0xee);
        const auto packet = PacketParser::parse(raw(bytes));
        CHECK(packet.payloadLength == 1);
        CHECK(packet.payload() == Bytes({'a'}));
        CHECK(!packet.malformed);
    });
    suite.run("parser UDP declared length bounds payload", [] {
        auto transport = udp({'a','b','c','d','e'});
        put16(transport, 4, 11);
        const auto packet = PacketParser::parse(raw(ethernet(ipv4(17, transport))));
        CHECK(packet.has(Protocol::Udp));
        CHECK(packet.payloadOffset == 42);
        CHECK(packet.payload() == Bytes({'a','b','c'}));
        CHECK(field(packet, "UDP", "Length").value == "11");
        checkBounds(packet);
    });
    suite.run("parser IPv4 echo fields", [] {
        const Bytes echo = {8, 0, 0x12, 0x34, 0xab, 0xcd, 0, 7, 'p'};
        const auto packet = PacketParser::parse(raw(ethernet(ipv4(1, echo))));
        CHECK(packet.has(Protocol::Icmp));
        CHECK(!packet.has(Protocol::Icmp6));
        CHECK(!packet.hasPorts);
        CHECK(field(packet, "ICMP", "Identifier").value == "43981");
        CHECK(field(packet, "ICMP", "Sequence").value == "7");
        CHECK(packet.payload() == Bytes({'p'}));
        checkBounds(packet);
    });
    suite.run("parser IPv6 echo fields", [] {
        const Bytes echo = {128, 0, 0x12, 0x34, 0, 42, 0, 2, 'q'};
        const auto packet = PacketParser::parse(raw(ethernet(ipv6(58, echo), 0x86dd)));
        CHECK(packet.has(Protocol::Icmp6) && packet.has(Protocol::Ipv6));
        CHECK(!packet.has(Protocol::Icmp));
        CHECK(field(packet, "ICMPv6", "Identifier").value == "42");
        CHECK(packet.protocolName() == "ICMPv6");
        CHECK(packet.payloadOffset == 62);
        checkBounds(packet);
    });
    suite.run("parser IPv4 fragments keep network layer", [] {
        auto network = ipv4(6, tcp({'x'}));
        put16(network, 6, 0x2001);
        const auto packet = PacketParser::parse(raw(ethernet(network)));
        CHECK(packet.fragmented);
        CHECK(packet.has(Protocol::Ipv4));
        CHECK(!packet.hasTcp && !packet.has(Protocol::Tcp));
        CHECK(field(packet, "IPv4", "Fragment Offset").value == "8");
        checkBounds(packet);
    });
    suite.run("parser IPv6 extensions reach UDP", [] {
        Bytes extension = {17, 0, 0, 0, 0, 0, 0, 0};
        const auto transport = udp({'z'});
        extension.insert(extension.end(), transport.begin(), transport.end());
        const auto packet = PacketParser::parse(raw(ethernet(ipv6(0, extension), 0x86dd)));
        CHECK(packet.has(Protocol::Udp));
        CHECK(packet.transportOffset == 62);
        CHECK(packet.payloadOffset == 70);
        CHECK(packet.payload() == Bytes({'z'}));
        CHECK(field(packet, "IPv6 Extension", "Hop-by-Hop Length").value == "8");
        checkBounds(packet);
    });
    suite.run("parser IPv6 extension count is bounded", [] {
        for (const auto count : {8, 9}) {
            Bytes extensions;
            for (int index = 0; index < count; ++index) {
                extensions.insert(extensions.end(), {static_cast<std::uint8_t>(index + 1 == count ? 17 : 0), 0, 0, 0, 0, 0, 0, 0});
            }
            const auto transport = udp({'z'});
            extensions.insert(extensions.end(), transport.begin(), transport.end());
            const auto packet = PacketParser::parse(raw(ethernet(ipv6(0, extensions), 0x86dd)));
            CHECK(packet.has(Protocol::Udp) == (count == 8));
            if (count == 9) CHECK(!packet.notices.empty());
            checkBounds(packet);
        }
    });
    suite.run("parser IPv6 fragments keep network layer", [] {
        Bytes fragment = {6, 0, 0, 1, 0xca, 0xfe, 0xba, 0xbe};
        const auto transport = tcp({'z'});
        fragment.insert(fragment.end(), transport.begin(), transport.end());
        const auto packet = PacketParser::parse(raw(ethernet(ipv6(44, fragment), 0x86dd)));
        CHECK(packet.fragmented && packet.has(Protocol::Ipv6));
        CHECK(!packet.hasTcp && !packet.has(Protocol::Tcp));
        CHECK(field(packet, "IPv6 Fragment", "Identification").value == "3405691582");
        CHECK(field(packet, "IPv6 Fragment", "More Fragments").value == "1");
        checkBounds(packet);
    });
    suite.run("parser IPv6 AH ESP and No Next Header remain bounded", [] {
        for (const auto next : {50, 51, 59}) {
            const auto packet = PacketParser::parse(raw(ethernet(ipv6(static_cast<std::uint8_t>(next), {}), 0x86dd)));
            CHECK(packet.has(Protocol::Ipv6));
            CHECK(!packet.hasTcp && !packet.hasPorts);
            CHECK(!packet.malformed);
            checkBounds(packet);
        }
    });
    suite.run("parser malformed IPv4 IHL and total length", [] {
        auto network = ipv4(6, tcp());
        network[0] = 0x44;
        auto packet = PacketParser::parse(raw(ethernet(network)));
        CHECK(packet.malformed && !packet.hasTcp);
        network[0] = 0x45;
        put16(network, 2, 10);
        packet = PacketParser::parse(raw(ethernet(network)));
        CHECK(packet.malformed && !packet.hasTcp);
        checkBounds(packet);
    });
    suite.run("parser malformed TCP Data Offset", [] {
        for (const auto offset : {0x40, 0xf0}) {
            auto transport = tcp();
            transport[12] = static_cast<std::uint8_t>(offset);
            const auto packet = PacketParser::parse(raw(ethernet(ipv4(6, transport))));
            CHECK(packet.malformed);
            CHECK(!packet.hasTcp);
            checkBounds(packet);
        }
    });
    suite.run("parser malformed UDP lengths", [] {
        for (const auto length : {0, 7, 40}) {
            auto transport = udp({'x'});
            put16(transport, 4, static_cast<std::uint16_t>(length));
            const auto packet = PacketParser::parse(raw(ethernet(ipv4(17, transport))));
            CHECK(packet.malformed);
            CHECK(packet.payloadLength == 0);
            checkBounds(packet);
        }
    });
    suite.run("parser malformed short ICMP echo", [] {
        const auto packet = PacketParser::parse(raw(ethernet(ipv4(1, {8, 0, 0, 0, 0, 0}))));
        CHECK(packet.malformed);
        CHECK(packet.has(Protocol::Icmp));
        checkBounds(packet);
    });
    suite.run("parser TCP payload capture truncation", [] {
        auto input = raw(ethernet(ipv4(6, tcp({'a','b','c','d'}))));
        input.bytes.resize(input.bytes.size() - 2);
        const auto packet = PacketParser::parse(input);
        CHECK(packet.hasTcp && packet.truncated);
        CHECK(packet.payload() == Bytes({'a','b'}));
        CHECK(!packet.malformed);
        checkBounds(packet);
    });
    suite.run("parser every captured prefix stays bounded", [] {
        const auto full = ethernet(ipv4(6, tcp({'a','b','c','d'})));
        for (std::size_t count = 0; count < full.size(); ++count) {
            auto input = raw(Bytes(full.begin(), full.begin() + static_cast<std::ptrdiff_t>(count)));
            input.wireLength = static_cast<std::uint32_t>(full.size());
            const auto packet = PacketParser::parse(input);
            CHECK(packet.truncated);
            checkBounds(packet);
        }
    });
    suite.run("parser malformed IPv6 extension lengths", [] {
        const Bytes extension = {17, 10, 0, 0, 0, 0, 0, 0};
        const auto packet = PacketParser::parse(raw(ethernet(ipv6(0, extension), 0x86dd)));
        CHECK(packet.malformed);
        CHECK(!packet.has(Protocol::Udp));
        checkBounds(packet);
    });
    suite.run("parser unsupported links and EtherType retain bytes", [] {
        const Bytes original = {1,2,3};
        const auto unknown = PacketParser::parse(raw(original, 99));
        CHECK(unknown.raw.bytes == original && !unknown.notices.empty());
        const auto unknownType = PacketParser::parse(raw(ethernet(Bytes(28), 0x88b5)));
        CHECK(!unknownType.has(Protocol::Ipv4));
        CHECK(unknownType.source.text == "aa:bb:cc:dd:ee:ff");
        CHECK(!unknownType.notices.empty());
    });
    suite.run("parser deterministic malformed packet corpus", [] {
        std::uint32_t state = 0x12345678;
        for (std::size_t count = 0; count < 2000; ++count) {
            state = state * 1664525U + 1013904223U;
            Bytes bytes(14 + (state % 128));
            for (auto& byte : bytes) { state = state * 1664525U + 1013904223U; byte = static_cast<std::uint8_t>(state >> 24U); }
            bytes[12] = count % 2 == 0 ? 0x08 : 0x86;
            bytes[13] = count % 2 == 0 ? 0x00 : 0xdd;
            if (bytes.size() > 14) bytes[14] = count % 2 == 0 ? 0x45 : 0x60;
            checkBounds(PacketParser::parse(raw(bytes)));
        }
    });
    suite.run("packet endpoint identity uses binary addresses", [] {
        Endpoint left;
        left.family = 6;
        left.address[15] = 1;
        left.port = 80;
        left.text = "::1";
        auto right = left;
        right.text = "0:0:0:0:0:0:0:1";
        CHECK(left == right);
        CHECK(!(left < right));
        right.port = 81;
        CHECK(left < right);
    });
    suite.run("packet safe payload and byte presentation", [] {
        PacketRecord packet;
        packet.raw.bytes = {0x41, 0x00, 0x0a};
        packet.payloadOffset = 1;
        packet.payloadLength = std::numeric_limits<std::size_t>::max();
        CHECK(packet.payload() == Bytes({0x00, 0x0a}));
        packet.payloadOffset = 100;
        CHECK(packet.payload().empty());
        CHECK(printableText({0x41, 0x00, 0x0a}) == "A.\n");
        CHECK(hexDump({0x41, 0x00, 0x0a}).find("41 00 0a") != std::string::npos);
        packet.add(Protocol::Ipv4);
        packet.add(Protocol::Tcp);
        packet.add(Protocol::Http);
        CHECK(packet.protocolName() == "HTTP");
    });
}
