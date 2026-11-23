#include "TestSupport.h"
#include "ParserFixtures.h"
#include "core/PacketParser.h"

#include <algorithm>
#include <array>
#include <string>

namespace {
using namespace sniffer;
using namespace parserfixtures;

void append16(Bytes& bytes, std::uint16_t value) {
    bytes.push_back(static_cast<std::uint8_t>(value >> 8U));
    bytes.push_back(static_cast<std::uint8_t>(value));
}

void append32(Bytes& bytes, std::uint32_t value) {
    bytes.push_back(static_cast<std::uint8_t>(value >> 24U));
    bytes.push_back(static_cast<std::uint8_t>(value >> 16U));
    bytes.push_back(static_cast<std::uint8_t>(value >> 8U));
    bytes.push_back(static_cast<std::uint8_t>(value));
}

Bytes domain(std::initializer_list<std::string> labels) {
    Bytes result;
    for (const auto& label : labels) {
        result.push_back(static_cast<std::uint8_t>(label.size()));
        result.insert(result.end(), label.begin(), label.end());
    }
    result.push_back(0);
    return result;
}

Bytes dnsHeader(std::uint16_t flags = 0x0100, std::uint16_t questions = 1,
                std::uint16_t answers = 0, std::uint16_t authority = 0, std::uint16_t additional = 0) {
    Bytes result;
    for (const auto value : {std::uint16_t{0x1234}, flags, questions, answers, authority, additional}) append16(result, value);
    return result;
}

Bytes query(std::uint16_t type = 1) {
    auto result = dnsHeader();
    const auto qname = domain({"example", "test"});
    result.insert(result.end(), qname.begin(), qname.end());
    append16(result, type);
    append16(result, 1);
    return result;
}

void record(Bytes& message, const Bytes& name, std::uint16_t type, const Bytes& data, std::uint16_t recordClass = 1) {
    message.insert(message.end(), name.begin(), name.end());
    append16(message, type);
    append16(message, recordClass);
    append32(message, 60);
    append16(message, static_cast<std::uint16_t>(data.size()));
    message.insert(message.end(), data.begin(), data.end());
}

Bytes answer(std::uint16_t type, const Bytes& data) {
    auto result = query(type);
    put16(result, 2, 0x8180);
    put16(result, 6, 1);
    record(result, {0xc0, 0x0c}, type, data);
    return result;
}

RawPacket dnsPacket(const Bytes& message, bool version6 = false, bool response = false, std::uint16_t port = 53) {
    auto transport = udp(message);
    put16(transport, 0, response ? port : 53000);
    put16(transport, 2, response ? 53000 : port);
    return raw(ethernet(version6 ? ipv6(17, transport) : ipv4(17, transport), version6 ? 0x86dd : 0x0800));
}

const Field& field(const PacketRecord& packet, const std::string& layer, const std::string& name) {
    const auto found = std::find_if(packet.fields.begin(), packet.fields.end(), [&](const auto& item) {
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
}

bool containsNotice(const PacketRecord& packet, const std::string& text) {
    return std::any_of(packet.notices.begin(), packet.notices.end(), [&](const auto& item) {
        return item.find(text) != std::string::npos;
    });
}

Bytes arp(std::uint16_t operation = 1) {
    Bytes result = {0, 1, 8, 0, 6, 4, 0, 0,
                    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 192, 0, 2, 1,
                    0, 0, 0, 0, 0, 0, 192, 0, 2, 2};
    put16(result, 6, operation);
    return result;
}
} // namespace

void runDnsArpTests(TestSuite& suite) {
    suite.run("DNS IPv4 UDP query exposes ID flags counts and question", [] {
        const auto packet = PacketParser::parse(dnsPacket(query()));
        CHECK(packet.has(Protocol::Dns) && packet.has(Protocol::Udp) && packet.has(Protocol::Ipv4));
        CHECK(packet.protocolName() == "DNS");
        CHECK(!packet.malformed && !packet.truncated);
        CHECK(field(packet, "DNS", "ID").value == "0x1234");
        CHECK(field(packet, "DNS", "Flags").value == "0x0100");
        CHECK(field(packet, "DNS", "QR").value == "0 (Query)");
        CHECK(field(packet, "DNS", "RD").value == "1");
        CHECK(field(packet, "DNS", "QDCOUNT").value == "1");
        CHECK(field(packet, "DNS", "ANCOUNT").value == "0");
        CHECK(field(packet, "DNS", "NSCOUNT").value == "0");
        CHECK(field(packet, "DNS", "ARCOUNT").value == "0");
        CHECK(field(packet, "DNS Question 1", "QNAME").value == "example.test.");
        CHECK(field(packet, "DNS Question 1", "QTYPE").value == "A (1)");
        CHECK(field(packet, "DNS Question 1", "QCLASS").value == "IN (1)");
        CHECK(field(packet, "DNS Question 1", "QNAME").offset == 54);
        CHECK(field(packet, "DNS Question 1", "QNAME").length == 14);
        CHECK(packet.summary.find("example.test.") != std::string::npos);
        checkBounds(packet);
    });
    suite.run("DNS compressed A response preserves address and source offsets", [] {
        const auto packet = PacketParser::parse(dnsPacket(answer(1, {203, 0, 113, 9}), false, true));
        CHECK(packet.has(Protocol::Dns));
        CHECK(field(packet, "DNS", "QR").value == "1 (Response)");
        CHECK(field(packet, "DNS", "ANCOUNT").value == "1");
        CHECK(field(packet, "DNS Answer 1", "NAME").value == "example.test.");
        CHECK(field(packet, "DNS Answer 1", "NAME").length == 2);
        CHECK(field(packet, "DNS Answer 1", "TYPE").value == "A (1)");
        CHECK(field(packet, "DNS Answer 1", "TTL").value == "60");
        CHECK(field(packet, "DNS Answer 1", "RDLENGTH").value == "4");
        CHECK(field(packet, "DNS Answer 1", "RDATA").value == "203.0.113.9");
        CHECK(field(packet, "DNS Answer 1", "RDATA").offset == 84);
        CHECK(packet.source.port == 53 && packet.destination.port == 53000);
        checkBounds(packet);
    });
    suite.run("DNS IPv6 UDP query and AAAA response", [] {
        const auto request = PacketParser::parse(dnsPacket(query(28), true));
        CHECK(request.has(Protocol::Dns) && request.has(Protocol::Ipv6));
        CHECK(field(request, "DNS Question 1", "QTYPE").value == "AAAA (28)");
        CHECK(field(request, "DNS Question 1", "QNAME").offset == 74);
        const Bytes address = {0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42};
        const auto response = PacketParser::parse(dnsPacket(answer(28, address), true, true));
        CHECK(response.has(Protocol::Dns) && response.has(Protocol::Ipv6));
        CHECK(field(response, "DNS Answer 1", "RDATA").value == "2001:db8::42");
        CHECK(field(response, "DNS Answer 1", "RDLENGTH").value == "16");
        checkBounds(request);
        checkBounds(response);
    });
    suite.run("DNS CNAME compression target can be reused by an A record", [] {
        auto message = query();
        put16(message, 2, 0x8180);
        put16(message, 6, 2);
        record(message, {0xc0, 0x0c}, 5, {5, 'a', 'l', 'i', 'a', 's', 0xc0, 0x0c});
        record(message, {0xc0, 0x2a}, 1, {192, 0, 2, 44});
        const auto packet = PacketParser::parse(dnsPacket(message, false, true));
        CHECK(packet.has(Protocol::Dns));
        CHECK(field(packet, "DNS Answer 1", "RDATA").value == "alias.example.test.");
        CHECK(field(packet, "DNS Answer 2", "NAME").value == "alias.example.test.");
        CHECK(field(packet, "DNS Answer 2", "RDATA").value == "192.0.2.44");
        checkBounds(packet);
    });
    suite.run("DNS authority additional and unknown record data remain visible", [] {
        auto message = query();
        put16(message, 2, 0x8180);
        put16(message, 8, 1);
        put16(message, 10, 1);
        record(message, {0xc0, 0x0c}, 2, {2, 'n', 's', 0xc0, 0x0c});
        record(message, {0}, 65000, {1, 2, 3});
        const auto packet = PacketParser::parse(dnsPacket(message, false, true));
        CHECK(packet.has(Protocol::Dns));
        CHECK(field(packet, "DNS", "NSCOUNT").value == "1");
        CHECK(field(packet, "DNS", "ARCOUNT").value == "1");
        CHECK(field(packet, "DNS Authority 1", "RDATA").value == "ns.example.test.");
        CHECK(field(packet, "DNS Additional 1", "TYPE").value == "65000");
        CHECK(field(packet, "DNS Additional 1", "RDLENGTH").value == "3");
        CHECK(field(packet, "DNS Additional 1", "RDATA").value == "原始 RDATA 3 字节");
        checkBounds(packet);
    });
    suite.run("DNS header-only error and TC status are represented", [] {
        const auto error = PacketParser::parse(dnsPacket(dnsHeader(0x8001, 0), false, true));
        CHECK(error.has(Protocol::Dns));
        CHECK(field(error, "DNS", "RCODE").value == "1");
        auto message = query();
        put16(message, 2, 0x8380);
        const auto truncated = PacketParser::parse(dnsPacket(message, false, true));
        CHECK(truncated.has(Protocol::Dns));
        CHECK(field(truncated, "DNS", "TC").value == "1");
        CHECK(containsNotice(truncated, "TC"));
        CHECK(!truncated.truncated);
    });
    suite.run("DNS common name-bearing resource records preserve their fields", [] {
        auto message = query();
        put16(message, 2, 0x8180);
        put16(message, 6, 4);
        record(message, {0xc0,0x0c}, 12, {0xc0,0x0c});
        record(message, {0xc0,0x0c}, 15, {0,10,0xc0,0x0c});
        Bytes soa = {0xc0,0x0c,0xc0,0x0c};
        for (const auto value : {42U,3600U,600U,86400U,60U}) append32(soa, value);
        record(message, {0xc0,0x0c}, 6, soa);
        record(message, {0xc0,0x0c}, 33, {0,1,0,2,0x1f,0x90,0xc0,0x0c});
        const auto packet = PacketParser::parse(dnsPacket(message, false, true));
        CHECK(packet.has(Protocol::Dns));
        CHECK(field(packet, "DNS Answer 1", "RDATA").value == "example.test.");
        CHECK(field(packet, "DNS Answer 2", "RDATA").value == "10 example.test.");
        CHECK(field(packet, "DNS Answer 3", "RDATA").value == "example.test. example.test. serial 42 refresh 3600 retry 600 expire 86400 minimum 60");
        CHECK(field(packet, "DNS Answer 4", "RDATA").value == "priority 1 weight 2 port 8080 example.test.");
        checkBounds(packet);
    });
    suite.run("DNS port selection includes source 53 and excludes other ports", [] {
        CHECK(PacketParser::parse(dnsPacket(answer(1, {192,0,2,1}), false, true)).has(Protocol::Dns));
        const auto other = PacketParser::parse(dnsPacket(query(), false, false, 9999));
        CHECK(other.has(Protocol::Udp));
        CHECK(!other.has(Protocol::Dns));
        CHECK(!other.malformed);
    });
    suite.run("DNS arbitrary UDP 53 bytes do not receive a DNS label", [] {
        for (const auto& message : {Bytes{'h','e','l','l','o'}, Bytes(12, 0), Bytes(20, 0xff)}) {
            const auto packet = PacketParser::parse(dnsPacket(message));
            CHECK(packet.has(Protocol::Udp));
            CHECK(!packet.has(Protocol::Dns));
            CHECK(containsNotice(packet, "DNS 候选"));
            checkBounds(packet);
        }
    });
    suite.run("DNS compression loops out-of-range and non-boundary pointers are rejected", [] {
        for (const auto& name : {Bytes{0xc0,0x0c}, Bytes{0xff,0xff}, Bytes{1,'a',0xc0,0x0c}}) {
            auto message = dnsHeader();
            message.insert(message.end(), name.begin(), name.end());
            append16(message, 1);
            append16(message, 1);
            const auto packet = PacketParser::parse(dnsPacket(message));
            CHECK(!packet.has(Protocol::Dns));
            CHECK(packet.malformed);
            CHECK(containsNotice(packet, "指针"));
            checkBounds(packet);
        }
        auto message = query();
        put16(message, 2, 0x8180);
        put16(message, 6, 1);
        record(message, {0xc0,0x0d}, 1, {192,0,2,1});
        const auto packet = PacketParser::parse(dnsPacket(message));
        CHECK(!packet.has(Protocol::Dns));
        CHECK(containsNotice(packet, "名称边界"));
    });
    suite.run("DNS forward pointer and incomplete pointer are rejected", [] {
        auto message = dnsHeader();
        message.insert(message.end(), {0xc0,0x12,0,1,0,1,1,'a',0});
        const auto forward = PacketParser::parse(dnsPacket(message));
        CHECK(!forward.has(Protocol::Dns) && forward.malformed);
        auto incomplete = dnsHeader();
        incomplete.push_back(0xc0);
        const auto packet = PacketParser::parse(dnsPacket(incomplete));
        CHECK(!packet.has(Protocol::Dns) && packet.malformed);
        CHECK(containsNotice(packet, "指针内容不足"));
    });
    suite.run("DNS compression pointer jump count is bounded", [] {
        for (const auto questions : {17, 18}) {
            auto message = dnsHeader(0x0100, static_cast<std::uint16_t>(questions));
            std::size_t previous = 12;
            message.insert(message.end(), {1, 'a', 0, 0, 1, 0, 1});
            for (int index = 1; index < questions; ++index) {
                const auto start = message.size();
                message.push_back(static_cast<std::uint8_t>(0xc0U | (previous >> 8U)));
                message.push_back(static_cast<std::uint8_t>(previous));
                append16(message, 1);
                append16(message, 1);
                previous = start;
            }
            const auto packet = PacketParser::parse(dnsPacket(message));
            CHECK(packet.has(Protocol::Dns) == (questions == 17));
            if (questions == 18) CHECK(containsNotice(packet, "16 次跳转"));
            checkBounds(packet);
        }
    });
    suite.run("DNS name and label size limits are enforced", [] {
        for (const auto lastLength : {61, 63}) {
            auto message = dnsHeader();
            const auto name = domain({std::string(63,'a'), std::string(63,'b'), std::string(63,'c'), std::string(static_cast<std::size_t>(lastLength),'d')});
            message.insert(message.end(), name.begin(), name.end());
            append16(message, 1);
            append16(message, 1);
            const auto packet = PacketParser::parse(dnsPacket(message));
            CHECK(packet.has(Protocol::Dns) == (lastLength == 61));
            if (lastLength == 63) CHECK(containsNotice(packet, "255 字节"));
            checkBounds(packet);
        }
        auto invalid = dnsHeader();
        invalid.insert(invalid.end(), {0x40,0,0,1,0,1});
        const auto packet = PacketParser::parse(dnsPacket(invalid));
        CHECK(!packet.has(Protocol::Dns));
        CHECK(containsNotice(packet, "标签类型"));
    });
    suite.run("DNS total record count is bounded", [] {
        auto message = dnsHeader(0x0100, 128);
        for (int index = 0; index < 128; ++index) message.insert(message.end(), {0,0,1,0,1});
        CHECK(PacketParser::parse(dnsPacket(message)).has(Protocol::Dns));
        const auto tooMany = PacketParser::parse(dnsPacket(dnsHeader(0x0100, 129)));
        CHECK(!tooMany.has(Protocol::Dns));
        CHECK(containsNotice(tooMany, "128 条"));
    });
    suite.run("DNS RDATA bounds and address lengths are validated", [] {
        for (const auto& message : {answer(1, {192,0,2}), answer(28, Bytes(15))}) {
            const auto packet = PacketParser::parse(dnsPacket(message));
            CHECK(!packet.has(Protocol::Dns) && packet.malformed);
            CHECK(containsNotice(packet, "RDLENGTH"));
            checkBounds(packet);
        }
        auto message = answer(1, {192,0,2,1});
        put16(message, 40, 1000);
        const auto packet = PacketParser::parse(dnsPacket(message));
        CHECK(!packet.has(Protocol::Dns) && packet.malformed);
        CHECK(containsNotice(packet, "RDATA 超出"));
    });
    suite.run("DNS CNAME encoded bytes remain inside RDATA", [] {
        auto message = query();
        put16(message, 2, 0x8180);
        put16(message, 6, 1);
        record(message, {0xc0,0x0c}, 5, {3,'a'});
        const auto packet = PacketParser::parse(dnsPacket(message));
        CHECK(!packet.has(Protocol::Dns) && packet.malformed);
        CHECK(containsNotice(packet, "标签内容不足"));
        checkBounds(packet);
    });
    suite.run("DNS reserved flags and undeclared tail are rejected", [] {
        auto message = query();
        put16(message, 2, 0x0140);
        auto packet = PacketParser::parse(dnsPacket(message));
        CHECK(!packet.has(Protocol::Dns));
        CHECK(containsNotice(packet, "保留标志位"));
        message = query();
        message.push_back(0);
        packet = PacketParser::parse(dnsPacket(message));
        CHECK(!packet.has(Protocol::Dns));
        CHECK(containsNotice(packet, "未声明的数据"));
    });
    suite.run("DNS captured truncation is visible at every prefix", [] {
        const auto full = dnsPacket(answer(1, {192,0,2,1}));
        for (std::size_t length = 0; length < full.bytes.size(); ++length) {
            auto input = full;
            input.bytes.resize(length);
            const auto packet = PacketParser::parse(input);
            CHECK(packet.truncated);
            CHECK(!packet.has(Protocol::Dns));
            checkBounds(packet);
        }
    });
    suite.run("DNS malformed deterministic corpus stays within packet bounds", [] {
        std::uint32_t state = 0x1a2b3c4dU;
        for (std::size_t index = 0; index < 1000; ++index) {
            state = state * 1664525U + 1013904223U;
            Bytes message(12 + state % 200);
            for (auto& byte : message) { state = state * 1664525U + 1013904223U; byte = static_cast<std::uint8_t>(state >> 24U); }
            message[2] = 1;
            message[3] = 0;
            put16(message, 4, 1);
            put16(message, 6, 0);
            put16(message, 8, 0);
            put16(message, 10, 0);
            checkBounds(PacketParser::parse(dnsPacket(message, index % 2 == 0)));
        }
    });
    suite.run("ARP request exposes addresses and fixed header fields", [] {
        const auto packet = PacketParser::parse(raw(ethernet(arp(), 0x0806)));
        CHECK(packet.has(Protocol::Arp));
        CHECK(packet.protocolName() == "ARP");
        CHECK(!packet.has(Protocol::Ipv4));
        CHECK(!packet.hasPorts && !packet.hasTcp && !packet.malformed && !packet.truncated);
        CHECK(packet.source.text == "192.0.2.1" && packet.destination.text == "192.0.2.2");
        CHECK(field(packet, "ARP", "HTYPE").value == "1");
        CHECK(field(packet, "ARP", "PTYPE").value == "0x0800");
        CHECK(field(packet, "ARP", "HLEN").value == "6");
        CHECK(field(packet, "ARP", "PLEN").value == "4");
        CHECK(field(packet, "ARP", "Opcode").value == "1");
        CHECK(field(packet, "ARP", "Sender MAC").value == "aa:bb:cc:dd:ee:ff");
        CHECK(field(packet, "ARP", "Sender IP").value == "192.0.2.1");
        CHECK(field(packet, "ARP", "Target MAC").value == "00:00:00:00:00:00");
        CHECK(field(packet, "ARP", "Target IP").value == "192.0.2.2");
        CHECK(field(packet, "ARP", "Sender IP").offset == 28);
        CHECK(field(packet, "ARP", "Target IP").offset == 38);
        CHECK(packet.summary.find("ARP 请求") != std::string::npos);
        checkBounds(packet);
    });
    suite.run("ARP response summarizes the sender hardware mapping", [] {
        auto message = arp(2);
        message[17] = 2;
        message[27] = 1;
        const auto packet = PacketParser::parse(raw(ethernet(message, 0x0806)));
        CHECK(packet.has(Protocol::Arp));
        CHECK(field(packet, "ARP", "Opcode").value == "2");
        CHECK(packet.source.text == "192.0.2.2" && packet.destination.text == "192.0.2.1");
        CHECK(packet.summary.find("aa:bb:cc:dd:ee:ff") != std::string::npos);
        CHECK(packet.summary.find("ARP 响应") != std::string::npos);
        checkBounds(packet);
    });
    suite.run("ARP capture truncation does not read incomplete addresses", [] {
        const auto full = raw(ethernet(arp(), 0x0806));
        for (std::size_t length = 0; length < full.bytes.size(); ++length) {
            auto input = full;
            input.bytes.resize(length);
            const auto packet = PacketParser::parse(input);
            CHECK(packet.truncated);
            if (length >= 14) CHECK(packet.has(Protocol::Arp));
            checkBounds(packet);
        }
    });
    suite.run("ARP invalid address lengths and unsupported formats are explicit", [] {
        for (const auto length : {0,5,255}) {
            auto message = arp();
            message[4] = static_cast<std::uint8_t>(length);
            const auto packet = PacketParser::parse(raw(ethernet(message, 0x0806)));
            CHECK(packet.has(Protocol::Arp) && packet.malformed);
            CHECK(packet.source.text == "aa:bb:cc:dd:ee:ff");
            CHECK(containsNotice(packet, "地址长度"));
            checkBounds(packet);
        }
        auto message = arp();
        put16(message, 0, 2);
        const auto packet = PacketParser::parse(raw(ethernet(message, 0x0806)));
        CHECK(packet.has(Protocol::Arp) && !packet.malformed);
        CHECK(containsNotice(packet, "尚未支持"));
        CHECK(field(packet, "ARP", "HTYPE").value == "2");
        checkBounds(packet);
    });
    suite.run("ARP unknown opcode and Ethernet padding keep known fields", [] {
        auto bytes = ethernet(arp(9), 0x0806);
        bytes.insert(bytes.end(), 18, 0xee);
        const auto packet = PacketParser::parse(raw(bytes));
        CHECK(packet.has(Protocol::Arp));
        CHECK(packet.source.text == "192.0.2.1");
        CHECK(field(packet, "ARP", "Opcode").value == "9");
        CHECK(containsNotice(packet, "操作码"));
        CHECK(packet.payloadLength == 0);
        checkBounds(packet);
    });
}
