#include "TestSupport.h"
#include "core/FilterParser.h"
#include <arpa/inet.h>

namespace {
using namespace sniffer;
Filter compile(const std::string& expression) {
    FilterError error;
    auto result = FilterParser::compile(expression, error);
    if (!result) throw std::runtime_error("Compile failed at " + std::to_string(error.position) + ": " + error.message);
    return *result;
}
PacketRecord packet(std::initializer_list<Protocol> protocols) {
    PacketRecord result;
    for (const auto protocol : protocols) result.add(protocol);
    return result;
}
}

void runFilterTests(TestSuite& suite) {
    suite.run("filter empty expressions accept all packets", [] {
        CHECK(compile("").matches(packet({})));
        CHECK(compile(" \t\n").matches(packet({Protocol::Ipv4, Protocol::Tcp})));
        CHECK(Filter().matches(packet({})));
    });
    suite.run("filter every protocol primitive", [] {
        const std::pair<const char*, Protocol> values[] = {
            {"http", Protocol::Http}, {"tcp", Protocol::Tcp}, {"udp", Protocol::Udp},
            {"ipv4", Protocol::Ipv4}, {"ipv6", Protocol::Ipv6}, {"icmp", Protocol::Icmp}, {"icmp6", Protocol::Icmp6},
            {"dns", Protocol::Dns}, {"arp", Protocol::Arp}
        };
        for (const auto& item : values) {
            const auto filter = compile(item.first);
            CHECK(filter.matches(packet({item.second})));
            CHECK(!filter.matches(packet({})));
        }
        CHECK(!compile("icmp").matches(packet({Protocol::Icmp6})));
        CHECK(!compile("icmp6").matches(packet({Protocol::Icmp})));
    });
    suite.run("filter case normalization and overlapping protocol tags", [] {
        const auto filter = compile("HTTP AnD TCP and IPv4");
        CHECK(filter.expression() == "http and tcp and ipv4");
        CHECK(filter.matches(packet({Protocol::Http, Protocol::Tcp, Protocol::Ipv4})));
        CHECK(!filter.matches(packet({Protocol::Http, Protocol::Tcp, Protocol::Ipv6})));
    });
    suite.run("filter operator precedence and parentheses", [] {
        const auto normal = compile("tcp or udp and ipv6");
        const auto grouped = compile("(tcp or udp) and ipv6");
        CHECK(normal.matches(packet({Protocol::Tcp, Protocol::Ipv4})));
        CHECK(!grouped.matches(packet({Protocol::Tcp, Protocol::Ipv4})));
        CHECK(normal.matches(packet({Protocol::Udp, Protocol::Ipv6})));
        CHECK(!normal.matches(packet({Protocol::Udp, Protocol::Ipv4})));
        CHECK(compile("not tcp and ipv6").matches(packet({Protocol::Udp, Protocol::Ipv6})));
        CHECK(!compile("not tcp and ipv6").matches(packet({Protocol::Udp, Protocol::Ipv4})));
        CHECK(compile("not not tcp").matches(packet({Protocol::Tcp})));
    });
    suite.run("filter task expressions", [] {
        CHECK(compile("tcp and ipv4").matches(packet({Protocol::Tcp, Protocol::Ipv4})));
        CHECK(compile("udp or icmp").matches(packet({Protocol::Icmp, Protocol::Ipv4})));
        CHECK(compile("ipv6 and (tcp or icmp6)").matches(packet({Protocol::Icmp6, Protocol::Ipv6})));
        CHECK(compile("http and not ipv6").matches(packet({Protocol::Http, Protocol::Tcp, Protocol::Ipv4})));
        CHECK(compile("not (tcp or udp)").matches(packet({Protocol::Icmp})));
        CHECK(!compile("not (tcp or udp)").matches(packet({Protocol::Udp})));
    });
    suite.run("filter expression result over complete protocol bit domain", [] {
        const auto filter = compile("(tcp or udp) and not ipv6 or http");
        for (std::uint32_t bits = 0; bits < 128; ++bits) {
            PacketRecord sample;
            sample.protocols = bits;
            const bool expected = (((bits & 4U) != 0 || (bits & 8U) != 0) && (bits & 2U) == 0) || (bits & 64U) != 0;
            CHECK(filter.matches(sample) == expected);
        }
    });
    suite.run("filter errors include exact input position", [] {
        const std::pair<const char*, std::size_t> cases[] = {
            {"tcp and", 7}, {"tcp udp", 4}, {"tcp && udp", 4},
            {"(tcp", 4}, {"tcp)", 3}, {"()", 1}, {"icmp7", 0},
            {"tcp and (udp or )", 16}, {"not", 3}
        };
        for (const auto& test : cases) {
            FilterError error;
            CHECK(!FilterParser::compile(test.first, error));
            CHECK(error.position == test.second);
            CHECK(!error.message.empty());
        }
    });
    suite.run("filter length and parenthesis depth boundaries", [] {
        CHECK(compile(std::string(256, ' ')).matches(packet({})));
        FilterError error;
        CHECK(!FilterParser::compile(std::string(257, ' '), error));
        CHECK(error.position == 256);
        CHECK(compile(std::string(16, '(') + "tcp" + std::string(16, ')')).matches(packet({Protocol::Tcp})));
        CHECK(!FilterParser::compile(std::string(17, '(') + "tcp" + std::string(17, ')'), error));
        CHECK(error.position == 16);
    });
    suite.run("filter unsuccessful compilation preserves an existing filter", [] {
        auto active = compile("tcp");
        FilterError error;
        const auto candidate = FilterParser::compile("udp and", error);
        if (candidate) active = *candidate;
        CHECK(active.matches(packet({Protocol::Tcp})));
        CHECK(!active.matches(packet({Protocol::Udp})));
    });
    suite.run("filter IPv4 address and direction use binary addresses", [] {
        auto sample = packet({Protocol::Ipv4, Protocol::Tcp});
        sample.source.family = sample.destination.family = 4;
        CHECK(inet_pton(AF_INET, "192.0.2.7", sample.source.address.data()) == 1);
        CHECK(inet_pton(AF_INET, "198.51.100.20", sample.destination.address.data()) == 1);
        CHECK(compile("ip.addr == 192.0.2.7").matches(sample));
        CHECK(compile("ip.addr==198.51.100.20").matches(sample));
        CHECK(compile("ip.src == 192.0.2.7 and ip.dst == 198.51.100.20").matches(sample));
        CHECK(!compile("ip.src == 198.51.100.20").matches(sample));
        CHECK(!compile("ip.dst == 192.0.2.7").matches(sample));
        CHECK(!compile("ip.addr == 192.0.2.70").matches(sample));
    });
    suite.run("filter IPv6 equivalent address spelling", [] {
        auto sample = packet({Protocol::Ipv6, Protocol::Udp});
        sample.source.family = sample.destination.family = 6;
        CHECK(inet_pton(AF_INET6, "2001:db8::a", sample.source.address.data()) == 1);
        CHECK(inet_pton(AF_INET6, "::1", sample.destination.address.data()) == 1);
        CHECK(compile("ip.src==2001:0DB8:0:0:0:0:0:A").matches(sample));
        CHECK(compile("ip.dst==::1").matches(sample));
        CHECK(!compile("ip.addr==0.0.0.0").matches(sample));
        CHECK(!compile("ip.src==::1").matches(sample));
    });
    suite.run("filter IP conditions require a captured IP layer", [] {
        auto sample = packet({Protocol::Arp});
        sample.source.family = 4;
        CHECK(inet_pton(AF_INET, "192.0.2.7", sample.source.address.data()) == 1);
        CHECK(!compile("ip.addr==192.0.2.7").matches(sample));
        CHECK(compile("arp and not ip.addr==192.0.2.7").matches(sample));
    });
    suite.run("filter TCP port and direction", [] {
        auto sample = packet({Protocol::Ipv4, Protocol::Tcp, Protocol::Http});
        sample.hasPorts = true;
        sample.source.port = 49152;
        sample.destination.port = 8080;
        CHECK(compile("http and tcp.port == 8080").matches(sample));
        CHECK(compile("tcp.port==49152").matches(sample));
        CHECK(compile("tcp.srcport == 49152 and tcp.dstport == 8080").matches(sample));
        CHECK(!compile("tcp.srcport == 8080").matches(sample));
        CHECK(!compile("tcp.dstport == 49152").matches(sample));
        CHECK(!compile("udp.port == 8080").matches(sample));
    });
    suite.run("filter UDP ports and protocol precedence", [] {
        auto sample = packet({Protocol::Ipv6, Protocol::Udp, Protocol::Dns});
        sample.hasPorts = true;
        sample.source.port = 53;
        sample.destination.port = 65535;
        CHECK(compile("dns and udp.srcport==53 and udp.dstport==65535").matches(sample));
        CHECK(compile("udp.port==53 or tcp.port==80 and ipv4").matches(sample));
        CHECK(!compile("(udp.port==53 or tcp.port==80) and ipv4").matches(sample));
        CHECK(!compile("tcp.port==53").matches(sample));
        CHECK(!compile("udp.dstport==53").matches(sample));
    });
    suite.run("filter port bounds and incomplete headers", [] {
        auto sample = packet({Protocol::Udp});
        sample.source.port = 0;
        sample.destination.port = 65535;
        CHECK(!compile("udp.port==0").matches(sample));
        sample.hasPorts = true;
        CHECK(compile("udp.port==0").matches(sample));
        CHECK(compile("udp.port==65535").matches(sample));
        CHECK(compile("udp.port==00000").matches(sample));
    });
    suite.run("filter malformed address and port values are rejected", [] {
        const char* cases[] = {"ip.addr == example.test", "ip.addr==192.0.2.999", "ip.addr==1.2.3", "ip.addr==2001:::1",
            "ip.addr==192.0.2.1/24", "ip.addr==::1%lo0", "tcp.port==65536", "udp.port==99999999999999999999999",
            "tcp.port==-1", "tcp.port==+80", "tcp.port==80.0", "udp.port==http", "tcp.port==", "ip.addr==",
            "ip.addr=127.0.0.1", "tcp.port===80", "tcp.port!=80", "tcp.port==80 443", "ip.foo==127.0.0.1"};
        for (const auto* expression : cases) {
            FilterError error;
            CHECK(!FilterParser::compile(expression, error));
            CHECK(!error.message.empty());
        }
    });
    suite.run("filter comparison errors retain exact token positions", [] {
        const std::pair<const char*, std::size_t> cases[] = {
            {"tcp.port 80", 9}, {"tcp.port==", 10}, {"tcp.port==65536", 10}, {"ip.addr==bad", 9}
        };
        for (const auto& test : cases) {
            FilterError error;
            CHECK(!FilterParser::compile(test.first, error));
            CHECK(error.position == test.second);
        }
    });
}
