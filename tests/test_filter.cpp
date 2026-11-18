#include "TestSupport.h"
#include "core/FilterParser.h"

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
            {"ipv4", Protocol::Ipv4}, {"ipv6", Protocol::Ipv6}, {"icmp", Protocol::Icmp}, {"icmp6", Protocol::Icmp6}
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
}
