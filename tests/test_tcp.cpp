#include "TestSupport.h"
#include "core/TcpTracker.h"

#include <algorithm>
#include <string>

using namespace sniffer;
namespace {
Endpoint client() {
    Endpoint result;
    result.family = 4;
    result.address[0] = 10;
    result.address[3] = 1;
    result.port = 50000;
    result.text = "10.0.0.1";
    return result;
}
Endpoint server() {
    auto result = client();
    result.address[3] = 2;
    result.port = 8080;
    result.text = "10.0.0.2";
    return result;
}
PacketRecord packet(std::uint64_t id, std::uint32_t sequence, std::uint8_t flags,
                    const std::string& payload = "", bool reverse = false, std::uint32_t acknowledgement = 0) {
    PacketRecord result;
    result.raw.id = id;
    result.raw.bytes = Bytes(payload.begin(), payload.end());
    result.raw.wireLength = static_cast<std::uint32_t>(payload.size());
    result.source = reverse ? server() : client();
    result.destination = reverse ? client() : server();
    result.hasPorts = true;
    result.hasTcp = true;
    result.add(Protocol::Ipv4);
    result.add(Protocol::Tcp);
    result.tcp.sequence = sequence;
    result.tcp.acknowledgement = acknowledgement;
    result.tcp.flags = flags;
    result.payloadLength = payload.size();
    return result;
}
std::uint64_t handshake(TcpTracker& tracker, std::uint32_t sequence = 100) {
    auto first = packet(1, sequence, 0x02);
    auto second = packet(2, 500, 0x12, "", true, sequence + 1);
    auto third = packet(3, sequence + 1, 0x10, "", false, 501);
    const auto id = tracker.ingest(first).connectionId;
    CHECK(tracker.ingest(second).connectionId == id);
    CHECK(tracker.ingest(third).connectionId == id);
    return id;
}
std::string dataOf(const StreamDirection& direction) {
    std::string result;
    for (const auto& block : direction.blocks) result.append(block.data.begin(), block.data.end());
    return result;
}
}

void runTcpTests(TestSuite& suite) {
    suite.run("TCP handshake and both directions share one connection", [] {
        TcpTracker tracker;
        const auto id = handshake(tracker);
        auto outbound = packet(4, 101, 0x18, "request");
        auto inbound = packet(5, 501, 0x18, "response", true);
        CHECK(tracker.ingest(outbound).connectionId == id);
        CHECK(tracker.ingest(inbound).connectionId == id);
        const auto trace = tracker.trace(id);
        CHECK(trace.has_value());
        CHECK(dataOf(trace->directions[0]) == "request");
        CHECK(dataOf(trace->directions[1]) == "response");
        CHECK(trace->connection.packetIds.size() == 5);
        CHECK(!trace->connection.midstream);
    });
    suite.run("TCP out of order segments produce sequence ordered content", [] {
        TcpTracker tracker;
        const auto id = handshake(tracker);
        auto later = packet(4, 106, 0x18, "world");
        auto earlier = packet(5, 101, 0x18, "Hello");
        tracker.ingest(later);
        tracker.ingest(earlier);
        const auto trace = tracker.trace(id);
        CHECK(dataOf(trace->directions[0]) == "Helloworld");
        CHECK(trace->directions[0].uniqueBytes == 10);
        CHECK(trace->directions[0].blocks.size() == 1);
    });
    suite.run("TCP full and partial retransmissions preserve one copy", [] {
        TcpTracker tracker;
        const auto id = handshake(tracker);
        auto first = packet(4, 101, 0x18, "abcdef");
        auto duplicate = packet(5, 101, 0x18, "abcdef");
        auto partial = packet(6, 104, 0x18, "defghi");
        tracker.ingest(first); tracker.ingest(duplicate); tracker.ingest(partial);
        const auto trace = tracker.trace(id);
        CHECK(dataOf(trace->directions[0]) == "abcdefghi");
        CHECK(trace->directions[0].conflicts.empty());
    });
    suite.run("TCP overlapping conflicts preserve earliest captured bytes", [] {
        TcpTracker tracker;
        const auto id = handshake(tracker);
        auto first = packet(4, 101, 0x18, "abcdef");
        auto conflict = packet(5, 104, 0x18, "XYZghi");
        tracker.ingest(first); tracker.ingest(conflict);
        const auto trace = tracker.trace(id);
        CHECK(dataOf(trace->directions[0]) == "abcdefghi");
        CHECK(trace->directions[0].conflicts.size() == 1);
        CHECK(trace->directions[0].conflicts[0].offset == 3);
        CHECK(trace->directions[0].conflicts[0].length == 3);
    });
    suite.run("TCP missing sequence ranges are represented as sparse gaps", [] {
        TcpTracker tracker;
        const auto id = handshake(tracker);
        auto first = packet(4, 101, 0x18, "abc");
        auto distant = packet(5, 1000000101U, 0x18, "xyz");
        tracker.ingest(first); tracker.ingest(distant);
        const auto trace = tracker.trace(id);
        CHECK(trace->directions[0].uniqueBytes == 6);
        CHECK(trace->directions[0].blocks.size() == 3);
        CHECK(trace->directions[0].blocks[1].gapLength == 999999997U);
        CHECK(trace->directions[0].blocks[1].data.empty());
    });
    suite.run("TCP SYN retransmission and new initial sequence distinguish connections", [] {
        TcpTracker tracker;
        auto first = packet(1, 100, 0x02);
        auto repeated = packet(2, 100, 0x02);
        auto next = packet(3, 1000, 0x02);
        CHECK(tracker.ingest(first).connectionId == 1);
        CHECK(tracker.ingest(repeated).connectionId == 1);
        CHECK(tracker.ingest(next).connectionId == 2);
        CHECK(tracker.connectionCount() == 2);
    });
    suite.run("TCP sequence number wraps once", [] {
        TcpTracker tracker;
        const auto id = handshake(tracker, 0xfffffffcU);
        auto before = packet(4, 0xfffffffdU, 0x18, "ABC");
        auto after = packet(5, 0U, 0x18, "DEF");
        tracker.ingest(after); tracker.ingest(before);
        CHECK(dataOf(tracker.trace(id)->directions[0]) == "ABCDEF");
    });
    suite.run("TCP payload carried with SYN starts after control sequence", [] {
        TcpTracker tracker;
        auto first = packet(1, 100, 0x02, "abc");
        auto second = packet(2, 104, 0x18, "def");
        const auto id = tracker.ingest(first).connectionId;
        tracker.ingest(second);
        CHECK(dataOf(tracker.trace(id)->directions[0]) == "abcdef");
        CHECK(tracker.trace(id)->directions[0].blocks[0].offset == 0);
    });
    suite.run("TCP midstream capture records incomplete origin", [] {
        TcpTracker tracker;
        auto later = packet(1, 1005, 0x18, "world");
        auto earlier = packet(2, 1000, 0x18, "Hello");
        const auto id = tracker.ingest(later).connectionId;
        tracker.ingest(earlier);
        const auto trace = tracker.trace(id);
        CHECK(trace->connection.midstream);
        CHECK(trace->connection.boundaryUncertain);
        CHECK(trace->directions[0].startIncomplete);
        CHECK(dataOf(trace->directions[0]) == "Helloworld");
    });
    suite.run("TCP HTTP header across segments updates previous payload packet IDs", [] {
        TcpTracker tracker;
        const auto id = handshake(tracker);
        const std::string begin = "GET / HTTP/1.1\r\nHo";
        const std::string end = "st: localhost:8080\r\n\r\n";
        auto first = packet(4, 101, 0x18, begin);
        auto second = packet(5, 101 + static_cast<std::uint32_t>(begin.size()), 0x18, end);
        CHECK(tracker.ingest(first).httpPacketIds.empty());
        const auto update = tracker.ingest(second);
        CHECK(update.httpPacketIds == (std::vector<std::uint64_t>{4, 5}));
        CHECK(second.has(Protocol::Http));
        const auto* connection = tracker.connection(id);
        CHECK(connection->http);
        CHECK(connection->httpMessages[0]->method == "GET");
        CHECK(connection->httpSourcePacketIds[0] == (std::vector<std::uint64_t>{4, 5}));
    });
    suite.run("TCP HTTP recognition waits for missing initial bytes", [] {
        TcpTracker tracker;
        const auto id = handshake(tracker);
        const std::string begin = "GET / HTTP/1.1\r\n";
        auto tail = packet(4, 101 + static_cast<std::uint32_t>(begin.size()), 0x18, "Host: local\r\n\r\n");
        CHECK(tracker.ingest(tail).httpPacketIds.empty());
        auto head = packet(5, 101, 0x18, begin);
        CHECK(tracker.ingest(head).httpPacketIds.size() == 2);
        CHECK(tracker.connection(id)->http);
    });
    suite.run("TCP request and response headers are stored independently", [] {
        TcpTracker tracker;
        const auto id = handshake(tracker);
        auto request = packet(4, 101, 0x18, "GET / HTTP/1.1\r\n\r\n");
        auto response = packet(5, 501, 0x18, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK", true);
        tracker.ingest(request); tracker.ingest(response);
        const auto* connection = tracker.connection(id);
        CHECK(connection->httpMessages[0]->method == "GET");
        CHECK(connection->httpMessages[1]->statusCode == 200);
        CHECK(response.has(Protocol::Http));
    });
    suite.run("TCP HTTP source IDs only include header contributing packets", [] {
        TcpTracker tracker;
        const auto id = handshake(tracker);
        const std::string head = "GET / HTTP/1.1\r\nContent-Length: 4\r\n\r\n";
        auto body = packet(4, 101 + static_cast<std::uint32_t>(head.size()), 0x18, "body");
        auto header = packet(5, 101, 0x18, head);
        tracker.ingest(body); tracker.ingest(header);
        CHECK(tracker.connection(id)->httpSourcePacketIds[0] == (std::vector<std::uint64_t>{5}));
    });
    suite.run("TCP both FIN flags and RST provide closing evidence", [] {
        TcpTracker tracker;
        const auto id = handshake(tracker);
        auto firstFin = packet(4, 101, 0x11);
        auto secondFin = packet(5, 501, 0x11, "", true);
        tracker.ingest(firstFin);
        CHECK(!tracker.connection(id)->closed);
        tracker.ingest(secondFin);
        CHECK(tracker.connection(id)->closed);
        auto newSyn = packet(6, 2000, 0x02);
        const auto secondId = tracker.ingest(newSyn).connectionId;
        auto reset = packet(7, 2001, 0x14);
        tracker.ingest(reset);
        CHECK(tracker.connection(secondId)->closed);
        CHECK(tracker.connection(secondId)->reset);
    });
    suite.run("TCP payload retransmission after FIN remains associated", [] {
        TcpTracker tracker;
        const auto id = handshake(tracker);
        auto data = packet(4, 101, 0x19, "abc");
        auto serverFin = packet(5, 501, 0x11, "", true);
        tracker.ingest(data); tracker.ingest(serverFin);
        auto retransmission = packet(6, 101, 0x19, "abc");
        CHECK(tracker.ingest(retransmission).connectionId == id);
        CHECK(tracker.connectionCount() == 1);
        CHECK(dataOf(tracker.trace(id)->directions[0]) == "abc");
    });
    suite.run("TCP content generation obeys the requested and absolute limits", [] {
        TcpTracker tracker;
        const auto id = handshake(tracker);
        auto data = packet(4, 101, 0x18, std::string(1024U * 1024U + 20U, 'x'));
        tracker.ingest(data);
        const auto shortTrace = tracker.trace(id, 7);
        CHECK(shortTrace->directions[0].uniqueBytes == 7);
        CHECK(shortTrace->directions[0].truncated);
        const auto fullTrace = tracker.trace(id, 4U * 1024U * 1024U);
        CHECK(fullTrace->directions[0].uniqueBytes == 1024U * 1024U);
        CHECK(fullTrace->directions[0].truncated);
    });
    suite.run("TCP invalid and fragmented packets do not create connections", [] {
        TcpTracker tracker;
        auto fragment = packet(1, 101, 0x18, "abc");
        fragment.fragmented = true;
        CHECK(tracker.ingest(fragment).connectionId == 0);
        auto malformed = packet(2, 101, 0x18, "abc");
        malformed.malformed = true;
        CHECK(tracker.ingest(malformed).connectionId == 0);
        CHECK(tracker.connectionCount() == 0);
    });
    suite.run("TCP excessive sequence span reports a bounded result", [] {
        TcpTracker tracker;
        const auto id = handshake(tracker);
        auto first = packet(4, 101, 0x18, "abc");
        auto distant = packet(5, 0x80000065U, 0x18, "xyz");
        tracker.ingest(first); tracker.ingest(distant);
        CHECK(!distant.notices.empty());
        const auto trace = tracker.trace(id);
        CHECK(trace->directions[0].truncated);
        CHECK(trace->directions[0].uniqueBytes == 3);
    });
    suite.run("TCP capture truncation is visible in the content state", [] {
        TcpTracker tracker;
        const auto id = handshake(tracker);
        auto data = packet(4, 101, 0x18, "abc");
        data.truncated = true;
        tracker.ingest(data);
        CHECK(tracker.trace(id)->directions[0].truncated);
    });
    suite.run("TCP clear resets all connection identities", [] {
        TcpTracker tracker;
        handshake(tracker);
        tracker.clear();
        CHECK(tracker.connectionCount() == 0);
        CHECK(!tracker.trace(1).has_value());
        CHECK(tracker.connection(1) == nullptr);
        CHECK(handshake(tracker) == 1);
    });
    suite.run("TCP FIN proves the exact trailing gap", [] {
        TcpTracker tracker;
        const auto id = handshake(tracker);
        auto data = packet(4, 101, 0x18, "abc");
        auto fin = packet(5, 111, 0x11);
        tracker.ingest(data); tracker.ingest(fin);
        const auto trace = tracker.trace(id);
        CHECK(trace->directions[0].uniqueBytes == 3);
        CHECK(trace->directions[0].blocks.size() == 2);
        CHECK(trace->directions[0].blocks[1].offset == 3);
        CHECK(trace->directions[0].blocks[1].gapLength == 7);
        CHECK(trace->directions[0].blocks[1].data.empty());
        CHECK(trace->directions[0].status.find("存在缺口") != std::string::npos);
        auto delayed = packet(6, 104, 0x18, "defghij");
        tracker.ingest(delayed);
        const auto complete = tracker.trace(id);
        CHECK(dataOf(complete->directions[0]) == "abcdefghij");
        CHECK(complete->directions[0].blocks.size() == 1);
        CHECK(complete->directions[0].status == "展示范围连续");
    });
    suite.run("TCP FIN gap remains sparse when payload is absent", [] {
        TcpTracker tracker;
        const auto id = handshake(tracker);
        auto fin = packet(4, 1000000101U, 0x11);
        tracker.ingest(fin);
        const auto trace = tracker.trace(id);
        CHECK(trace->directions[0].uniqueBytes == 0);
        CHECK(trace->directions[0].blocks.size() == 1);
        CHECK(trace->directions[0].blocks[0].offset == 0);
        CHECK(trace->directions[0].blocks[0].gapLength == 1000000000U);
        CHECK(trace->directions[0].blocks[0].data.empty());
    });
    suite.run("TCP display limit does not convert captured bytes into a FIN gap", [] {
        TcpTracker tracker;
        const auto id = handshake(tracker);
        auto data = packet(4, 101, 0x18, "abcdefghij");
        auto fin = packet(5, 111, 0x11);
        tracker.ingest(data); tracker.ingest(fin);
        const auto trace = tracker.trace(id, 3);
        CHECK(trace->directions[0].uniqueBytes == 3);
        CHECK(trace->directions[0].truncated);
        CHECK(trace->directions[0].blocks.size() == 1);
        CHECK(trace->directions[0].blocks[0].gapLength == 0);
    });
    suite.run("TCP FIN payload and sequence wrap preserve terminal offsets", [] {
        TcpTracker tracker;
        const auto id = handshake(tracker, 0xfffffffcU);
        auto data = packet(4, 0xfffffffdU, 0x18, "ABC");
        auto fin = packet(5, 4, 0x11);
        tracker.ingest(data); tracker.ingest(fin);
        const auto trace = tracker.trace(id);
        CHECK(trace->directions[0].blocks.size() == 2);
        CHECK(trace->directions[0].blocks[1].offset == 3);
        CHECK(trace->directions[0].blocks[1].gapLength == 4);
        TcpTracker withPayload;
        const auto payloadId = handshake(withPayload);
        auto payloadFin = packet(4, 101, 0x19, "abc");
        withPayload.ingest(payloadFin);
        CHECK(withPayload.trace(payloadId)->directions[0].blocks.size() == 1);
        CHECK(dataOf(withPayload.trace(payloadId)->directions[0]) == "abc");
    });
    suite.run("TCP oversized HTTP candidate produces a specific notice", [] {
        TcpTracker tracker;
        const auto id = handshake(tracker);
        auto large = packet(4, 101, 0x18, "GET / HTTP/1.1\r\nX-Large: " + std::string(20000, 'x'));
        tracker.ingest(large);
        CHECK(large.notices == (std::vector<std::string>{"HTTP 头部超过 16 KiB 识别上限。"}));
        CHECK(!tracker.connection(id)->http);
        CHECK(!large.has(Protocol::Http));
        TcpTracker binaryTracker;
        handshake(binaryTracker);
        auto binary = packet(4, 101, 0x18, std::string(20000, '\0'));
        binaryTracker.ingest(binary);
        CHECK(binary.notices.empty());
        TcpTracker textTracker;
        handshake(textTracker);
        auto ordinary = packet(4, 101, 0x18, std::string(20000, 'x'));
        textTracker.ingest(ordinary);
        CHECK(ordinary.notices.empty());
    });
    suite.run("TCP delayed historical SYN ACK preserves the active connection", [] {
        TcpTracker tracker;
        const auto oldId = handshake(tracker);
        auto oldClientFin = packet(4, 101, 0x11);
        auto oldServerFin = packet(5, 501, 0x11, "", true);
        tracker.ingest(oldClientFin); tracker.ingest(oldServerFin);
        CHECK(tracker.connection(oldId)->closed);
        auto nextSyn = packet(6, 1000, 0x02);
        const auto newId = tracker.ingest(nextSyn).connectionId;
        CHECK(newId != oldId);
        auto delayed = packet(7, 500, 0x12, "", true, 101);
        CHECK(tracker.ingest(delayed).connectionId == oldId);
        CHECK(tracker.connection(oldId)->closed);
        CHECK(tracker.connectionCount() == 2);
        auto currentSynAck = packet(8, 9000, 0x12, "", true, 1001);
        CHECK(tracker.ingest(currentSynAck).connectionId == newId);
        auto response = packet(9, 9001, 0x18, "current", true, 1001);
        CHECK(tracker.ingest(response).connectionId == newId);
        CHECK(tracker.connectionCount() == 2);
        CHECK(dataOf(tracker.trace(newId)->directions[1]) == "current");
        CHECK(!tracker.trace(newId)->directions[1].startIncomplete);
        CHECK(tracker.connection(oldId)->packetIds.back() == 7);
    });
    suite.run("TCP SYN ACK can acknowledge payload carried with SYN", [] {
        TcpTracker tracker;
        auto syn = packet(1, 100, 0x02, "abc");
        const auto id = tracker.ingest(syn).connectionId;
        auto synAck = packet(2, 500, 0x12, "", true, 104);
        CHECK(tracker.ingest(synAck).connectionId == id);
        CHECK(tracker.connectionCount() == 1);
        CHECK(dataOf(tracker.trace(id)->directions[0]) == "abc");
    });
}
