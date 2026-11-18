#include "DemoPackets.h"
#include "capture/CaptureWorker.h"
#include <QDateTime>
#include <QFile>
#include <pcap/pcap.h>
#include <sys/socket.h>
#include <cstring>

namespace sniffer {
namespace {
void put16(Bytes& bytes, std::size_t offset, std::uint16_t value) {
    bytes[offset] = static_cast<std::uint8_t>(value >> 8U);
    bytes[offset + 1] = static_cast<std::uint8_t>(value);
}
void put32(Bytes& bytes, std::size_t offset, std::uint32_t value) {
    for (int i = 0; i < 4; ++i) bytes[offset + static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(value >> (24 - i * 8));
}
std::uint16_t checksum(const Bytes& bytes) {
    std::uint32_t sum = 0;
    for (std::size_t i = 0; i < bytes.size(); i += 2)
        sum += (static_cast<std::uint32_t>(bytes[i]) << 8U) | (i + 1 < bytes.size() ? bytes[i + 1] : 0U);
    while (sum >> 16U) sum = (sum & 0xFFFFU) + (sum >> 16U);
    return static_cast<std::uint16_t>(~sum);
}
Bytes nullPrefix(int family) {
    Bytes prefix(4);
    const std::uint32_t hostFamily = static_cast<std::uint32_t>(family);
    std::memcpy(prefix.data(), &hostFamily, sizeof(hostFamily));
    return prefix;
}
Bytes ipv4(std::uint8_t protocol, Bytes payload) {
    Bytes ip(20);
    ip[0] = 0x45;
    put16(ip, 2, static_cast<std::uint16_t>(20 + payload.size()));
    put16(ip, 4, 0x1001);
    put16(ip, 6, 0x4000);
    ip[8] = 64; ip[9] = protocol;
    ip[12] = 127; ip[15] = 1; ip[16] = 127; ip[19] = 1;
    put16(ip, 10, checksum(ip));
    ip.insert(ip.end(), payload.begin(), payload.end());
    auto packet = nullPrefix(AF_INET);
    packet.insert(packet.end(), ip.begin(), ip.end());
    return packet;
}
Bytes tcp(bool reverse, std::uint32_t seq, std::uint32_t ack, std::uint8_t flags, const std::string& payload = {}) {
    Bytes segment(20);
    put16(segment, 0, reverse ? 8080 : 49152);
    put16(segment, 2, reverse ? 49152 : 8080);
    put32(segment, 4, seq); put32(segment, 8, ack);
    segment[12] = 0x50; segment[13] = flags; put16(segment, 14, 32768);
    segment.insert(segment.end(), payload.begin(), payload.end());
    Bytes pseudo{127,0,0,1,127,0,0,1,0,6,0,0};
    put16(pseudo, 10, static_cast<std::uint16_t>(segment.size()));
    pseudo.insert(pseudo.end(), segment.begin(), segment.end());
    put16(segment, 16, checksum(pseudo));
    return ipv4(6, std::move(segment));
}
Bytes ipv6(std::uint8_t protocol, Bytes payload) {
    Bytes ip(40);
    ip[0] = 0x60; put16(ip, 4, static_cast<std::uint16_t>(payload.size()));
    ip[6] = protocol; ip[7] = 64; ip[23] = 1; ip[39] = 1;
    ip.insert(ip.end(), payload.begin(), payload.end());
    auto packet = nullPrefix(AF_INET6);
    packet.insert(packet.end(), ip.begin(), ip.end());
    return packet;
}
Bytes udp(bool version6) {
    const std::string payload = "course-udp-demo";
    Bytes segment(8); put16(segment, 0, 53000); put16(segment, 2, 9999);
    put16(segment, 4, static_cast<std::uint16_t>(8 + payload.size()));
    segment.insert(segment.end(), payload.begin(), payload.end());
    if (version6) {
        Bytes pseudo(40); pseudo[15] = 1; pseudo[31] = 1;
        put32(pseudo, 32, static_cast<std::uint32_t>(segment.size())); pseudo[39] = 17;
        pseudo.insert(pseudo.end(), segment.begin(), segment.end());
        const auto value = checksum(pseudo); put16(segment, 6, value ? value : 0xFFFF);
        return ipv6(17, std::move(segment));
    }
    return ipv4(17, std::move(segment));
}
Bytes echo(bool version6) {
    Bytes payload{static_cast<std::uint8_t>(version6 ? 128 : 8),0,0,0,0x12,0x34,0,1,'d','e','m','o'};
    if (version6) {
        Bytes pseudo(40); pseudo[15] = 1; pseudo[31] = 1;
        put32(pseudo, 32, static_cast<std::uint32_t>(payload.size())); pseudo[39] = 58;
        pseudo.insert(pseudo.end(), payload.begin(), payload.end());
        put16(payload, 2, checksum(pseudo));
        return ipv6(58, std::move(payload));
    }
    put16(payload, 2, checksum(payload));
    return ipv4(1, std::move(payload));
}
}

std::vector<RawPacket> builtInDemoPackets() {
    std::vector<RawPacket> records;
    const auto start = QDateTime::currentMSecsSinceEpoch() * 1000;
    auto add = [&](Bytes bytes) {
        RawPacket packet;
        packet.id = records.size() + 1;
        packet.timestampMicros = start + static_cast<std::int64_t>(records.size()) * 1357;
        packet.wireLength = static_cast<std::uint32_t>(bytes.size());
        packet.linkType = DLT_NULL;
        packet.bytes = std::move(bytes);
        records.push_back(std::move(packet));
    };
    const std::string request = "GET /demo HTTP/1.1\r\nHost: localhost:8080\r\nUser-Agent: CourseSniffer-Demo\r\nConnection: close\r\n\r\n";
    const std::string body = "CourseSniffer local HTTP demonstration.\n";
    const std::string response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: " +
        std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
    const std::uint32_t requestEnd = 1001 + static_cast<std::uint32_t>(request.size());
    const std::uint32_t responseEnd = 9001 + static_cast<std::uint32_t>(response.size());
    add(tcp(false, 1000, 0, 0x02));
    add(tcp(true, 9000, 1001, 0x12));
    add(tcp(false, 1001, 9001, 0x10));
    add(tcp(false, 1001, 9001, 0x18, request.substr(0, 12)));
    add(tcp(false, 1013, 9001, 0x18, request.substr(12)));
    add(tcp(true, 9001, requestEnd, 0x10));
    add(tcp(true, 9001, requestEnd, 0x18, response.substr(0, 40)));
    add(tcp(true, 9041, requestEnd, 0x18, response.substr(40)));
    add(tcp(false, requestEnd, responseEnd, 0x10));
    add(tcp(false, requestEnd, responseEnd, 0x11));
    add(tcp(true, responseEnd, requestEnd + 1, 0x11));
    add(tcp(false, requestEnd + 1, responseEnd + 1, 0x10));
    add(udp(false)); add(echo(false)); add(udp(true)); add(echo(true));
    return records;
}

std::vector<RawPacket> readDemoPcap(const QString& path, QString* error) {
    char buffer[PCAP_ERRBUF_SIZE]{};
    auto* handle = pcap_open_offline(QFile::encodeName(path).constData(), buffer);
    if (!handle) { if (error) *error = QString::fromLocal8Bit(buffer); return {}; }
    std::vector<RawPacket> result;
    std::size_t byteCount = 0;
    const int linkType = pcap_datalink(handle);
    pcap_pkthdr* header = nullptr;
    const unsigned char* bytes = nullptr;
    int status = 0;
    if (error) error->clear();
    while ((status = pcap_next_ex(handle, &header, &bytes)) >= 0) {
        if (status == 0) continue;
        if (result.size() >= CaptureWorker::MaxSessionPackets ||
            header->caplen > CaptureWorker::MaxSessionBytes - byteCount) {
            if (error) *error = QStringLiteral("样例文件已达到会话容量上限");
            break;
        }
        RawPacket packet;
        packet.id = result.size() + 1;
        packet.timestampMicros = static_cast<std::int64_t>(header->ts.tv_sec) * 1000000 + header->ts.tv_usec;
        packet.wireLength = header->len;
        packet.linkType = linkType;
        packet.bytes.assign(bytes, bytes + header->caplen);
        byteCount += packet.bytes.size();
        result.push_back(std::move(packet));
    }
    if (status == PCAP_ERROR && error) *error = QString::fromLocal8Bit(pcap_geterr(handle));
    pcap_close(handle);
    return result;
}
}
