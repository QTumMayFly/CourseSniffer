#include "DnsParser.h"

#include <algorithm>
#include <arpa/inet.h>
#include <iomanip>
#include <set>
#include <sstream>
#include <utility>

namespace sniffer {
namespace {
constexpr std::size_t MaximumRecords = 128;
constexpr std::size_t MaximumNameLength = 255;
constexpr std::size_t MaximumPointerJumps = 16;

struct DnsFailure {
    std::string message;
    std::size_t offset = 0;
    bool limited = false;
};

std::string hexValue(std::uint64_t value, int width) {
    std::ostringstream text;
    text << "0x" << std::hex << std::setfill('0') << std::setw(width) << value;
    return text.str();
}

std::string typeName(std::uint16_t value) {
    const char* name = nullptr;
    switch (value) {
    case 1: name = "A"; break;
    case 2: name = "NS"; break;
    case 5: name = "CNAME"; break;
    case 6: name = "SOA"; break;
    case 12: name = "PTR"; break;
    case 15: name = "MX"; break;
    case 16: name = "TXT"; break;
    case 28: name = "AAAA"; break;
    case 33: name = "SRV"; break;
    case 41: name = "OPT"; break;
    case 255: name = "ANY"; break;
    default: break;
    }
    return name ? std::string(name) + " (" + std::to_string(value) + ")" : std::to_string(value);
}

std::string className(std::uint16_t value) {
    return value == 1 ? "IN (1)" : std::to_string(value);
}

class Decoder {
public:
    explicit Decoder(const PacketRecord& packet)
        : bytes_(packet.raw.bytes), base_(packet.payloadOffset), length_(packet.payloadLength) {}

    void parse() {
        need(0, 12, length_, "头部长度不足");
        id_ = u16(0);
        flags_ = u16(2);
        const auto opcode = static_cast<unsigned>((flags_ >> 11U) & 15U);
        if ((flags_ & 0x0040U) != 0) fail("保留标志位无效", 2);
        if (opcode != 0) fail("当前解析器支持标准查询与响应", 2, true);
        const std::array<std::uint16_t, 4> counts = {u16(4), u16(6), u16(8), u16(10)};
        std::size_t total = 0;
        for (const auto count : counts) total += count;
        if (total > MaximumRecords) fail("记录总数超过 128 条", 4, true);
        const bool response = (flags_ & 0x8000U) != 0;
        if ((!response && counts[0] == 0) || (total == 0 && (flags_ & 0x000fU) == 0))
            fail("问题与资源记录均为空", 4);

        field("DNS", "ID", hexValue(id_, 4), 0, 2);
        field("DNS", "Flags", hexValue(flags_, 4), 2, 2);
        field("DNS", "QR", response ? "1 (Response)" : "0 (Query)", 2, 2);
        field("DNS", "Opcode", std::to_string(opcode), 2, 2);
        const std::pair<const char*, std::uint16_t> bits[] = {
            {"AA", 0x0400}, {"TC", 0x0200}, {"RD", 0x0100}, {"RA", 0x0080},
            {"AD", 0x0020}, {"CD", 0x0010}
        };
        for (const auto& item : bits)
            field("DNS", item.first, (flags_ & item.second) != 0 ? "1" : "0", 2, 2);
        field("DNS", "RCODE", std::to_string(flags_ & 15U), 2, 2);
        const char* countNames[] = {"QDCOUNT", "ANCOUNT", "NSCOUNT", "ARCOUNT"};
        for (std::size_t index = 0; index < counts.size(); ++index)
            field("DNS", countNames[index], std::to_string(counts[index]), 4 + 2 * index, 2);

        std::size_t position = 12;
        for (std::size_t index = 0; index < counts[0]; ++index) {
            const auto layer = "DNS Question " + std::to_string(index + 1);
            const auto start = position;
            const auto questionName = name(position, length_);
            field(layer, "QNAME", questionName, start, position - start);
            need(position, 4, length_, "问题字段长度不足");
            const auto type = u16(position);
            const auto queryClass = u16(position + 2);
            if (type == 0 || queryClass == 0) fail("问题类型或类别无效", position);
            field(layer, "QTYPE", typeName(type), position, 2);
            field(layer, "QCLASS", className(queryClass), position + 2, 2);
            position += 4;
            if (index == 0) firstQuestion_ = questionName + " " + typeName(type);
        }
        const char* sections[] = {"DNS Answer ", "DNS Authority ", "DNS Additional "};
        for (std::size_t section = 0; section < 3; ++section) {
            for (std::size_t index = 0; index < counts[section + 1]; ++index) {
                resource(position, std::string(sections[section]) + std::to_string(index + 1), section == 0);
            }
        }
        if (position != length_) fail("记录末尾包含未声明的数据", position);
        summary_ = std::string(response ? "DNS 响应 " : "DNS 查询 ") + hexValue(id_, 4);
        if (!firstQuestion_.empty()) summary_ += "，" + firstQuestion_;
        if (response) {
            summary_ += "，回答 " + std::to_string(counts[1]) + " 条";
            if (!firstAnswer_.empty()) summary_ += "，" + firstAnswer_;
            if ((flags_ & 15U) != 0) summary_ += "，RCODE " + std::to_string(flags_ & 15U);
        }
    }

    std::vector<Field> fields;
    std::string summary_;
    std::uint16_t flags_ = 0;

private:
    const Bytes& bytes_;
    std::size_t base_;
    std::size_t length_;
    std::uint16_t id_ = 0;
    std::set<std::size_t> nameOffsets_;
    std::string firstQuestion_;
    std::string firstAnswer_;

    [[noreturn]] static void fail(const std::string& message, std::size_t position, bool limited = false) {
        throw DnsFailure{message, position, limited};
    }
    void need(std::size_t position, std::size_t count, std::size_t end, const std::string& message) const {
        if (end > length_ || position > end || count > end - position) fail(message, position);
    }
    std::uint8_t byte(std::size_t position) const { return bytes_[base_ + position]; }
    std::uint16_t u16(std::size_t position) const {
        return static_cast<std::uint16_t>((static_cast<unsigned>(byte(position)) << 8U) | byte(position + 1));
    }
    std::uint32_t u32(std::size_t position) const {
        return (static_cast<std::uint32_t>(byte(position)) << 24U)
             | (static_cast<std::uint32_t>(byte(position + 1)) << 16U)
             | (static_cast<std::uint32_t>(byte(position + 2)) << 8U)
             | static_cast<std::uint32_t>(byte(position + 3));
    }
    void field(const std::string& layer, const std::string& name, const std::string& value,
               std::size_t position, std::size_t length) {
        need(position, length, length_, "字段超出负载范围");
        fields.push_back({layer, name, value, base_ + position, length});
    }

    std::string name(std::size_t& position, std::size_t encodedEnd) {
        std::size_t cursor = position;
        std::size_t consumed = 0;
        std::size_t expanded = 1;
        std::size_t jumps = 0;
        bool jumped = false;
        std::vector<std::size_t> visited;
        std::string result;
        for (;;) {
            const auto end = jumped ? length_ : encodedEnd;
            need(cursor, 1, end, "名称内容不足");
            if (std::find(visited.begin(), visited.end(), cursor) != visited.end()) fail("名称压缩指针形成循环", cursor);
            visited.push_back(cursor);
            if (visited.size() > 144) fail("名称解析超过操作数量限制", cursor, true);
            nameOffsets_.insert(cursor);
            const auto labelLength = byte(cursor);
            if ((labelLength & 0xc0U) == 0xc0U) {
                need(cursor, 2, end, "名称压缩指针内容不足");
                const std::size_t target = (static_cast<std::size_t>(labelLength & 0x3fU) << 8U) | byte(cursor + 1);
                if (target >= length_) fail("名称压缩指针超出负载范围", cursor);
                if (target < 12 || target >= cursor || nameOffsets_.find(target) == nameOffsets_.end())
                    fail("名称压缩指针未指向已有名称边界", cursor);
                if (++jumps > MaximumPointerJumps) fail("名称压缩指针超过 16 次跳转", cursor, true);
                if (!jumped) consumed += 2;
                jumped = true;
                cursor = target;
                continue;
            }
            if ((labelLength & 0xc0U) != 0) fail("名称标签类型无效", cursor);
            if (labelLength == 0) {
                if (!jumped) ++consumed;
                position += consumed;
                return result.empty() ? "." : result;
            }
            need(cursor + 1, labelLength, end, "名称标签内容不足");
            expanded += static_cast<std::size_t>(labelLength) + 1;
            if (expanded > MaximumNameLength) fail("展开名称超过 255 字节", cursor);
            for (std::size_t index = 0; index < labelLength; ++index) {
                const auto character = byte(cursor + 1 + index);
                if (character >= 33 && character <= 126 && character != '.' && character != '\\') {
                    result.push_back(static_cast<char>(character));
                } else {
                    result.push_back('\\');
                    result.push_back(static_cast<char>('0' + character / 100));
                    result.push_back(static_cast<char>('0' + (character / 10) % 10));
                    result.push_back(static_cast<char>('0' + character % 10));
                }
            }
            result.push_back('.');
            if (!jumped) consumed += static_cast<std::size_t>(labelLength) + 1;
            cursor += static_cast<std::size_t>(labelLength) + 1;
        }
    }

    std::string addressData(std::size_t position, int family) const {
        char output[INET6_ADDRSTRLEN]{};
        const auto* value = inet_ntop(family, bytes_.data() + base_ + position, output, sizeof(output));
        return value ? value : "地址转换失败";
    }

    std::string rdata(std::uint16_t type, std::uint16_t recordClass, std::size_t begin, std::size_t end) {
        const auto length = end - begin;
        if (recordClass == 1 && (type == 1 || type == 28)) {
            const std::size_t expected = type == 1 ? 4U : 16U;
            if (length != expected) fail("地址记录的 RDLENGTH 无效", begin);
            return addressData(begin, type == 1 ? AF_INET : AF_INET6);
        }
        if (type == 2 || type == 5 || type == 12) {
            auto cursor = begin;
            const auto value = name(cursor, end);
            if (cursor != end) fail("名称记录的 RDLENGTH 无效", cursor);
            return value;
        }
        if (type == 15) {
            need(begin, 3, end, "MX 记录内容不足");
            auto cursor = begin + 2;
            const auto exchange = name(cursor, end);
            if (cursor != end) fail("MX 记录的 RDLENGTH 无效", cursor);
            return std::to_string(u16(begin)) + " " + exchange;
        }
        if (type == 6) {
            auto cursor = begin;
            const auto primary = name(cursor, end);
            const auto mailbox = name(cursor, end);
            need(cursor, 20, end, "SOA 数值字段内容不足");
            if (end - cursor != 20) fail("SOA 记录的 RDLENGTH 无效", cursor);
            return primary + " " + mailbox + " serial " + std::to_string(u32(cursor))
                 + " refresh " + std::to_string(u32(cursor + 4)) + " retry " + std::to_string(u32(cursor + 8))
                 + " expire " + std::to_string(u32(cursor + 12)) + " minimum " + std::to_string(u32(cursor + 16));
        }
        if (type == 33) {
            need(begin, 7, end, "SRV 记录内容不足");
            auto cursor = begin + 6;
            const auto target = name(cursor, end);
            if (cursor != end) fail("SRV 记录的 RDLENGTH 无效", cursor);
            return "priority " + std::to_string(u16(begin)) + " weight " + std::to_string(u16(begin + 2))
                 + " port " + std::to_string(u16(begin + 4)) + " " + target;
        }
        return "原始 RDATA " + std::to_string(length) + " 字节";
    }

    void resource(std::size_t& position, const std::string& layer, bool answer) {
        const auto start = position;
        const auto owner = name(position, length_);
        field(layer, "NAME", owner, start, position - start);
        need(position, 10, length_, "资源记录头部长度不足");
        const auto type = u16(position);
        const auto recordClass = u16(position + 2);
        const auto ttl = u32(position + 4);
        const auto length = u16(position + 8);
        if (type == 0 || recordClass == 0) fail("资源记录类型或类别无效", position);
        field(layer, "TYPE", typeName(type), position, 2);
        field(layer, "CLASS", className(recordClass), position + 2, 2);
        field(layer, "TTL", std::to_string(ttl), position + 4, 4);
        field(layer, "RDLENGTH", std::to_string(length), position + 8, 2);
        position += 10;
        need(position, length, length_, "RDATA 超出负载范围");
        const auto value = rdata(type, recordClass, position, position + length);
        field(layer, "RDATA", value, position, length);
        position += length;
        if (answer && firstAnswer_.empty()) firstAnswer_ = typeName(type) + " " + value;
    }
};
} // namespace

bool DnsParser::parse(PacketRecord& packet) {
    if (!packet.has(Protocol::Udp) || !packet.hasPorts ||
        (packet.source.port != 53 && packet.destination.port != 53)) return false;
    const auto& bytes = packet.raw.bytes;
    if (packet.payloadOffset > bytes.size() || packet.payloadLength > bytes.size() - packet.payloadOffset) {
        packet.malformed = true;
        packet.notices.emplace_back("DNS 候选负载范围无效。");
        return false;
    }
    if (packet.transportOffset <= bytes.size() && 8 <= bytes.size() - packet.transportOffset) {
        const auto udpLength = (static_cast<unsigned>(bytes[packet.transportOffset + 4]) << 8U)
                             | bytes[packet.transportOffset + 5];
        if (udpLength >= 8 && packet.payloadLength < udpLength - 8U) {
            packet.truncated = true;
            packet.notices.emplace_back("DNS 候选负载捕获内容不完整。");
            return false;
        }
    }
    try {
        Decoder decoder(packet);
        decoder.parse();
        packet.fields.insert(packet.fields.end(), decoder.fields.begin(), decoder.fields.end());
        packet.add(Protocol::Dns);
        packet.summary = std::move(decoder.summary_);
        if ((decoder.flags_ & 0x0200U) != 0) packet.notices.emplace_back("DNS 响应设置了 TC 标志，响应内容受到发送方截断。");
        return true;
    } catch (const DnsFailure& error) {
        if (!error.limited && !packet.truncated) packet.malformed = true;
        packet.notices.emplace_back("DNS 候选负载：" + error.message + "，DNS 偏移 " + std::to_string(error.offset) + "。");
        return false;
    }
}
} // namespace sniffer
