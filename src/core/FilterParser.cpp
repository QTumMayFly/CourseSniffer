#include "FilterParser.h"

#include <cctype>
#include <arpa/inet.h>
#include <stdexcept>
#include <utility>

namespace sniffer {

struct FilterNode {
    enum class Kind { Protocol, Address, Port, And, Or, Not } kind = Kind::Protocol;
    enum class Side { Either, Source, Destination } side = Side::Either;
    Protocol protocol = Protocol::Ipv4;
    int addressFamily = 0;
    std::array<std::uint8_t, 16> address{};
    std::uint16_t port = 0;
    std::shared_ptr<const FilterNode> left;
    std::shared_ptr<const FilterNode> right;
    bool matches(const PacketRecord& packet) const {
        switch (kind) {
        case Kind::Protocol: return packet.has(protocol);
        case Kind::Address: {
            if (!packet.has(Protocol::Ipv4) && !packet.has(Protocol::Ipv6)) return false;
            const auto same = [this](const Endpoint& endpoint) {
                if (endpoint.family != addressFamily) return false;
                const auto length = addressFamily == 4 ? 4U : 16U;
                for (std::size_t index = 0; index < length; ++index)
                    if (endpoint.address[index] != address[index]) return false;
                return true;
            };
            return (side != Side::Destination && same(packet.source)) ||
                   (side != Side::Source && same(packet.destination));
        }
        case Kind::Port:
            if (!packet.hasPorts || !packet.has(protocol)) return false;
            return (side != Side::Destination && packet.source.port == port) ||
                   (side != Side::Source && packet.destination.port == port);
        case Kind::And: return left->matches(packet) && right->matches(packet);
        case Kind::Or: return left->matches(packet) || right->matches(packet);
        case Kind::Not: return !left->matches(packet);
        }
        return false;
    }
};

namespace {
struct ParseFailure { FilterError error; };
enum class TokenKind { Word, Equal, Left, Right, End };
struct Token { TokenKind kind; std::string text; std::size_t position; };

class Parser {
public:
    explicit Parser(std::string input) : input_(std::move(input)) { next(); }
    std::shared_ptr<const FilterNode> parse() {
        if (token_.kind == TokenKind::End) return {};
        auto result = parseOr();
        if (token_.kind != TokenKind::End) fail("表达式包含多余内容。");
        return result;
    }
private:
    std::string input_;
    std::size_t cursor_ = 0;
    std::size_t depth_ = 0;
    Token token_{TokenKind::End, {}, 0};
    [[noreturn]] void fail(const std::string& message) const {
        throw ParseFailure{{token_.position, message}};
    }
    void next() {
        while (cursor_ < input_.size() && std::isspace(static_cast<unsigned char>(input_[cursor_]))) ++cursor_;
        const auto start = cursor_;
        if (cursor_ == input_.size()) { token_ = {TokenKind::End, {}, cursor_}; return; }
        const auto character = input_[cursor_++];
        if (character == '(') { token_ = {TokenKind::Left, "(", start}; return; }
        if (character == ')') { token_ = {TokenKind::Right, ")", start}; return; }
        if (character == '=' && cursor_ < input_.size() && input_[cursor_] == '=') {
            ++cursor_;
            token_ = {TokenKind::Equal, "==", start};
            return;
        }
        const auto isIdentifier = [](unsigned char byte) {
            return std::isalnum(byte) || byte == '_' || byte == '.' || byte == ':';
        };
        if (!isIdentifier(static_cast<unsigned char>(character))) {
            throw ParseFailure{{start, "过滤表达式包含无效字符。"}};
        }
        while (cursor_ < input_.size() && isIdentifier(static_cast<unsigned char>(input_[cursor_]))) ++cursor_;
        token_ = {TokenKind::Word, input_.substr(start, cursor_ - start), start};
    }
    static std::shared_ptr<const FilterNode> operation(FilterNode::Kind kind,
            std::shared_ptr<const FilterNode> left, std::shared_ptr<const FilterNode> right = {}) {
        auto node = std::make_shared<FilterNode>();
        node->kind = kind;
        node->left = std::move(left);
        node->right = std::move(right);
        return node;
    }
    std::shared_ptr<const FilterNode> parseOr() {
        auto left = parseAnd();
        while (token_.kind == TokenKind::Word && token_.text == "or") {
            next();
            left = operation(FilterNode::Kind::Or, std::move(left), parseAnd());
        }
        return left;
    }
    std::shared_ptr<const FilterNode> parseAnd() {
        auto left = parseUnary();
        while (token_.kind == TokenKind::Word && token_.text == "and") {
            next();
            left = operation(FilterNode::Kind::And, std::move(left), parseUnary());
        }
        return left;
    }
    std::shared_ptr<const FilterNode> parseUnary() {
        if (token_.kind == TokenKind::Word && token_.text == "not") {
            next();
            return operation(FilterNode::Kind::Not, parseUnary());
        }
        return parsePrimary();
    }
    std::shared_ptr<const FilterNode> parsePrimary() {
        if (token_.kind == TokenKind::Left) {
            if (++depth_ > 16) fail("括号嵌套超过 16 层。");
            next();
            auto inner = parseOr();
            if (token_.kind != TokenKind::Right) fail("表达式缺少右括号。");
            --depth_;
            next();
            return inner;
        }
        if (token_.kind != TokenKind::Word) fail("此处需要协议名称、字段条件或左括号。");
        const std::pair<const char*, Protocol> protocols[] = {
            {"http", Protocol::Http}, {"tcp", Protocol::Tcp}, {"udp", Protocol::Udp},
            {"ipv4", Protocol::Ipv4}, {"ipv6", Protocol::Ipv6},
            {"icmp", Protocol::Icmp}, {"icmp6", Protocol::Icmp6},
            {"dns", Protocol::Dns}, {"arp", Protocol::Arp}
        };
        for (const auto& item : protocols) if (token_.text == item.first) {
            auto node = std::make_shared<FilterNode>();
            node->protocol = item.second;
            next();
            return node;
        }
        const auto field = token_.text;
        auto node = std::make_shared<FilterNode>();
        if (field == "ip.addr" || field == "ip.src" || field == "ip.dst") {
            node->kind = FilterNode::Kind::Address;
            if (field == "ip.src") node->side = FilterNode::Side::Source;
            if (field == "ip.dst") node->side = FilterNode::Side::Destination;
        } else if (field == "tcp.port" || field == "tcp.srcport" || field == "tcp.dstport" ||
                   field == "udp.port" || field == "udp.srcport" || field == "udp.dstport") {
            node->kind = FilterNode::Kind::Port;
            node->protocol = field.compare(0, 3, "tcp") == 0 ? Protocol::Tcp : Protocol::Udp;
            if (field.find(".srcport") != std::string::npos) node->side = FilterNode::Side::Source;
            if (field.find(".dstport") != std::string::npos) node->side = FilterNode::Side::Destination;
        } else {
            fail("未知协议名称或字段：" + token_.text + "。");
        }
        next();
        if (token_.kind != TokenKind::Equal) fail("字段条件需要使用 == 连接取值。");
        next();
        if (token_.kind != TokenKind::Word) fail("字段条件缺少地址或端口取值。");
        if (node->kind == FilterNode::Kind::Address) {
            if (inet_pton(AF_INET, token_.text.c_str(), node->address.data()) == 1) node->addressFamily = 4;
            else if (inet_pton(AF_INET6, token_.text.c_str(), node->address.data()) == 1) node->addressFamily = 6;
            else fail("请输入有效的 IPv4 或 IPv6 数字地址。");
        } else {
            unsigned value = 0;
            for (const unsigned char byte : token_.text) {
                if (byte < '0' || byte > '9') fail("端口需要使用 0 至 65535 的十进制整数。");
                value = value * 10 + static_cast<unsigned>(byte - '0');
                if (value > 65535) fail("端口需要使用 0 至 65535 的十进制整数。");
            }
            node->port = static_cast<std::uint16_t>(value);
        }
        next();
        return node;
    }
};
} // namespace

Filter::Filter() = default;
bool Filter::matches(const PacketRecord& packet) const { return !root_ || root_->matches(packet); }

std::optional<Filter> FilterParser::compile(const std::string& expression, FilterError& error) {
    error = {};
    if (expression.size() > 256) {
        error = {256, "过滤表达式超过 256 个字符。"};
        return std::nullopt;
    }
    std::string normalized = expression;
    for (auto& byte : normalized) byte = static_cast<char>(std::tolower(static_cast<unsigned char>(byte)));
    try {
        Filter result;
        result.root_ = Parser(normalized).parse();
        result.expression_ = std::move(normalized);
        return result;
    } catch (const ParseFailure& failure) {
        error = failure.error;
        return std::nullopt;
    }
}

} // namespace sniffer
