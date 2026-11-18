#include "FilterParser.h"

#include <cctype>
#include <stdexcept>
#include <utility>

namespace sniffer {

struct FilterNode {
    enum class Kind { Protocol, And, Or, Not } kind = Kind::Protocol;
    Protocol protocol = Protocol::Ipv4;
    std::shared_ptr<const FilterNode> left;
    std::shared_ptr<const FilterNode> right;
    bool matches(const PacketRecord& packet) const {
        switch (kind) {
        case Kind::Protocol: return packet.has(protocol);
        case Kind::And: return left->matches(packet) && right->matches(packet);
        case Kind::Or: return left->matches(packet) || right->matches(packet);
        case Kind::Not: return !left->matches(packet);
        }
        return false;
    }
};

namespace {
struct ParseFailure { FilterError error; };
enum class TokenKind { Word, Left, Right, End };
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
        const auto isIdentifier = [](unsigned char byte) { return std::isalnum(byte) || byte == '_'; };
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
        if (token_.kind != TokenKind::Word) fail("此处需要协议名称或左括号。");
        const std::pair<const char*, Protocol> protocols[] = {
            {"http", Protocol::Http}, {"tcp", Protocol::Tcp}, {"udp", Protocol::Udp},
            {"ipv4", Protocol::Ipv4}, {"ipv6", Protocol::Ipv6},
            {"icmp", Protocol::Icmp}, {"icmp6", Protocol::Icmp6}
        };
        for (const auto& item : protocols) if (token_.text == item.first) {
            auto node = std::make_shared<FilterNode>();
            node->protocol = item.second;
            next();
            return node;
        }
        fail("未知协议名称：" + token_.text + "。");
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
