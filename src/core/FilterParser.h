#pragma once
#include "PacketRecord.h"
#include <memory>
#include <optional>

namespace sniffer {
struct FilterNode;
struct FilterError {
    std::size_t position = 0;
    std::string message;
};
class Filter {
public:
    Filter();
    bool matches(const PacketRecord& packet) const;
    const std::string& expression() const { return expression_; }
private:
    std::shared_ptr<const FilterNode> root_;
    std::string expression_;
    friend class FilterParser;
};
class FilterParser {
public:
    static std::optional<Filter> compile(const std::string& expression, FilterError& error);
};
}
