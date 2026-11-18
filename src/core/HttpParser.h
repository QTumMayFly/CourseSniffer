#pragma once
#include "PacketRecord.h"
#include <utility>

namespace sniffer {
enum class HttpState { NeedMore, Recognized, NotHttp, TooLarge };
struct HttpMessage {
    std::string startLine;
    std::string version;
    std::string method;
    std::string target;
    int statusCode = 0;
    std::size_t headerBytes = 0;
    std::vector<std::pair<std::string, std::string>> headers;
};
struct HttpResult {
    HttpState state = HttpState::NeedMore;
    HttpMessage message;
};
class HttpParser {
public:
    static HttpResult parse(const Bytes& prefix);
};
}
