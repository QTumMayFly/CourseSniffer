#include "HttpParser.h"

#include <algorithm>
#include <string_view>

namespace sniffer {
namespace {
constexpr std::size_t HeaderLimit = 16U * 1024U;

bool tokenCharacter(unsigned char value) {
    if ((value >= '0' && value <= '9') || (value >= 'A' && value <= 'Z') ||
        (value >= 'a' && value <= 'z')) return true;
    constexpr std::string_view punctuation = "!#$%&'*+-.^_`|~";
    return punctuation.find(static_cast<char>(value)) != std::string_view::npos;
}

bool validVersion(std::string_view version) {
    return version == "HTTP/1.0" || version == "HTTP/1.1";
}

bool parseStartLine(std::string_view line, HttpMessage& message) {
    message.startLine = std::string(line);
    if (line.substr(0, 5) == "HTTP/") {
        if (line.size() < 13 || !validVersion(line.substr(0, 8)) ||
            line[8] != ' ' || line[12] != ' ') return false;
        int status = 0;
        for (std::size_t i = 9; i < 12; ++i) {
            if (line[i] < '0' || line[i] > '9') return false;
            status = status * 10 + line[i] - '0';
        }
        if (status < 100 || status > 599) return false;
        for (std::size_t i = 13; i < line.size(); ++i) {
            const auto value = static_cast<unsigned char>(line[i]);
            if ((value < 32 && value != '\t') || value == 127) return false;
        }
        message.version = std::string(line.substr(0, 8));
        message.statusCode = status;
        return true;
    }

    const auto firstSpace = line.find(' ');
    if (firstSpace == std::string_view::npos || firstSpace == 0) return false;
    const auto secondSpace = line.find(' ', firstSpace + 1);
    if (secondSpace == std::string_view::npos || secondSpace == firstSpace + 1 ||
        !validVersion(line.substr(secondSpace + 1))) return false;
    for (std::size_t i = 0; i < firstSpace; ++i) {
        if (!tokenCharacter(static_cast<unsigned char>(line[i]))) return false;
    }
    for (std::size_t i = firstSpace + 1; i < secondSpace; ++i) {
        const auto value = static_cast<unsigned char>(line[i]);
        if (value < 33 || value > 126) return false;
    }
    message.method = std::string(line.substr(0, firstSpace));
    message.target = std::string(line.substr(firstSpace + 1, secondSpace - firstSpace - 1));
    message.version = std::string(line.substr(secondSpace + 1));
    return true;
}

bool parseHeader(std::string_view line, HttpMessage& message) {
    const auto colon = line.find(':');
    if (colon == std::string_view::npos || colon == 0) return false;
    for (std::size_t i = 0; i < colon; ++i) {
        if (!tokenCharacter(static_cast<unsigned char>(line[i]))) return false;
    }
    auto value = line.substr(colon + 1);
    for (const unsigned char byte : value) {
        if ((byte < 32 && byte != '\t') || byte == 127) return false;
    }
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) value.remove_prefix(1);
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) value.remove_suffix(1);
    message.headers.emplace_back(std::string(line.substr(0, colon)), std::string(value));
    return true;
}
} // namespace

HttpResult HttpParser::parse(const Bytes& prefix) {
    HttpResult result;
    if (prefix.empty()) return result;
    const std::string_view text(reinterpret_cast<const char*>(prefix.data()), prefix.size());
    const auto terminator = text.find("\r\n\r\n");
    const bool complete = terminator != std::string_view::npos;
    const std::size_t examined = complete ? terminator + 4 : text.size();
    const bool oversized = examined > HeaderLimit || (!complete && examined == HeaderLimit);
    const auto checkedLength = std::min(examined, HeaderLimit);
    const auto headerView = text.substr(0, checkedLength);

    // 头部采用 CRLF 分隔。报文正文中的二进制内容不参与头部判断。
    for (std::size_t i = 0; i < checkedLength; ++i) {
        const auto byte = prefix[i];
        if (byte == '\r') {
            if (i + 1 < checkedLength && prefix[i + 1] != '\n') {
                result.state = HttpState::NotHttp;
                return result;
            }
        } else if (byte == '\n') {
            if (i == 0 || prefix[i - 1] != '\r') {
                result.state = HttpState::NotHttp;
                return result;
            }
        } else if ((byte < 32 && byte != '\t') || byte == 127) {
            result.state = HttpState::NotHttp;
            return result;
        }
    }

    const auto firstLineEnd = headerView.find("\r\n");
    if (firstLineEnd == std::string_view::npos) {
        if (oversized) result.state = HttpState::TooLarge;
        return result;
    }
    if (!parseStartLine(headerView.substr(0, firstLineEnd), result.message)) {
        result.state = HttpState::NotHttp;
        return result;
    }

    std::size_t position = firstLineEnd + 2;
    while (position < checkedLength) {
        const auto end = headerView.find("\r\n", position);
        if (end == std::string_view::npos) {
            if (oversized) result.state = HttpState::TooLarge;
            return result;
        }
        if (end == position) {
            result.message.headerBytes = end + 2;
            result.state = HttpState::Recognized;
            return result;
        }
        if (!parseHeader(headerView.substr(position, end - position), result.message)) {
            result.state = HttpState::NotHttp;
            return result;
        }
        position = end + 2;
    }
    if (oversized) result.state = HttpState::TooLarge;
    return result;
}
} // namespace sniffer
