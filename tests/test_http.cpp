#include "TestSupport.h"
#include "core/HttpParser.h"

using namespace sniffer;
namespace {
Bytes bytes(const std::string& text) { return Bytes(text.begin(), text.end()); }
HttpResult parse(const std::string& text) { return HttpParser::parse(bytes(text)); }
}

void runHttpTests(TestSuite& suite) {
    suite.run("HTTP request fields and custom host port", [] {
        const auto result = parse("GET /course?item=1 HTTP/1.1\r\nHost: localhost:8080\r\nContent-Length: 0\r\n\r\n");
        CHECK(result.state == HttpState::Recognized);
        CHECK(result.message.method == "GET");
        CHECK(result.message.target == "/course?item=1");
        CHECK(result.message.version == "HTTP/1.1");
        CHECK(result.message.headers.size() == 2);
        CHECK(result.message.headers[0].first == "Host");
        CHECK(result.message.headers[0].second == "localhost:8080");
    });
    suite.run("HTTP response version and status", [] {
        const auto result = parse("HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nhello");
        CHECK(result.state == HttpState::Recognized);
        CHECK(result.message.statusCode == 200);
        CHECK(result.message.method.empty());
        CHECK(result.message.version == "HTTP/1.0");
        CHECK(result.message.headerBytes == 45);
    });
    suite.run("HTTP headers optional and extension methods valid", [] {
        const auto result = parse("PROPFIND / HTTP/1.1\r\n\r\n");
        CHECK(result.state == HttpState::Recognized);
        CHECK(result.message.method == "PROPFIND");
        CHECK(result.message.headers.empty());
    });
    suite.run("HTTP header whitespace and duplicate fields preserved", [] {
        const auto result = parse("GET / HTTP/1.1\r\nX-Value:\t value \t\r\nX-Value:\r\n\r\n");
        CHECK(result.state == HttpState::Recognized);
        CHECK(result.message.headers.size() == 2);
        CHECK(result.message.headers[0].second == "value");
        CHECK(result.message.headers[1].second.empty());
    });
    suite.run("HTTP incomplete prefixes wait for more bytes", [] {
        CHECK(parse("").state == HttpState::NeedMore);
        CHECK(parse("GE").state == HttpState::NeedMore);
        CHECK(parse("GET / HTTP/1.1\r\nHost: local\r").state == HttpState::NeedMore);
        CHECK(parse("GET / HTTP/1.1\r\nHost: local\r\n").state == HttpState::NeedMore);
    });
    suite.run("HTTP response permits empty reason phrase", [] {
        CHECK(parse("HTTP/1.1 204 \r\n\r\n").state == HttpState::Recognized);
        CHECK(parse("HTTP/1.1 204\r\n\r\n").state == HttpState::NotHttp);
    });
    suite.run("HTTP binary body is outside header validation", [] {
        auto request = bytes("POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\n");
        request.insert(request.end(), {0, 1, 13, 255});
        const auto result = HttpParser::parse(request);
        CHECK(result.state == HttpState::Recognized);
        CHECK(result.message.headerBytes == request.size() - 4);
    });
    suite.run("HTTP bare newlines and embedded controls are rejected", [] {
        CHECK(parse("GET / HTTP/1.1\n\n").state == HttpState::NotHttp);
        CHECK(parse("GET / HTTP/1.1\rX: y\r\n\r\n").state == HttpState::NotHttp);
        auto request = bytes("GET / HTTP/1.1\r\nHost: ");
        request.push_back(0);
        CHECK(HttpParser::parse(request).state == HttpState::NotHttp);
    });
    suite.run("HTTP request line validates separators and version", [] {
        CHECK(parse("GET  / HTTP/1.1\r\n\r\n").state == HttpState::NotHttp);
        CHECK(parse("GET / HTTP/2.0\r\n\r\n").state == HttpState::NotHttp);
        CHECK(parse("GET\t/ HTTP/1.1\r\n\r\n").state == HttpState::NotHttp);
        CHECK(parse("GET / HTTP/1.1 extra\r\n\r\n").state == HttpState::NotHttp);
    });
    suite.run("HTTP status code validates all three digits", [] {
        CHECK(parse("HTTP/1.1 20A OK\r\n\r\n").state == HttpState::NotHttp);
        CHECK(parse("HTTP/1.1 099 OK\r\n\r\n").state == HttpState::NotHttp);
        CHECK(parse("HTTP/1.1 599 Custom\r\n\r\n").state == HttpState::Recognized);
    });
    suite.run("HTTP header names validate token characters", [] {
        CHECK(parse("GET / HTTP/1.1\r\nHost : x\r\n\r\n").state == HttpState::NotHttp);
        CHECK(parse("GET / HTTP/1.1\r\n: x\r\n\r\n").state == HttpState::NotHttp);
        CHECK(parse("GET / HTTP/1.1\r\n folded\r\n\r\n").state == HttpState::NotHttp);
    });
    suite.run("HTTP TLS prefix is rejected", [] {
        CHECK(HttpParser::parse(Bytes{0x16, 0x03, 0x03, 0x00, 0x10}).state == HttpState::NotHttp);
    });
    suite.run("HTTP header bound applies before the body", [] {
        CHECK(parse(std::string(16U * 1024U, 'G')).state == HttpState::TooLarge);
        const std::string base = "GET / HTTP/1.1\r\nX: ";
        const std::string ending = "\r\n\r\n";
        const auto exact = base + std::string(16U * 1024U - base.size() - ending.size(), 'a') + ending;
        CHECK(parse(exact).state == HttpState::Recognized);
        CHECK(parse(exact + std::string(1000, '\0')).state == HttpState::Recognized);
        CHECK(parse(base + std::string(16U * 1024U, 'a') + ending).state == HttpState::TooLarge);
    });
    suite.run("HTTP oversized candidate retains a validated start line", [] {
        const auto result = parse("GET /course HTTP/1.1\r\nX-Large: " + std::string(20U * 1024U, 'a'));
        CHECK(result.state == HttpState::TooLarge);
        CHECK(result.message.version == "HTTP/1.1");
        CHECK(result.message.method == "GET");
        CHECK(result.message.target == "/course");
        CHECK(parse(std::string(20U * 1024U, '\0')).state == HttpState::NotHttp);
        const auto plain = parse(std::string(20U * 1024U, 'a'));
        CHECK(plain.message.version.empty());
    });
}
