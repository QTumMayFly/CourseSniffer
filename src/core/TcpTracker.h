#pragma once
#include "HttpParser.h"
#include <memory>
#include <optional>

namespace sniffer {
struct StreamBlock {
    std::int64_t offset = 0;
    Bytes data;
    std::uint64_t gapLength = 0;
    std::vector<std::uint64_t> packetIds;
};
struct StreamConflict {
    std::int64_t offset = 0;
    std::uint64_t length = 0;
};
struct StreamDirection {
    Endpoint source;
    Endpoint destination;
    std::vector<StreamBlock> blocks;
    std::vector<StreamConflict> conflicts;
    std::size_t uniqueBytes = 0;
    bool truncated = false;
    bool startIncomplete = false;
    std::string status;
};
struct ConnectionInfo {
    std::uint64_t id = 0;
    Endpoint a;
    Endpoint b;
    bool midstream = false;
    bool closed = false;
    bool reset = false;
    bool boundaryUncertain = false;
    bool http = false;
    std::vector<std::uint64_t> packetIds;
    std::vector<std::uint64_t> payloadPacketIds;
    std::array<std::optional<HttpMessage>, 2> httpMessages;
    std::array<std::vector<std::uint64_t>, 2> httpSourcePacketIds;
};
struct StreamView {
    ConnectionInfo connection;
    std::array<StreamDirection, 2> directions;
};
struct TrackerUpdate {
    std::uint64_t connectionId = 0;
    std::vector<std::uint64_t> httpPacketIds;
};
class TcpTracker {
public:
    TcpTracker();
    ~TcpTracker();
    TcpTracker(TcpTracker&&) noexcept;
    TcpTracker& operator=(TcpTracker&&) noexcept;
    TcpTracker(const TcpTracker&) = delete;
    TcpTracker& operator=(const TcpTracker&) = delete;
    TrackerUpdate ingest(PacketRecord& packet);
    const ConnectionInfo* connection(std::uint64_t id) const;
    std::optional<StreamView> trace(std::uint64_t id, std::size_t contentLimit = 1024U * 1024U) const;
    std::size_t connectionCount() const;
    void clear();
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

std::string streamText(const StreamDirection& direction, bool hexadecimal = false);
}
