#include "TcpTracker.h"

#include <algorithm>
#include <limits>
#include <map>
#include <sstream>
#include <tuple>

namespace sniffer {
namespace {
constexpr std::uint8_t Fin = 0x01;
constexpr std::uint8_t Syn = 0x02;
constexpr std::uint8_t Rst = 0x04;
constexpr std::uint8_t Ack = 0x10;
constexpr std::size_t HeaderLimit = 16U * 1024U;
constexpr std::size_t ContentLimit = 1024U * 1024U;
constexpr std::int64_t SequenceHalf = 2147483648LL;

std::int64_t relativeSequence(std::uint32_t sequence, std::uint32_t reference) {
    const std::uint32_t difference = sequence - reference;
    return difference < 0x80000000U ? static_cast<std::int64_t>(difference)
                                  : static_cast<std::int64_t>(difference) - 4294967296LL;
}

struct Piece {
    Bytes data;
    std::uint64_t packetId = 0;
};

struct DirectionState {
    bool referenceSet = false;
    std::uint32_t reference = 0;
    bool synSeen = false;
    std::uint32_t synSequence = 0;
    std::uint32_t synAcknowledgement = 0;
    std::size_t synPayloadLength = 0;
    bool finSeen = false;
    std::optional<std::int64_t> finEnd;
    bool captureTruncated = false;
    bool sequenceLimited = false;
    std::map<std::int64_t, Piece> pieces;
    std::vector<StreamConflict> conflicts;
};

struct ConnectionState {
    ConnectionInfo info;
    std::array<DirectionState, 2> directions;
};

using ConnectionKey = std::pair<Endpoint, Endpoint>;

ConnectionKey keyFor(const PacketRecord& packet) {
    return packet.destination < packet.source
        ? ConnectionKey{packet.destination, packet.source}
        : ConnectionKey{packet.source, packet.destination};
}

void appendId(std::vector<std::uint64_t>& ids, std::uint64_t id) {
    if (std::find(ids.begin(), ids.end(), id) == ids.end()) ids.push_back(id);
}

void mergeConflicts(DirectionState& direction) {
    auto& ranges = direction.conflicts;
    std::sort(ranges.begin(), ranges.end(), [](const auto& left, const auto& right) {
        return left.offset < right.offset;
    });
    std::vector<StreamConflict> merged;
    for (const auto& range : ranges) {
        if (!merged.empty() && range.offset <= merged.back().offset + static_cast<std::int64_t>(merged.back().length)) {
            auto& back = merged.back();
            const auto end = std::max(back.offset + static_cast<std::int64_t>(back.length),
                                      range.offset + static_cast<std::int64_t>(range.length));
            back.length = static_cast<std::uint64_t>(end - back.offset);
        } else {
            merged.push_back(range);
        }
    }
    ranges = std::move(merged);
}

void establishReference(DirectionState& direction, std::uint32_t sequence, bool fromSyn) {
    if (!direction.referenceSet) {
        direction.referenceSet = true;
        direction.reference = sequence;
        return;
    }
    if (!fromSyn || direction.reference == sequence) return;
    const auto shift = relativeSequence(direction.reference, sequence);
    std::map<std::int64_t, Piece> moved;
    for (auto& entry : direction.pieces) moved.emplace(entry.first + shift, std::move(entry.second));
    for (auto& conflict : direction.conflicts) conflict.offset += shift;
    if (direction.finEnd) *direction.finEnd += shift;
    direction.pieces = std::move(moved);
    direction.reference = sequence;
}

bool insertPayload(DirectionState& direction, std::uint32_t sequence,
                   const Bytes& bytes, std::uint64_t packetId) {
    if (bytes.empty()) return true;
    establishReference(direction, sequence, false);
    const auto start = relativeSequence(sequence, direction.reference);
    const auto end = start + static_cast<std::int64_t>(bytes.size());
    std::int64_t minimum = start;
    std::int64_t maximum = end;
    if (!direction.pieces.empty()) {
        minimum = std::min(minimum, direction.pieces.begin()->first);
        const auto& last = *direction.pieces.rbegin();
        maximum = std::max(maximum, last.first + static_cast<std::int64_t>(last.second.data.size()));
    }
    if (maximum - minimum >= SequenceHalf) {
        direction.sequenceLimited = true;
        return false;
    }

    auto position = direction.pieces.lower_bound(start);
    if (position != direction.pieces.begin()) {
        const auto previous = std::prev(position);
        if (previous->first + static_cast<std::int64_t>(previous->second.data.size()) > start) position = previous;
    }
    std::vector<std::pair<std::int64_t, Piece>> additions;
    auto cursor = start;
    while (cursor < end) {
        if (position == direction.pieces.end() || position->first >= end) {
            const auto offset = static_cast<std::size_t>(cursor - start);
            additions.push_back({cursor, {Bytes(bytes.begin() + static_cast<std::ptrdiff_t>(offset), bytes.end()), packetId}});
            break;
        }
        if (position->first > cursor) {
            const auto uncoveredEnd = std::min(end, position->first);
            const auto beginOffset = static_cast<std::size_t>(cursor - start);
            const auto endOffset = static_cast<std::size_t>(uncoveredEnd - start);
            additions.push_back({cursor, {Bytes(bytes.begin() + static_cast<std::ptrdiff_t>(beginOffset),
                                               bytes.begin() + static_cast<std::ptrdiff_t>(endOffset)), packetId}});
            cursor = uncoveredEnd;
            if (cursor == end) break;
        }
        const auto pieceEnd = position->first + static_cast<std::int64_t>(position->second.data.size());
        if (pieceEnd <= cursor) {
            ++position;
            continue;
        }
        const auto overlapEnd = std::min(end, pieceEnd);
        auto conflictStart = overlapEnd;
        for (auto offset = cursor; offset < overlapEnd; ++offset) {
            const auto existing = position->second.data[static_cast<std::size_t>(offset - position->first)];
            const auto incoming = bytes[static_cast<std::size_t>(offset - start)];
            if (existing != incoming) {
                if (conflictStart == overlapEnd) conflictStart = offset;
            } else if (conflictStart != overlapEnd) {
                direction.conflicts.push_back({conflictStart, static_cast<std::uint64_t>(offset - conflictStart)});
                conflictStart = overlapEnd;
            }
        }
        if (conflictStart != overlapEnd) {
            direction.conflicts.push_back({conflictStart, static_cast<std::uint64_t>(overlapEnd - conflictStart)});
        }
        cursor = overlapEnd;
        ++position;
    }
    for (auto& entry : additions) direction.pieces.emplace(entry.first, std::move(entry.second));
    mergeConflicts(direction);
    return true;
}

std::pair<Bytes, std::vector<std::uint64_t>> httpPrefix(const DirectionState& direction, std::size_t limit = HeaderLimit) {
    Bytes prefix;
    std::vector<std::uint64_t> ids;
    if (direction.pieces.empty()) return {prefix, ids};
    std::int64_t expected = direction.synSeen ? 0 : direction.pieces.begin()->first;
    for (const auto& entry : direction.pieces) {
        const auto end = entry.first + static_cast<std::int64_t>(entry.second.data.size());
        if (end <= expected) continue;
        if (entry.first > expected) break;
        const auto skip = static_cast<std::size_t>(expected - entry.first);
        const auto count = std::min(limit - prefix.size(), entry.second.data.size() - skip);
        prefix.insert(prefix.end(), entry.second.data.begin() + static_cast<std::ptrdiff_t>(skip),
                      entry.second.data.begin() + static_cast<std::ptrdiff_t>(skip + count));
        appendId(ids, entry.second.packetId);
        expected += static_cast<std::int64_t>(count);
        if (prefix.size() == limit) break;
    }
    return {std::move(prefix), std::move(ids)};
}

StreamDirection buildDirection(const ConnectionState& connection, std::size_t index, std::size_t limit) {
    const auto& state = connection.directions[index];
    StreamDirection result;
    result.source = index == 0 ? connection.info.a : connection.info.b;
    result.destination = index == 0 ? connection.info.b : connection.info.a;
    result.startIncomplete = !state.synSeen;
    result.truncated = state.captureTruncated || state.sequenceLimited;
    result.conflicts = state.conflicts;
    limit = std::min(limit, ContentLimit);
    std::int64_t expected = state.synSeen ? 0 : (state.pieces.empty() ? 0 : state.pieces.begin()->first);
    bool hasGap = false;
    bool contentLimited = false;

    for (const auto& entry : state.pieces) {
        const auto pieceEnd = entry.first + static_cast<std::int64_t>(entry.second.data.size());
        if (pieceEnd <= expected) continue;
        if (result.uniqueBytes == limit) {
            result.truncated = true;
            contentLimited = true;
            break;
        }
        if (entry.first > expected) {
            result.blocks.push_back({expected, {}, static_cast<std::uint64_t>(entry.first - expected), {}});
            hasGap = true;
            expected = entry.first;
        }
        const auto skip = static_cast<std::size_t>(expected - entry.first);
        const auto count = std::min(limit - result.uniqueBytes, entry.second.data.size() - skip);
        if (count == 0) continue;
        if (!result.blocks.empty() && result.blocks.back().gapLength == 0 &&
            result.blocks.back().offset + static_cast<std::int64_t>(result.blocks.back().data.size()) == expected) {
            auto& block = result.blocks.back();
            block.data.insert(block.data.end(), entry.second.data.begin() + static_cast<std::ptrdiff_t>(skip),
                              entry.second.data.begin() + static_cast<std::ptrdiff_t>(skip + count));
            appendId(block.packetIds, entry.second.packetId);
        } else {
            result.blocks.push_back({expected,
                Bytes(entry.second.data.begin() + static_cast<std::ptrdiff_t>(skip),
                      entry.second.data.begin() + static_cast<std::ptrdiff_t>(skip + count)),
                0, {entry.second.packetId}});
        }
        result.uniqueBytes += count;
        expected += static_cast<std::int64_t>(count);
        if (count < entry.second.data.size() - skip) {
            result.truncated = true;
            contentLimited = true;
            break;
        }
    }

    // FIN 的序号确定应用负载结束位置，缺失范围只保存位置和长度。
    if (!contentLimited && state.finEnd && *state.finEnd > expected) {
        result.blocks.push_back({expected, {}, static_cast<std::uint64_t>(*state.finEnd - expected), {}});
        hasGap = true;
    }

    std::vector<std::string> labels;
    if (result.startIncomplete) labels.emplace_back("捕获起始不完整");
    if (hasGap) labels.emplace_back("存在缺口");
    if (!result.conflicts.empty()) labels.emplace_back("存在重叠冲突");
    if (state.captureTruncated) labels.emplace_back("包含截断报文");
    if (state.sequenceLimited) labels.emplace_back("序号跨度超出处理范围");
    if (result.truncated && !state.captureTruncated && !state.sequenceLimited) labels.emplace_back("达到内容上限");
    if (result.uniqueBytes == 0) labels.emplace_back("尚未捕获应用负载");
    if (labels.empty()) labels.emplace_back("展示范围连续");
    for (const auto& label : labels) {
        if (!result.status.empty()) result.status += "；";
        result.status += label;
    }
    return result;
}
} // namespace

struct TcpTracker::Impl {
    std::map<std::uint64_t, ConnectionState> connections;
    std::map<ConnectionKey, std::uint64_t> active;
    std::uint64_t nextId = 1;

    ConnectionState& create(const ConnectionKey& key, bool midstream, bool makeActive = true) {
        ConnectionState state;
        state.info.id = nextId++;
        state.info.a = key.first;
        state.info.b = key.second;
        state.info.midstream = midstream;
        state.info.boundaryUncertain = midstream;
        const auto id = state.info.id;
        if (makeActive) active[key] = id;
        return connections.emplace(id, std::move(state)).first->second;
    }

    ConnectionState* matchSynAck(const ConnectionKey& key, std::size_t directionIndex,
                                std::uint32_t sequence, std::uint32_t acknowledgement) {
        ConnectionState* awaitingResponse = nullptr;
        for (auto it = connections.rbegin(); it != connections.rend(); ++it) {
            auto& candidate = it->second;
            if (!(candidate.info.a == key.first) || !(candidate.info.b == key.second)) continue;
            const auto& initiator = candidate.directions[1U - directionIndex];
            const auto& responder = candidate.directions[directionIndex];
            if (!initiator.synSeen) continue;
            const auto acknowledged = acknowledgement - initiator.synSequence;
            if (acknowledged < 1U || static_cast<std::uint64_t>(acknowledged) >
                                      1U + static_cast<std::uint64_t>(initiator.synPayloadLength)) continue;
            if (responder.synSeen) {
                if (responder.synSequence == sequence) return &candidate;
            } else if (!candidate.info.closed && !awaitingResponse) {
                awaitingResponse = &candidate;
            }
        }
        return awaitingResponse;
    }
};

TcpTracker::TcpTracker() : impl_(std::make_unique<Impl>()) {}
TcpTracker::~TcpTracker() = default;
TcpTracker::TcpTracker(TcpTracker&&) noexcept = default;
TcpTracker& TcpTracker::operator=(TcpTracker&&) noexcept = default;

TrackerUpdate TcpTracker::ingest(PacketRecord& packet) {
    TrackerUpdate update;
    if (!packet.hasTcp || !packet.hasPorts || packet.fragmented || packet.malformed ||
        (packet.source.family != 4 && packet.source.family != 6) ||
        packet.source.family != packet.destination.family) return update;
    const auto key = keyFor(packet);
    const std::size_t directionIndex = packet.source == key.first ? 0U : 1U;
    const bool syn = (packet.tcp.flags & Syn) != 0;
    const bool startingSyn = syn && (packet.tcp.flags & Ack) == 0;
    const Bytes payload = packet.payload();
    auto found = impl_->active.find(key);
    ConnectionState* connection = found == impl_->active.end() ? nullptr : &impl_->connections.at(found->second);
    bool matchedSynAck = false;
    bool preserveActive = false;
    if (syn && !startingSyn) {
        if (auto* matching = impl_->matchSynAck(key, directionIndex, packet.tcp.sequence,
                                              packet.tcp.acknowledgement)) {
            connection = matching;
            matchedSynAck = true;
        } else if (connection && connection->directions[1U - directionIndex].synSeen) {
            connection = nullptr;
            preserveActive = true;
        }
    }

    if (connection && startingSyn) {
        const auto& direction = connection->directions[directionIndex];
        const auto& reverse = connection->directions[1U - directionIndex];
        const bool retransmission = direction.synSeen && direction.synSequence == packet.tcp.sequence && !connection->info.closed;
        const auto earlierAcknowledged = reverse.synAcknowledgement - packet.tcp.sequence;
        const bool matchingEarlierSynAck = !direction.synSeen && reverse.synSeen &&
            earlierAcknowledged >= 1U && static_cast<std::uint64_t>(earlierAcknowledged) <= 1U + payload.size() &&
            !connection->info.closed;
        if (!retransmission && !matchingEarlierSynAck) connection = nullptr;
        if (matchingEarlierSynAck) {
            connection->info.midstream = false;
            connection->info.boundaryUncertain = false;
        }
    } else if (connection && syn && !matchedSynAck) {
        const auto& direction = connection->directions[directionIndex];
        if (connection->info.closed || (direction.synSeen && direction.synSequence != packet.tcp.sequence)) connection = nullptr;
    } else if (connection && connection->info.closed && packet.payloadLength != 0) {
        connection->info.boundaryUncertain = true;
    }
    if (!connection) connection = &impl_->create(key, !startingSyn, !preserveActive);
    auto& info = connection->info;
    auto& direction = connection->directions[directionIndex];
    packet.connectionId = info.id;
    update.connectionId = info.id;
    info.packetIds.push_back(packet.raw.id);
    if (syn) {
        establishReference(direction, packet.tcp.sequence + std::uint32_t{1}, true);
        direction.synSeen = true;
        direction.synSequence = packet.tcp.sequence;
        direction.synAcknowledgement = packet.tcp.acknowledgement;
        direction.synPayloadLength = std::max(direction.synPayloadLength, payload.size());
    }

    if (!payload.empty()) {
        info.payloadPacketIds.push_back(packet.raw.id);
        const auto payloadSequence = packet.tcp.sequence + (syn ? std::uint32_t{1} : std::uint32_t{0});
        if (!insertPayload(direction, payloadSequence, payload, packet.raw.id)) {
            packet.notices.emplace_back("TCP 序号跨度超出处理范围");
        }
    }
    direction.captureTruncated = direction.captureTruncated || packet.truncated;
    if ((packet.tcp.flags & Fin) != 0) {
        direction.finSeen = true;
        if (!packet.truncated) {
            const auto endingSequence = packet.tcp.sequence + (syn ? std::uint32_t{1} : std::uint32_t{0})
                                      + static_cast<std::uint32_t>(payload.size());
            establishReference(direction, endingSequence, false);
            const auto endingOffset = relativeSequence(endingSequence, direction.reference);
            if (!direction.finEnd) direction.finEnd = endingOffset;
            else if (*direction.finEnd != endingOffset) packet.notices.emplace_back("TCP FIN 结束位置存在差异。");
        }
    }
    if ((packet.tcp.flags & Rst) != 0) {
        info.reset = true;
        info.closed = true;
    }
    if (connection->directions[0].finSeen && connection->directions[1].finSeen) info.closed = true;

    bool newRecognition = false;
    if (!info.httpMessages[directionIndex] && !payload.empty()) {
        auto prefix = httpPrefix(direction);
        auto result = HttpParser::parse(prefix.first);
        if (result.state == HttpState::Recognized) {
            auto sourcePrefix = httpPrefix(direction, result.message.headerBytes);
            info.httpMessages[directionIndex] = std::move(result.message);
            info.httpSourcePacketIds[directionIndex] = std::move(sourcePrefix.second);
            info.http = true;
            newRecognition = true;
        } else if (result.state == HttpState::TooLarge && !result.message.version.empty()) {
            packet.notices.emplace_back("HTTP 头部超过 16 KiB 识别上限。");
        }
    }
    if (info.http && !payload.empty()) packet.add(Protocol::Http);
    if (newRecognition) update.httpPacketIds = info.payloadPacketIds;
    else if (info.http && !payload.empty()) update.httpPacketIds.push_back(packet.raw.id);
    return update;
}

const ConnectionInfo* TcpTracker::connection(std::uint64_t id) const {
    const auto found = impl_->connections.find(id);
    return found == impl_->connections.end() ? nullptr : &found->second.info;
}

std::optional<StreamView> TcpTracker::trace(std::uint64_t id, std::size_t contentLimit) const {
    const auto found = impl_->connections.find(id);
    if (found == impl_->connections.end()) return std::nullopt;
    StreamView result;
    result.connection = found->second.info;
    result.directions[0] = buildDirection(found->second, 0, contentLimit);
    result.directions[1] = buildDirection(found->second, 1, contentLimit);
    return result;
}

std::size_t TcpTracker::connectionCount() const { return impl_->connections.size(); }
void TcpTracker::clear() { impl_ = std::make_unique<Impl>(); }

std::string streamText(const StreamDirection& direction, bool hexadecimal) {
    std::ostringstream output;
    for (const auto& block : direction.blocks) {
        if (block.gapLength != 0) {
            output << "\n[缺失 " << block.gapLength << " 字节，起始偏移 " << block.offset << "]\n";
            continue;
        }
        if (hexadecimal) output << "[相对偏移 " << block.offset << "]\n" << hexDump(block.data, block.data.size());
        else output << printableText(block.data);
    }
    for (const auto& conflict : direction.conflicts) {
        output << "\n[重叠冲突：起始偏移 " << conflict.offset << "，长度 " << conflict.length << " 字节]\n";
    }
    return output.str();
}
} // namespace sniffer
