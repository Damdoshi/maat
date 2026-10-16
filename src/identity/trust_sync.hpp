#pragma once
#include "identity/replicated_trust.hpp"
#include <cstdint>
#include <iosfwd>
#include <vector>

namespace maat { namespace identity {

// Alpha8: strictly bounded PUBLIC signed-event sync over byte streams.
// The stream must be carried over a dedicated, separately configured SSH
// channel with forced command and a pinned SSH host key. Neither an SSH peer
// nor any protocol field grants authority to add keys.
constexpr std::uint16_t kTrustSyncMaxEvents=64;

enum class TrustSyncStatus : std::uint8_t {
    events=0, cursor_conflict=1, history_unavailable=2,
    peer_behind=3, wrong_registry=4, fork_quarantine=5
};
struct TrustSyncRequest {
    TrustHash registryId{};
    std::uint64_t cursor=0;
    TrustHash cursorHash{};
    std::uint16_t maxEvents=kTrustSyncMaxEvents;
    // A signed, optional *witness* to the requester's last event. The server
    // can detect a signed fork, not merely an arbitrary untrusted hash claim.
    std::vector<std::uint8_t> cursorEvidence;
};
struct TrustSyncResponse {
    TrustSyncStatus status=TrustSyncStatus::events;
    std::uint64_t peerSequence=0; // informational, NEVER trusted alone
    TrustHash peerHead{};
    std::vector<std::uint8_t> tipEvidence; // peer's signed last event
    // On fork quarantine, independently verifiable signed contradictory pair;
    // a peer's bare claim of quarantine never forces local quarantine.
    std::vector<std::uint8_t> forkA;
    std::vector<std::uint8_t> forkB;
    std::vector<std::vector<std::uint8_t>> events; // at most 64 bounded events
};

TrustSyncRequest makeTrustSyncRequest(const ReplicatedTrust& local,
                                     std::uint16_t maxEvents=kTrustSyncMaxEvents);
TrustSyncResponse answerTrustSync(ReplicatedTrust& local,
                                  const TrustSyncRequest& request,
                                  std::int64_t now);
// Signature-check all data; atomically apply the batch only if its full chain
// matches the request cursor. On an AUTHENTIC signed fork, persist quarantine.
// Returns number of newly applied events; never returns an identity decision.
std::size_t acceptTrustSync(ReplicatedTrust& local,
                            const TrustSyncRequest& request,
                            const TrustSyncResponse& response,
                            std::int64_t now);
void writeTrustSyncRequest(std::ostream& out,const TrustSyncRequest& request);
bool readTrustSyncRequest(std::istream& in,TrustSyncRequest& request);
void writeTrustSyncResponse(std::ostream& out,const TrustSyncResponse& response);
TrustSyncResponse readTrustSyncResponse(std::istream& in);

}} // namespace maat::identity
