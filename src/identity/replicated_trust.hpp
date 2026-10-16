#pragma once

#include <array>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

struct sqlite3;

namespace maat { namespace identity {

// This database is a node-local PUBLIC-KEY CACHE, never a citizen identity
// directory exposed to an anonymous BBS verifier. Signed deltas travel over
// untrusted gossip; the authority is not contacted for a verification.
using TrustHash = std::array<std::uint8_t, 32>;
using TrustSignature = std::array<std::uint8_t, 64>;
using BbsIssuerKey = std::array<std::uint8_t, 96>;

enum class TrustOperation : std::uint8_t {
    heartbeat = 0,
    add_citizen_key = 1,
    revoke_citizen_key = 2,
    add_bbs_issuer = 3,
    revoke_bbs_issuer = 4
};

// Canonical signed, hash-chained gossip event. Public-key revocations are
// tombstones; a key cannot be resurrected after revocation. Individual
// anonymous-BBS credential revocation is NOT provided by this data structure.
struct TrustDelta final {
    TrustHash registryId{};
    std::uint64_t sequence = 0;
    std::int64_t issuedAt = 0;
    std::int64_t validUntil = 0;
    TrustHash previousHash{};
    TrustOperation operation = TrustOperation::heartbeat;
    std::vector<std::uint8_t> publicKey;
    TrustSignature signature{};
};

// Network bytes are authenticated: decode first, verify before applying.
// Signing bytes have domain separation and a strict, architecture-independent
// binary format; the signature is appended only by encodeTrustDelta().
std::vector<std::uint8_t> trustDeltaSigningBytes(const TrustDelta& delta);
std::vector<std::uint8_t> encodeTrustDelta(const TrustDelta& delta);
TrustDelta decodeTrustDelta(const std::vector<std::uint8_t>& encoded);
TrustHash trustDeltaHash(const TrustDelta& delta);

class ReplicatedTrust final {
    sqlite3* db_ = nullptr;
    TrustHash registryId_{};
    TrustHash authorityPublicKey_{};
    mutable std::mutex mutex_;
public:
    // Bootstrap requires independently authenticated registry ID and Ed25519
    // authority public key. Neither can be replaced by a gossip message.
    ReplicatedTrust(const std::string& path, TrustHash registryId,
                    TrustHash authorityPublicKey);
    ~ReplicatedTrust();
    ReplicatedTrust(const ReplicatedTrust&) = delete;
    ReplicatedTrust& operator=(const ReplicatedTrust&) = delete;

    // nowSeconds is verifier-local UTC Unix time. No network I/O.
    // Throws on malformed, invalid, forked, replayed, expired or unsigned data.
    void apply(const TrustDelta& delta, std::int64_t nowSeconds);
    void applyEncoded(const std::vector<std::uint8_t>& wire, std::int64_t nowSeconds);
    // Atomic bounded historical catch-up; expired earlier deltas never grant
    // authorization while the most recent signed head is stale.
    void applyHistoricalBatch(const std::vector<TrustDelta>& deltas,
                              std::int64_t nowSeconds);
    void validateSignedPeerEvent(const TrustDelta& event,std::int64_t nowSeconds) const;
    void observeSignedPeerEvent(const TrustDelta& event,std::int64_t nowSeconds);
    std::vector<TrustDelta> historyAfter(std::uint64_t cursor,
                                        const TrustHash& cursorHash,
                                        std::size_t maxEvents) const;
    bool historicalEvent(std::uint64_t sequence,TrustDelta& out) const;
    // Gossipable independent proof of authority equivocation: TWO distinct
    // authenticated events at the identical registry sequence. A third-party
    // node may quarantine without having adopted either branch.
    void observeSignedForkPair(const TrustDelta& first,const TrustDelta& second,
                               std::int64_t nowSeconds);
    bool forkProof(TrustDelta& first,TrustDelta& second) const;
    bool forked() const;
    bool fresh(std::int64_t nowSeconds) const;
    bool citizenKeyActive(const TrustHash& key, std::int64_t nowSeconds) const;
    bool bbsIssuerActive(const BbsIssuerKey& key, std::int64_t nowSeconds) const;
    TrustHash registryId() const {return registryId_;}
    std::uint64_t sequence() const;
    TrustHash headHash() const;
};

}} // namespace maat::identity
