#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace maat { namespace identity {

// EXPERIMENTAL: ONLY proves that an issuer-pinned BBS signature covers a
// fixed 'active' message and that a pseudonym is cryptographically bound to
// the holder's hidden nym secret and to this verifier's scope.
// NOT civil identity verification; NOT an online revocation check; never set
// $_AUTH.identity_verified or replace the existing SSH authorization path.
struct BbsNymPresentation final {
    std::array<std::uint8_t, 32> challenge{};
    std::array<std::uint8_t, 48> pseudonym{};
    std::vector<std::uint8_t> proof;
};

class BbsPresentationGate final {
    const std::array<std::uint8_t, 96> issuerPublicKey_;
    const std::string serviceId_;
    std::mutex mutex_;
    std::map<std::array<std::uint8_t, 32>, std::chrono::steady_clock::time_point> pending_;
public:
    BbsPresentationGate(std::array<std::uint8_t, 96> trustedIssuerKey,
                        const std::string& canonicalServiceId);
    BbsPresentationGate(const BbsPresentationGate&) = delete;
    BbsPresentationGate& operator=(const BbsPresentationGate&) = delete;

    // Verifier-owned 32-byte random challenge, valid 60 seconds. No caller-
    // supplied nonce or scope. May throw on OS randomness failure.
    std::array<std::uint8_t, 32> challenge();

    // Consumes challenge BEFORE invoking the crypto backend, including on
    // malformed/invalid proof, failure, and missing Rust backend.
    // On success returns the hex-encoded service-specific pseudonym for
    // caller-side ban policy; false always when BBS backend is unavailable.
    bool verifyAndConsume(const BbsNymPresentation& presentation,
                          std::string& scopedPseudonymHex);
};

}} // namespace maat::identity
