#pragma once

#include "identity/authority_commands.hpp"

#include <array>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace maat { namespace identity {

class CitizenRegistry;

// Sensitive private issuer protocol. Never serialize BbsBoundIssueRequest to
// a relying website: its fixed anchor links every enrollment/renewal.
struct BbsBoundIssueRequest final {
    Fingerprint citizenKey{};
    Fingerprint challenge{};
    std::array<std::uint8_t,48> nymAnchor{};
    std::array<std::uint8_t,144> commitment{};
    std::array<std::uint8_t,80> bindingProof{};
    Ed25519Signature citizenSignature{};
};
struct BbsBoundCredential final {
    std::array<std::uint8_t,80> blindSignature{};
};

// Canonical holder-signed request; no service name, address, or context.
std::vector<std::uint8_t> bbsBoundRequestBytes(const Fingerprint& registryId,
                                               const BbsBoundIssueRequest& request);

class BbsBoundIssuer final {
    CitizenRegistry& registry_;
    Fingerprint registryId_{};
    Fingerprint bbsSeed_{};
    Fingerprint entropyKey_{};
    std::array<std::uint8_t,96> issuerPublicKey_{};
    std::mutex mutex_;
    std::mutex issueMutex_;
    std::map<Fingerprint,std::int64_t> challenges_;
public:
    // Privileged provisioning only; refuses secret/key replacement once pinned.
    static void bootstrap(CitizenRegistry& registry, const Fingerprint& registryId,
                          const Fingerprint& bbsSeed, const Fingerprint& entropyKey);
    BbsBoundIssuer(CitizenRegistry& registry, const Fingerprint& registryId,
                   const Fingerprint& bbsSeed, const Fingerprint& entropyKey);
    ~BbsBoundIssuer();
    BbsBoundIssuer(const BbsBoundIssuer&) = delete;
    BbsBoundIssuer& operator=(const BbsBoundIssuer&) = delete;

    std::array<std::uint8_t,96> issuerPublicKey() const { return issuerPublicKey_; }
    Fingerprint challenge();
    BbsBoundCredential issue(const BbsBoundIssueRequest& request);
};

}} // namespace maat::identity
