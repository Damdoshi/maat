#pragma once

#include "identity/authority_commands.hpp"

#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace maat { namespace identity {

// Alpha4 prepares for BBS + per-verifier linkability. It is NOT a BBS/ZK
// implementation. In particular, the scope-free credential below MUST NEVER
// be forwarded to a service: its stable commitment is globally linkable.
// No SSH, broker, Apache, PHP or public service accepts this credential.
struct ScopeFreeCredential final {
    Fingerprint registryId{};
    Fingerprint serial{};
    Fingerprint nymCommitment{};
    std::uint64_t notBefore = 0;
    std::uint64_t expiresAt = 0;
    Ed25519Signature issuerSignature{};
};

struct ScopeFreeIssueRequest final {
    Fingerprint citizenKey{};     // Only the private issuer sees it.
    Fingerprint nymCommitment{};  // Stable, unique *per citizen* in private DB.
    Fingerprint challenge{};      // One-use challenge from issuer.
    Ed25519Signature citizenSignature{};
    // Deliberately NO service ID or service challenge in this request.
};

// Serialization of domain-separated, canonical Ed25519 transcripts.
std::vector<std::uint8_t> scopeFreeRequestBytes(const Fingerprint& registryId,
                                                 const ScopeFreeIssueRequest& request);
std::vector<std::uint8_t> scopeFreeCredentialBytes(const ScopeFreeCredential& credential);

// Holder-side aids for future anonymous credential proof. The commitment is
// SHA256(domain || secret) for a prototype ONLY; a BBS nym proof will require
// the secret-binding construction from its vetted specification. This local
// candidate nullifier has NO verifying value until such a proof is available.
Fingerprint prototypeNymCommitment(const Fingerprint& holderSecret);
Fingerprint unverifiedLocalScopeNullifier(const Fingerprint& holderSecret,
                                          const Fingerprint& registryId,
                                          const std::string& serviceId);

class CitizenRegistry;
class ScopeFreeCredentialIssuer final {
    CitizenRegistry& registry_;
    Fingerprint registryId_{};
    Fingerprint signingSeed_{};
    std::mutex mutex_;
    std::map<Fingerprint, std::int64_t> challenges_;
public:
    // Only called in an explicitly privileged provisioning process.
    static void bootstrap(CitizenRegistry& registry, const Fingerprint& registryId,
                          const Fingerprint& issuerSeed);
    ScopeFreeCredentialIssuer(CitizenRegistry& registry, const Fingerprint& registryId,
                              const Fingerprint& issuerSeed);
    ~ScopeFreeCredentialIssuer();
    ScopeFreeCredentialIssuer(const ScopeFreeCredentialIssuer&) = delete;
    ScopeFreeCredentialIssuer& operator=(const ScopeFreeCredentialIssuer&) = delete;

    Fingerprint challenge();
    ScopeFreeCredential issue(const ScopeFreeIssueRequest& request);
};

}} // namespace maat::identity
