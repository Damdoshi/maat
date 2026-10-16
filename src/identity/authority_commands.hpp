#pragma once

#include "identity/citizen_registry.hpp"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace maat { namespace identity {

using Ed25519Signature = std::array<std::uint8_t, 64>;

enum class RegistryOperation : std::uint8_t {
    enroll = 1, add_key = 2, revoke_key = 3,
    revoke_citizen = 4, set_anonymous_permission = 5
};

// Domain-separated, fixed-width signed command; all fields are included in the
// signature. Exactly one operation per monotonically increasing sequence.
// Unused fields MUST be zero/empty, eliminating ambiguous interpretations.
struct AuthorityInstruction {
    RegistryOperation operation = RegistryOperation::enroll;
    std::uint64_t sequence = 0;
    Fingerprint registryId{};         // Random public namespace, pinned at bootstrap.
    std::string citizenId;            // Empty for enroll.
    Fingerprint subjectCommitment{}; // Only for enroll.
    Fingerprint publicKey{};         // Enroll, add_key, revoke_key.
    AnonymousPermission permission = AnonymousPermission::denied;
};

// Deterministic signing bytes, not JSON or text serialization. This API does
// not sign commands and never accepts a private key. Throws on invalid fields.
std::vector<std::uint8_t> authoritySigningBytes(const AuthorityInstruction& command);

struct AuthorityResult {
    bool changed = false;
    std::string citizenId; // Returned only for successful enrollment.
};

// Security boundary for authority-issued registry mutations. The persistent
// authority public key is pinned during an explicit, privileged bootstrap.
// An externally signed command is verified with Ed25519, checked for replay,
// applied and journalled atomically in one SQLite transaction.
// This is a library for a private trusted process, NOT a network daemon.
class RegistryAuthority final {
    CitizenRegistry& registry_;
    Fingerprint publicKey_;
    Fingerprint registryId_;
public:
    static void bootstrap(CitizenRegistry& registry, const Fingerprint& publicKey,
                          const Fingerprint& registryId);
    RegistryAuthority(CitizenRegistry& registry, const Fingerprint& pinnedPublicKey,
                      const Fingerprint& registryId);
    AuthorityResult apply(const AuthorityInstruction& command,
                          const Ed25519Signature& signature);
};

}} // namespace maat::identity
