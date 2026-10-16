#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>

struct sqlite3;

namespace maat {
namespace identity {

// Fixed-length, opaque values. A subject commitment is an authority-generated,
// secret-keyed commitment: NEVER a plain hash of a civil number or a name.
using Fingerprint = std::array<std::uint8_t, 32>;

enum class CitizenStatus { active = 1, revoked = 2 };
enum class AnonymousPermission { denied = 0, allowed = 1, suspended = 2 };

struct CitizenRecord {
    std::string id;
    CitizenStatus status;
    AnonymousPermission anonymous;
};

// Private administrative store; all mutations go through RegistryAuthority,
// which verifies signed commands and enforces a persistent replay counter.
// Never expose this database to SSH/HTTP workers.
class RegistryAuthority;
class ScopedCredentialIssuer;
class ScopeFreeCredentialIssuer;
class BbsBoundIssuer;
class CitizenRegistry final {
    friend class RegistryAuthority;
    friend class ScopedCredentialIssuer;
    friend class ScopeFreeCredentialIssuer;
    friend class BbsBoundIssuer;
    sqlite3* db_ = nullptr;

    // Raw SQL invariants; intentionally private to enforce the signing gate.
    std::string enroll(const Fingerprint& subjectCommitment,
                       const Fingerprint& initialEd25519Key);
    bool addKey(const std::string& citizenId, const Fingerprint& ed25519Key);
    bool revokeKey(const std::string& citizenId, const Fingerprint& ed25519Key);
    bool revokeCitizen(const std::string& citizenId);
    bool setAnonymousPermission(const std::string& citizenId,
                                AnonymousPermission permission);
public:
    explicit CitizenRegistry(const std::string& databasePath);
    ~CitizenRegistry();
    CitizenRegistry(const CitizenRegistry&) = delete;
    CitizenRegistry& operator=(const CitizenRegistry&) = delete;

    std::optional<CitizenRecord> lookup(const std::string& citizenId) const;
    // Administrative lookup only. Never expose this mapping to a web service.
    std::optional<std::string> activeKeyOwner(const Fingerprint& ed25519Key) const;
};

// Deliberately separate from CitizenRegistry: a service keeps only a scoped
// anonymous nullifier, not a citizen ID, civil identity or SSH public key.
// A future *verified* proof must bind the nullifier deterministically to
// (citizen secret, service scope), even across credential/key renewals.
class ServiceBanLedger final {
    sqlite3* db_ = nullptr;
public:
    explicit ServiceBanLedger(const std::string& databasePath);
    ~ServiceBanLedger();
    ServiceBanLedger(const ServiceBanLedger&) = delete;
    ServiceBanLedger& operator=(const ServiceBanLedger&) = delete;

    bool ban(const std::string& serviceId, const Fingerprint& scopedNullifier);
    bool unban(const std::string& serviceId, const Fingerprint& scopedNullifier);
    bool isBanned(const std::string& serviceId, const Fingerprint& scopedNullifier) const;
};

} // namespace identity
} // namespace maat
