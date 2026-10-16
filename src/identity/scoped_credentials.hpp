#pragma once

#include "identity/citizen_registry.hpp"
#include "identity/authority_commands.hpp"

#include <array>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace maat { namespace identity {

// 0.20-alpha3 is an explicitly *issuer-mediated*, privacy-scoped credential,
// NOT an anonymous ZK credential. The trusted issuer knows the citizen and the
// requested service. The service only receives an issuer-signed nullifier,
// a short-lived holder key, and a scope; no citizen ID or permanent SSH key.
// Signed messages are canonical, length-delimited and domain-separated.
struct ScopedCredential {
    Fingerprint registryId{};
    Fingerprint serial{};
    Fingerprint nullifier{};
    Fingerprint holderKey{};
    std::string serviceId;
    std::uint64_t notBefore = 0;
    std::uint64_t expiresAt = 0;
    Ed25519Signature issuerSignature{};
};

struct CredentialRequest {
    Fingerprint citizenKey{};  // Presented ONLY to the trusted issuer.
    Fingerprint holderKey{};   // An independent, fresh Ed25519 public key.
    Fingerprint challenge{};   // One-use challenge from the issuer.
    std::string serviceId;
    Ed25519Signature citizenSignature{};
};

std::vector<std::uint8_t> credentialRequestBytes(const Fingerprint& registryId,
                                                   const CredentialRequest& request);
std::vector<std::uint8_t> credentialSigningBytes(const ScopedCredential& credential);
std::vector<std::uint8_t> credentialPresentationBytes(const ScopedCredential& credential,
                                                        const Fingerprint& challenge);

// Trusted, private *issuer* service; keep its two secrets outside the registry
// DB and never provide this object to an SSH/HTTP worker or public endpoint.
// A distinct issuer Ed25519 key is used (NOT the offline authority command key).
class ScopedCredentialIssuer final {
    CitizenRegistry& registry_;
    Fingerprint registryId_{};
    Fingerprint signingSeed_{};
    Fingerprint nullifierSecret_{};
    std::mutex mutex_;
    std::map<Fingerprint, std::int64_t> challenges_;
public:
    static void bootstrap(CitizenRegistry& registry, const Fingerprint& registryId,
                          const Fingerprint& issuerSigningSeed,
                          const Fingerprint& nullifierSecret);
    ScopedCredentialIssuer(CitizenRegistry& registry, const Fingerprint& registryId,
                           const Fingerprint& issuerSigningSeed,
                           const Fingerprint& nullifierSecret);
    ~ScopedCredentialIssuer();
    ScopedCredentialIssuer(const ScopedCredentialIssuer&) = delete;
    ScopedCredentialIssuer& operator=(const ScopedCredentialIssuer&) = delete;

    Fingerprint challenge();
    ScopedCredential issue(const CredentialRequest& request);
};

// The service has ONLY issuer's public key, a pinned registry namespace and
// its own private ban DB. Every presentation requires a freshly generated,
// one-use challenge and a signature by the short-lived holder private key.
// This API intentionally has NO method returning a citizen ID and has NO
// authority to set SSH/PHP identity_verified.
class ScopedCredentialVerifier final {
    Fingerprint issuerPublicKey_{};
    Fingerprint registryId_{};
    std::string serviceId_;
    ServiceBanLedger& bans_;
    std::mutex mutex_;
    std::map<Fingerprint, std::int64_t> challenges_;
public:
    ScopedCredentialVerifier(const Fingerprint& issuerPublicKey,
                             const Fingerprint& registryId, std::string serviceId,
                             ServiceBanLedger& bans);
    Fingerprint challenge();
    bool verify(const ScopedCredential& credential, const Fingerprint& challenge,
                const Ed25519Signature& holderSignature);
};

}} // namespace maat::identity
