#pragma once

#include "identity/bbs_presentation_gate.hpp"
#include "identity/replicated_trust.hpp"

namespace maat { namespace identity {

// BBS proofs use ONLY a locally replicated, authority-signed issuer key set.
// NO citizen key is revealed or looked up during an anonymous presentation.
// CRITICAL: this blocks revoked ISSUERS, not revoked INDIVIDUAL holders.
class BbsReplicatedGate final {
    ReplicatedTrust& replica_;
    const BbsIssuerKey issuer_;
    BbsPresentationGate proofGate_;
public:
    BbsReplicatedGate(ReplicatedTrust& replica, BbsIssuerKey issuer,
                      const std::string& canonicalServiceId);
    std::array<std::uint8_t,32> challenge();
    bool verifyAndConsume(const BbsNymPresentation& presentation,
                          std::int64_t localUnixSeconds, std::string& pseudonymHex);
};

}} // namespace maat::identity
