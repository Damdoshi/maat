#include "identity/bbs_replicated_gate.hpp"

namespace maat { namespace identity {
BbsReplicatedGate::BbsReplicatedGate(ReplicatedTrust& replica,BbsIssuerKey issuer,
                                     const std::string& service)
    :replica_(replica),issuer_(issuer),proofGate_(issuer,service) {}

std::array<std::uint8_t,32> BbsReplicatedGate::challenge() {
    return proofGate_.challenge();
}
bool BbsReplicatedGate::verifyAndConsume(const BbsNymPresentation& presentation,
                                         std::int64_t now,std::string& pseudonymHex) {
    pseudonymHex.clear();
    // Consume challenge even when the replica is stale or issuer revoked;
    // re-check the locally signed trust state AFTER cryptographic verification
    // to prevent accepting an issuer revoked during verification.
    std::string candidate;
    if (!proofGate_.verifyAndConsume(presentation,candidate) ||
        !replica_.bbsIssuerActive(issuer_,now)) return false;
    pseudonymHex.swap(candidate);
    return true;
}
}} // namespace maat::identity
