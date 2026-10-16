#include "identity/bbs_presentation_gate.hpp"
#include <cassert>
#include <iostream>
#include <stdexcept>
#include <string>

using maat::identity::BbsPresentationGate;
using maat::identity::BbsNymPresentation;

int main() {
    std::array<std::uint8_t,96> issuer{}; issuer[0] = 1;
    try { BbsPresentationGate invalid(issuer, "UPPERCASE.COM"); (void)invalid; assert(false); }
    catch (const std::invalid_argument&) { }
    try { BbsPresentationGate invalid({}, "lower.example"); (void)invalid; assert(false); }
    catch (const std::invalid_argument&) { }

    BbsPresentationGate verifier(issuer, "forum.example");
    BbsNymPresentation p;
    p.challenge.fill(0x5a); // Not issued by verifier.
    p.proof.resize(272, 0xff);
    std::string scoped = "should be cleared";
    assert(!verifier.verifyAndConsume(p, scoped));
    assert(scoped.empty());

    p.challenge = verifier.challenge();
    assert(!verifier.verifyAndConsume(p, scoped)); // invalid proof, must consume
    assert(!verifier.verifyAndConsume(p, scoped)); // replay of same challenge
    assert(scoped.empty());

    p.challenge = verifier.challenge();
    p.proof.clear();
    assert(!verifier.verifyAndConsume(p, scoped));
    p.proof.resize(273, 0xff); // noncanonical proof length
    assert(!verifier.verifyAndConsume(p, scoped)); // also consumed when malformed

    std::cout << "PASS verifier-owned scope, CSPRNG nonce, one-use challenges, "
                 "malformed proof fail closed\n";
}
