// End-to-end TEST fixture: Rust BBS issuance/proof -> native C++ proof gate.
// This test intentionally has no administrative or SSH integration.
#include "identity/bbs_presentation_gate.hpp"
#include "identity/bbs_replicated_gate.hpp"
#include <openssl/evp.h>

#include <array>
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

using maat::identity::BbsNymPresentation;
using maat::identity::BbsPresentationGate;
using maat::identity::BbsReplicatedGate;
using maat::identity::ReplicatedTrust;
using maat::identity::TrustDelta;
using maat::identity::TrustHash;
using maat::identity::TrustOperation;

#define CHECK(expr) do { \
    if (!(expr)) throw std::runtime_error("CHECK failed: " #expr); \
} while (0)

namespace {
struct Fixture {
    std::array<std::uint8_t, 96> publicKey{};
    std::vector<std::uint8_t> proof;
    std::array<std::uint8_t, 48> pseudonym{};
};

std::string hex(const std::uint8_t* data, std::size_t count) {
    const char* alphabet = "0123456789abcdef";
    std::string output;
    output.reserve(count * 2);
    for (std::size_t i = 0; i < count; ++i) {
        output.push_back(alphabet[data[i] >> 4]);
        output.push_back(alphabet[data[i] & 15]);
    }
    return output;
}

std::vector<std::uint8_t> decode(const std::string& encoded) {
    if (encoded.size() % 2 != 0) throw std::runtime_error("odd fixture hex");
    auto digit = [](unsigned char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return -1;
    };
    std::vector<std::uint8_t> bytes;
    bytes.reserve(encoded.size() / 2);
    for (std::size_t i = 0; i < encoded.size(); i += 2) {
        int high = digit(static_cast<unsigned char>(encoded[i]));
        int low = digit(static_cast<unsigned char>(encoded[i+1]));
        if (high < 0 || low < 0) throw std::runtime_error("invalid fixture hex");
        bytes.push_back(static_cast<std::uint8_t>((high << 4) | low));
    }
    return bytes;
}

template <std::size_t N>
void assign(const std::string& encoded, std::array<std::uint8_t, N>& dst) {
    const std::vector<std::uint8_t> v = decode(encoded);
    if (v.size() != N) throw std::runtime_error("fixture field has wrong size");
    std::copy(v.begin(), v.end(), dst.begin());
}

// Avoid invoking a shell even in tests. Only non-secret, controlled arguments.
Fixture generate(const std::string& service,
                 const std::array<std::uint8_t, 32>& challenge,
                 const char* prover="42", const char* entropy="9") {
    int fds[2];
    if (pipe(fds) < 0) throw std::runtime_error("pipe failed");
    const std::string challengeHex = hex(challenge.data(), challenge.size());
    const pid_t pid = fork();
    if (pid < 0) {
        close(fds[0]); close(fds[1]);
        throw std::runtime_error("fork failed");
    }
    if (pid == 0) {
        close(fds[0]);
        if (dup2(fds[1], STDOUT_FILENO) == -1) _exit(127);
        close(fds[1]);
        execl(MAAT_BBS_TEST_FIXTURE_PATH, MAAT_BBS_TEST_FIXTURE_PATH,
              service.c_str(), challengeHex.c_str(), prover, entropy,
              static_cast<char*>(nullptr));
        _exit(127);
    }
    close(fds[1]);
    std::string output;
    char buf[4096];
    ssize_t bytes = 0;
    while ((bytes = read(fds[0], buf, sizeof(buf))) > 0) {
        output.append(buf, static_cast<std::size_t>(bytes));
        if (output.size() > 200000) break;
    }
    close(fds[0]);
    int status = 0;
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0 || output.size() > 200000)
        throw std::runtime_error("Rust BBS fixture generation failed");

    Fixture fixture;
    unsigned fields = 0;
    std::size_t start = 0;
    while (start < output.size()) {
        std::size_t end = output.find('\n', start);
        if (end == std::string::npos) end = output.size();
        const std::string line = output.substr(start, end - start);
        if (line.compare(0, 3, "PK=") == 0) {
            assign(line.substr(3), fixture.publicKey); fields |= 1;
        } else if (line.compare(0, 6, "PROOF=") == 0) {
            fixture.proof = decode(line.substr(6)); fields |= 2;
        } else if (line.compare(0, 4, "NYM=") == 0) {
            assign(line.substr(4), fixture.pseudonym); fields |= 4;
        } else if (!line.empty()) {
            throw std::runtime_error("unexpected fixture output");
        }
        start = end + 1;
    }
    if (fields != 7) throw std::runtime_error("incomplete BBS fixture");
    return fixture;
}

BbsNymPresentation presentation(const std::array<std::uint8_t, 32>& challenge,
                                const Fixture& fixture) {
    BbsNymPresentation p;
    p.challenge = challenge;
    p.proof = fixture.proof;
    p.pseudonym = fixture.pseudonym;
    return p;
}
}

int main() {
    // Test fixture key is fixed and PUBLIC. Never a real citizen credential.
    std::array<std::uint8_t, 32> arbitrary{};
    arbitrary.fill(0x31);
    const Fixture first = generate("forum.example", arbitrary);
    BbsPresentationGate forum(first.publicKey, "forum.example");
    BbsPresentationGate chat(first.publicKey, "chat.example");
    std::string scoped;

    auto ch1 = forum.challenge();
    Fixture valid = generate("forum.example", ch1);
    CHECK(forum.verifyAndConsume(presentation(ch1, valid), scoped));
    CHECK(scoped == hex(valid.pseudonym.data(), valid.pseudonym.size()));
    CHECK(!forum.verifyAndConsume(presentation(ch1, valid), scoped)); // replay
    CHECK(scoped.empty());

    auto ch2 = forum.challenge();
    Fixture renewal = generate("forum.example", ch2);
    CHECK(renewal.pseudonym == valid.pseudonym); // stability after proof renewal
    CHECK(forum.verifyAndConsume(presentation(ch2, renewal), scoped));

    auto ch3 = chat.challenge();
    Fixture differentService = generate("chat.example", ch3);
    CHECK(differentService.pseudonym != valid.pseudonym); // scope separation
    CHECK(chat.verifyAndConsume(presentation(ch3, differentService), scoped));

    auto ch4 = chat.challenge();
    Fixture wrongService = generate("forum.example", ch4);
    CHECK(!chat.verifyAndConsume(presentation(ch4, wrongService), scoped));

    auto ch5 = forum.challenge();
    Fixture wrongChallenge = generate("forum.example", arbitrary);
    CHECK(!forum.verifyAndConsume(presentation(ch5, wrongChallenge), scoped));

    auto ch6 = forum.challenge();
    Fixture changed = generate("forum.example", ch6);
    changed.proof[changed.proof.size() / 2] ^= 0x01;
    CHECK(!forum.verifyAndConsume(presentation(ch6, changed), scoped));

    auto ch7 = forum.challenge();
    Fixture changedNym = generate("forum.example", ch7, "43", "9");
    CHECK(changedNym.pseudonym != valid.pseudonym); // unbound secret is NOT anti-Sybil
    CHECK(forum.verifyAndConsume(presentation(ch7, changedNym), scoped));

    auto ch8 = forum.challenge();
    Fixture changedEntropy = generate("forum.example", ch8, "42", "10");
    CHECK(changedEntropy.pseudonym != valid.pseudonym); // issuer entropy must be pinned
    CHECK(forum.verifyAndConsume(presentation(ch8, changedEntropy), scoped));

    // Real BBS proof + *offline* signed replicated-issuer authorization.
    // This exercises issuer-wide revocation, not anonymous-holder revocation.
    const TrustHash namespaceId = []{TrustHash id{}; id.fill(0x19); return id;}();
    const TrustHash secret = []{TrustHash key{}; key.fill(0x35); return key;}();
    EVP_PKEY* authority = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519,nullptr,
                                                        secret.data(),secret.size());
    CHECK(authority!=nullptr);
    TrustHash authorityPk{};
    std::size_t publicLen=authorityPk.size();
    CHECK(EVP_PKEY_get_raw_public_key(authority,authorityPk.data(),&publicLen)==1 &&
          publicLen==32);
    char location[]="/tmp/maat-bbs-trust-e2e-XXXXXX";
    CHECK(mkdtemp(location)!=nullptr);
    const std::string storePath=std::string(location)+"/public.sqlite";
    {
        ReplicatedTrust trust(storePath,namespaceId,authorityPk);
        BbsReplicatedGate local(trust,first.publicKey,"forum.example");
        constexpr std::int64_t current=1792166400;
        auto publish=[&](TrustOperation operation,const std::vector<std::uint8_t>& key) {
            TrustDelta d;
            d.registryId=namespaceId;
            d.sequence=trust.sequence()+1;
            d.previousHash=trust.headHash();
            d.issuedAt=current-5;
            d.validUntil=current+3600;
            d.operation=operation;
            d.publicKey=key;
            auto payload=maat::identity::trustDeltaSigningBytes(d);
            EVP_MD_CTX* ctx=EVP_MD_CTX_new();
            CHECK(ctx!=nullptr);
            std::size_t len=d.signature.size();
            const bool ok=EVP_DigestSignInit(ctx,nullptr,nullptr,nullptr,authority)==1 &&
                EVP_DigestSign(ctx,d.signature.data(),&len,payload.data(),payload.size())==1 &&
                len==d.signature.size();
            EVP_MD_CTX_free(ctx);
            CHECK(ok);
            trust.applyEncoded(maat::identity::encodeTrustDelta(d),current);
        };
        auto ch9=local.challenge();
        Fixture proof9=generate("forum.example",ch9);
        CHECK(!local.verifyAndConsume(presentation(ch9,proof9),current,scoped));
        CHECK(scoped.empty()); // missing trust state
        publish(TrustOperation::heartbeat,{});
        auto ch10=local.challenge();
        Fixture proof10=generate("forum.example",ch10);
        CHECK(!local.verifyAndConsume(presentation(ch10,proof10),current,scoped));
        CHECK(scoped.empty()); // signed trust state, issuer not enrolled
        publish(TrustOperation::add_bbs_issuer,
                std::vector<std::uint8_t>(first.publicKey.begin(),first.publicKey.end()));
        auto ch11=local.challenge();
        Fixture proof11=generate("forum.example",ch11);
        CHECK(local.verifyAndConsume(presentation(ch11,proof11),current,scoped));
        CHECK(scoped==hex(proof11.pseudonym.data(),proof11.pseudonym.size()));
        auto ch12=local.challenge();
        Fixture proof12=generate("forum.example",ch12);
        CHECK(!local.verifyAndConsume(presentation(ch12,proof12),current+3600,scoped));
        CHECK(scoped.empty()); // expired cache always fails closed
        publish(TrustOperation::revoke_bbs_issuer,
                std::vector<std::uint8_t>(first.publicKey.begin(),first.publicKey.end()));
        auto ch13=local.challenge();
        Fixture proof13=generate("forum.example",ch13);
        CHECK(!local.verifyAndConsume(presentation(ch13,proof13),current,scoped));
        CHECK(scoped.empty()); // authentic BBS proof, now revoked issuer
    }
    EVP_PKEY_free(authority);
    std::remove(storePath.c_str());
    std::remove((storePath+"-wal").c_str());
    std::remove((storePath+"-shm").c_str());
    rmdir(location);

    std::cout << "PASS Rust-issued BBS proof verified from C++, per-service pseudonym, "
                 "one-use challenge, scope/mutation rejection; "
                 "renewal bypass remains to be solved; offline signed issuer revocation works\n";
}
