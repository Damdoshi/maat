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
#include <fstream>
#include <ctime>
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
        execl("/opt/maat/bin/maat-bbs-fixture", "/opt/maat/bin/maat-bbs-fixture",
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

int main(int argc,char** argv) {
    try {
        CHECK(argc==3);
        const std::string dir=argv[1];
        const bool expected=std::string(argv[2])=="allow";
        CHECK(expected || std::string(argv[2])=="deny");
        std::ifstream roots(dir+"/root.txt");
        std::string id,authority,citizen;
        CHECK(static_cast<bool>(roots>>id>>authority>>citizen));
        TrustHash registry{};
        TrustHash authorityKey{};
        assign(id,registry);
        assign(authority,authorityKey);
        ReplicatedTrust trust(dir+"/trust.sqlite",registry,authorityKey);
        std::array<std::uint8_t,32> dummy{};
        const Fixture issuer=generate("forum.example",dummy);
        BbsReplicatedGate gate(trust,issuer.publicKey,"forum.example");
        const auto challenge=gate.challenge();
        const Fixture credential=generate("forum.example",challenge);
        std::string pseudonym;
        const bool accepted=gate.verifyAndConsume(presentation(challenge,credential),
                              static_cast<std::int64_t>(std::time(nullptr)),pseudonym);
        CHECK(accepted==expected);
        CHECK(accepted ? !pseudonym.empty() : pseudonym.empty());
        std::cout<<"PASS BBS gate decision "<<(accepted?"allow":"deny")
                 <<" at replicated sequence "<<trust.sequence()<<"\n";
        return 0;
    } catch(const std::exception& e) {
        std::cerr<<"BBS P2P gate: "<<e.what()<<"\n";
        return 1;
    }
}
