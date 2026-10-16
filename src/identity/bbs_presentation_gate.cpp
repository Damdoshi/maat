#include "identity/bbs_presentation_gate.hpp"

#include <openssl/rand.h>
#include <algorithm>
#include <stdexcept>

#ifdef MAAT_ENABLE_BBS
extern "C" int maat_bbs_nym_verify_v1(const unsigned char* public_key,
                                        std::size_t public_key_len,
                                        const unsigned char* proof,
                                        std::size_t proof_len,
                                        const unsigned char* pseudonym,
                                        std::size_t pseudonym_len,
                                        const unsigned char* context,
                                        std::size_t context_len,
                                        const unsigned char* presentation_header,
                                        std::size_t presentation_header_len);
#endif

namespace maat { namespace identity {
namespace {
const auto kChallengeLifetime = std::chrono::seconds(60);
constexpr std::size_t kMaxPending = 1024;
const char kContextPrefix[] = "MAAT:BBS-NYM:SERVICE:";
const char kPresentationPrefix[] = "MAAT:BBS-PRESENTATION-V1:";

bool validService(const std::string& service) {
    if (service.empty() || service.size() > 200 || service.front() == '.' ||
        service.back() == '.' || service.front() == '-' || service.back() == '-')
        return false;
    for (unsigned char c : service) {
        if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
            c == '.' || c == '-') continue;
        return false; // ASCII lower-case ID / punycode, canonicalized externally
    }
    return true;
}

std::string hex(const std::array<std::uint8_t, 48>& input) {
    const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(input.size() * 2);
    for (const std::uint8_t b : input) {
        out.push_back(digits[b >> 4]);
        out.push_back(digits[b & 15]);
    }
    return out;
}
}

BbsPresentationGate::BbsPresentationGate(std::array<std::uint8_t, 96> trustedIssuerKey,
                                         const std::string& canonicalServiceId)
    : issuerPublicKey_(trustedIssuerKey), serviceId_(canonicalServiceId) {
    if (!validService(serviceId_) ||
        std::all_of(issuerPublicKey_.begin(), issuerPublicKey_.end(),
                    [](std::uint8_t b) { return b == 0; }))
        throw std::invalid_argument("BBS issuer key and canonical service ID required");
}

std::array<std::uint8_t, 32> BbsPresentationGate::challenge() {
    std::array<std::uint8_t, 32> bytes{};
    if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1)
        throw std::runtime_error("OS randomness unavailable");
    std::lock_guard<std::mutex> lock(mutex_);
    auto now = std::chrono::steady_clock::now();
    for (auto it = pending_.begin(); it != pending_.end(); ) {
        if (it->second <= now) it = pending_.erase(it);
        else ++it;
    }
    if (pending_.size() >= kMaxPending)
        throw std::runtime_error("too many outstanding BBS challenges");
    if (!pending_.emplace(bytes, now + kChallengeLifetime).second)
        throw std::runtime_error("duplicate random BBS challenge");
    return bytes;
}

bool BbsPresentationGate::verifyAndConsume(const BbsNymPresentation& p,
                                           std::string& scopedPseudonymHex) {
    scopedPseudonymHex.clear();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto it = pending_.find(p.challenge);
        if (it == pending_.end()) return false;
        const bool inTime = it->second > std::chrono::steady_clock::now();
        pending_.erase(it); // single use even on malformed/falsified input
        if (!inTime) return false;
    }
    if (p.proof.size() < 272 || p.proof.size() > 64 * 1024 ||
        (p.proof.size() - 272) % 32 != 0) return false;
#ifdef MAAT_ENABLE_BBS
    std::string context = std::string(kContextPrefix) + serviceId_;
    std::string ph(kPresentationPrefix);
    ph.append(reinterpret_cast<const char*>(p.challenge.data()), p.challenge.size());
    const int verified = maat_bbs_nym_verify_v1(
        issuerPublicKey_.data(), issuerPublicKey_.size(),
        p.proof.data(), p.proof.size(), p.pseudonym.data(), p.pseudonym.size(),
        reinterpret_cast<const unsigned char*>(context.data()), context.size(),
        reinterpret_cast<const unsigned char*>(ph.data()), ph.size());
    if (verified == 1) {
        scopedPseudonymHex = hex(p.pseudonym);
        return true;
    }
#else
    (void)kContextPrefix;
    (void)kPresentationPrefix;
    (void)hex;
#endif
    return false;
}

}} // namespace maat::identity
