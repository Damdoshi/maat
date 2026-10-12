#include "monitor_protocol.hpp"
#include <algorithm>
#include <stdexcept>
#include <cctype>

namespace maat {
namespace {
class Reader {
    const std::vector<uint8_t>& bytes_;
    size_t offset_ = 0;
public:
    explicit Reader(const std::vector<uint8_t>& b): bytes_(b) {}
    std::vector<uint8_t> next(size_t max) {
        if (bytes_.size()-offset_ < 4) throw std::invalid_argument("short length");
        size_t n = (size_t(bytes_[offset_])<<24)|(size_t(bytes_[offset_+1])<<16)|
                   (size_t(bytes_[offset_+2])<<8)|bytes_[offset_+3];
        offset_ += 4;
        if (n > max || n > bytes_.size()-offset_) throw std::invalid_argument("invalid length");
        std::vector<uint8_t> value(bytes_.begin()+offset_, bytes_.begin()+offset_+n);
        offset_ += n;
        return value;
    }
    bool finished() const { return offset_ == bytes_.size(); }
};
void put(std::vector<uint8_t>& out, const std::vector<uint8_t>& value) {
    const uint32_t n = static_cast<uint32_t>(value.size());
    out.push_back(uint8_t(n>>24)); out.push_back(uint8_t(n>>16));
    out.push_back(uint8_t(n>>8)); out.push_back(uint8_t(n));
    out.insert(out.end(), value.begin(), value.end());
}
std::vector<uint8_t> chars(const std::string& s) {
    return std::vector<uint8_t>(s.begin(),s.end());
}
}
PublicKey::PublicKey(const std::vector<uint8_t>& b):blob_(b) {
    // Standard raw ssh-ed25519 public-key blob: string "ssh-ed25519", string 32B.
    if (blob_.size() != 51 || blob_[0] != 0 || blob_[1] != 0 || blob_[2] != 0 ||
        blob_[3] != 11 || blob_[15] != 0 || blob_[16] != 0 || blob_[17] != 0 ||
        blob_[18] != 32 || !std::equal(blob_.begin()+4,blob_.begin()+15,
                                       "ssh-ed25519"))
        throw std::invalid_argument("not a raw Ed25519 SSH public key");
}
AuthenticatedSession::AuthenticatedSession(const std::string& user,
        const std::vector<uint8_t>& session, const PublicKey& key):
        user_(user), session_(session), key_(key) {
    if (user_.empty() || user_.size()>128 || session_.size()<16 || session_.size()>128)
        throw std::invalid_argument("invalid user or SSH session identifier");
    for (unsigned char c: user_) if (c<33 || c>126 || c=='/' || c=='\\')
        throw std::invalid_argument("invalid user character");
}
AuthenticatedSession MonitorMessage::decode(const std::vector<uint8_t>& raw) {
    if (raw.size()<32 || raw.size()>2048) throw std::invalid_argument("message size");
    Reader reader(raw);
    const auto magic=reader.next(16);
    if (magic!=chars("MAATMON2")) throw std::invalid_argument("protocol version");
    const auto user=reader.next(128);
    const auto id=reader.next(128);
    const auto key=reader.next(1024);
    if (!reader.finished()) throw std::invalid_argument("trailing bytes");
    return AuthenticatedSession(std::string(user.begin(),user.end()),id,PublicKey(key));
}
std::vector<uint8_t> MonitorMessage::encode(const AuthenticatedSession& identity) {
    std::vector<uint8_t> out;
    put(out,chars("MAATMON2")); put(out,chars(identity.user()));
    put(out,identity.sessionId()); put(out,identity.key().blob());
    return out;
}
}
