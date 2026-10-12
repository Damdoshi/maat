#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace maat {
class PublicKey {
    std::vector<uint8_t> blob_;
public:
    explicit PublicKey(const std::vector<uint8_t>& blob);
    const std::vector<uint8_t>& blob() const { return blob_; }
};
class AuthenticatedSession {
    std::string user_;
    std::vector<uint8_t> session_;
    PublicKey key_;
public:
    AuthenticatedSession(const std::string& user, const std::vector<uint8_t>& session,
                         const PublicKey& key);
    const std::string& user() const { return user_; }
    const std::vector<uint8_t>& sessionId() const { return session_; }
    const PublicKey& key() const { return key_; }
};
class MonitorMessage {
public:
    static AuthenticatedSession decode(const std::vector<uint8_t>& raw);
    static std::vector<uint8_t> encode(const AuthenticatedSession& identity);
};
}
