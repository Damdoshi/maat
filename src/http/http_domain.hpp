#pragma once
#include <array>
#include <cstdint>
#include <string>
#include <vector>
#include "monitor_protocol.hpp"
#include <sqlite3.h>
#include <sys/types.h>

namespace maat {
class SessionIdentifier {
    std::vector<uint8_t> id_;
public:
    explicit SessionIdentifier(const std::string& hex);
    const std::vector<uint8_t>& bytes() const { return id_; }
};
class RequestTicket {
    std::array<uint8_t,32> value_{};
public:
    RequestTicket();
    explicit RequestTicket(const std::string& hex);
    std::string hex() const;
    const std::array<uint8_t,32>& bytes() const { return value_; }
};
// Host-reserved, never-reused UIDs for SSH-to-HTTP session isolation.
// UIDs must not be shared with other services; configuration must explicitly
// reserve this range at the host/system administration level.
class UIDRange {
    uint64_t first_, last_;
public:
    static constexpr uint64_t defaultFirst = 1000000000ULL;
    static constexpr uint64_t defaultLast  = 2099999999ULL;
    UIDRange(uint64_t first=defaultFirst, uint64_t last=defaultLast);
    uint64_t first() const { return first_; }
    uint64_t last() const { return last_; }
    bool contains(uint64_t uid) const { return uid>=first_ && uid<=last_; }
};
// Deliberately restricted Dabsic block reader, not a general Dabsic interpreter.
// Reject unknown keys, duplicate fields, missing fields and extra blocks.
class UIDRangeConfiguration {
public:
    static UIDRange parse(const std::string& source);
    static UIDRange read(const std::string& path);
};
class EphemeralUID {
    uid_t value_;
public:
    explicit EphemeralUID(uint64_t value, const UIDRange& range=UIDRange());
    uid_t value() const { return value_; }
};
class IdentityRepository {
    sqlite3* db_=nullptr;
    UIDRange range_;
public:
    explicit IdentityRepository(const std::string& path, const UIDRange& range=UIDRange());
    ~IdentityRepository();
    IdentityRepository(const IdentityRepository&)=delete;
    IdentityRepository& operator=(const IdentityRepository&)=delete;
    bool bind(const SessionIdentifier& session, uid_t& bridgeUID);
    bool issue(const SessionIdentifier& session, const RequestTicket& ticket);
    bool consume(const RequestTicket& ticket, std::string& user, std::vector<uint8_t>& key);
};
class HTTPRequest {
    std::string header_, body_;
public:
    static HTTPRequest read(int fd, size_t maxBody=1048576);
    std::string forwarded(const std::string& ticket) const;
};
std::vector<uint8_t> requestMessage(const std::string& magic, const std::string& hex);
std::string readString(const std::vector<uint8_t>& packet, size_t& offset, size_t max);
}
