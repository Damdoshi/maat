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
// Dependency-inverted host-side UID collision policy. Implementations must
// fail closed if the host account directory cannot be queried reliably.
class UIDCollisionPolicy {
public:
    virtual ~UIDCollisionPolicy() = default;
    virtual bool isFree(uid_t uid) const = 0;
};
class NSSUIDCollisionPolicy final : public UIDCollisionPolicy {
public:
    bool isFree(uid_t uid) const override;
};
const UIDCollisionPolicy& systemUIDCollisionPolicy();

class IdentityRepository {
    sqlite3* db_=nullptr;
    UIDRange range_;
    const UIDCollisionPolicy& uidPolicy_;
public:
    explicit IdentityRepository(const std::string& path,
                                const UIDRange& range=UIDRange(),
                                const UIDCollisionPolicy& uidPolicy=systemUIDCollisionPolicy());
    ~IdentityRepository();
    IdentityRepository(const IdentityRepository&)=delete;
    IdentityRepository& operator=(const IdentityRepository&)=delete;
    bool bind(const SessionIdentifier& session, uid_t& bridgeUID);
    bool identityForBoundSession(const SessionIdentifier& sid,std::string& user,std::vector<uint8_t>& key);
};
class HTTPRequest {
    std::string header_, body_;
public:
    static HTTPRequest read(int fd, size_t maxBody=1048576);
    static size_t expectedBodyLength(const std::string& header, size_t maxBody=1048576);
    static HTTPRequest fromFrame(const std::string& header, const std::string& body,
                                 size_t maxBody=1048576);
    std::string forwarded() const;
};
std::vector<uint8_t> requestMessage(const std::string& magic, const std::string& hex);
std::string readString(const std::vector<uint8_t>& packet, size_t& offset, size_t max);
}
