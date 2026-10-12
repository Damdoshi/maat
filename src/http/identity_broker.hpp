#pragma once
#include "http_domain.hpp"
#include <sys/types.h>
namespace maat {
class RootSessionBinder {
    IdentityRepository& repository_;
public:
    explicit RootSessionBinder(IdentityRepository& r):repository_(r){}
    // Accept one broker-side session endpoint via SCM_RIGHTS from root.
    // On success, caller owns the returned descriptor and closes it on EOF.
    int receive(int peerSocket, SessionIdentifier& session, uid_t& bridgeUID);
};
class SessionTicketChannel {
    IdentityRepository& repository_;
    SessionIdentifier session_;
public:
    SessionTicketChannel(IdentityRepository& r, const SessionIdentifier& s):repository_(r),session_(s){}
    bool serve(int sessionFd);
};
class TicketVerifier {
    IdentityRepository& repository_;
    uid_t phpUID_;
public:
    TicketVerifier(IdentityRepository& r,uid_t uid):repository_(r),phpUID_(uid){}
    bool serve(int fd);
};
}
