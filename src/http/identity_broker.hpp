#pragma once
#include "http_domain.hpp"
#include "connection_proof.hpp"
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
class SessionConnectionChannel {
    PendingHTTPConnections& registry_;
    IdentityRepository& repository_;
    SessionIdentifier session_;
public:
    SessionConnectionChannel(PendingHTTPConnections& registry,IdentityRepository& repository,
                             const SessionIdentifier& session)
        :registry_(registry),repository_(repository),session_(session){}
    bool serve(int capabilityFD);
};
class AcceptedConnectionVerifier {
    PendingHTTPConnections& registry_;
    IdentityRepository& repository_;
    uid_t apacheUID_;
public:
    AcceptedConnectionVerifier(PendingHTTPConnections& registry,IdentityRepository& repository,uid_t apacheUID)
        :registry_(registry),repository_(repository),apacheUID_(apacheUID){}
    bool serve(int brokerFD);
};
}
