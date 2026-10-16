#pragma once
#include "http_domain.hpp"
#include <sys/socket.h>
#include <netinet/in.h>
#include <chrono>
#include <vector>

namespace maat {
// One proof has two kernel socket endpoints of the SAME live TCP connection.
// The peer provides a descriptor, never a connection tuple or bearer string.
// The broker owns all descriptors until validation or expiry.
class TCPConnectionProof {
    sockaddr_in local_{};
    sockaddr_in remote_{};
    uint64_t netnsCookie_=0;
public:
    explicit TCPConnectionProof(int connectedFD);
    bool matchesAccepted(int acceptedFD) const;
};

class PendingHTTPConnections {
    struct Connection {
        int clientFD;
        TCPConnectionProof proof;
        SessionIdentifier session;
        std::chrono::steady_clock::time_point expires;
        Connection(int fd, const TCPConnectionProof& p, const SessionIdentifier& sid);
    };
    std::vector<Connection> pending_;
public:
    PendingHTTPConnections()=default;
    ~PendingHTTPConnections();
    PendingHTTPConnections(const PendingHTTPConnections&)=delete;
    PendingHTTPConnections& operator=(const PendingHTTPConnections&)=delete;
    bool remember(int clientFD, const SessionIdentifier& session);
    bool matchOnce(int acceptedFD, SessionIdentifier& session);
    void expire();
    size_t size() const {return pending_.size();}
};

// Receives exactly one SCM_RIGHTS fd, rejecting all malformed ancillary data.
int receiveOneFD(int messageFD, const char* version);
bool sendOneFD(int channelFD, int transferredFD, const char* version);
}
