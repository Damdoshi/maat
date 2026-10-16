#include "connection_proof.hpp"
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdexcept>
#include <cstring>
#include <cerrno>

namespace maat {
namespace {
sockaddr_in endpoint(int fd, bool peer) {
    sockaddr_storage storage{};
    socklen_t length=sizeof(storage);
    const int result=peer ? getpeername(fd,reinterpret_cast<sockaddr*>(&storage),&length)
                          : getsockname(fd,reinterpret_cast<sockaddr*>(&storage),&length);
    if(result!=0 || storage.ss_family!=AF_INET || length!=sizeof(sockaddr_in))
        throw std::invalid_argument("not a connected IPv4 endpoint");
    sockaddr_in value{};std::memcpy(&value,&storage,sizeof(value));
    if((ntohl(value.sin_addr.s_addr)&0xff000000UL)!=0x7f000000UL || value.sin_port==0)
        throw std::invalid_argument("not a loopback TCP endpoint");
    return value;
}
bool same(const sockaddr_in& a, const sockaddr_in& b) {
    return a.sin_port==b.sin_port && a.sin_addr.s_addr==b.sin_addr.s_addr;
}
void checkSocket(int fd) {
    int domain=0,type=0,accepting=0;
    socklen_t len=sizeof(int);
    if(getsockopt(fd,SOL_SOCKET,SO_DOMAIN,&domain,&len)!=0 || domain!=AF_INET ||
       getsockopt(fd,SOL_SOCKET,SO_TYPE,&type,&len)!=0 || type!=SOCK_STREAM ||
       getsockopt(fd,SOL_SOCKET,SO_ACCEPTCONN,&accepting,&len)!=0 || accepting!=0)
        throw std::invalid_argument("descriptor is not a connected TCP stream");
}
}
TCPConnectionProof::TCPConnectionProof(int fd) {
    checkSocket(fd);
    socklen_t n=sizeof(netnsCookie_);
    if(getsockopt(fd,SOL_SOCKET,SO_NETNS_COOKIE,&netnsCookie_,&n)!=0 || n!=sizeof(netnsCookie_))
        throw std::invalid_argument("cannot verify TCP network namespace");
    local_=endpoint(fd,false);
    remote_=endpoint(fd,true);
}
bool TCPConnectionProof::matchesAccepted(int fd) const {
    try {
        checkSocket(fd);
        uint64_t cookie=0;socklen_t size=sizeof(cookie);
        if(getsockopt(fd,SOL_SOCKET,SO_NETNS_COOKIE,&cookie,&size)!=0 ||
           size!=sizeof(cookie) || cookie!=netnsCookie_) return false;
        const auto local=endpoint(fd,false), remote=endpoint(fd,true);
        return same(local,remote_) && same(remote,local_);
    }catch(const std::exception&){return false;}
}
PendingHTTPConnections::Connection::Connection(int fd,const TCPConnectionProof& p,
                                                const SessionIdentifier& sid)
    :clientFD(fd),proof(p),session(sid),expires(std::chrono::steady_clock::now()+std::chrono::seconds(15)) {}
PendingHTTPConnections::~PendingHTTPConnections(){for(const auto& c:pending_)close(c.clientFD);}
void PendingHTTPConnections::expire() {
    const auto now=std::chrono::steady_clock::now();
    for(size_t i=pending_.size();i>0;--i) if(pending_[i-1].expires<=now) {
        close(pending_[i-1].clientFD);
        pending_.erase(pending_.begin()+static_cast<long>(i-1));
    }
}
bool PendingHTTPConnections::remember(int fd,const SessionIdentifier& sid) {
    expire();
    if(pending_.size()>=256) return false;
    try {
        TCPConnectionProof proof(fd);
        for(const auto& p:pending_) if(p.proof.matchesAccepted(fd)) return false;
        pending_.emplace_back(fd,proof,sid);
        return true;
    }catch(const std::exception&){return false;}
}
bool PendingHTTPConnections::matchOnce(int acceptedFD, SessionIdentifier& sid) {
    expire();
    for(size_t i=0;i<pending_.size();++i) {
        if(pending_[i].proof.matchesAccepted(acceptedFD)) {
            sid=pending_[i].session;
            close(pending_[i].clientFD);
            pending_.erase(pending_.begin()+static_cast<long>(i));
            return true;
        }
    }
    return false;
}
int receiveOneFD(int socketFD,const char* version) {
    unsigned char payload[64]{};
    union {cmsghdr align;char bytes[CMSG_SPACE(sizeof(int)*4)];} ancillary{};
    iovec io{payload,sizeof(payload)};
    msghdr msg{};msg.msg_iov=&io;msg.msg_iovlen=1;
    msg.msg_control=ancillary.bytes;msg.msg_controllen=sizeof(ancillary.bytes);
    const ssize_t count=recvmsg(socketFD,&msg,MSG_CMSG_CLOEXEC|MSG_TRUNC);
    int fd=-1,total=0;
    for(cmsghdr* c=CMSG_FIRSTHDR(&msg);c;c=CMSG_NXTHDR(&msg,c)) {
        if(c->cmsg_level!=SOL_SOCKET || c->cmsg_type!=SCM_RIGHTS || c->cmsg_len<CMSG_LEN(0)) continue;
        const size_t length=(c->cmsg_len-CMSG_LEN(0))/sizeof(int);
        const int* passed=reinterpret_cast<const int*>(CMSG_DATA(c));
        for(size_t i=0;i<length;++i) {if(++total==1)fd=passed[i];else close(passed[i]);}
    }
    if(count<=0 || count>static_cast<ssize_t>(sizeof(payload)) ||
       (msg.msg_flags&(MSG_TRUNC|MSG_CTRUNC)) || total!=1) {if(fd>=0)close(fd);return -1;}
    try {
        std::vector<uint8_t> p(payload,payload+count);size_t off=0;
        if(readString(p,off,24)!=version || readString(p,off,0)!="" || off!=p.size())
            throw std::invalid_argument("invalid control packet");
        return fd;
    }catch(const std::exception&){close(fd);return -1;}
}
bool sendOneFD(int sock,int transferredFD,const char* version) {
    auto p=requestMessage(version,"");
    iovec io{p.data(),p.size()};
    union {cmsghdr align;char bytes[CMSG_SPACE(sizeof(int))];} ancillary{};
    msghdr msg{};msg.msg_iov=&io;msg.msg_iovlen=1;
    msg.msg_control=ancillary.bytes;msg.msg_controllen=sizeof(ancillary.bytes);
    cmsghdr* c=CMSG_FIRSTHDR(&msg);
    c->cmsg_level=SOL_SOCKET;c->cmsg_type=SCM_RIGHTS;c->cmsg_len=CMSG_LEN(sizeof(int));
    std::memcpy(CMSG_DATA(c),&transferredFD,sizeof(transferredFD));
    return sendmsg(sock,&msg,MSG_NOSIGNAL)==static_cast<ssize_t>(p.size());
}
}
