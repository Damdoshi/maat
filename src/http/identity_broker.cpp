#include "identity_broker.hpp"
#include <sys/socket.h>
#include <unistd.h>
#include <vector>
#include <cstring>
#include <string>
#include <stdexcept>
#include <arpa/inet.h>
namespace maat {
namespace {
bool peer(int fd,uid_t uid){ucred c{};socklen_t n=sizeof(c);return getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&c,&n)==0 && n==sizeof(c) && c.uid==uid;}
std::vector<uint8_t> recvPacket(int fd) {
    std::vector<uint8_t> r(512);
    ssize_t n=recv(fd,r.data(),r.size(),MSG_TRUNC);
    if(n<=0 || n>ssize_t(r.size())) throw std::invalid_argument("invalid packet size");
    r.resize(size_t(n)); return r;
}
void put(std::vector<uint8_t>& b,const std::string& s) {
    uint32_t n=uint32_t(s.size());
    b.push_back(uint8_t(n>>24));b.push_back(uint8_t(n>>16));b.push_back(uint8_t(n>>8));b.push_back(uint8_t(n));
    b.insert(b.end(),s.begin(),s.end());
}
}
int RootSessionBinder::receive(int fd, SessionIdentifier& session, uid_t& bridgeUID) {
    if(!peer(fd,0)) return -1;
    uint8_t data[512]{};
    union { cmsghdr align; char buf[CMSG_SPACE(sizeof(int)*4)]; } ancillary{};
    iovec vector{data,sizeof(data)};
    msghdr msg{};msg.msg_iov=&vector;msg.msg_iovlen=1;
    msg.msg_control=ancillary.buf;msg.msg_controllen=sizeof(ancillary.buf);
    const ssize_t n=recvmsg(fd,&msg,MSG_CMSG_CLOEXEC|MSG_TRUNC);
    if(n<=0 || n>ssize_t(sizeof(data)) || (msg.msg_flags&(MSG_TRUNC|MSG_CTRUNC))) return -1;
    int borrowed=-1; int nfd=0;
    for(cmsghdr* c=CMSG_FIRSTHDR(&msg);c;c=CMSG_NXTHDR(&msg,c)) {
        if(c->cmsg_level!=SOL_SOCKET || c->cmsg_type!=SCM_RIGHTS) continue;
        if(c->cmsg_len<CMSG_LEN(0)) return -1;
        auto length=(c->cmsg_len-CMSG_LEN(0))/sizeof(int);
        const int* passed=reinterpret_cast<const int*>(CMSG_DATA(c));
        for(size_t i=0;i<length;++i) { if(nfd++==0) borrowed=passed[i]; else close(passed[i]); }
    }
    if(nfd!=1 || borrowed<0) {if(borrowed>=0)close(borrowed);return -1;}
    try {
        int domain=0,type=0;socklen_t sz=sizeof(int);
        if(getsockopt(borrowed,SOL_SOCKET,SO_DOMAIN,&domain,&sz)!=0 || domain!=AF_UNIX ||
           getsockopt(borrowed,SOL_SOCKET,SO_TYPE,&type,&sz)!=0 || type!=SOCK_SEQPACKET)
            throw std::invalid_argument("wrong endpoint type");
        std::vector<uint8_t> packet(data,data+n);size_t off=0;
        if(readString(packet,off,20)!="MAATBIND3") throw std::invalid_argument("version");
        SessionIdentifier sid(readString(packet,off,256));
        uid_t assigned=0;
        if(off!=packet.size() || !repository_.bind(sid,assigned))
            throw std::invalid_argument("unknown/replayed session or UID exhausted");
        // Binary network-order reply: 10-byte magic + 4-byte UID. A bridge
        // may never choose its own UID, nor does it receive the allocation.
        uint8_t ack[14]{};
        std::memcpy(ack,"MAATBOUND3",10);
        uint32_t networkUID=htonl(static_cast<uint32_t>(EphemeralUID(assigned).value()));
        std::memcpy(ack+10,&networkUID,sizeof(networkUID));
        if(send(fd,ack,sizeof(ack),MSG_NOSIGNAL)!=ssize_t(sizeof(ack)))
            throw std::runtime_error("no acknowledgment");
        bridgeUID=assigned;
        session=sid;
        return borrowed;
    }catch(const std::exception&){close(borrowed);return -1;}
}
bool SessionTicketChannel::serve(int fd) {
    try {
        auto p=recvPacket(fd);size_t off=0;
        if(readString(p,off,20)!="MAATGET2" || off!=p.size()) return false;
        RequestTicket ticket;
        if(!repository_.issue(session_,ticket)) return false;
        auto msg=requestMessage("MAATHTTP1",ticket.hex());
        return send(fd,msg.data(),msg.size(),MSG_NOSIGNAL)==ssize_t(msg.size());
    }catch(const std::exception&){return false;}
}
bool TicketVerifier::serve(int fd) {
    if(!peer(fd,phpUID_)) return false;
    try {
        auto p=recvPacket(fd);size_t off=0;
        if(readString(p,off,20)!="MAATCHECK1") return false;
        RequestTicket ticket(readString(p,off,64));
        if(off!=p.size()) return false;
        std::string user;std::vector<uint8_t> key;
        if(!repository_.consume(ticket,user,key)) return false;
        std::vector<uint8_t> msg; put(msg,"MAATIDENT1");put(msg,user);
        put(msg,std::string(key.begin(),key.end()));
        return send(fd,msg.data(),msg.size(),MSG_NOSIGNAL)==ssize_t(msg.size());
    }catch(const std::exception&){return false;}
}
}
