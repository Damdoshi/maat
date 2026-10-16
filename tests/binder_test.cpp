#include "http/http_domain.hpp"
#include "http/identity_broker.hpp"
#include "replay_store.hpp"
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <string>
#include <cstring>
#include <arpa/inet.h>

using namespace maat;
class AvailableUIDs final : public UIDCollisionPolicy {
public:
    bool isFree(uid_t) const override { return true; }
};

static void ck(bool x,const char* m){if(!x){std::fprintf(stderr,"FAIL: %s\n",m);std::exit(1);}}
static std::vector<uint8_t> key(){std::vector<uint8_t> k(51);k[3]=11;for(int i=0;i<11;++i)k[4+i]="ssh-ed25519"[i];k[18]=32;return k;}
static int sendClaim(int target,const std::string& session,int fd,int number=1){
    auto payload=requestMessage("MAATBIND3",session);
    iovec v{payload.data(),payload.size()};
    union { cmsghdr a; char c[CMSG_SPACE(sizeof(int)*2)]; } control{};
    msghdr m{};m.msg_iov=&v;m.msg_iovlen=1;
    if(number){
        m.msg_control=control.c;m.msg_controllen=CMSG_SPACE(sizeof(int)*number);
        cmsghdr* h=CMSG_FIRSTHDR(&m);h->cmsg_level=SOL_SOCKET;h->cmsg_type=SCM_RIGHTS;h->cmsg_len=CMSG_LEN(sizeof(int)*number);
        int* rights=(int*)CMSG_DATA(h);
        for(int i=0;i<number;++i)rights[i]=fd;
    }
    return sendmsg(target,&m,MSG_NOSIGNAL);
}
int main(){
    // MAATBIND3 is *deliberately* accepted only from UID 0. The positive
    // SCM_RIGHTS tests require a disposable privileged test environment.
    if(geteuid()!=0) {
        std::puts("SKIP: privileged MAATBIND3 tests require UID 0; use isolated root CI");
        return 77;
    }
    char name[]="/tmp/maat-bind-XXXXXX";int f=mkstemp(name);ck(f>=0,"mkstemp");close(f);
    ReplayStore store(name);AvailableUIDs testUIDs;IdentityRepository repo(name,UIDRange(),testUIDs);RootSessionBinder binder(repo);
    int conn[2],channel[2];
    ck(socketpair(AF_UNIX,SOCK_SEQPACKET,0,conn)==0,"connection");
    ck(socketpair(AF_UNIX,SOCK_SEQPACKET,0,channel)==0,"session");
    SessionIdentifier sid(std::string(64,'c'));
    SessionIdentifier result(std::string(64,'0'));
    uid_t isolatedUID=0;
    ck(sendClaim(conn[0],std::string(64,'c'),channel[1])>0,"send unknown");
    ck(binder.receive(conn[1],result,isolatedUID)==-1,"reject unverified session");
    auto identity=AuthenticatedSession("tester",std::vector<uint8_t>(32,0xcc),PublicKey(key()));
    ck(store.record(identity),"record SSH claim");
    ck(sendClaim(conn[0],std::string(64,'c'),channel[1],0)>0,"missing FD");
    ck(binder.receive(conn[1],result,isolatedUID)==-1,"reject missing FD");
    ck(sendClaim(conn[0],std::string(64,'c'),channel[1],2)>0,"extra FDs");
    ck(binder.receive(conn[1],result,isolatedUID)==-1,"reject surplus FDs");
    ck(sendClaim(conn[0],std::string(64,'c'),channel[1])>0,"valid rights");
    int remote=binder.receive(conn[1],result,isolatedUID);
    ck(remote>=0,"accept bound endpoint");
    char ack[16]{};
    ck(recv(conn[0],ack,sizeof(ack),0)==14 && std::string(ack,10)=="MAATBOUND3","bind ack");
    ck(isolatedUID>=UIDRange::defaultFirst && isolatedUID<=UIDRange::defaultLast,"UID in reserved range");
    uint32_t wire=0;
    std::memcpy(&wire,ack+10,4);
    ck(ntohl(wire)==isolatedUID,"ack UID matches SQLite allocation");
    // Session capability is accepted but cannot mint bearer tickets.
    // Sending a packet without a connected TCP FD must fail closed.
    auto m=requestMessage("MAATLINK1","");
    ck(send(channel[0],m.data(),m.size(),0)==(ssize_t)m.size(),"malformed registration packet");
    PendingHTTPConnections pending;
    SessionConnectionChannel registrar(pending,repo,result);
    ck(!registrar.serve(remote),"registration without TCP FD rejected");
    close(remote);close(channel[0]);close(channel[1]);
    ck(sendClaim(conn[0],std::string(64,'c'),-1,0)>0,"no rights replay");
    ck(binder.receive(conn[1],result,isolatedUID)<0,"replay without endpoint denied");
    close(conn[0]);close(conn[1]);
    unlink(name);unlink((std::string(name)+"-wal").c_str());unlink((std::string(name)+"-shm").c_str());
    std::puts("PASS privileged session FD binding / missing FD / multiple FDs / replay");
}
