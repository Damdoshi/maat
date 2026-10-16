#include "http/identity_broker.hpp"
#include "replay_store.hpp"
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

static int cases=0;
static void check(bool ok,const char* message) {
    ++cases;
    if(!ok){std::fprintf(stderr,"FAIL %s\n",message);std::exit(1);}
}
class TestUIDs final :public maat::UIDCollisionPolicy {
public:bool isFree(uid_t)const override{return true;}
};
static std::vector<uint8_t> key(int offset) {
    std::vector<uint8_t> k(51);k[3]=11;
    std::memcpy(k.data()+4,"ssh-ed25519",11);k[18]=32;
    for(int i=0;i<32;++i)k[i+19]=static_cast<uint8_t>(i+offset);
    return k;
}
struct TCPPair {int client=-1,server=-1;};
static TCPPair pair() {
    int listener=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0);
    check(listener>=0,"listen socket");
    sockaddr_in address{};address.sin_family=AF_INET;
    address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);address.sin_port=0;
    check(bind(listener,reinterpret_cast<sockaddr*>(&address),sizeof(address))==0,"bind tcp");
    check(listen(listener,4)==0,"listen tcp");
    socklen_t length=sizeof(address);
    check(getsockname(listener,reinterpret_cast<sockaddr*>(&address),&length)==0,"listen address");
    TCPPair result;
    result.client=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0);
    check(result.client>=0,"client socket");
    check(connect(result.client,reinterpret_cast<sockaddr*>(&address),sizeof(address))==0,"connect TCP");
    result.server=accept4(listener,nullptr,nullptr,SOCK_CLOEXEC);
    check(result.server>=0,"accept TCP");close(listener);
    return result;
}
static bool registerFD(maat::SessionConnectionChannel& channel,int client,int* ready=nullptr) {
    int ipc[2];check(socketpair(AF_UNIX,SOCK_SEQPACKET,0,ipc)==0,"capability socketpair");
    check(maat::sendOneFD(ipc[0],client,"MAATLINK1"),"send real client descriptor");
    bool result=channel.serve(ipc[1]);
    if(result && ready) {
        char ack[128];ssize_t n=recv(ipc[0],ack,sizeof(ack),0);
        check(n>0,"registered ack");
        std::vector<uint8_t> bytes(ack,ack+n);size_t off=0;
        check(maat::readString(bytes,off,20)=="MAATREADY1" &&
              maat::readString(bytes,off,0)=="" && off==bytes.size(),"ack format");
        *ready=1;
    }
    close(ipc[0]);close(ipc[1]);return result;
}
static bool verifyFD(maat::AcceptedConnectionVerifier& verifier,int accepted,std::string *name=nullptr,
                     std::vector<uint8_t>* observed=nullptr) {
    int ipc[2];check(socketpair(AF_UNIX,SOCK_SEQPACKET,0,ipc)==0,"verifier socketpair");
    check(maat::sendOneFD(ipc[0],accepted,"MAATLOOKUP2"),"send accepted descriptor");
    bool result=verifier.serve(ipc[1]);
    if(result) {
        unsigned char reply[512];ssize_t n=recv(ipc[0],reply,sizeof(reply),0);
        check(n>0,"verifier response");
        std::vector<uint8_t> bytes(reply,reply+n);size_t off=0;
        check(maat::readString(bytes,off,20)=="MAATIDENT2","response type");
        std::string u=maat::readString(bytes,off,64), k=maat::readString(bytes,off,51);
        check(off==bytes.size() && k.size()==51,"response framing");
        if(name) *name=u;
        if(observed) observed->assign(k.begin(),k.end());
    }
    close(ipc[0]);close(ipc[1]);return result;
}
int main() {
    const TCPPair alice=pair(),bob=pair(),attacker=pair();
    maat::TCPConnectionProof aliceProof(alice.client);
    check(aliceProof.matchesAccepted(alice.server),"valid two-sided TCP proof");
    check(!aliceProof.matchesAccepted(bob.server),"cross-session swap rejected");
    check(!aliceProof.matchesAccepted(attacker.server),"unregistered connection rejected");
    int unixFD[2];check(socketpair(AF_UNIX,SOCK_STREAM,0,unixFD)==0,"unix socketpair");
    check(!aliceProof.matchesAccepted(unixFD[0]),"not a TCP descriptor");
    close(unixFD[0]);close(unixFD[1]);

    char path[]="/tmp/maat-connection-db-XXXXXX";
    int f=mkstemp(path);check(f>=0,"sqlite fixture");close(f);
    TestUIDs policy;
    {
        maat::ReplayStore monitor(path);
        maat::IdentityRepository repo(path,maat::UIDRange(),policy);
        maat::PendingHTTPConnections pending;
        const std::string s1(64,'a'),s2(64,'b');
        auto id1=maat::AuthenticatedSession("maatweb",std::vector<uint8_t>(32,0xaa),maat::PublicKey(key(11)));
        auto id2=maat::AuthenticatedSession("maatweb",std::vector<uint8_t>(32,0xbb),maat::PublicKey(key(77)));
        check(monitor.record(id1) && monitor.record(id2),"monitor attests two SSH keys");
        uid_t u1=0,u2=0;
        check(repo.bind(maat::SessionIdentifier(s1),u1),"bound first authentic session");
        check(repo.bind(maat::SessionIdentifier(s2),u2) && u1!=u2,"different sessions/UIDs");
        maat::SessionConnectionChannel a(pending,repo,maat::SessionIdentifier(s1));
        maat::SessionConnectionChannel b(pending,repo,maat::SessionIdentifier(s2));
        maat::AcceptedConnectionVerifier verifier(pending,repo,getuid());
        maat::AcceptedConnectionVerifier wrongUID(pending,repo,getuid()+1);
        check(!verifyFD(verifier,attacker.server),"HTTP client without SSH fails closed");
        int ready=0;
        check(registerFD(a,alice.client,&ready) && ready,"Alice registers connection using FD");
        check(registerFD(b,bob.client,&ready),"Bob registers separate connection");
        check(pending.size()==2,"two outstanding authenticated connections");
        check(!verifyFD(wrongUID,alice.server),"Apache UID mismatch rejected");
        check(!verifyFD(verifier,attacker.server),"attacker cannot claim existing session");
        check(!verifyFD(verifier,alice.client),"presenting client-side fd cannot masquerade as accepted end");
        std::string name;std::vector<uint8_t> k;
        check(verifyFD(verifier,bob.server,&name,&k) && k==key(77),"Bob key exactly matches SSH monitor");
        check(verifyFD(verifier,alice.server,&name,&k) && k==key(11),"Alice key exactly matches SSH monitor");
        check(!verifyFD(verifier,alice.server),"replay of accepted socket rejected");
        check(!verifyFD(verifier,bob.server),"Bob socket replay rejected");
        check(pending.size()==0,"proofs consumed and descriptors released");
    }
    for(int fd:{alice.client,alice.server,bob.client,bob.server,attacker.client,attacker.server}) close(fd);
    unlink(path);unlink((std::string(path)+"-wal").c_str());unlink((std::string(path)+"-shm").c_str());
    std::fprintf(stderr,"PASS %d TCP descriptor/identity/replay checks\n",cases);
}
