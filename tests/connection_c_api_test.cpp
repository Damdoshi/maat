/* Traversal through C Apache client protocol -> real C++ broker verifier.
 * Uses real Linux TCP and SCM_RIGHTS sockets; no Apache/SSH daemon here. */
#include "http/identity_broker.hpp"
#include "replay_store.hpp"
extern "C" {
#include "../modules/mod_maat/maat_broker_client.h"
}
#include <thread>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
static void verify(bool value, const char* reason) {
    if(!value){std::fprintf(stderr,"FAIL %s\n",reason);std::exit(1);}
}
class FreeUID final:public maat::UIDCollisionPolicy {
public:bool isFree(uid_t)const override{return true;}
};
static std::vector<uint8_t> key() {
    std::vector<uint8_t> k(51);k[3]=11;
    std::memcpy(k.data()+4,"ssh-ed25519",11);k[18]=32;
    for(int i=19;i<51;++i)k[i]=static_cast<uint8_t>(i);
    return k;
}
struct Pair {int c,s;};
static Pair tcp() {
    int listener=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0);
    verify(listener>=0,"tcp socket");
    sockaddr_in a{};a.sin_family=AF_INET;a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    verify(bind(listener,reinterpret_cast<sockaddr*>(&a),sizeof(a))==0,"tcp bind");
    verify(listen(listener,4)==0,"tcp listen");
    socklen_t n=sizeof(a);
    verify(getsockname(listener,reinterpret_cast<sockaddr*>(&a),&n)==0,"tcp name");
    int client=socket(AF_INET,SOCK_STREAM,0);
    verify(connect(client,reinterpret_cast<sockaddr*>(&a),sizeof(a))==0,"tcp connect");
    int server=accept(listener,nullptr,nullptr);verify(server>=0,"tcp accept");
    close(listener);return {client,server};
}
int main() {
    char path[]="/tmp/maat-c-api-XXXXXX";int f=mkstemp(path);
    verify(f>=0,"fixture");close(f);
    {
        FreeUID policy;
        maat::ReplayStore monitor(path);
        maat::IdentityRepository repo(path,maat::UIDRange(),policy);
        auto attested=maat::AuthenticatedSession("maatweb",std::vector<uint8_t>(32,0x77),maat::PublicKey(key()));
        verify(monitor.record(attested),"record SSH-authenticated key");
        const maat::SessionIdentifier sid(std::string(64,'7'));
        uid_t uid=0;verify(repo.bind(sid,uid),"bind SSH session");
        maat::PendingHTTPConnections pending;
        Pair connection=tcp();
        // Broker session channel: registration must carry a real client TCP FD.
        int channel[2];verify(socketpair(AF_UNIX,SOCK_SEQPACKET,0,channel)==0,"channel");
        verify(maat::sendOneFD(channel[0],connection.c,"MAATLINK1"),"client FD from bridge");
        maat::SessionConnectionChannel registrar(pending,repo,sid);
        verify(registrar.serve(channel[1]),"broker registered TCP proof");
        char ack[128];verify(recv(channel[0],ack,sizeof(ack),0)>0,"ack");
        // Do not close the SSH capability: the *same* attested session may
        // register a second, distinct TCP connection, never the same proof.
        Pair second=tcp();
        verify(maat::sendOneFD(channel[0],second.c,"MAATLINK1"),"second request FD on same SSH capability");
        verify(registrar.serve(channel[1]),"second TCP proof registered on same capability");
        verify(recv(channel[0],ack,sizeof(ack),0)>0,"second request acknowledgement");
        close(channel[0]);close(channel[1]);
        maat::AcceptedConnectionVerifier verifier(pending,repo,getuid());
        int lookup[2];verify(socketpair(AF_UNIX,SOCK_SEQPACKET,0,lookup)==0,"lookup");
        timeval timeout{};timeout.tv_sec=2;
        setsockopt(lookup[0],SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
        bool brokerAccepted=false;
        std::thread broker([&](){brokerAccepted=verifier.serve(lookup[1]);});
        struct maat_verified_identity identity{};
        bool clientAccepted=maat_broker_verify_fd(lookup[0],getuid(),connection.s,&identity);
        broker.join();
        verify(clientAccepted && brokerAccepted,"cross-language broker/client agreement");
        verify(std::strcmp(identity.ssh_user,"maatweb")==0,"SSH username");
        verify(std::memcmp(identity.public_key,key().data(),51)==0,"actual key returned");
        // Two sequential requests from the same capability must each receive
        // their own one-use accepted-FD proof and matching verified key.
        brokerAccepted=false;
        std::thread secondBroker([&](){brokerAccepted=verifier.serve(lookup[1]);});
        struct maat_verified_identity secondIdentity{};
        bool secondAccepted=maat_broker_verify_fd(lookup[0],getuid(),second.s,&secondIdentity);
        secondBroker.join();
        verify(secondAccepted && brokerAccepted,"second distinct proof accepted");
        verify(std::memcmp(secondIdentity.public_key,key().data(),51)==0,
               "second proof identifies same SSH key");
        // One-use: old FD cannot be redeemed again.
        std::thread replay([&](){brokerAccepted=verifier.serve(lookup[1]);shutdown(lookup[1],SHUT_WR);});
        struct maat_verified_identity rejected{};
        bool replayed=maat_broker_verify_fd(lookup[0],getuid(),connection.s,&rejected);
        replay.join();
        verify(!replayed && !brokerAccepted,"replay refused cross-language");
        close(lookup[0]);close(lookup[1]);close(connection.c);close(connection.s);
        close(second.c);close(second.s);
    }
    unlink(path);unlink((std::string(path)+"-wal").c_str());unlink((std::string(path)+"-shm").c_str());
    std::puts("PASS C Apache IPC / C++ broker / kernel TCP credentials, replay denied");
}
