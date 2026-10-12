#include "monitor_protocol.hpp"
#include "replay_store.hpp"
#include "receiver.hpp"
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <vector>
#include <random>

static int checks=0;
static void check(bool b, const char* msg) {
    ++checks;
    if (!b) { std::fprintf(stderr,"FAIL: %s\n",msg); std::exit(1); }
}
template <typename F> static void rejected(F fn,const char* msg) {
    bool bad=false;
    try { fn(); } catch(const std::invalid_argument&) { bad=true; }
    check(bad,msg);
}
static std::vector<uint8_t> key() {
    std::vector<uint8_t> k(51,0);
    k[3]=11;
    const char* s="ssh-ed25519";
    for(int i=0;i<11;++i) k[4+i]=uint8_t(s[i]);
    k[18]=32;
    for(int i=0;i<32;++i) k[19+i]=uint8_t(i+1);
    return k;
}
static maat::AuthenticatedSession identity(uint8_t marker=1) {
    return maat::AuthenticatedSession("maatuser",std::vector<uint8_t>(32,marker),maat::PublicKey(key()));
}
static bool exchange(maat::MonitorReceiver& r,const std::vector<uint8_t>& packet) {
    int fd[2]; check(socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,fd)==0,"socketpair");
    check(send(fd[0],packet.data(),packet.size(),0)==ssize_t(packet.size()),"send packet");
    bool result=r.receive(fd[1]);
    if(result) {
        char buf[16]{};
        check(recv(fd[0],buf,sizeof(buf),MSG_DONTWAIT)==7,"ack length");
        check(std::memcmp(buf,"MAATOK2",7)==0,"ack content");
    }
    close(fd[0]);close(fd[1]);
    return result;
}
int main() {
    auto valid=maat::MonitorMessage::encode(identity());
    check(maat::MonitorMessage::decode(valid).user()=="maatuser","round trip");
    rejected([] { maat::PublicKey bad(std::vector<uint8_t>(51)); },"fake public key");
    rejected([] { maat::AuthenticatedSession bad("bad\nuser",std::vector<uint8_t>(32),maat::PublicKey(key())); },"invalid username");
    rejected([] { maat::AuthenticatedSession bad("maatuser",std::vector<uint8_t>(3),maat::PublicKey(key())); },"short session");
    auto corrupted=valid; corrupted[4]='X';
    rejected([&] { maat::MonitorMessage::decode(corrupted); },"wrong magic");
    corrupted=valid; corrupted.push_back(1);
    rejected([&] { maat::MonitorMessage::decode(corrupted); },"trailing garbage");
    corrupted=valid; corrupted[0]=127;
    rejected([&] { maat::MonitorMessage::decode(corrupted); },"oversized field");
    corrupted=valid; corrupted.resize(corrupted.size()-1);
    rejected([&] { maat::MonitorMessage::decode(corrupted); },"truncated blob");
    auto fakekey=valid; fakekey.back()=0xff; // still well-formed: opaque Ed25519 point
    check(maat::MonitorMessage::decode(fakekey).key().blob()!=key(),"opaque pubkey retained");

    char filename[]="/tmp/maat-db-XXXXXX";
    int temp=mkstemp(filename); check(temp>=0,"mkstemp"); close(temp);
    {
        maat::ReplayStore store(filename);
        maat::MonitorReceiver receiver(store,getuid());
        check(exchange(receiver,valid),"real socket accepted");
        check(!exchange(receiver,valid),"duplicate rejected");
        check(!exchange(receiver,corrupted),"truncated packet rejected");
        check(exchange(receiver,maat::MonitorMessage::encode(identity(2))),"distinct session accepted");
        maat::MonitorReceiver otherUid(store,getuid()+1);
        check(!exchange(otherUid,maat::MonitorMessage::encode(identity(3))),"untrusted peer UID rejected");
    }
    {
        maat::ReplayStore reopened(filename);
        check(!reopened.record(identity()),"replay survives reopen");
        check(reopened.record(identity(3)),"new session survives reopen");
    }
    unlink(filename);
    std::string wal=std::string(filename)+"-wal";
    std::string shm=std::string(filename)+"-shm";
    unlink(wal.c_str());unlink(shm.c_str());
    // Deterministic malformed-packet smoke-fuzz, checked under ASan/UBSan.
    std::mt19937 engine(0x4D414154);
    for(int n=0;n<5000;++n) {
        std::vector<uint8_t> fuzz(engine()%200);
        for(auto& byte:fuzz) byte=static_cast<uint8_t>(engine());
        try { (void)maat::MonitorMessage::decode(fuzz); }
        catch(const std::invalid_argument&) {}
    }
    check(true,"5000 parser fuzz inputs without crash");
    std::fprintf(stderr,"PASS: %d checks + 5000 fuzz inputs\n",checks);
    return 0;
}
