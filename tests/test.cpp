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
#include <thread>
#include <chrono>
#include <atomic>

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
static bool monitor_exchange(maat::MonitorReceiver& r,const std::vector<uint8_t>& packet) {
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
        check(monitor_exchange(receiver,valid),"real socket accepted");
        check(!monitor_exchange(receiver,valid),"duplicate rejected");
        check(!monitor_exchange(receiver,corrupted),"truncated packet rejected");
        check(monitor_exchange(receiver,maat::MonitorMessage::encode(identity(2))),"distinct session accepted");
        // Reproduce a broker writer holding BEGIN IMMEDIATE while OpenSSH
        // submits another valid assertion. Before the busy-timeout fix,
        // ReplayStore::record() fails instantly with SQLITE_BUSY.
        sqlite3* broker=nullptr;
        check(sqlite3_open_v2(filename,&broker,SQLITE_OPEN_READWRITE|SQLITE_OPEN_FULLMUTEX,
                              nullptr)==SQLITE_OK,"second SQLite writer opened");
        check(sqlite3_exec(broker,"BEGIN IMMEDIATE",nullptr,nullptr,nullptr)==SQLITE_OK,
              "simulate broker write transaction");
        std::atomic<bool> committed{false};
        std::thread release([&] {
            std::this_thread::sleep_for(std::chrono::milliseconds(180));
            committed.store(sqlite3_exec(broker,"COMMIT",nullptr,nullptr,nullptr)==SQLITE_OK);
        });
        const auto start=std::chrono::steady_clock::now();
        const bool accepted=monitor_exchange(receiver,maat::MonitorMessage::encode(identity(4)));
        const auto waited=std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now()-start).count();
        release.join();
        sqlite3_close(broker);
        check(committed.load(),"broker transaction completed");
        check(accepted,"valid SSH assertion waited for SQLite writer and was accepted");
        check(waited>=100,"concurrent SQLite assertion did not fail immediately");
        check(!monitor_exchange(receiver,maat::MonitorMessage::encode(identity(4))),
              "replay rejected after SQLite contention");
        // A writer that does not release its lock must NOT cause OpenSSH to
        // acknowledge authentication. Bound waiting is not infinite retry.
        check(sqlite3_open_v2(filename,&broker,SQLITE_OPEN_READWRITE|SQLITE_OPEN_FULLMUTEX,
                              nullptr)==SQLITE_OK,"locked-writer SQLite opened");
        check(sqlite3_exec(broker,"BEGIN IMMEDIATE",nullptr,nullptr,nullptr)==SQLITE_OK,
              "simulate stalled broker transaction");
        const auto blockedAt=std::chrono::steady_clock::now();
        const bool incorrectlyAccepted=monitor_exchange(receiver,maat::MonitorMessage::encode(identity(5)));
        const auto blockedMs=std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now()-blockedAt).count();
        check(!incorrectlyAccepted,"stalled SQLite writer must fail closed");
        check(blockedMs>=950 && blockedMs<1900,"SQLite busy wait remains bounded");
        check(sqlite3_exec(broker,"COMMIT",nullptr,nullptr,nullptr)==SQLITE_OK,
              "release stalled broker lock");
        sqlite3_close(broker);
        check(monitor_exchange(receiver,maat::MonitorMessage::encode(identity(5))),
              "previously unacknowledged assertion can be submitted after lock releases");
        maat::MonitorReceiver otherUid(store,getuid()+1);
        check(!monitor_exchange(otherUid,maat::MonitorMessage::encode(identity(3))),"untrusted peer UID rejected");
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
