#include "http/http_domain.hpp"
#include "http/identity_broker.hpp"
#include "monitor_protocol.hpp"
#include "replay_store.hpp"
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <stdexcept>
#include <vector>
#include <algorithm>
namespace {
int count=0;
void check(bool ok,const char* message) {
    ++count;
    if(!ok){std::fprintf(stderr,"FAIL %s\n",message);std::exit(1);}
}
template <typename F> void bad(F f,const char* m) {
    bool threw=false;try{f();}catch(const std::invalid_argument&){threw=true;}
    check(threw,m);
}
std::vector<uint8_t> key() {
    std::vector<uint8_t> k(51,0);k[3]=11;
    for(int i=0;i<11;++i)k[4+i]=uint8_t("ssh-ed25519"[i]);
    k[18]=32;
    for(int i=0;i<32;++i)k[19+i]=uint8_t(i+1);
    return k;
}
std::string sessionHex(){return std::string(64,'a');}
std::string issue(maat::SessionTicketChannel& issuer,bool expect){
    int fds[2];check(socketpair(AF_UNIX,SOCK_SEQPACKET,0,fds)==0,"socketpair issue");
    auto msg=maat::requestMessage("MAATGET2","");msg.resize(4+8);
    check(send(fds[0],msg.data(),msg.size(),0)==ssize_t(msg.size()),"issue send");
    bool accepted=issuer.serve(fds[1]);check(accepted==expect,"issue acceptance");
    std::string token;
    if(accepted) {
        uint8_t reply[256];ssize_t n=recv(fds[0],reply,sizeof(reply),MSG_DONTWAIT);
        check(n>0,"issue response");
        std::vector<uint8_t> bytes(reply,reply+n);size_t off=0;
        check(maat::readString(bytes,off,40)=="MAATHTTP1","issue version");
        token=maat::readString(bytes,off,64);
        check(off==bytes.size(),"no trailing reply bytes");
    }
    close(fds[0]);close(fds[1]);return token;
}
bool verify(maat::TicketVerifier& verifier,const std::string& token,std::string* name=nullptr){
    int fds[2];check(socketpair(AF_UNIX,SOCK_SEQPACKET,0,fds)==0,"socketpair verify");
    auto msg=maat::requestMessage("MAATCHECK1",token);
    check(send(fds[0],msg.data(),msg.size(),0)==ssize_t(msg.size()),"verify send");
    bool accepted=verifier.serve(fds[1]);
    if(accepted) {
        uint8_t buf[256];ssize_t n=recv(fds[0],buf,sizeof(buf),MSG_DONTWAIT);
        check(n>0,"verify response");
        std::vector<uint8_t> bytes(buf,buf+n);size_t off=0;
        check(maat::readString(bytes,off,20)=="MAATIDENT1","verify version");
        auto user=maat::readString(bytes,off,128);
        auto key=maat::readString(bytes,off,51);
        check(user=="maatweb" && key.size()==51 && off==bytes.size(),"SSH identity returned");
        if(name)*name=user;
    }
    close(fds[0]);close(fds[1]);return accepted;
}
maat::HTTPRequest parse(const std::string& wire){
    int p[2];check(pipe(p)==0,"pipe");
    check(write(p[1],wire.data(),wire.size())==ssize_t(wire.size()),"feed request");
    close(p[1]);auto r=maat::HTTPRequest::read(p[0]);close(p[0]);return r;
}
}
int main(){
    const std::string config="[UIDRange\n First=1000000000\n Last=2099999999\n]\n";
    auto range=maat::UIDRangeConfiguration::parse(config);
    check(range.first()==1000000000ULL && range.last()==2099999999ULL,"Dabsic UID range parse");
    bad([]{maat::UIDRangeConfiguration::parse("[UIDRange\n First=42\n Last=2000000000\n]\n");},"reject dangerously low UID range");
    bad([]{maat::UIDRangeConfiguration::parse("[UIDRange\n First=1000000000\n Last=4294967295\n]\n");},"reject invalid signed UID range");
    bad([]{maat::UIDRangeConfiguration::parse("[UIDRange\n First=1000000000\n First=1000000001\n Last=2000000000\n]\n");},"reject duplicate key");
    bad([]{maat::UIDRangeConfiguration::parse("[UIDRange\n First=1000000000\n Last=2000000000\n Extra=1\n]\n");},"reject unknown key");
    bad([]{maat::UIDRangeConfiguration::parse("[UIDRange\n First=1000000000\n]");},"reject missing last UID");
    bad([]{maat::UIDRangeConfiguration::parse("[UIDRange\n First=1000000000\n Last=2000000000\n]\n[Another\n]");},"reject extra block");
    bad([]{maat::UIDRangeConfiguration::parse("[UIDRange\n First=1000000000\n Last=2000000000\n");},"reject missing closing bracket");
    bad([]{maat::UIDRangeConfiguration::parse("[UIDRange\n First=+1000000000\n Last=2000000000\n]");},"reject signed/invalid integer");
    check(maat::UIDRange(2000000000ULL,2000000000ULL).contains(2000000000ULL),"single UID range valid");
    bad([]{maat::UIDRange(2000000000ULL,1000000000ULL);},"reversed UID range rejected");
    if(geteuid()==0) {
        char fname[]="/tmp/maat-uid-config-XXXXXX";
        int configFD=mkstemp(fname);
        check(configFD>=0,"UID config test file created");
        check(write(configFD,config.data(),config.size())==ssize_t(config.size()),"UID config fixture written");
        close(configFD);
        check(maat::UIDRangeConfiguration::read(fname).last()==range.last(),"secure UID config file loaded");
        check(chmod(fname,0666)==0,"make config insecure");
        bool refused=false;
        try {maat::UIDRangeConfiguration::read(fname);}catch(const std::runtime_error&){refused=true;}
        check(refused,"reject group/world writable configuration");
        check(chmod(fname,0600)==0,"restore secure config mode");
        std::string link=std::string(fname)+".link";
        check(symlink(fname,link.c_str())==0,"create UID config symlink");
        refused=false;
        try{maat::UIDRangeConfiguration::read(link);}catch(const std::runtime_error&){refused=true;}
        check(refused,"reject symlink UID configuration");
        unlink(link.c_str());unlink(fname);
    }
    bad([]{maat::SessionIdentifier s("aBcdef");},"hex case rejected");
    bad([]{maat::SessionIdentifier s("deadbeef");},"short session rejected");
    bad([]{maat::RequestTicket t("deadbeef");},"short ticket rejected");
    bad([]{maat::EphemeralUID(999999999ULL);},"UID below reserved range rejected");
    bad([]{maat::EphemeralUID(2100000000ULL);},"UID beyond reserved range rejected");
    check(maat::EphemeralUID(1000000000ULL).value()==1000000000U,"first reserved UID valid");
    maat::RequestTicket generated;
    check(generated.hex().size()==64,"secure token length");
    maat::RequestTicket reconstructed(generated.hex());
    check(generated.hex()==reconstructed.hex(),"token roundtrip");
    auto request=parse("POST /whoami.php HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\nX-Maat-Ticket: evil\r\nX-Maat-User: fake\r\n\r\ntest");
    auto clean=request.forwarded(generated.hex());
    check(clean.find("X-Maat-User: fake")==std::string::npos,"identity header scrub");
    check(clean.find("X-Maat-Ticket: evil")==std::string::npos,"ticket header scrub");
    check(clean.find("test")!=std::string::npos,"POST body preserved");
    check(clean.find("X-Maat-Ticket: "+generated.hex())!=std::string::npos,"issued ticket injected");
    bad([]{parse("GET / HTTP/1.1\r\nHost: local\r\nTransfer-Encoding: chunked\r\n\r\n");},"chunked rejected");
    bad([]{parse("GET / HTTP/1.1\r\nHost: local\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n");},"duplicate length rejected");
    bad([]{parse("GET / HTTP/1.1\r\nHost: local\r\nConnection: upgrade\r\n\r\n");},"upgrade rejected");
    bad([]{parse("GET / HTTP/1.1\r\nHost: local\r\nHost: local\r\n\r\n");},"duplicate host rejected");
    bad([]{parse("GET / HTTP/1.1\r\nHost: local\r\n\r\nx");},"pipelining rejected");
    bad([]{parse("POST / HTTP/1.1\r\nHost: local\r\n\r\n");},"missing POST length");
    bad([]{parse("GET / HTTP/1.0\r\nHost: local\r\n\r\n");},"old protocol rejected");
    bad([]{parse("GET / HTTP/1.1\r\nHost: local\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\nabc");},"smuggling rejected");
    char path[]="/tmp/maat-http-XXXXXX";
    int fd=mkstemp(path);check(fd>=0,"temp db");close(fd);
    {
        maat::ReplayStore monitor(path);
        maat::IdentityRepository repo(path);
        maat::SessionTicketChannel issuer(repo,maat::SessionIdentifier(sessionHex()));
        maat::TicketVerifier verifier(repo,getuid());
        check(issue(issuer,false).empty(),"unregistered session denied");
        auto identity=maat::AuthenticatedSession("maatweb",std::vector<uint8_t>(32,0xaa),maat::PublicKey(key()));
        check(monitor.record(identity),"valid SSH monitor assertion persisted");
        uid_t allocatedUID=0;
        check(repo.bind(maat::SessionIdentifier(sessionHex()),allocatedUID),"root binds authenticated session once");
        check(!repo.bind(maat::SessionIdentifier(sessionHex()),allocatedUID),"binding replay denied");
        const auto token=issue(issuer,true);
        check(token.size()==64,"ticket issued");
        check(issue(issuer,false).empty(),"SSH session cannot mint second token");
        check(!verify(verifier,std::string(64,'1')),"fake ticket rejected");
        check(verify(verifier,token),"valid ticket consumed");
        check(!verify(verifier,token),"replay rejected");

        maat::TicketVerifier wrongUid(repo,getuid()+1);
        check(!verify(wrongUid,token),"wrong PHP UID rejected");
    }
    uid_t firstUID=0;
    {
        maat::IdentityRepository reopened(path);
        maat::TicketVerifier verifier(reopened,getuid());
        check(!verify(verifier,generated.hex()),"unknown token after reopen");
        uid_t replayUID=0;
        check(!reopened.bind(maat::SessionIdentifier(sessionHex()),replayUID),"session binding replay survives restart");
        // The ledger and assignment are durable: a second real monitor
        // assertion receives a DIFFERENT, monotonically increasing UID.
        maat::ReplayStore monitor(path);
        const std::string another(64,'b');
        auto second=maat::AuthenticatedSession("maatweb",std::vector<uint8_t>(32,0xbb),maat::PublicKey(key()));
        check(monitor.record(second),"second SSH assertion persisted");
        check(reopened.bind(maat::SessionIdentifier(another),firstUID),"second session bound after DB restart");
        check(firstUID==1000000001U,"UID ledger strictly monotonic across restart");
    }
    {
        maat::IdentityRepository reopened(path);
        maat::ReplayStore monitor(path);
        const std::string third(64,'d');
        auto thirdIdentity=maat::AuthenticatedSession("maatweb",std::vector<uint8_t>(32,0xdd),maat::PublicKey(key()));
        check(monitor.record(thirdIdentity),"third SSH assertion persisted");
        uid_t newerUID=0;
        check(reopened.bind(maat::SessionIdentifier(third),newerUID),"third session allocated");
        check(newerUID>firstUID,"allocated UID cannot be recycled after restart");
    }
    unlink(path);unlink((std::string(path)+"-wal").c_str());unlink((std::string(path)+"-shm").c_str());
    std::fprintf(stderr,"PASS %d HTTP/session/broker checks\n",count);
}
