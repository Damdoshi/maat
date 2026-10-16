#include "identity/trust_sync.hpp"
#include "identity/trust_peers.hpp"

#include <ext/stdio_filebuf.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace maat::identity;
namespace {
void require(bool ok,const char* what) {
    if(!ok)throw std::runtime_error(what);
}
TrustHash parseHash(const char* hex) {
    require(hex && std::strlen(hex)==64,"expected pinned 32-byte hex trust root");
    TrustHash result{};
    for(std::size_t i=0;i<result.size();++i) {
        auto digit=[](char c)->int {
            if(c>='0'&&c<='9')return c-'0';
            if(c>='a'&&c<='f')return c-'a'+10;
            if(c>='A'&&c<='F')return c-'A'+10;
            return -1;
        };
        const int high=digit(hex[i*2]),low=digit(hex[i*2+1]);
        require(high>=0 && low>=0,"nonhex trust root");
        result[i]=static_cast<std::uint8_t>(high*16+low);
    }
    return result;
}
std::int64_t clockNow() {
    auto now=std::time(nullptr);
    require(now>0,"system clock not initialized");
    return static_cast<std::int64_t>(now);
}
unsigned parseNumber(const char* arg,unsigned min,unsigned max) {
    require(arg && *arg,"empty numeric sync setting");
    char* end=nullptr;
    errno=0;
    const auto n=std::strtoul(arg,&end,10);
    require(!errno && end && !*end && n>=min && n<=max,"invalid numeric sync setting");
    return static_cast<unsigned>(n);
}
void requireLocalFile(const std::string& path,bool privateKey) {
    require(!path.empty() && path[0]=='/',"SSH credentials must use absolute paths");
    const int fd=open(path.c_str(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    require(fd>=0,"cannot open operator-pinned SSH credential file");
    struct stat st{};
    const bool okay=fstat(fd,&st)==0 && S_ISREG(st.st_mode) &&
        st.st_nlink==1 && (st.st_uid==0 || st.st_uid==geteuid()) &&
        (st.st_mode&0022)==0 && st.st_size>0 &&
        (!privateKey || (st.st_mode&0077)==0);
    close(fd);
    require(okay,"unsafe SSH private key or pinned known_hosts permissions");
}
void serve(ReplicatedTrust& local) {
    // A dedicated sshd ForceCommand executes this exact mode. No arbitrary
    // shell commands or roots are read from the remote peer's input.
    for(unsigned page=0;page<4096;++page) {
        TrustSyncRequest request;
        if(!readTrustSyncRequest(std::cin,request))return;
        const auto response=answerTrustSync(local,request,clockNow());
        writeTrustSyncResponse(std::cout,response);
    }
    throw std::runtime_error("trust sync request quota exceeded");
}
class SshChannel final {
    pid_t pid_=-1;
    int to_=-1,from_=-1;
public:
    SshChannel(const std::string& destination,const std::string& port,
               const std::string& identity,const std::string& knownHosts) {
        // No shell, interpolation, or remote command: the remote dedicated
        // sshd must enforce a fixed ForceCommand for its maat-sync account.
        require(!destination.empty() && destination.size()<256 &&
                destination[0]!='-' && identity.size()<4096,
                "invalid SSH destination or key path");
        for(const char c:destination)
            require((c>='a'&&c<='z')||(c>='A'&&c<='Z')||
                    (c>='0'&&c<='9')||c=='@'||c=='.'||c=='-'||
                    c=='_'||c=='['||c==']'||c==':',
                    "invalid SSH destination character");
        // A local trusted peers file supplies the host-key database. Never
        // accept a remotely supplied key or enable StrictHostKeyChecking=accept-new.
        require(knownHosts.empty() || (knownHosts[0]=='/' &&
                knownHosts.size()<4096),"invalid pinned known_hosts path");
        if(!knownHosts.empty()) {
            requireLocalFile(identity,true);
            requireLocalFile(knownHosts,false);
        }
        int in[2],out[2];
        require(pipe(in)==0,"SSH stdin pipe failure");
        if(pipe(out)!=0){close(in[0]);close(in[1]);throw std::runtime_error("SSH stdout pipe failure");}
        pid_=fork();
        if(pid_<0) {
            close(in[0]);close(in[1]);close(out[0]);close(out[1]);
            throw std::runtime_error("SSH process fork failure");
        }
        if(pid_==0) {
            if(dup2(in[0],STDIN_FILENO)<0 || dup2(out[1],STDOUT_FILENO)<0)_exit(126);
            close(in[0]);close(in[1]);close(out[0]);close(out[1]);
            const std::string knownOption="UserKnownHostsFile="+knownHosts;
            // GNU timeout bounds a malicious or broken SSH server that keeps
            // a channel alive without returning a protocol response.
            // No shell is ever involved. -F /dev/null disables user-supplied
            // SSH config, ProxyCommand and unexpected remote-command settings.
            if(!knownHosts.empty()) {
                execl("/usr/bin/timeout","timeout","--signal=TERM",
                      "--kill-after=5s","30s","/usr/bin/ssh","-F","/dev/null",
                      "-T","-o","BatchMode=yes","-o","IdentitiesOnly=yes",
                      "-o","StrictHostKeyChecking=yes",
                      "-o",knownOption.c_str(),"-o","GlobalKnownHostsFile=/dev/null",
                      "-o","UpdateHostKeys=no","-o","HostKeyAlgorithms=ssh-ed25519",
                      "-o","ConnectTimeout=10",
                      "-o","ConnectionAttempts=1","-o","ClearAllForwardings=yes",
                      "-o","RequestTTY=no","-o","ProxyCommand=none",
                      "-o","ProxyJump=none","-o","ServerAliveInterval=10",
                      "-o","ServerAliveCountMax=2","-p",port.c_str(),
                      "-i",identity.c_str(),destination.c_str(),
                      static_cast<char*>(nullptr));
            } else {
                execl("/usr/bin/timeout","timeout","--signal=TERM",
                      "--kill-after=5s","30s","/usr/bin/ssh","-F","/dev/null",
                      "-T","-o","BatchMode=yes","-o","IdentitiesOnly=yes",
                      "-o","StrictHostKeyChecking=yes","-o","UpdateHostKeys=no",
                      "-o","ConnectTimeout=10","-o","ConnectionAttempts=1",
                      "-o","ClearAllForwardings=yes","-o","RequestTTY=no",
                      "-o","ProxyCommand=none","-o","ProxyJump=none",
                      "-o","ServerAliveInterval=10","-o","ServerAliveCountMax=2",
                      "-p",port.c_str(),"-i",identity.c_str(),
                      destination.c_str(),static_cast<char*>(nullptr));
            }
            _exit(127);
        }
        close(in[0]);close(out[1]);to_=in[1];from_=out[0];
    }
    ~SshChannel(){
        if(to_>=0)close(to_);
        if(from_>=0)close(from_);
        if(pid_>0) {
            int status=0;
            while(waitpid(pid_,&status,0)<0 && errno==EINTR){}
        }
    }
    int writer()const{return to_;}
    int reader()const{return from_;}
};
std::size_t pull(ReplicatedTrust& local,const std::string& host,
          const std::string& port,const std::string& identity,
          const std::string& knownHosts,unsigned maxPages,bool requireFresh) {
    SshChannel channel(host,port,identity,knownHosts);
    const int writeFd=dup(channel.writer());
    require(writeFd>=0,"SSH channel duplication failed");
    const int readFd=dup(channel.reader());
    if(readFd<0){close(writeFd);throw std::runtime_error("SSH channel duplication failed");}
    // Filebuf owns the duplicates; SshChannel closes the originals.
    __gnu_cxx::stdio_filebuf<char> writer(writeFd,std::ios::out);
    __gnu_cxx::stdio_filebuf<char> reader(readFd,std::ios::in);
    std::ostream out(&writer);
    std::istream in(&reader);
    std::size_t applied=0;
    bool completed=false;
    for(unsigned page=0;page<maxPages;++page) {
        auto request=makeTrustSyncRequest(local);
        writeTrustSyncRequest(out,request);
        const auto response=readTrustSyncResponse(in);
        const auto delta=acceptTrustSync(local,request,response,clockNow());
        applied+=delta;
        // A short page does not mean EOF: a peer might provide only a
        // partial response while advertising an AUTHENTIC newer signed tip.
        // Keep reading until our locally committed head catches that tip.
        const bool signedMore = !response.tipEvidence.empty() &&
            decodeTrustDelta(response.tipEvidence).sequence>local.sequence();
        if(delta==0 || !signedMore) {completed=true;break;}
    }
    std::fprintf(stderr,"Maât signed trust sync: %zu new events, local sequence %llu, "
                 "fresh=%s, forked=%s\n",applied,
                 static_cast<unsigned long long>(local.sequence()),
                 local.fresh(clockNow())?"yes":"NO",
                 local.forked()?"YES":"no");
    require(completed,"sync page budget exhausted; rerun to continue");
    require(!local.forked(),"trust fork quarantined");
    // Catching up to a peer does not imply a fresh authority heartbeat.
    // Always refuse to declare the local register usable if it is still stale.
    if(requireFresh)
        require(local.fresh(clockNow()),"trust sync incomplete/stale: verifier remains closed");
    return applied;
}
void round(ReplicatedTrust& local,const std::string& peersFile) {
    // Every peer may fail, but an unavailable peer must not block trying the
    // others. The trust root remains pinned across attempts. A cryptographically
    // demonstrated fork is permanent quarantine, not a retryable network error.
    const auto peers=loadTrustPeers(peersFile);
    bool exchanged=false;
    for(const auto& peer:peers) {
        if(local.forked())throw std::runtime_error("signed fork: local trust quarantined");
        try {
            (void)pull(local,peer.destination,peer.port,peer.privateKey,
                       peer.knownHosts,peer.maxPages,false);
            exchanged=true;
        } catch(const std::exception& e) {
            std::fprintf(stderr,"Maât peer %s:%s failed: %s\n",
                         peer.destination.c_str(),peer.port.c_str(),e.what());
        }
        if(local.forked())throw std::runtime_error("signed fork: local trust quarantined");
        if(exchanged && local.fresh(clockNow())) {
            std::fprintf(stderr,"Maât: local signed trust pool is fresh (sequence %llu)\n",
                         static_cast<unsigned long long>(local.sequence()));
            return;
        }
    }
    require(exchanged,"all SSH trust peers unavailable or invalid");
    require(local.fresh(clockNow()),"all peers exhausted; signed pool still stale");
}
void usage() {
    std::fprintf(stderr,
        "usage:\n  maat-trust-sync serve DB REGISTRY_HEX AUTHORITY_ED25519_HEX\n"
        "  maat-trust-sync pull DB REGISTRY_HEX AUTHORITY_ED25519_HEX "
        "SSH_USER_AT_HOST SSH_PORT SSH_IDENTITY [MAX_PAGES]\n"
        "  maat-trust-sync round DB REGISTRY_HEX AUTHORITY_ED25519_HEX /absolute/peers.conf\n"
        "Serve ONLY as a forced command in a separate sshd; pin the server SSH host key.\n");
}
}
int main(int argc,char** argv) {
    // A peer can close SSH while we write a request. Turn SIGPIPE into an
    // ordinary I/O error so 'round' can fail over instead of crashing.
    struct sigaction ignore{};
    ignore.sa_handler=SIG_IGN;
    sigemptyset(&ignore.sa_mask);
    sigaction(SIGPIPE,&ignore,nullptr);
    try {
        if(argc<5){usage();return 2;}
        const std::string mode(argv[1]);
        const auto registry=parseHash(argv[3]),authority=parseHash(argv[4]);
        ReplicatedTrust db(argv[2],registry,authority);
        if(mode=="serve" && argc==5)serve(db);
        else if(mode=="pull" && (argc==8 || argc==9)) {
            auto port=parseNumber(argv[6],1,65535);
            (void)port;
            const auto pages=argc==9?parseNumber(argv[8],1,4096):4096;
            (void)pull(db,argv[5],argv[6],argv[7],"",pages,true);
        } else if(mode=="round" && argc==6) {
            round(db,argv[5]);
        } else {usage();return 2;}
        return 0;
    } catch(const std::exception& e) {
        std::fprintf(stderr,"Maât trust sync refused: %s\n",e.what());
        return 1;
    }
}
