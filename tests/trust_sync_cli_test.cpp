#include "identity/trust_sync.hpp"

#include <ext/stdio_filebuf.h>
#include <openssl/evp.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <exception>
#include <ios>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
using namespace maat::identity;
namespace {
void check(bool ok,const char* why) {
    if(!ok){std::fprintf(stderr,"FAIL trust CLI: %s\n",why);std::exit(1);}
}
std::string hex(const TrustHash& h) {
    constexpr char digits[]="0123456789abcdef";
    std::string out;
    for(auto n:h){out.push_back(digits[n>>4]);out.push_back(digits[n&15]);}
    return out;
}
struct Signer final {
    EVP_PKEY* key=nullptr;
    TrustHash pub{};
    Signer() {
        TrustHash seed{};
        for(std::size_t i=0;i<seed.size();++i)seed[i]=static_cast<std::uint8_t>(i+17);
        key=EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519,nullptr,seed.data(),seed.size());
        check(key!=nullptr,"Ed25519 test signer setup");
        std::size_t n=pub.size();
        check(EVP_PKEY_get_raw_public_key(key,pub.data(),&n)==1 && n==32,
              "Ed25519 public key extraction");
    }
    ~Signer(){EVP_PKEY_free(key);}
    void sign(TrustDelta& d) const {
        const auto body=trustDeltaSigningBytes(d);
        auto* ctx=EVP_MD_CTX_new();
        check(ctx!=nullptr,"Ed25519 sign context");
        std::size_t n=d.signature.size();
        const bool ok=EVP_DigestSignInit(ctx,nullptr,nullptr,nullptr,key)==1 &&
            EVP_DigestSign(ctx,d.signature.data(),&n,body.data(),body.size())==1 &&
            n==d.signature.size();
        EVP_MD_CTX_free(ctx);check(ok,"Ed25519 event sign");
    }
};
}
int main(int argc,char** argv) {
    check(argc==2 && argv[1][0]=='/',"CLI executable path required");
    char dir[]="/tmp/maat-cli-XXXXXX";
    check(mkdtemp(dir)!=nullptr,"temp directory");
    const std::string source=std::string(dir)+"/source.sqlite";
    const std::string target=std::string(dir)+"/target.sqlite";
    Signer signer;
    TrustHash registry{},citizen{};
    for(std::size_t i=0;i<registry.size();++i) {
        registry[i]=static_cast<std::uint8_t>(i+1);
        citizen[i]=static_cast<std::uint8_t>(i+101);
    }
    const auto now=static_cast<std::int64_t>(std::time(nullptr));
    check(now>0,"system clock");
    {
        ReplicatedTrust origin(source,registry,signer.pub);
        TrustDelta previous;
        for(unsigned i=0;i<65;++i) {
            TrustDelta d;
            d.registryId=registry;
            d.sequence=i+1;
            d.previousHash=i?trustDeltaHash(previous):TrustHash{};
            d.issuedAt=now-30;
            d.validUntil=now+3600;
            if(i==0) {
                d.operation=TrustOperation::add_citizen_key;
                d.publicKey.assign(citizen.begin(),citizen.end());
            }
            signer.sign(d);
            origin.apply(d,now);
            previous=d;
        }
    }
    int to[2],from[2];
    check(pipe(to)==0 && pipe(from)==0,"CLI pipes");
    const pid_t pid=fork();
    check(pid>=0,"CLI fork");
    if(pid==0) {
        if(dup2(to[0],STDIN_FILENO)<0 || dup2(from[1],STDOUT_FILENO)<0)_exit(126);
        close(to[0]);close(to[1]);close(from[0]);close(from[1]);
        const auto root=hex(registry),authority=hex(signer.pub);
        execl(argv[1],argv[1],"serve",source.c_str(),root.c_str(),
              authority.c_str(),static_cast<char*>(nullptr));
        _exit(127);
    }
    close(to[0]);close(from[1]);
    {
        __gnu_cxx::stdio_filebuf<char> writer(to[1],std::ios::out);
        __gnu_cxx::stdio_filebuf<char> reader(from[0],std::ios::in);
        std::ostream out(&writer);
        std::istream in(&reader);
        ReplicatedTrust replica(target,registry,signer.pub);
        for(unsigned expected:{64U,1U,0U}) {
            const auto request=makeTrustSyncRequest(replica);
            writeTrustSyncRequest(out,request);
            const auto response=readTrustSyncResponse(in);
            check(acceptTrustSync(replica,request,response,now)==expected,
                  "actual binary serve process pages 64,1,0");
        }
        check(replica.sequence()==65 && replica.fresh(now) &&
              replica.citizenKeyActive(citizen,now),"actual CLI signed pool replay");
    }
    int status=0;
    check(waitpid(pid,&status,0)==pid && WIFEXITED(status) && WEXITSTATUS(status)==0,
          "server exits cleanly on EOF");
    for(const auto& p:{source,target}) {
        unlink(p.c_str());unlink((p+"-wal").c_str());unlink((p+"-shm").c_str());
    }
    rmdir(dir);
    std::puts("PASS actual trust-sync serve subprocess: framed 64+1+0, signature-checked replica");
}
