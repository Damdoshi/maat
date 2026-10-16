// SPDX-License-Identifier: MIT
// Alpha10 disposable QEMU laboratory ONLY: holds a private authority signing
// key on node A. Never install or use this tool outside the lab.
#include "identity/replicated_trust.hpp"
#include "identity/trust_sync.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
using namespace maat::identity;
namespace {
void require(bool condition,const char* message) {
    if(!condition)throw std::runtime_error(message);
}
using Key=std::unique_ptr<EVP_PKEY,decltype(&EVP_PKEY_free)>;
using Context=std::unique_ptr<EVP_PKEY_CTX,decltype(&EVP_PKEY_CTX_free)>;
TrustHash randomHash() {
    TrustHash h{};
    require(RAND_bytes(h.data(),static_cast<int>(h.size()))==1,"randomness unavailable");
    return h;
}
std::string hex(const TrustHash& h) {
    const char* digits="0123456789abcdef";
    std::string s;
    for(auto n:h){s+=digits[n>>4];s+=digits[n&15];}
    return s;
}
TrustHash unhex(const std::string& s) {
    require(s.size()==64,"invalid 32-byte hex value");
    TrustHash h{};
    for(std::size_t i=0;i<32;++i) {
        auto digit=[](char c)->int {
            if(c>='0' && c<='9')return c-'0';
            if(c>='a' && c<='f')return c-'a'+10;
            return -1;
        };
        int a=digit(s[i*2]),b=digit(s[i*2+1]);
        require(a>=0 && b>=0,"invalid hex digit");
        h[i]=static_cast<std::uint8_t>(a*16+b);
    }
    return h;
}
std::string readLine(const std::string& path) {
    std::ifstream in(path);
    std::string s;
    require(static_cast<bool>(std::getline(in,s)),"cannot read laboratory metadata");
    return s;
}
void writeFile(const std::string& path,const std::string& content) {
    const int fd=open(path.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600);
    require(fd>=0,"cannot create lab file safely (existing file?)");
    const auto n=write(fd,content.data(),content.size());
    require(close(fd)==0 && n==static_cast<ssize_t>(content.size()),
            "incomplete lab metadata write");
}
// Minimal deterministic load of a lab key; actual key is generated randomly on A.
Key loadPrivate(const std::string& path) {
    struct stat st{};
    require(lstat(path.c_str(),&st)==0 && S_ISREG(st.st_mode) &&
            (st.st_mode&0077)==0 && st.st_uid==geteuid(),
            "lab authority private key has unsafe owner or permissions");
    const auto seed=unhex(readLine(path));
    Key key(EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519,nullptr,
                  seed.data(),seed.size()),EVP_PKEY_free);
    require(key!=nullptr,"Ed25519 signing key could not be loaded");
    return key;
}
TrustHash publicKey(EVP_PKEY* key) {
    TrustHash h{};
    std::size_t n=h.size();
    require(EVP_PKEY_get_raw_public_key(key,h.data(),&n)==1 && n==h.size(),
            "Ed25519 public key unavailable");
    return h;
}
void sign(EVP_PKEY* key,TrustDelta& d) {
    auto* ctx=EVP_MD_CTX_new();
    require(ctx!=nullptr,"Ed25519 signing context unavailable");
    const auto message=trustDeltaSigningBytes(d);
    std::size_t n=d.signature.size();
    const bool ok=EVP_DigestSignInit(ctx,nullptr,nullptr,nullptr,key)==1 &&
        EVP_DigestSign(ctx,d.signature.data(),&n,message.data(),message.size())==1 &&
        n==d.signature.size();
    EVP_MD_CTX_free(ctx);
    require(ok,"Ed25519 event signing failed");
}
struct PublicRoot {
    TrustHash id{},pub{},citizen{};
};
PublicRoot root(const std::string& dir) {
    PublicRoot result;
    std::ifstream in(dir+"/root.txt");
    std::string id,pub,citizen;
    require(static_cast<bool>(in>>id>>pub>>citizen),"invalid public root fixture");
    result.id=unhex(id);result.pub=unhex(pub);result.citizen=unhex(citizen);
    return result;
}
std::int64_t now() {
    const auto t=std::time(nullptr);
    require(t>0,"system clock not initialized");
    return static_cast<std::int64_t>(t);
}
void append(ReplicatedTrust& db,EVP_PKEY* key,const PublicRoot& r,
            TrustOperation op,const std::vector<std::uint8_t>& material) {
    TrustDelta d;
    d.registryId=r.id;
    d.sequence=db.sequence()+1;
    if(d.sequence>1)d.previousHash=db.headHash();
    d.issuedAt=now()-30;
    d.validUntil=now()+3600;
    d.operation=op;
    d.publicKey=material;
    sign(key,d);
    db.apply(d,now());
}
void init(const std::string& dir) {
    // The fixture requires a disposable guest marker; never use it on a host.
    require(access("/etc/maat-disposable-p2p-lab",F_OK)==0,
            "refusing test authority generation outside disposable QEMU VM");
    const auto privateSeed=randomHash();
    Key key(EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519,nullptr,
             privateSeed.data(),privateSeed.size()),EVP_PKEY_free);
    require(key!=nullptr,"Ed25519 key generation failed");
    PublicRoot r{randomHash(),publicKey(key.get()),randomHash()};
    writeFile(dir+"/authority.key",hex(privateSeed)+"\n");
    writeFile(dir+"/root.txt",hex(r.id)+"\n"+hex(r.pub)+"\n"+hex(r.citizen)+"\n");
    ReplicatedTrust db(dir+"/trust.sqlite",r.id,r.pub);
    const std::vector<std::uint8_t> citizen(r.citizen.begin(),r.citizen.end());
    append(db,key.get(),r,TrustOperation::add_citizen_key,citizen);
    for(unsigned i=1;i<171;++i)append(db,key.get(),r,TrustOperation::heartbeat,{});
    require(db.sequence()==171 && db.citizenKeyActive(r.citizen,now()),
            "lab seed not authenticated");
    std::cout<<"LAB INIT sequence="<<db.sequence()<<"\n";
}
void revokeCitizen(const std::string& dir) {
    require(access("/etc/maat-disposable-p2p-lab",F_OK)==0,
            "refusing signing outside disposable QEMU VM");
    const auto r=root(dir);
    auto key=loadPrivate(dir+"/authority.key");
    require(publicKey(key.get())==r.pub,"authority signing key mismatch");
    ReplicatedTrust db(dir+"/trust.sqlite",r.id,r.pub);
    const std::vector<std::uint8_t> citizen(r.citizen.begin(),r.citizen.end());
    require(db.citizenKeyActive(r.citizen,now()),"citizen already revoked");
    append(db,key.get(),r,TrustOperation::revoke_citizen_key,citizen);
    require(!db.citizenKeyActive(r.citizen,now()),"revocation not in effect");
    std::cout<<"LAB REVOKE sequence="<<db.sequence()<<"\n";
}
void bbsIssuerChange(const std::string& dir, const std::string& encoded,
                     TrustOperation operation) {
    require(access("/etc/maat-disposable-p2p-lab",F_OK)==0,
            "refusing signing outside disposable QEMU VM");
    require(encoded.size()==192,"BBS issuer must be 96 bytes of hex");
    std::vector<std::uint8_t> issuer;
    issuer.reserve(96);
    for(std::size_t i=0;i<encoded.size();i+=2) {
        auto digit=[](char c)->int {
            if(c>='0'&&c<='9')return c-'0';
            if(c>='a'&&c<='f')return c-'a'+10;
            return -1;
        };
        const int a=digit(encoded[i]),b=digit(encoded[i+1]);
        require(a>=0&&b>=0,"invalid BBS issuer key hex");
        issuer.push_back(static_cast<std::uint8_t>(a*16+b));
    }
    const auto r=root(dir);
    auto signingKey=loadPrivate(dir+"/authority.key");
    require(publicKey(signingKey.get())==r.pub,"authority key mismatch");
    ReplicatedTrust db(dir+"/trust.sqlite",r.id,r.pub);
    append(db,signingKey.get(),r,operation,issuer);
    std::cout<<"LAB BBS sequence="<<db.sequence()<<"\n";
}
void status(const std::string& dir) {
    const auto r=root(dir);
    ReplicatedTrust db(dir+"/trust.sqlite",r.id,r.pub);
    std::cout<<"sequence="<<db.sequence()<<" fresh="<<(db.fresh(now())?1:0)
             <<" active="<<(db.citizenKeyActive(r.citizen,now())?1:0)
             <<" forked="<<(db.forked()?1:0)<<"\n";
}
void poison() {
    // Test-only hostile *peer*, without the authority's private key.
    // It supplies a plausible event with a forged signature. Client must
    // verify locally and refuse it before ANY mutation is committed.
    TrustSyncRequest request;
    while(readTrustSyncRequest(std::cin,request)) {
        TrustDelta d;
        d.registryId=request.registryId;
        d.sequence=request.cursor+1;
        d.previousHash=request.cursorHash;
        d.issuedAt=now()-30;
        d.validUntil=now()+3600;
        d.operation=TrustOperation::heartbeat;
        TrustSyncResponse reply;
        reply.status=TrustSyncStatus::events;
        reply.peerSequence=d.sequence;
        reply.events.push_back(encodeTrustDelta(d));
        writeTrustSyncResponse(std::cout,reply);
    }
}
}
int main(int argc,char** argv) {
    try {
        if(argc==4 && (std::strcmp(argv[1],"bbs-add")==0 ||
                       std::strcmp(argv[1],"bbs-revoke")==0)) {
            bbsIssuerChange(argv[2],argv[3],
                std::strcmp(argv[1],"bbs-add")==0 ?
                TrustOperation::add_bbs_issuer : TrustOperation::revoke_bbs_issuer);
            return 0;
        }
        require((argc==3 && (std::strcmp(argv[1],"init")==0 ||
                              std::strcmp(argv[1],"revoke")==0 ||
                              std::strcmp(argv[1],"status")==0)) ||
                (argc==2 && std::strcmp(argv[1],"poison")==0),
                "usage: maat-trust-lab init|revoke|status DIR ; or poison");
        const std::string mode(argv[1]);
        if(mode=="init")init(argv[2]);
        else if(mode=="revoke")revokeCitizen(argv[2]);
        else if(mode=="status")status(argv[2]);
        else poison();
    }catch(const std::exception& e) {
        std::fprintf(stderr,"Maât disposable P2P lab: %s\n",e.what());
        return 1;
    }
    return 0;
}
