#include "identity/bbs_bound_issuer.hpp"
#include "identity/citizen_registry.hpp"

#include <openssl/evp.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <stdexcept>
#include <string>
#include <vector>

extern "C" int maat_bbs_holder_commit_v1(const unsigned char*,unsigned char*,unsigned char*);
extern "C" int maat_bbs_holder_binding_v1(const unsigned char*,const unsigned char*,
                                           const unsigned char*,const unsigned char*,
                                           const unsigned char*,const unsigned char*,
                                           unsigned char*,unsigned char*);

using namespace maat::identity;
namespace {
void check(bool ok,const char* text) {
    if(!ok){std::fprintf(stderr,"FAIL bound issuer: %s\n",text);std::exit(1);}
}
template<class F> void rejects(F f,const char* text){
    try {f();}catch(const std::exception&){return;}
    check(false,text);
}
Fingerprint bytes(unsigned seed){
    Fingerprint r{};
    for(std::size_t i=0;i<r.size();++i)r[i]=std::uint8_t((seed+3*i)%251);
    return r;
}
struct EdKey final {
    Fingerprint seed{}, pub{};
    EVP_PKEY* key=nullptr;
    explicit EdKey(unsigned n):seed(bytes(n)) {
        key=EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519,nullptr,seed.data(),32);
        if(!key)throw std::runtime_error("Ed25519 setup");
        std::size_t len=pub.size();
        if(EVP_PKEY_get_raw_public_key(key,pub.data(),&len)!=1 || len!=32)
            throw std::runtime_error("Ed25519 pub");
    }
    ~EdKey(){EVP_PKEY_free(key);}
    EdKey(const EdKey&)=delete;
    EdKey& operator=(const EdKey&)=delete;
    Ed25519Signature sign(const std::vector<std::uint8_t>& b)const{
        EVP_MD_CTX* ctx=EVP_MD_CTX_new();
        if(!ctx)throw std::runtime_error("Ed25519 ctx");
        Ed25519Signature s{};std::size_t len=s.size();
        const bool ok=EVP_DigestSignInit(ctx,nullptr,nullptr,nullptr,key)==1 &&
             EVP_DigestSign(ctx,s.data(),&len,b.data(),b.size())==1 && len==64;
        EVP_MD_CTX_free(ctx);
        if(!ok)throw std::runtime_error("Ed25519 sign");
        return s;
    }
};
AuthorityInstruction instruction(RegistryOperation op,unsigned seq,
                                  const Fingerprint& ns,const std::string& id=""){
    AuthorityInstruction r{};r.operation=op;r.sequence=seq;r.registryId=ns;r.citizenId=id;
    return r;
}
AuthorityResult apply(RegistryAuthority& root,const EdKey& key,AuthorityInstruction command){
    return root.apply(command,key.sign(authoritySigningBytes(command)));
}
BbsBoundIssueRequest prepare(BbsBoundIssuer& issuer,const Fingerprint& ns,
                              const EdKey& citizen,unsigned prover){
    BbsBoundIssueRequest r{};
    r.citizenKey=citizen.pub;r.challenge=issuer.challenge();
    Fingerprint scalar{};scalar.back()=std::uint8_t(prover);
    Fingerprint blind{};
    check(maat_bbs_holder_commit_v1(scalar.data(),r.commitment.data(),blind.data())==1,
          "real Rust nym commitment");
    check(maat_bbs_holder_binding_v1(scalar.data(),blind.data(),r.commitment.data(),
            ns.data(),r.citizenKey.data(),r.challenge.data(),
            r.nymAnchor.data(),r.bindingProof.data())==1,"real Rust binding proof");
    r.citizenSignature=citizen.sign(bbsBoundRequestBytes(ns,r));
    return r;
}
}
int main(){
    char dir[]="/tmp/maat-bbs-bound-XXXXXX";
    check(mkdtemp(dir)!=nullptr,"temporary issuer DB");
    const std::string path=std::string(dir)+"/citizens.db";
    const Fingerprint ns=bytes(8), other=bytes(9);
    const Fingerprint bbsKey=bytes(75), entropyKey=bytes(90), changedEntropy=bytes(91);
    EdKey root(10), alice(30), rotated(31), bob(50), forged(60);
    std::string aId;
    std::array<std::uint8_t,48> savedAnchor{};
    {
        CitizenRegistry registry(path);
        RegistryAuthority::bootstrap(registry,root.pub,ns);
        RegistryAuthority admin(registry,root.pub,ns);
        auto enrollment=instruction(RegistryOperation::enroll,1,ns);
        enrollment.subjectCommitment=bytes(130);
        enrollment.publicKey=alice.pub;
        aId=apply(admin,root,enrollment).citizenId;
        auto e2=instruction(RegistryOperation::enroll,2,ns);
        e2.subjectCommitment=bytes(131);e2.publicKey=bob.pub;
        const auto bId=apply(admin,root,e2).citizenId;
        rejects([&]{BbsBoundIssuer::bootstrap(registry,other,bbsKey,entropyKey);},
                "reject wrong namespace");
        BbsBoundIssuer::bootstrap(registry,ns,bbsKey,entropyKey);
        rejects([&]{BbsBoundIssuer::bootstrap(registry,ns,bbsKey,changedEntropy);},
                "reject issuer PRF secret rotation");
        rejects([&]{BbsBoundIssuer::bootstrap(registry,ns,entropyKey,bbsKey);},
                "reject BBS signing key rotation");
        BbsBoundIssuer issuer(registry,ns,bbsKey,entropyKey);
        rejects([&]{issuer.issue(prepare(issuer,ns,alice,42));},"permission default deny");
        auto allow=instruction(RegistryOperation::set_anonymous_permission,3,ns,aId);
        allow.permission=AnonymousPermission::allowed;apply(admin,root,allow);
        auto bAllow=instruction(RegistryOperation::set_anonymous_permission,4,ns,bId);
        bAllow.permission=AnonymousPermission::allowed;apply(admin,root,bAllow);
        auto req=prepare(issuer,ns,alice,42);
        req.citizenSignature=forged.sign(bbsBoundRequestBytes(ns,req));
        rejects([&]{issuer.issue(req);},"forged holder signature");
        rejects([&]{issuer.issue(req);},"forged signature consumes nonce");
        auto first=prepare(issuer,ns,alice,42);
        savedAnchor=first.nymAnchor;
        const auto signedFirst=issuer.issue(first);
        check(signedFirst.blindSignature[0]!=0,"BBS blind signature issued");
        rejects([&]{issuer.issue(first);},"challenge replay");
        auto renewed=prepare(issuer,ns,alice,42);
        check(renewed.nymAnchor==savedAnchor && renewed.commitment!=first.commitment,
              "fresh blind commitment, stable private anchor");
        issuer.issue(renewed);
        auto altered=prepare(issuer,ns,alice,43);
        check(altered.nymAnchor!=savedAnchor,"different secret has different anchor");
        rejects([&]{issuer.issue(altered);},"cannot reset citizen nym");
        auto tampered=prepare(issuer,ns,alice,42);
        tampered.bindingProof.back()^=1;
        tampered.citizenSignature=alice.sign(bbsBoundRequestBytes(ns,tampered));
        rejects([&]{issuer.issue(tampered);},"Rust rejects false linkage proof");
        auto owner=prepare(issuer,ns,bob,42);
        rejects([&]{issuer.issue(owner);},"two citizens cannot share same anchor");
        auto otherOwner=prepare(issuer,ns,bob,50);
        issuer.issue(otherOwner);
        auto add=instruction(RegistryOperation::add_key,5,ns,aId);
        add.publicKey=rotated.pub;apply(admin,root,add);
        auto rotatedRequest=prepare(issuer,ns,rotated,42);
        check(rotatedRequest.nymAnchor==savedAnchor,"rotation retained hidden scalar");
        issuer.issue(rotatedRequest);
        rejects([&]{issuer.issue(prepare(issuer,ns,rotated,43));},
                "SSH-key rotation cannot alter bound scalar");
        auto suspend=instruction(RegistryOperation::set_anonymous_permission,6,ns,aId);
        suspend.permission=AnonymousPermission::suspended;apply(admin,root,suspend);
        rejects([&]{issuer.issue(prepare(issuer,ns,rotated,42));},"suspension closes issuance");
        auto reactivate=instruction(RegistryOperation::set_anonymous_permission,7,ns,aId);
        reactivate.permission=AnonymousPermission::allowed;apply(admin,root,reactivate);
        issuer.issue(prepare(issuer,ns,rotated,42));
    }
    {
        CitizenRegistry registry(path);
        BbsBoundIssuer issuer(registry,ns,bbsKey,entropyKey);
        auto reissued=prepare(issuer,ns,rotated,42);
        check(reissued.nymAnchor==savedAnchor,"restart retains pinned anchor");
        issuer.issue(reissued);
        rejects([&]{issuer.issue(prepare(issuer,ns,rotated,43));},
                "restart cannot reset nym");
    }
    std::remove(path.c_str());std::remove((path+"-wal").c_str());
    std::remove((path+"-shm").c_str());rmdir(dir);
    std::puts("PASS private BBS blind issuance: pinned holder anchor, stable issuer PRF,\n"
              "     replay/refusal/rotation/persistence; NOT connected to SSH or PHP");
}
