#include "identity/privacy_bootstrap.hpp"
#include "identity/citizen_registry.hpp"

#include <openssl/evp.h>
#include <sqlite3.h>
#include <unistd.h>
#include <sys/stat.h>

#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <stdexcept>
#include <string>
#include <vector>

using namespace maat::identity;
namespace {
void check(bool ok, const char* message) {
    if (!ok) { std::fprintf(stderr,"FAIL privacy: %s\n",message); std::exit(1); }
}
template<typename F> void rejects(F f, const char* message) {
    try { f(); } catch (const std::exception&) { return; }
    check(false,message);
}
Fingerprint bytes(unsigned start) {
    Fingerprint out{};
    for (std::size_t i=0;i<out.size();++i)
        out[i]=std::uint8_t((start+3*i)%251);
    return out;
}
struct Key final {
    Fingerprint seed{},publicKey{};
    EVP_PKEY* key=nullptr;
    explicit Key(unsigned start):seed(bytes(start)) {
        key=EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519,nullptr,seed.data(),32);
        if (!key) throw std::runtime_error("test Ed25519 failed");
        std::size_t n=publicKey.size();
        if (EVP_PKEY_get_raw_public_key(key,publicKey.data(),&n)!=1 || n!=32)
            throw std::runtime_error("test public key failed");
    }
    ~Key() { EVP_PKEY_free(key); }
    Key(const Key&)=delete;
    Key& operator=(const Key&)=delete;
    Ed25519Signature sign(const std::vector<std::uint8_t>& msg) const {
        EVP_MD_CTX* c=EVP_MD_CTX_new();
        if (!c) throw std::runtime_error("test sign context failed");
        Ed25519Signature sig{};
        std::size_t n=sig.size();
        const bool ok=EVP_DigestSignInit(c,nullptr,nullptr,nullptr,key)==1 &&
                      EVP_DigestSign(c,sig.data(),&n,msg.data(),msg.size())==1 && n==64;
        EVP_MD_CTX_free(c);
        if (!ok) throw std::runtime_error("test signature failed");
        return sig;
    }
};
AuthorityInstruction instruction(RegistryOperation op, std::uint64_t seq,
                                 const Fingerprint& namespaceId,
                                 const std::string& citizenId="") {
    AuthorityInstruction cmd{};
    cmd.operation=op; cmd.sequence=seq; cmd.registryId=namespaceId;
    cmd.citizenId=citizenId;
    return cmd;
}
AuthorityResult apply(RegistryAuthority& authority, const Key& key, AuthorityInstruction cmd) {
    return authority.apply(cmd,key.sign(authoritySigningBytes(cmd)));
}
ScopeFreeIssueRequest request(ScopeFreeCredentialIssuer& issuer, const Fingerprint& ns,
                              const Key& holder, const Fingerprint& commitment) {
    ScopeFreeIssueRequest r{};
    r.citizenKey=holder.publicKey;
    r.nymCommitment=commitment;
    r.challenge=issuer.challenge();
    r.citizenSignature=holder.sign(scopeFreeRequestBytes(ns,r));
    return r;
}
void validateReceipt(const ScopeFreeCredential& c, const Key& issuer) {
    const auto bytes=scopeFreeCredentialBytes(c);
    EVP_MD_CTX* ctx=EVP_MD_CTX_new();
    check(ctx!=nullptr,"allocate receipt verifier");
    EVP_PKEY* key=EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519,nullptr,
                                               issuer.publicKey.data(),32);
    check(key!=nullptr,"receipt issuer key");
    check(EVP_DigestVerifyInit(ctx,nullptr,nullptr,nullptr,key)==1 &&
          EVP_DigestVerify(ctx,c.issuerSignature.data(),64,bytes.data(),bytes.size())==1,
          "receipt signed by issuer");
    EVP_PKEY_free(key);
    EVP_MD_CTX_free(ctx);
}
}

int main() {
    char temp[]="/tmp/maat-privacy-XXXXXX";
    check(mkdtemp(temp)!=nullptr,"temporary private directory");
    const std::string db=std::string(temp)+"/citizens.db";
    const Fingerprint ns=bytes(4), otherNs=bytes(5);
    Key root(10), issuerKey(20), unauthorized(30), alice(40), rotated(50), bob(60);
    const Fingerprint secretA=bytes(90), secretB=bytes(100);
    const Fingerprint nymA=prototypeNymCommitment(secretA);
    const Fingerprint nymB=prototypeNymCommitment(secretB);
    const auto aScope=unverifiedLocalScopeNullifier(secretA,ns,"example.com");
    check(aScope==unverifiedLocalScopeNullifier(secretA,ns,"example.com"),
          "holder local tag stable");
    check(aScope!=unverifiedLocalScopeNullifier(secretA,ns,"another.com"),
          "different service yields different local tag");
    check(aScope!=unverifiedLocalScopeNullifier(secretB,ns,"example.com"),
          "different secret yields different local tag");
    check(aScope!=unverifiedLocalScopeNullifier(secretA,otherNs,"example.com"),
          "registry namespace domain separation");
    rejects([&]{unverifiedLocalScopeNullifier(secretA,ns,"EXAMPLE.COM");},
            "reject noncanonical scopes");
    {
        CitizenRegistry registry(db);
        RegistryAuthority::bootstrap(registry,root.publicKey,ns);
        RegistryAuthority admin(registry,root.publicKey,ns);
        auto enrollment=instruction(RegistryOperation::enroll,1,ns);
        enrollment.subjectCommitment=bytes(140);
        enrollment.publicKey=alice.publicKey;
        const auto aliceId=apply(admin,root,enrollment).citizenId;
        auto enrollBob=instruction(RegistryOperation::enroll,2,ns);
        enrollBob.subjectCommitment=bytes(141);
        enrollBob.publicKey=bob.publicKey;
        const auto bobId=apply(admin,root,enrollBob).citizenId;
        check(aliceId!=bobId,"different citizens");
        rejects([&]{ScopeFreeCredentialIssuer::bootstrap(registry,ns,root.seed);},
                "issuer cannot reuse registry authority key");
        ScopeFreeCredentialIssuer::bootstrap(registry,ns,issuerKey.seed);
        rejects([&]{ScopeFreeCredentialIssuer::bootstrap(registry,ns,unauthorized.seed);},
                "issuer key cannot be silently changed");
        rejects([&]{ScopeFreeCredentialIssuer wrong(registry,otherNs,issuerKey.seed);},
                "registry namespace mismatch");
        ScopeFreeCredentialIssuer issuer(registry,ns,issuerKey.seed);
        rejects([&]{issuer.issue(request(issuer,ns,alice,nymA));},
                "anonymity permission default deny");
        auto allow=instruction(RegistryOperation::set_anonymous_permission,3,ns,aliceId);
        allow.permission=AnonymousPermission::allowed;
        apply(admin,root,allow);
        auto allowBob=instruction(RegistryOperation::set_anonymous_permission,4,ns,bobId);
        allowBob.permission=AnonymousPermission::allowed;
        apply(admin,root,allowBob);
        auto bad=request(issuer,ns,alice,nymA);
        bad.citizenSignature=unauthorized.sign(scopeFreeRequestBytes(ns,bad));
        rejects([&]{issuer.issue(bad);},"forged holder signature refused");
        rejects([&]{issuer.issue(bad);},"forged request consumes nonce");
        auto good=request(issuer,ns,alice,nymA);
        auto first=issuer.issue(good);
        validateReceipt(first,issuerKey);
        check(first.nymCommitment==nymA && first.registryId==ns,
              "no service in signed receipt");
        check(first.expiresAt-first.notBefore==300,"short bounded lifetime");
        rejects([&]{issuer.issue(good);},"issued challenge not replayable");
        auto next=issuer.issue(request(issuer,ns,alice,nymA));
        check(next.nymCommitment==first.nymCommitment && next.serial!=first.serial,
              "renewal keeps commitment with fresh serial");
        rejects([&]{issuer.issue(request(issuer,ns,alice,nymB));},
                "one citizen cannot change committed nym");
        rejects([&]{issuer.issue(request(issuer,ns,bob,nymA));},
                "two citizens cannot bind the same nym");
        const auto bobCredential=issuer.issue(request(issuer,ns,bob,nymB));
        validateReceipt(bobCredential,issuerKey);
        auto addKey=instruction(RegistryOperation::add_key,5,ns,aliceId);
        addKey.publicKey=rotated.publicKey;
        apply(admin,root,addKey);
        auto rotation=issuer.issue(request(issuer,ns,rotated,nymA));
        check(rotation.nymCommitment==first.nymCommitment,
              "citizen SSH key rotation cannot change the nym commitment");
        rejects([&]{issuer.issue(request(issuer,ns,rotated,nymB));},
                "rotated citizen key cannot reset nym");
        auto suspend=instruction(RegistryOperation::set_anonymous_permission,6,ns,aliceId);
        suspend.permission=AnonymousPermission::suspended;
        apply(admin,root,suspend);
        rejects([&]{issuer.issue(request(issuer,ns,alice,nymA));},
                "suspension refuses new scope-free receipts");
        rejects([&]{issuer.issue(request(issuer,ns,rotated,nymA));},
                "suspension also applies after key rotation");
        auto unsuspend=instruction(RegistryOperation::set_anonymous_permission,7,ns,aliceId);
        unsuspend.permission=AnonymousPermission::allowed;
        apply(admin,root,unsuspend);
        auto unrevoked=issuer.issue(request(issuer,ns,rotated,nymA));
        check(unrevoked.nymCommitment==nymA,"unsuspend retains same nym");
        auto revoke=instruction(RegistryOperation::revoke_citizen,8,ns,aliceId);
        apply(admin,root,revoke);
        rejects([&]{issuer.issue(request(issuer,ns,rotated,nymA));},
                "revocation prevents new issuance");
    }
    {
        CitizenRegistry registry(db);
        ScopeFreeCredentialIssuer issuer(registry,ns,issuerKey.seed);
        rejects([&]{issuer.issue(request(issuer,ns,alice,nymA));},
                "revocation survives restart");
        auto renewed=issuer.issue(request(issuer,ns,bob,nymB));
        check(renewed.nymCommitment==nymB,"commitment survives restart");
        validateReceipt(renewed,issuerKey);
    }
    // A service receives neither the citizen permanent key nor this globally
    // correlatable nym commitment: there is NO usable proof verifier in alpha4.
    std::remove(db.c_str());
    std::remove((db+"-wal").c_str());
    std::remove((db+"-shm").c_str());
    rmdir(temp);
    std::puts("PASS scope-free issuer, frozen nym, replay/revocation/key rotation; NO ZK verifier");
}
