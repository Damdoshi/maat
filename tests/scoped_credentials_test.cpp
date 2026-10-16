#include "identity/authority_commands.hpp"
#include "identity/scoped_credentials.hpp"

#include <openssl/evp.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <ctime>
#include <cstdlib>
#include <stdexcept>
#include <string>
#include <vector>

using namespace maat::identity;
namespace {
void check(bool value, const char* msg) {
    if (!value) { std::fprintf(stderr,"FAIL scoped credential: %s\n",msg); std::exit(1); }
}
template<typename F> void rejects(F f, const char* msg) {
    try { f(); } catch (const std::exception&) { return; }
    check(false,msg);
}
Fingerprint bytes(unsigned start) {
    Fingerprint f{};
    for (std::size_t i=0;i<f.size();++i) f[i]=std::uint8_t(start + i*3);
    return f;
}
struct Signer {
    EVP_PKEY* key=nullptr;
    Fingerprint seed{};
    Fingerprint publicKey{};
    explicit Signer(unsigned start):seed(bytes(start)) {
        key=EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519,nullptr,seed.data(),seed.size());
        if (!key) throw std::runtime_error("test signing key failed");
        std::size_t n=publicKey.size();
        if (EVP_PKEY_get_raw_public_key(key,publicKey.data(),&n)!=1 || n!=32)
            throw std::runtime_error("test public key failed");
    }
    ~Signer() { EVP_PKEY_free(key); }
    Signer(const Signer&)=delete;
    Signer& operator=(const Signer&)=delete;
    Ed25519Signature sign(const std::vector<std::uint8_t>& bytes) const {
        EVP_MD_CTX* ctx=EVP_MD_CTX_new();
        if (!ctx) throw std::runtime_error("test signing allocation failed");
        Ed25519Signature sig{};
        std::size_t n=sig.size();
        const bool ok=EVP_DigestSignInit(ctx,nullptr,nullptr,nullptr,key)==1 &&
                      EVP_DigestSign(ctx,sig.data(),&n,bytes.data(),bytes.size())==1 && n==64;
        EVP_MD_CTX_free(ctx);
        if (!ok) throw std::runtime_error("test Ed25519 sign failed");
        return sig;
    }
};
AuthorityInstruction command(RegistryOperation operation, std::uint64_t sequence,
                              const Fingerprint& registryId, const std::string& citizenId="") {
    AuthorityInstruction ins{};
    ins.operation=operation;
    ins.sequence=sequence;
    ins.registryId=registryId;
    ins.citizenId=citizenId;
    return ins;
}
void submit(RegistryAuthority& authority, const Signer& signer, AuthorityInstruction ins) {
    authority.apply(ins,signer.sign(authoritySigningBytes(ins)));
}
CredentialRequest requestFor(ScopedCredentialIssuer& issuer, const Fingerprint& registryId,
                             const Signer& citizen, const Signer& holder,
                             const std::string& scope) {
    CredentialRequest request{};
    request.citizenKey=citizen.publicKey;
    request.holderKey=holder.publicKey;
    request.challenge=issuer.challenge();
    request.serviceId=scope;
    request.citizenSignature=citizen.sign(credentialRequestBytes(registryId,request));
    return request;
}
bool present(ScopedCredentialVerifier& verifier, const ScopedCredential& credential,
             const Signer& holder) {
    const auto nonce=verifier.challenge();
    return verifier.verify(credential,nonce,
                           holder.sign(credentialPresentationBytes(credential,nonce)));
}
}

int main() {
    char directory[]="/tmp/maat-scoped-credentials-XXXXXX";
    check(mkdtemp(directory)!=nullptr,"private temp directory");
    const std::string db=std::string(directory)+"/registry.db";
    const std::string bansDb=std::string(directory)+"/bans.db";
    const Fingerprint registryId=bytes(30), otherRegistry=bytes(31);
    const Fingerprint nullifierSecret=bytes(90), differentSecret=bytes(91);
    Signer authoritySigner(1), issuerSigner(20), citizen(40), holder1(50),
           holder2(60), attacker(70), otherCitizen(80), rotatedCitizen(83);
    Fingerprint stableNullifier{};
    {
        CitizenRegistry registry(db);
        RegistryAuthority::bootstrap(registry,authoritySigner.publicKey,registryId);
        RegistryAuthority authority(registry,authoritySigner.publicKey,registryId);
        auto enroll=command(RegistryOperation::enroll,1,registryId);
        enroll.subjectCommitment=bytes(100);
        enroll.publicKey=citizen.publicKey;
        const std::string citizenId=authority.apply(enroll,authoritySigner.sign(
            authoritySigningBytes(enroll))).citizenId;
        auto enroll2=command(RegistryOperation::enroll,2,registryId);
        enroll2.subjectCommitment=bytes(101);
        enroll2.publicKey=otherCitizen.publicKey;
        const std::string otherId=authority.apply(enroll2,authoritySigner.sign(
            authoritySigningBytes(enroll2))).citizenId;
        check(citizenId!=otherId,"distinct citizen IDs");
        rejects([&]{ ScopedCredentialIssuer unprovisioned(registry,registryId,
                          issuerSigner.seed,nullifierSecret); },"issuer must be provisioned");
        rejects([&]{ ScopedCredentialIssuer::bootstrap(registry,registryId,
                          authoritySigner.seed,nullifierSecret); },
                "issuer and offline authority cannot share signing key");
        ScopedCredentialIssuer::bootstrap(registry,registryId,issuerSigner.seed,nullifierSecret);
        ScopedCredentialIssuer::bootstrap(registry,registryId,issuerSigner.seed,nullifierSecret);
        rejects([&]{ ScopedCredentialIssuer::bootstrap(registry,registryId,
                          issuerSigner.seed,differentSecret); },"secret change cannot reset nullifiers");
        rejects([&]{ ScopedCredentialIssuer::bootstrap(registry,otherRegistry,
                          issuerSigner.seed,nullifierSecret); },"cannot bootstrap other namespace");
        rejects([&]{ ScopedCredentialIssuer wrong(registry,registryId,
                          attacker.seed,nullifierSecret); },"issuer signer cannot rotate silently");
        rejects([&]{ ScopedCredentialIssuer wrong(registry,registryId,
                          issuerSigner.seed,differentSecret); },"PRF secret cannot rotate silently");
        ScopedCredentialIssuer issuer(registry,registryId,issuerSigner.seed,nullifierSecret);
        ServiceBanLedger bans(bansDb);
        ScopedCredentialVerifier verifierA(issuerSigner.publicKey,registryId,"site-a.example",bans);
        ScopedCredentialVerifier verifierB(issuerSigner.publicKey,registryId,"site-b.example",bans);
        auto denied=requestFor(issuer,registryId,citizen,holder1,"site-a.example");
        rejects([&]{issuer.issue(denied);},"anonymous privilege default-deny");
        auto grant=command(RegistryOperation::set_anonymous_permission,3,registryId,citizenId);
        grant.permission=AnonymousPermission::allowed;
        submit(authority,authoritySigner,grant);
        auto valid=requestFor(issuer,registryId,citizen,holder1,"site-a.example");
        auto spoof=valid;
        spoof.holderKey=attacker.publicKey;
        rejects([&]{issuer.issue(spoof);},"issue request signature binds the holder key");
        rejects([&]{issuer.issue(valid);},"invalid request consumes nonce");
        valid=requestFor(issuer,registryId,citizen,holder1,"site-a.example");
        const auto credential=issuer.issue(valid);
        stableNullifier=credential.nullifier;
        check(credential.serviceId=="site-a.example","scope is explicit");
        check(credential.expiresAt-credential.notBefore==300,"credential at most 5min");
        check(present(verifierA,credential,holder1),"valid issuer and holder signatures");
        check(!present(verifierB,credential,holder1),"cross-service assertion rejected");
        check(!present(verifierA,credential,attacker),"wrong holder rejected");
        auto altered=credential;
        altered.nullifier[0]^=0x01;
        check(!present(verifierA,altered,holder1),"tampered nullifier rejected");
        altered=credential;
        altered.expiresAt-=1;
        check(!present(verifierA,altered,holder1),"extended expiry rejected");
        altered=credential;
        altered.issuerSignature[0]^=0x01;
        check(!present(verifierA,altered,holder1),"forged issuer signature rejected");
        altered=credential;
        altered.expiresAt=std::uint64_t(std::time(nullptr))-1;
        altered.notBefore=altered.expiresAt-300;
        altered.issuerSignature=issuerSigner.sign(credentialSigningBytes(altered));
        check(!present(verifierA,altered,holder1),"expired but correctly signed token rejected");
        altered=credential;
        altered.notBefore=std::uint64_t(std::time(nullptr))+30;
        altered.expiresAt=altered.notBefore+300;
        altered.issuerSignature=issuerSigner.sign(credentialSigningBytes(altered));
        check(!present(verifierA,altered,holder1),"not-yet-valid signed token rejected");
        altered=credential;
        altered.expiresAt=altered.notBefore+301;
        rejects([&]{credentialSigningBytes(altered);},"credential period over 300 seconds refused");
        const auto replayNonce=verifierA.challenge();
        const auto replayProof=holder1.sign(credentialPresentationBytes(credential,replayNonce));
        check(verifierA.verify(credential,replayNonce,replayProof),"valid one-use proof");
        rejects([&]{verifierA.verify(credential,replayNonce,replayProof);},"presentation replay refused");
        rejects([&]{verifierA.verify(credential,bytes(211),replayProof);},"invented challenge refused");
        ScopedCredentialVerifier foreign(attacker.publicKey,registryId,"site-a.example",bans);
        check(!present(foreign,credential,holder1),"wrong issuer pin rejected");
        ScopedCredentialVerifier foreignRegistry(issuerSigner.publicKey,otherRegistry,"site-a.example",bans);
        check(!present(foreignRegistry,credential,holder1),"wrong registry rejected");
        const auto renewal=issuer.issue(requestFor(issuer,registryId,citizen,holder2,"site-a.example"));
        check(renewal.nullifier==stableNullifier,"same citizen has stable service nullifier after renewal");
        check(renewal.holderKey!=credential.holderKey,"renewal changes holder key");
        const auto onOtherService=issuer.issue(requestFor(issuer,registryId,citizen,holder2,"site-b.example"));
        check(onOtherService.nullifier!=stableNullifier,"different services get different nullifiers");
        check(present(verifierB,onOtherService,holder2),"credential usable in its own scope");
        auto addKey=command(RegistryOperation::add_key,4,registryId,citizenId);
        addKey.publicKey=rotatedCitizen.publicKey;
        submit(authority,authoritySigner,addKey);
        const auto rotatedCredential=issuer.issue(requestFor(issuer,registryId,rotatedCitizen,
                                                             holder1,"site-a.example"));
        check(rotatedCredential.nullifier==stableNullifier,
              "permanent citizen SSH key rotation preserves nullifier");
        check(bans.ban("site-a.example",stableNullifier),"ban stored for service");
        check(!present(verifierA,renewal,holder2),"ban survives renewal");
        check(present(verifierB,onOtherService,holder2),"ban does not leak across scopes");
        auto badRequest=requestFor(issuer,registryId,otherCitizen,attacker,"site-a.example");
        rejects([&]{issuer.issue(badRequest);},"other citizen must be allowed explicitly");
        auto suspend=command(RegistryOperation::set_anonymous_permission,5,registryId,citizenId);
        suspend.permission=AnonymousPermission::suspended;
        submit(authority,authoritySigner,suspend);
        rejects([&]{issuer.issue(requestFor(issuer,registryId,citizen,holder2,"site-a.example"));},
                "suspended citizen cannot receive new credentials");
        // An already issued credential is still valid until its bounded expiry.
        // Alpha3 has no signed revocation feed: this is a KNOWN LIMITATION.
        check(present(verifierB,onOtherService,holder2),"existing credential valid during bounded TTL");
        grant.sequence=6;
        submit(authority,authoritySigner,grant);
        auto revokeKey=command(RegistryOperation::revoke_key,7,registryId,citizenId);
        revokeKey.publicKey=citizen.publicKey;
        submit(authority,authoritySigner,revokeKey);
        rejects([&]{issuer.issue(requestFor(issuer,registryId,citizen,holder1,"site-b.example"));},
                "revoked citizen key cannot issue new credentials");
        check(present(verifierB,onOtherService,holder2),"existing credential persists until expiry");
        check(issuer.issue(requestFor(issuer,registryId,rotatedCitizen,holder2,"site-b.example"))
                  .nullifier==onOtherService.nullifier,
              "still-authorized rotated permanent key retains same nullifier");
        const auto revokeCitizen=command(RegistryOperation::revoke_citizen,8,registryId,citizenId);
        submit(authority,authoritySigner,revokeCitizen);
        rejects([&]{issuer.issue(requestFor(issuer,registryId,rotatedCitizen,holder2,"site-b.example"));},
                "revoked citizen cannot issue with rotated key");
    }
    {
        CitizenRegistry registry(db);
        ScopedCredentialIssuer issuer(registry,registryId,issuerSigner.seed,nullifierSecret);
        ServiceBanLedger bans(bansDb);
        ScopedCredentialVerifier verifier(issuerSigner.publicKey,registryId,"site-a.example",bans);
        check(bans.isBanned("site-a.example",stableNullifier),"ban survives process restart");
        check(bans.unban("site-a.example",stableNullifier),"unban allowed by local service");
        check(!bans.isBanned("site-a.example",stableNullifier),"unban persists");
    }
    for (const auto& f : {db,bansDb}) {
        unlink((f+"-shm").c_str()); unlink((f+"-wal").c_str()); unlink(f.c_str());
    }
    check(rmdir(directory)==0,"test directory removed");
    std::puts("PASS scoped credentials: citizen possession, default-deny, issuer pinning, stable service nullifiers, cross-scope isolation, challenge replay refusal, five-minute expiry, local bans, revocation on NEW issuance");
}
