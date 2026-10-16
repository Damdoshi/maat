#include "identity/citizen_registry.hpp"
#include "identity/authority_commands.hpp"

#include <openssl/evp.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <unistd.h>

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace maat::identity;

namespace {
const Fingerprint registryId = []{ Fingerprint v{}; for (unsigned i=0;i<32;++i) v[i]=std::uint8_t(195+i); return v; }();
void check(bool success, const char* why) {
    if (!success) { std::fprintf(stderr, "FAIL registry: %s\n",why); std::exit(1); }
}
Fingerprint bytes(unsigned seed) {
    Fingerprint value{};
    for (unsigned i=0; i<32; ++i) value[i]=std::uint8_t(seed+i*7);
    return value;
}
template<class F> void rejects(F action, const char* why) {
    try { action(); } catch (const std::exception&) { return; }
    check(false,why);
}
struct Signer final {
    EVP_PKEY* key = nullptr;
    Fingerprint publicKey{};
    explicit Signer(unsigned seed) {
        auto secret = bytes(seed);
        key=EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519,nullptr,secret.data(),secret.size());
        if (!key) throw std::runtime_error("test key unavailable");
        std::size_t len=publicKey.size();
        if (EVP_PKEY_get_raw_public_key(key,publicKey.data(),&len)!=1 || len!=32)
            throw std::runtime_error("test public key unavailable");
    }
    ~Signer() { if (key) EVP_PKEY_free(key); }
    Ed25519Signature sign(const AuthorityInstruction& command) const {
        const auto payload=authoritySigningBytes(command);
        EVP_MD_CTX* ctx=EVP_MD_CTX_new();
        if (!ctx) throw std::runtime_error("test signing context unavailable");
        Ed25519Signature signature{};
        std::size_t len=signature.size();
        const bool success=EVP_DigestSignInit(ctx,nullptr,nullptr,nullptr,key)==1 &&
            EVP_DigestSign(ctx,signature.data(),&len,payload.data(),payload.size())==1 &&
            len==signature.size();
        EVP_MD_CTX_free(ctx);
        if (!success) throw std::runtime_error("test signing failed");
        return signature;
    }
};
AuthorityInstruction enrollment(unsigned long long seq,const Fingerprint& subject,
                                 const Fingerprint& key) {
    AuthorityInstruction cmd;
    cmd.operation=RegistryOperation::enroll;
    cmd.sequence=seq; cmd.registryId=registryId; cmd.subjectCommitment=subject; cmd.publicKey=key;
    return cmd;
}
AuthorityInstruction onCitizen(RegistryOperation op, unsigned long long seq,
                                const std::string& id) {
    AuthorityInstruction cmd;
    cmd.operation=op; cmd.sequence=seq; cmd.registryId=registryId; cmd.citizenId=id;
    return cmd;
}
AuthorityResult submit(RegistryAuthority& auth, const Signer& signer,
                       const AuthorityInstruction& instruction) {
    return auth.apply(instruction,signer.sign(instruction));
}
void checkEventCount(const std::string& file, int count) {
    sqlite3* db=nullptr;
    check(sqlite3_open_v2(file.c_str(),&db,SQLITE_OPEN_READONLY,nullptr)==SQLITE_OK,
          "audit DB open");
    sqlite3_stmt* statement=nullptr;
    check(sqlite3_prepare_v2(db,"SELECT COUNT(*) FROM registry_authority_events",-1,
                             &statement,nullptr)==SQLITE_OK,"audit DB query");
    check(sqlite3_step(statement)==SQLITE_ROW && sqlite3_column_int(statement,0)==count,
          "audit log has exactly one event per applied command");
    sqlite3_finalize(statement); sqlite3_close(db);
}
} // namespace

int main() {
    char directory[]="/tmp/maat-identity-test-XXXXXX";
    check(mkdtemp(directory)!=nullptr,"private test directory creation");
    const std::string registryPath=std::string(directory)+"/citizens.sqlite";
    const std::string banPath=std::string(directory)+"/site.sqlite";
    const auto subjectA=bytes(1), subjectB=bytes(2);
    const auto aKey=bytes(10), rotated=bytes(30);
    Signer signer(223), adversary(224);
    std::string aliceId;
    std::uint64_t nextSeq=1;
    {
        CitizenRegistry unprovisioned(registryPath);
        rejects([&]{RegistryAuthority absent(unprovisioned,signer.publicKey,registryId);},
                "cannot administer before privileged bootstrap");
        RegistryAuthority::bootstrap(unprovisioned,signer.publicKey,registryId);
        RegistryAuthority::bootstrap(unprovisioned,signer.publicKey,registryId);
        rejects([&]{RegistryAuthority::bootstrap(unprovisioned,signer.publicKey,bytes(231));},
                "registry namespace immutable after bootstrap");
        rejects([&]{RegistryAuthority::bootstrap(unprovisioned,adversary.publicKey,registryId);},
                "authority key cannot be silently replaced");
        rejects([&]{RegistryAuthority unauthorized(unprovisioned,adversary.publicKey,registryId);},
                "wrong authority key rejected");
        RegistryAuthority admin(unprovisioned,signer.publicKey,registryId);
        ServiceBanLedger bans(banPath);

        auto enroll=enrollment(nextSeq,subjectA,aKey);
        auto invalidSignature=signer.sign(enroll);
        invalidSignature[4]^=0x55;
        rejects([&]{admin.apply(enroll,invalidSignature);},"invalid signature rejected");
        rejects([&]{admin.apply(enroll,adversary.sign(enroll));},"wrong signer rejected");
        auto altered=enroll;
        altered.registryId=bytes(232);
        rejects([&]{admin.apply(altered,signer.sign(altered));},
                "cross-registry signed instruction refused");
        altered=enroll;
        altered.publicKey=bytes(11);
        rejects([&]{admin.apply(altered,signer.sign(enroll));},
                "signature binds all command fields");
        rejects([&]{admin.apply(enrollment(2,subjectA,aKey),
                                 signer.sign(enrollment(2,subjectA,aKey)));},
                "out-of-order command refused");
        aliceId=submit(admin,signer,enroll).citizenId;
        ++nextSeq;
        check(aliceId.size()==64,"opaque citizen ID has fixed size");
        check(unprovisioned.lookup(aliceId)->status==CitizenStatus::active,
              "new citizen valid");
        check(unprovisioned.lookup(aliceId)->anonymous==AnonymousPermission::denied,
              "anonymous mode DENIED by default");
        check(unprovisioned.activeKeyOwner(aKey)==aliceId,
              "registered key belongs to citizen");
        rejects([&]{admin.apply(enroll,signer.sign(enroll));},"replayed enrollment rejected");
        rejects([&]{submit(admin,signer,enrollment(nextSeq,subjectA,bytes(40)));},
                "duplicate real person rejected");
        rejects([&]{submit(admin,signer,enrollment(nextSeq,subjectB,aKey));},
                "key cannot be assigned to multiple people");
        rejects([&]{submit(admin,signer,enrollment(nextSeq,Fingerprint{},bytes(60)));},
                "zero subject commitment rejected");
        rejects([&]{submit(admin,signer,enrollment(nextSeq,bytes(60),Fingerprint{}));},
                "zero public key rejected");
        rejects([&]{unprovisioned.lookup("alice");},"invalid citizen ID refused");
        check(!unprovisioned.lookup(std::string(64,'0')),
              "unknown citizen not implicitly created");
        auto grant=onCitizen(RegistryOperation::set_anonymous_permission,nextSeq++,aliceId);
        grant.permission=AnonymousPermission::allowed;
        check(submit(admin,signer,grant).changed,"authority explicitly grants anonymity");
        rejects([&]{admin.apply(grant,signer.sign(grant));},"grant replay rejected");
        auto noOp=onCitizen(RegistryOperation::set_anonymous_permission,nextSeq++,aliceId);
        noOp.permission=AnonymousPermission::allowed;
        check(!submit(admin,signer,noOp).changed,"no-op logged and sequence consumed");
        auto suspend=onCitizen(RegistryOperation::set_anonymous_permission,nextSeq++,aliceId);
        suspend.permission=AnonymousPermission::suspended;
        check(submit(admin,signer,suspend).changed,"anonymity suspended");
        check(unprovisioned.activeKeyOwner(aKey)==aliceId,
              "anonymous suspension preserves identified access");
        grant.sequence=nextSeq++;
        check(submit(admin,signer,grant).changed,"authority reinstates anonymous permission");
        auto add=onCitizen(RegistryOperation::add_key,nextSeq++,aliceId);
        add.publicKey=rotated;
        check(submit(admin,signer,add).changed,"rotation adds key");
        check(unprovisioned.activeKeyOwner(rotated)==aliceId,"rotation key active");
        auto revoke=onCitizen(RegistryOperation::revoke_key,nextSeq++,aliceId);
        revoke.publicKey=aKey;
        check(submit(admin,signer,revoke).changed,"key revocation works");
        check(!unprovisioned.activeKeyOwner(aKey),"revoked key cannot authenticate");
        revoke.sequence=nextSeq++;
        check(!submit(admin,signer,revoke).changed,"revocation idempotent");
        rejects([&]{submit(admin,signer,enrollment(nextSeq,bytes(70),aKey));},
                "revoked key cannot be reassigned");
        AuthorityInstruction malformed=onCitizen(RegistryOperation::revoke_citizen,nextSeq,aliceId);
        malformed.publicKey=aKey;
        rejects([&]{authoritySigningBytes(malformed);},"unused fields rejected");
        malformed=onCitizen(RegistryOperation::set_anonymous_permission,nextSeq,aliceId);
        malformed.permission=AnonymousPermission(99);
        rejects([&]{authoritySigningBytes(malformed);},"invalid permission rejected");
        malformed=onCitizen(RegistryOperation::revoke_citizen,nextSeq,"../padded");
        rejects([&]{authoritySigningBytes(malformed);},"bad citizen ID rejected");

        const auto nullifier=bytes(90);
        check(!bans.isBanned("site-a.example",nullifier),"new nullifier not banned");
        check(bans.ban("site-a.example",nullifier),"service ban added");
        check(!bans.ban("site-a.example",nullifier),"service ban unique");
        check(bans.isBanned("site-a.example",nullifier),"ban works within scope");
        check(!bans.isBanned("site-b.example",nullifier),"bans isolated by service");
        rejects([&]{bans.ban("../escape",nullifier);},"invalid scope refused");
        rejects([&]{bans.ban("site-a.example",Fingerprint{});},"zero nullifier refused");
    }
    checkEventCount(registryPath,int(nextSeq)-1);
    // The sequence and authority public key survive reopening.
    {
        CitizenRegistry registry(registryPath);
        RegistryAuthority admin(registry,signer.publicKey,registryId);
        rejects([&]{RegistryAuthority incorrect(registry,adversary.publicKey,registryId);},
                "wrong authority after restart rejected");
        rejects([&]{submit(admin,signer,enrollment(1,bytes(70),bytes(80)));},
                "old sequence remains invalid after restart");
        check(registry.activeKeyOwner(rotated)==aliceId,"rotated key survived restart");
        check(!registry.activeKeyOwner(aKey),"revoked key survived restart");
        // Eight independently opened databases race to apply *different*
        // signed enrollments at one sequence. The single monotonic replay
        // counter and SQLite serialization admit exactly one.
        std::atomic<unsigned> winners{0};
        std::vector<std::thread> workers;
        for (unsigned i=0; i<8; ++i) {
            workers.emplace_back([&,i]{
                try {
                    CitizenRegistry concurrent(registryPath);
                    RegistryAuthority a(concurrent,signer.publicKey,registryId);
                    auto instruction=enrollment(nextSeq,bytes(140),bytes(170+i));
                    const auto signature=signer.sign(instruction);
                    if (a.apply(instruction,signature).changed) ++winners;
                } catch (const std::exception&) { /* rejected / serialized */ }
            });
        }
        for (auto& worker:workers) worker.join();
        check(winners==1,"only one signed concurrent enrollment accepted");
        ++nextSeq;
        auto revoke=onCitizen(RegistryOperation::revoke_citizen,nextSeq++,aliceId);
        check(submit(admin,signer,revoke).changed,"citizen globally revoked");
        check(!registry.activeKeyOwner(rotated),"global revocation disables keys");
        auto grant=onCitizen(RegistryOperation::set_anonymous_permission,nextSeq++,aliceId);
        grant.permission=AnonymousPermission::allowed;
        check(!submit(admin,signer,grant).changed,"revoked citizen cannot regain anonymity");
        auto add=onCitizen(RegistryOperation::add_key,nextSeq++,aliceId);
        add.publicKey=bytes(80);
        check(!submit(admin,signer,add).changed,"revoked citizen cannot rotate key");
        revoke.sequence=nextSeq++;
        check(!submit(admin,signer,revoke).changed,"citizen revocation irreversible");
        check(registry.lookup(aliceId)->status==CitizenStatus::revoked,
              "revoked status persists");
        rejects([&]{submit(admin,signer,enrollment(nextSeq,subjectA,bytes(70)));},
                "re-enrollment after revocation denied");
        ServiceBanLedger bans(banPath);
        check(bans.isBanned("site-a.example",bytes(90)),"ban persisted across restart");
        check(bans.unban("site-a.example",bytes(90)),"local unban possible");
        check(!bans.isBanned("site-a.example",bytes(90)),"unban effective");
    }
    checkEventCount(registryPath,int(nextSeq)-1);
    // Even two registries provisioned with the same signing authority may not
    // execute each other's signed instructions (namespace bound in signature).
    const std::string secondPath=std::string(directory)+"/other.sqlite";
    {
        CitizenRegistry other(secondPath);
        const auto otherId=bytes(234);
        RegistryAuthority::bootstrap(other,signer.publicKey,otherId);
        RegistryAuthority otherAdmin(other,signer.publicKey,otherId);
        auto cross=enrollment(1,bytes(190),bytes(191));
        rejects([&]{otherAdmin.apply(cross,signer.sign(cross));},
                "signed instruction cannot cross registry instances");
        cross.registryId=otherId;
        check(submit(otherAdmin,signer,cross).changed,
              "correctly scoped registry instruction accepted");
    }
    check(chmod(registryPath.c_str(),0644)==0,"make DB insecure");
    rejects([&]{CitizenRegistry insecure(registryPath);},"insecure DB rejected");
    check(chmod(registryPath.c_str(),0600)==0,"restore permissions");
    const std::string link=std::string(directory)+"/link.sqlite";
    check(symlink(registryPath.c_str(),link.c_str())==0,"symlink negative test");
    rejects([&]{CitizenRegistry insecure(link);},"symlink DB rejected");
    unlink(link.c_str());
    for (auto file : {registryPath,banPath,secondPath}) {
        unlink((file+"-shm").c_str()); unlink((file+"-wal").c_str()); unlink(file.c_str());
    }
    check(rmdir(directory)==0,"test directory removed");
    std::puts("PASS Maât identity authority: Ed25519 signatures, pinned authority, strict canonical commands, durable replay prevention, transactional audit, concurrent enrollment, per-service bans");
}
