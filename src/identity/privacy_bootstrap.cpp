#include "identity/privacy_bootstrap.hpp"
#include "identity/citizen_registry.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <sqlite3.h>

#include <algorithm>
#include <ctime>
#include <limits>
#include <stdexcept>

namespace maat { namespace identity {
namespace {
constexpr std::uint64_t maxLifetime = 300;
constexpr std::int64_t nonceLifetime = 60;
constexpr std::size_t maxPending = 1024;

void nonzero(const Fingerprint& f) {
    if (std::all_of(f.begin(),f.end(),[](std::uint8_t b){return b==0;}))
        throw std::invalid_argument("Maât scope-free: empty cryptographic value");
}
void scope(const std::string& s) {
    if (s.empty() || s.size()>128)
        throw std::invalid_argument("Maât scope-free: invalid service ID");
    for (char c:s)
        if (!((c>='a'&&c<='z') || (c>='0'&&c<='9') || c=='.' || c=='-' || c=='_'))
            throw std::invalid_argument("Maât scope-free: noncanonical service ID");
}
void append(std::vector<std::uint8_t>& b, const Fingerprint& f) {
    b.insert(b.end(),f.begin(),f.end());
}
void u64(std::vector<std::uint8_t>& b, std::uint64_t x) {
    for (int i=7;i>=0;--i) b.push_back(std::uint8_t(x>>(8*i)));
}
std::vector<std::uint8_t> domain(const char* text, std::size_t n) {
    return {text,text+n}; // Include trailing NUL for domain separation.
}
Fingerprint digest(const std::vector<std::uint8_t>& b) {
    Fingerprint h{};
    if (!SHA256(b.data(),b.size(),h.data()))
        throw std::runtime_error("Maât scope-free: SHA256 failed");
    return h;
}
Fingerprint randomValue() {
    Fingerprint f{};
    if (RAND_bytes(f.data(),int(f.size()))!=1)
        throw std::runtime_error("Maât scope-free: random generator failed");
    nonzero(f);
    return f;
}
Fingerprint publicKey(const Fingerprint& seed) {
    nonzero(seed);
    EVP_PKEY* k=EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519,nullptr,seed.data(),seed.size());
    if (!k) throw std::runtime_error("Maât scope-free: invalid issuer seed");
    Fingerprint pub{};
    std::size_t n=pub.size();
    const int ok=EVP_PKEY_get_raw_public_key(k,pub.data(),&n);
    EVP_PKEY_free(k);
    if (ok!=1 || n!=pub.size())
        throw std::runtime_error("Maât scope-free: public key derivation failed");
    return pub;
}
void verifySignature(const Fingerprint& pub, const std::vector<std::uint8_t>& data,
                     const Ed25519Signature& sig) {
    EVP_PKEY* k=EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519,nullptr,pub.data(),pub.size());
    if (!k) throw std::runtime_error("Maât scope-free: invalid citizen public key");
    EVP_MD_CTX* ctx=EVP_MD_CTX_new();
    if (!ctx) { EVP_PKEY_free(k); throw std::runtime_error("Maât scope-free: no signature context"); }
    const bool valid=EVP_DigestVerifyInit(ctx,nullptr,nullptr,nullptr,k)==1 &&
        EVP_DigestVerify(ctx,sig.data(),sig.size(),data.data(),data.size())==1;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(k);
    if (!valid) throw std::runtime_error("Maât scope-free: invalid citizen signature");
}
Ed25519Signature sign(const Fingerprint& seed, const std::vector<std::uint8_t>& bytes) {
    EVP_PKEY* k=EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519,nullptr,seed.data(),seed.size());
    if (!k) throw std::runtime_error("Maât scope-free: invalid issuer key");
    EVP_MD_CTX* ctx=EVP_MD_CTX_new();
    if (!ctx) { EVP_PKEY_free(k); throw std::runtime_error("Maât scope-free: signing context failed"); }
    Ed25519Signature signature{};
    std::size_t n=signature.size();
    const bool valid=EVP_DigestSignInit(ctx,nullptr,nullptr,nullptr,k)==1 &&
        EVP_DigestSign(ctx,signature.data(),&n,bytes.data(),bytes.size())==1;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(k);
    if (!valid || n!=signature.size())
        throw std::runtime_error("Maât scope-free: issuer signature failed");
    return signature;
}
void sql(sqlite3* db, const char* command) {
    if (sqlite3_exec(db,command,nullptr,nullptr,nullptr)!=SQLITE_OK)
        throw std::runtime_error("Maât scope-free: SQLite operation refused");
}
class Statement final {
    sqlite3_stmt* s_=nullptr;
public:
    Statement(sqlite3* db, const char* statement) {
        if (sqlite3_prepare_v2(db,statement,-1,&s_,nullptr)!=SQLITE_OK)
            throw std::runtime_error("Maât scope-free: SQLite statement failed");
    }
    ~Statement() { sqlite3_finalize(s_); }
    void blob(int index, const Fingerprint& f) {
        if (sqlite3_bind_blob(s_,index,f.data(),int(f.size()),SQLITE_TRANSIENT)!=SQLITE_OK)
            throw std::runtime_error("Maât scope-free: SQLite blob failure");
    }
    void text(int index,const std::string& t) {
        if (sqlite3_bind_text(s_,index,t.c_str(),-1,SQLITE_TRANSIENT)!=SQLITE_OK)
            throw std::runtime_error("Maât scope-free: SQLite text failure");
    }
    int step() { return sqlite3_step(s_); }
    void done() { if (step()!=SQLITE_DONE) throw std::runtime_error("Maât scope-free: write refused"); }
    sqlite3_stmt* get() const { return s_; }
};
void schema(sqlite3* db) {
    sql(db,"CREATE TABLE IF NOT EXISTS privacy_issuer_anchor("
           "singleton INTEGER PRIMARY KEY CHECK(singleton=1),"
           "issuer_key BLOB NOT NULL CHECK(length(issuer_key)=32))");
    sql(db,"CREATE TABLE IF NOT EXISTS privacy_nym_binding("
           "citizen_id TEXT PRIMARY KEY REFERENCES citizens(citizen_id),"
           "nym_commitment BLOB NOT NULL UNIQUE CHECK(length(nym_commitment)=32))");
}
void checkPins(sqlite3* db, const Fingerprint& registryId, const Fingerprint& pub,
               bool mustExist) {
    Statement authority(db,"SELECT public_key,registry_id FROM registry_authority WHERE singleton=1");
    if (authority.step()!=SQLITE_ROW || sqlite3_column_bytes(authority.get(),0)!=32 ||
        sqlite3_column_bytes(authority.get(),1)!=32 ||
        CRYPTO_memcmp(sqlite3_column_blob(authority.get(),1),registryId.data(),32)!=0 ||
        CRYPTO_memcmp(sqlite3_column_blob(authority.get(),0),pub.data(),32)==0)
        throw std::runtime_error("Maât scope-free: missing namespace or reused authority key");
    sql(db,"CREATE TABLE IF NOT EXISTS scoped_issuer_anchor("
           "singleton INTEGER PRIMARY KEY CHECK(singleton=1),"
           "issuer_key BLOB NOT NULL CHECK(length(issuer_key)=32),"
           "prf_tag BLOB NOT NULL CHECK(length(prf_tag)=32))");
    // Never use the same seed for alpha3 scoped credentials and scope-free
    // receipts, otherwise cross-protocol signing domains are the only barrier.
    Statement legacy(db,"SELECT issuer_key FROM scoped_issuer_anchor WHERE singleton=1");
    if (legacy.step()==SQLITE_ROW && sqlite3_column_bytes(legacy.get(),0)==32 &&
        CRYPTO_memcmp(sqlite3_column_blob(legacy.get(),0),pub.data(),32)==0)
        throw std::runtime_error("Maât scope-free: reused legacy issuer key");
    if (mustExist) {
        Statement anchor(db,"SELECT issuer_key FROM privacy_issuer_anchor WHERE singleton=1");
        if (anchor.step()!=SQLITE_ROW || sqlite3_column_bytes(anchor.get(),0)!=32 ||
            CRYPTO_memcmp(sqlite3_column_blob(anchor.get(),0),pub.data(),32)!=0)
            throw std::runtime_error("Maât scope-free: issuer not provisioned");
    }
}
void purge(std::map<Fingerprint,std::int64_t>& m,std::int64_t now) {
    for (auto it=m.begin();it!=m.end();) {
        if (it->second<now) it=m.erase(it);
        else ++it;
    }
}
} // namespace

Fingerprint prototypeNymCommitment(const Fingerprint& secret) {
    nonzero(secret);
    static constexpr char label[]="MAAT/PRIVACY/NYM-COMMITMENT/PROTOTYPE/V1";
    auto data=domain(label,sizeof(label));
    append(data,secret);
    return digest(data);
}
Fingerprint unverifiedLocalScopeNullifier(const Fingerprint& secret,
                                          const Fingerprint& registryId,
                                          const std::string& serviceId) {
    nonzero(secret); nonzero(registryId); scope(serviceId);
    static constexpr char label[]="MAAT/PRIVACY/UNVERIFIED-SCOPE-TAG/PROTOTYPE/V1";
    auto data=domain(label,sizeof(label));
    append(data,registryId);
    data.push_back(std::uint8_t(serviceId.size()));
    data.insert(data.end(),serviceId.begin(),serviceId.end());
    Fingerprint out{};
    unsigned int length=0;
    if (!HMAC(EVP_sha256(),secret.data(),int(secret.size()),data.data(),data.size(),
              out.data(),&length) || length!=out.size())
        throw std::runtime_error("Maât scope-free: local HMAC failure");
    return out;
}
std::vector<std::uint8_t> scopeFreeRequestBytes(const Fingerprint& registryId,
                                                 const ScopeFreeIssueRequest& r) {
    nonzero(registryId); nonzero(r.citizenKey); nonzero(r.nymCommitment); nonzero(r.challenge);
    static constexpr char label[]="MAAT/PRIVACY/ISSUANCE-REQUEST/V1";
    auto out=domain(label,sizeof(label));
    append(out,registryId); append(out,r.citizenKey);
    append(out,r.nymCommitment); append(out,r.challenge);
    return out;
}
std::vector<std::uint8_t> scopeFreeCredentialBytes(const ScopeFreeCredential& c) {
    nonzero(c.registryId); nonzero(c.serial); nonzero(c.nymCommitment);
    if (!c.notBefore || c.expiresAt<=c.notBefore || c.expiresAt-c.notBefore>maxLifetime)
        throw std::invalid_argument("Maât scope-free: malformed lifetime");
    static constexpr char label[]="MAAT/PRIVACY/SCOPE-FREE-CREDENTIAL-NOT-FOR-DISCLOSURE/V1";
    auto out=domain(label,sizeof(label));
    append(out,c.registryId); append(out,c.serial); append(out,c.nymCommitment);
    u64(out,c.notBefore); u64(out,c.expiresAt);
    return out;
}
void ScopeFreeCredentialIssuer::bootstrap(CitizenRegistry& registry,
                                          const Fingerprint& registryId,
                                          const Fingerprint& issuerSeed) {
    nonzero(registryId);
    const auto pub=publicKey(issuerSeed);
    sql(registry.db_,"BEGIN IMMEDIATE");
    try {
        schema(registry.db_);
        checkPins(registry.db_,registryId,pub,false);
        Statement s(registry.db_,"INSERT OR IGNORE INTO privacy_issuer_anchor"
                                   "(singleton,issuer_key) VALUES(1,?1)");
        s.blob(1,pub); s.done();
        checkPins(registry.db_,registryId,pub,true);
        sql(registry.db_,"COMMIT");
    } catch (...) { sqlite3_exec(registry.db_,"ROLLBACK",nullptr,nullptr,nullptr); throw; }
}
ScopeFreeCredentialIssuer::ScopeFreeCredentialIssuer(CitizenRegistry& registry,
                                                      const Fingerprint& registryId,
                                                      const Fingerprint& issuerSeed)
 : registry_(registry),registryId_(registryId),signingSeed_(issuerSeed) {
    nonzero(registryId_);
    checkPins(registry_.db_,registryId_,publicKey(signingSeed_),true);
}
ScopeFreeCredentialIssuer::~ScopeFreeCredentialIssuer() {
    OPENSSL_cleanse(signingSeed_.data(),signingSeed_.size());
}
Fingerprint ScopeFreeCredentialIssuer::challenge() {
    const auto now=std::int64_t(std::time(nullptr));
    std::lock_guard<std::mutex> lock(mutex_);
    purge(challenges_,now);
    if (challenges_.size()>=maxPending)
        throw std::runtime_error("Maât scope-free: challenge budget exceeded");
    auto value=randomValue();
    if (!challenges_.emplace(value,now+nonceLifetime).second)
        throw std::runtime_error("Maât scope-free: challenge collision");
    return value;
}
ScopeFreeCredential ScopeFreeCredentialIssuer::issue(const ScopeFreeIssueRequest& req) {
    auto transcript=scopeFreeRequestBytes(registryId_,req);
    {
        const auto now=std::int64_t(std::time(nullptr));
        std::lock_guard<std::mutex> lock(mutex_);
        const auto it=challenges_.find(req.challenge);
        if (it==challenges_.end() || it->second<now)
            throw std::runtime_error("Maât scope-free: challenge missing/replayed/expired");
        challenges_.erase(it);
    }
    verifySignature(req.citizenKey,transcript,req.citizenSignature);
    sql(registry_.db_,"BEGIN IMMEDIATE");
    try {
        // The citizen state, key ownership and pinned nym are seen in one
        // transactional SQLite snapshot, also used for the following write.
        Statement eligible(registry_.db_,
            "SELECT k.citizen_id FROM citizen_keys k JOIN citizens c "
            "ON c.citizen_id=k.citizen_id WHERE k.public_key=?1 AND k.revoked=0 "
            "AND c.status=1 AND c.anonymous_permission=1");
        eligible.blob(1,req.citizenKey);
        if (eligible.step()!=SQLITE_ROW || sqlite3_column_bytes(eligible.get(),0)!=64)
            throw std::runtime_error("Maât scope-free: not eligible");
        const auto* owner=sqlite3_column_text(eligible.get(),0);
        if (!owner) throw std::runtime_error("Maât scope-free: missing citizen ID");
        const std::string citizen(reinterpret_cast<const char*>(owner),64);
        {
            Statement bind(registry_.db_,
                "INSERT OR IGNORE INTO privacy_nym_binding(citizen_id,nym_commitment)"
                " VALUES(?1,?2)");
            bind.text(1,citizen); bind.blob(2,req.nymCommitment); bind.done();
        }
        {
            Statement pinned(registry_.db_,
                "SELECT nym_commitment FROM privacy_nym_binding WHERE citizen_id=?1");
            pinned.text(1,citizen);
            if (pinned.step()!=SQLITE_ROW || sqlite3_column_bytes(pinned.get(),0)!=32 ||
                CRYPTO_memcmp(sqlite3_column_blob(pinned.get(),0),req.nymCommitment.data(),32)!=0)
                throw std::runtime_error("Maât scope-free: nym binding already pinned");
        }
        ScopeFreeCredential result{};
        result.registryId=registryId_;
        result.nymCommitment=req.nymCommitment;
        result.serial=randomValue();
        result.notBefore=std::uint64_t(std::time(nullptr));
        result.expiresAt=result.notBefore+maxLifetime;
        result.issuerSignature=sign(signingSeed_,scopeFreeCredentialBytes(result));
        sql(registry_.db_,"COMMIT");
        return result;
    } catch (...) { sqlite3_exec(registry_.db_,"ROLLBACK",nullptr,nullptr,nullptr); throw; }
}

}} // namespace maat::identity
