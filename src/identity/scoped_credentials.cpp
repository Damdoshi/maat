#include "identity/scoped_credentials.hpp"

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
constexpr std::uint64_t maxLifetime = 300; // Five minutes; bounded revocation delay.
constexpr std::int64_t challengeLifetime = 60;
constexpr std::size_t maxOutstanding = 1024;

void requireNonzero(const Fingerprint& f) {
    if (std::all_of(f.begin(), f.end(), [](std::uint8_t b){ return b==0; }))
        throw std::invalid_argument("Maât credentials: empty cryptographic value");
}
void scope(const std::string& id) {
    if (id.empty() || id.size()>128)
        throw std::invalid_argument("Maât credentials: invalid service scope");
    for (const char c : id)
        if (!((c>='a' && c<='z') || (c>='0' && c<='9') || c=='.' || c=='-' || c=='_'))
            throw std::invalid_argument("Maât credentials: invalid service scope");
}
void append(std::vector<std::uint8_t>& out, const Fingerprint& f) {
    out.insert(out.end(),f.begin(),f.end());
}
void appendU64(std::vector<std::uint8_t>& out, std::uint64_t value) {
    for (int i=7; i>=0; --i) out.push_back(std::uint8_t(value>>(i*8)));
}
void appendScope(std::vector<std::uint8_t>& out, const std::string& id) {
    scope(id);
    out.push_back(std::uint8_t(id.size()));
    out.insert(out.end(),id.begin(),id.end());
}
std::vector<std::uint8_t> domain(const char* literal, std::size_t length) {
    // Includes the trailing NUL, as in the administrative signing protocol.
    return std::vector<std::uint8_t>(literal,literal+length);
}
void sql(sqlite3* db, const char* query) {
    if (sqlite3_exec(db,query,nullptr,nullptr,nullptr)!=SQLITE_OK)
        throw std::runtime_error("Maât credentials: SQLite operation refused");
}
class Statement final {
    sqlite3_stmt* s_ = nullptr;
public:
    Statement(sqlite3* db, const char* query) {
        if (sqlite3_prepare_v2(db,query,-1,&s_,nullptr)!=SQLITE_OK)
            throw std::runtime_error("Maât credentials: SQLite statement failed");
    }
    ~Statement() { if (s_) sqlite3_finalize(s_); }
    Statement(const Statement&)=delete;
    Statement& operator=(const Statement&)=delete;
    void blob(int position, const Fingerprint& value) {
        if (sqlite3_bind_blob(s_,position,value.data(),int(value.size()),SQLITE_TRANSIENT)!=SQLITE_OK)
            throw std::runtime_error("Maât credentials: SQLite blob failed");
    }
    int step() { return sqlite3_step(s_); }
    sqlite3_stmt* get() { return s_; }
    void done() { if (step()!=SQLITE_DONE) throw std::runtime_error("Maât credentials: SQLite write failed"); }
};
Fingerprint randomFingerprint() {
    Fingerprint f{};
    if (RAND_bytes(f.data(),int(f.size()))!=1)
        throw std::runtime_error("Maât credentials: randomness unavailable");
    requireNonzero(f);
    return f;
}
Fingerprint keyFromSeed(const Fingerprint& seed) {
    requireNonzero(seed);
    EVP_PKEY* p = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519,nullptr,seed.data(),seed.size());
    if (!p) throw std::runtime_error("Maât credentials: cannot create Ed25519 issuer key");
    Fingerprint publicKey{};
    std::size_t len = publicKey.size();
    const int ok = EVP_PKEY_get_raw_public_key(p,publicKey.data(),&len);
    EVP_PKEY_free(p);
    if (ok!=1 || len!=publicKey.size()) throw std::runtime_error("Maât credentials: cannot extract public key");
    return publicKey;
}
Ed25519Signature sign(const Fingerprint& seed, const std::vector<std::uint8_t>& data) {
    EVP_PKEY* p = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519,nullptr,seed.data(),seed.size());
    if (!p) throw std::runtime_error("Maât credentials: signing key invalid");
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) { EVP_PKEY_free(p); throw std::runtime_error("Maât credentials: signing context unavailable"); }
    Ed25519Signature signature{};
    std::size_t length = signature.size();
    const bool ok = EVP_DigestSignInit(ctx,nullptr,nullptr,nullptr,p)==1 &&
                    EVP_DigestSign(ctx,signature.data(),&length,data.data(),data.size())==1;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(p);
    if (!ok || length!=signature.size()) throw std::runtime_error("Maât credentials: signing failed");
    return signature;
}
bool verifySignature(const Fingerprint& key, const std::vector<std::uint8_t>& data,
                     const Ed25519Signature& signature) {
    EVP_PKEY* p = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519,nullptr,key.data(),key.size());
    if (!p) return false;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) { EVP_PKEY_free(p); return false; }
    const bool ok = EVP_DigestVerifyInit(ctx,nullptr,nullptr,nullptr,p)==1 &&
                    EVP_DigestVerify(ctx,signature.data(),signature.size(),data.data(),data.size())==1;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(p);
    return ok;
}
Fingerprint secretTag(const Fingerprint& secret) {
    static constexpr char label[] = "MAAT/CREDENTIAL/NULLIFIER-SECRET-ANCHOR/V1";
    std::vector<std::uint8_t> message=domain(label,sizeof(label));
    append(message,secret);
    Fingerprint digest{};
    if (!SHA256(message.data(),message.size(),digest.data()))
        throw std::runtime_error("Maât credentials: anchor hash failed");
    return digest;
}
Fingerprint scopedNullifier(const Fingerprint& secret, const Fingerprint& registryId,
                             const std::string& citizenId, const std::string& serviceId) {
    static constexpr char label[] = "MAAT/CREDENTIAL/SCOPED-NULLIFIER/V1";
    std::vector<std::uint8_t> message = domain(label,sizeof(label));
    append(message,registryId);
    // Citizen IDs are random, fixed-length hex from registry; never sent to service.
    if (citizenId.size()!=64) throw std::runtime_error("Maât credentials: invalid citizen ID");
    message.insert(message.end(),citizenId.begin(),citizenId.end());
    appendScope(message,serviceId);
    Fingerprint result{};
    unsigned int length = 0;
    if (!HMAC(EVP_sha256(),secret.data(),int(secret.size()),message.data(),message.size(),
              result.data(),&length) || length!=result.size())
        throw std::runtime_error("Maât credentials: PRF failed");
    return result;
}
void checkRegistryNamespace(sqlite3* db, const Fingerprint& registryId) {
    Statement s(db,"SELECT registry_id FROM registry_authority WHERE singleton=1");
    if (s.step()!=SQLITE_ROW || sqlite3_column_bytes(s.get(),0)!=32 ||
        CRYPTO_memcmp(sqlite3_column_blob(s.get(),0),registryId.data(),32)!=0)
        throw std::runtime_error("Maât credentials: registry authority namespace missing/mismatched");
}
void rejectAuthorityKeyReuse(sqlite3* db, const Fingerprint& issuerPublicKey) {
    Statement s(db,"SELECT public_key FROM registry_authority WHERE singleton=1");
    if (s.step()!=SQLITE_ROW || sqlite3_column_bytes(s.get(),0)!=32)
        throw std::runtime_error("Maât credentials: authority key missing");
    if (CRYPTO_memcmp(sqlite3_column_blob(s.get(),0),issuerPublicKey.data(),32)==0)
        throw std::invalid_argument("Maât credentials: issuer key must differ from offline authority key");
}
void anchorTable(sqlite3* db) {
    sql(db,"CREATE TABLE IF NOT EXISTS scoped_issuer_anchor ("
           "singleton INTEGER PRIMARY KEY CHECK(singleton=1),"
           "issuer_key BLOB NOT NULL CHECK(length(issuer_key)=32),"
           "prf_tag BLOB NOT NULL CHECK(length(prf_tag)=32))");
}
void checkAnchor(sqlite3* db, const Fingerprint& key, const Fingerprint& tag) {
    Statement s(db,"SELECT issuer_key,prf_tag FROM scoped_issuer_anchor WHERE singleton=1");
    if (s.step()!=SQLITE_ROW || sqlite3_column_bytes(s.get(),0)!=32 ||
        sqlite3_column_bytes(s.get(),1)!=32 ||
        CRYPTO_memcmp(sqlite3_column_blob(s.get(),0),key.data(),32)!=0 ||
        CRYPTO_memcmp(sqlite3_column_blob(s.get(),1),tag.data(),32)!=0)
        throw std::runtime_error("Maât credentials: issuer anchor missing/mismatched");
}
// Only challenges generated by this instance can be consumed. They are bound
// into signed transcripts, and never persist after process exit.
void purge(std::map<Fingerprint,std::int64_t>& m, std::int64_t now) {
    for (auto it=m.begin(); it!=m.end(); )
        if (it->second < now) it=m.erase(it); else ++it;
}
Fingerprint makeChallenge(std::map<Fingerprint,std::int64_t>& m, std::mutex& mu) {
    const std::int64_t now = std::time(nullptr);
    std::lock_guard<std::mutex> lock(mu);
    purge(m,now);
    if (m.size()>=maxOutstanding)
        throw std::runtime_error("Maât credentials: too many pending challenges");
    const Fingerprint nonce=randomFingerprint();
    if (!m.emplace(nonce,now+challengeLifetime).second)
        throw std::runtime_error("Maât credentials: nonce collision");
    return nonce;
}
void consumeChallenge(std::map<Fingerprint,std::int64_t>& m, std::mutex& mu,
                      const Fingerprint& nonce) {
    const std::int64_t now = std::time(nullptr);
    std::lock_guard<std::mutex> lock(mu);
    auto it=m.find(nonce);
    if (it==m.end() || it->second < now)
        throw std::runtime_error("Maât credentials: missing/expired/replayed challenge");
    m.erase(it); // Invalid presentations consume their challenge too.
}
} // namespace

std::vector<std::uint8_t> credentialRequestBytes(const Fingerprint& registryId,
                                                   const CredentialRequest& req) {
    requireNonzero(registryId); requireNonzero(req.citizenKey);
    requireNonzero(req.holderKey); requireNonzero(req.challenge);
    if (req.citizenKey==req.holderKey)
        throw std::invalid_argument("Maât credentials: cannot disclose permanent key to service");
    static constexpr char label[] = "MAAT/CREDENTIAL/ISSUE-REQUEST/V1";
    auto out=domain(label,sizeof(label));
    append(out,registryId);
    appendScope(out,req.serviceId);
    append(out,req.citizenKey);
    append(out,req.holderKey);
    append(out,req.challenge);
    return out;
}
std::vector<std::uint8_t> credentialSigningBytes(const ScopedCredential& c) {
    requireNonzero(c.registryId); requireNonzero(c.serial);
    requireNonzero(c.nullifier); requireNonzero(c.holderKey);
    if (c.notBefore==0 || c.expiresAt<=c.notBefore ||
        c.expiresAt-c.notBefore>maxLifetime)
        throw std::invalid_argument("Maât credentials: invalid validity period");
    static constexpr char label[] = "MAAT/CREDENTIAL/SCOPED-ASSERTION/V1";
    auto out=domain(label,sizeof(label));
    append(out,c.registryId);
    appendScope(out,c.serviceId);
    append(out,c.serial); append(out,c.nullifier); append(out,c.holderKey);
    appendU64(out,c.notBefore); appendU64(out,c.expiresAt);
    return out;
}
std::vector<std::uint8_t> credentialPresentationBytes(const ScopedCredential& c,
                                                        const Fingerprint& challenge) {
    requireNonzero(challenge);
    static constexpr char label[] = "MAAT/CREDENTIAL/HOLDER-PRESENTATION/V1";
    auto out=domain(label,sizeof(label));
    const auto credentialBytes=credentialSigningBytes(c);
    out.insert(out.end(),credentialBytes.begin(),credentialBytes.end());
    out.insert(out.end(),c.issuerSignature.begin(),c.issuerSignature.end());
    append(out,challenge);
    return out;
}
void ScopedCredentialIssuer::bootstrap(CitizenRegistry& registry,
                                       const Fingerprint& registryId,
                                       const Fingerprint& issuerSeed,
                                       const Fingerprint& prfSecret) {
    requireNonzero(registryId); requireNonzero(prfSecret);
    const Fingerprint pub=keyFromSeed(issuerSeed);
    const Fingerprint tag=secretTag(prfSecret);
    sql(registry.db_,"BEGIN IMMEDIATE");
    try {
        checkRegistryNamespace(registry.db_,registryId);
        rejectAuthorityKeyReuse(registry.db_,pub);
        anchorTable(registry.db_);
        Statement s(registry.db_,"INSERT OR IGNORE INTO scoped_issuer_anchor"
                    "(singleton,issuer_key,prf_tag) VALUES(1,?1,?2)");
        s.blob(1,pub); s.blob(2,tag); s.done();
        checkAnchor(registry.db_,pub,tag);
        sql(registry.db_,"COMMIT");
    } catch (...) { sqlite3_exec(registry.db_,"ROLLBACK",nullptr,nullptr,nullptr); throw; }
}
ScopedCredentialIssuer::ScopedCredentialIssuer(CitizenRegistry& registry,
                                                const Fingerprint& registryId,
                                                const Fingerprint& issuerSeed,
                                                const Fingerprint& prfSecret)
  : registry_(registry), registryId_(registryId), signingSeed_(issuerSeed),
    nullifierSecret_(prfSecret) {
    requireNonzero(registryId_); requireNonzero(nullifierSecret_);
    const Fingerprint pub=keyFromSeed(signingSeed_);
    checkRegistryNamespace(registry_.db_,registryId_);
    rejectAuthorityKeyReuse(registry_.db_,pub);
    checkAnchor(registry_.db_,pub,secretTag(nullifierSecret_));
}
ScopedCredentialIssuer::~ScopedCredentialIssuer() {
    OPENSSL_cleanse(signingSeed_.data(),signingSeed_.size());
    OPENSSL_cleanse(nullifierSecret_.data(),nullifierSecret_.size());
}
Fingerprint ScopedCredentialIssuer::challenge() { return makeChallenge(challenges_,mutex_); }
ScopedCredential ScopedCredentialIssuer::issue(const CredentialRequest& req) {
    const auto transcript=credentialRequestBytes(registryId_,req);
    consumeChallenge(challenges_,mutex_,req.challenge);
    if (!verifySignature(req.citizenKey,transcript,req.citizenSignature))
        throw std::runtime_error("Maât credentials: missing citizen possession proof");
    // One SQLite statement observes key ownership, citizen status, anonymous
    // permission and holder-key exclusion in the SAME read snapshot.
    // This is trusted issuer-side only; never expose its result to the service.
    Statement eligible(registry_.db_,
        "SELECT k.citizen_id FROM citizen_keys k JOIN citizens c "
        "ON k.citizen_id=c.citizen_id WHERE k.public_key=?1 "
        "AND k.revoked=0 AND c.status=1 AND c.anonymous_permission=1 "
        "AND NOT EXISTS (SELECT 1 FROM citizen_keys h WHERE h.public_key=?2)");
    eligible.blob(1,req.citizenKey);
    eligible.blob(2,req.holderKey);
    if (eligible.step()!=SQLITE_ROW)
        throw std::runtime_error("Maât credentials: citizen/key/permission not eligible");
    const auto* citizenBytes=sqlite3_column_text(eligible.get(),0);
    if (!citizenBytes || sqlite3_column_bytes(eligible.get(),0)!=64)
        throw std::runtime_error("Maât credentials: invalid citizen ID in store");
    const std::string owner(reinterpret_cast<const char*>(citizenBytes),64);
    ScopedCredential c{};
    c.registryId=registryId_;
    c.serviceId=req.serviceId;
    c.serial=randomFingerprint();
    c.nullifier=scopedNullifier(nullifierSecret_,registryId_,owner,req.serviceId);
    c.holderKey=req.holderKey;
    c.notBefore=std::uint64_t(std::time(nullptr));
    c.expiresAt=c.notBefore+maxLifetime;
    c.issuerSignature=sign(signingSeed_,credentialSigningBytes(c));
    return c;
}
ScopedCredentialVerifier::ScopedCredentialVerifier(const Fingerprint& publicKey,
                                                   const Fingerprint& registryId,
                                                   std::string serviceId,
                                                   ServiceBanLedger& bans)
  : issuerPublicKey_(publicKey), registryId_(registryId),
    serviceId_(std::move(serviceId)), bans_(bans) {
    requireNonzero(issuerPublicKey_); requireNonzero(registryId_);
    scope(serviceId_);
}
Fingerprint ScopedCredentialVerifier::challenge() { return makeChallenge(challenges_,mutex_); }
bool ScopedCredentialVerifier::verify(const ScopedCredential& c,
                                      const Fingerprint& nonce,
                                      const Ed25519Signature& holderSignature) {
    // Deliberately consume before any validation; failed attempts cannot retry
    // oracles indefinitely with the same verifier-issued nonce.
    consumeChallenge(challenges_,mutex_,nonce);
    try {
        if (c.registryId!=registryId_ || c.serviceId!=serviceId_) return false;
        const auto signedBytes=credentialSigningBytes(c);
        const auto now=std::uint64_t(std::time(nullptr));
        if (now<c.notBefore || now>=c.expiresAt) return false;
        if (!verifySignature(issuerPublicKey_,signedBytes,c.issuerSignature)) return false;
        if (bans_.isBanned(serviceId_,c.nullifier)) return false;
        return verifySignature(c.holderKey,credentialPresentationBytes(c,nonce),holderSignature);
    } catch (const std::exception&) { return false; }
}

}} // namespace maat::identity
