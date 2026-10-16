#include "identity/bbs_bound_issuer.hpp"
#include "identity/citizen_registry.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <sqlite3.h>

#include <algorithm>
#include <ctime>
#include <cstring>
#include <stdexcept>

extern "C" int maat_bbs_issuer_public_key_v1(const unsigned char*, unsigned char*);
extern "C" int maat_bbs_bound_sign_v1(const unsigned char*, const unsigned char*,
                                       const unsigned char*, const unsigned char*,
                                       const unsigned char*, const unsigned char*,
                                       const unsigned char*, const unsigned char*,
                                       unsigned char*);

namespace maat { namespace identity {
namespace {
constexpr std::int64_t challengeLifetime = 60;
constexpr std::size_t maxPending = 1024;
void nonzero(const Fingerprint& v) {
    if (std::all_of(v.begin(),v.end(),[](std::uint8_t x){return x==0;}))
        throw std::invalid_argument("Maât BBS: empty value");
}
void append(std::vector<std::uint8_t>& out,const Fingerprint& v) {
    out.insert(out.end(),v.begin(),v.end());
}
template<std::size_t N> void append(std::vector<std::uint8_t>& out,const std::array<std::uint8_t,N>& v) {
    out.insert(out.end(),v.begin(),v.end());
}
void exec(sqlite3* db,const char* query) {
    if (sqlite3_exec(db,query,nullptr,nullptr,nullptr)!=SQLITE_OK)
        throw std::runtime_error("Maât BBS: database refused operation");
}
class Statement final {
    sqlite3_stmt* p_=nullptr;
public:
    Statement(sqlite3* db, const char* text) {
        if (sqlite3_prepare_v2(db,text,-1,&p_,nullptr)!=SQLITE_OK)
            throw std::runtime_error("Maât BBS: invalid database statement");
    }
    ~Statement(){sqlite3_finalize(p_);}
    void blob(int i,const void* p,std::size_t n) {
        if (sqlite3_bind_blob(p_,i,p,static_cast<int>(n),SQLITE_TRANSIENT)!=SQLITE_OK)
            throw std::runtime_error("Maât BBS: bind failure");
    }
    template<std::size_t N> void blob(int i,const std::array<std::uint8_t,N>& a){ blob(i,a.data(),a.size()); }
    void text(int i,const std::string& s) {
        if (sqlite3_bind_text(p_,i,s.c_str(),-1,SQLITE_TRANSIENT)!=SQLITE_OK)
            throw std::runtime_error("Maât BBS: text bind failure");
    }
    int step(){return sqlite3_step(p_);}
    void done(){if(step()!=SQLITE_DONE) throw std::runtime_error("Maât BBS: write refused");}
    sqlite3_stmt* raw()const{return p_;}
};

std::array<std::uint8_t,96> issuerKey(const Fingerprint& seed) {
    nonzero(seed);
    std::array<std::uint8_t,96> out{};
    if (maat_bbs_issuer_public_key_v1(seed.data(),out.data())!=1)
        throw std::runtime_error("Maât BBS: invalid signer seed or unavailable backend");
    return out;
}

template<std::size_t N>
std::array<std::uint8_t,N> mac(const Fingerprint& key,const std::vector<std::uint8_t>& msg,
                              const EVP_MD* alg) {
    std::array<std::uint8_t,N> out{};
    unsigned int size=0;
    if (!HMAC(alg,key.data(),static_cast<int>(key.size()),msg.data(),msg.size(),out.data(),&size)
        || size!=N) throw std::runtime_error("Maât BBS: HMAC failure");
    return out;
}
std::vector<std::uint8_t> prefix(const char* domain,std::size_t len,
                                  const Fingerprint& registryId) {
    std::vector<std::uint8_t> result(domain,domain+len); // include final NUL
    append(result,registryId);
    return result;
}
Fingerprint entropyPin(const Fingerprint& secret,const Fingerprint& registryId) {
    static constexpr char label[]="MAAT/BBS/ENTROPY-KEY-PIN/V1";
    return mac<32>(secret,prefix(label,sizeof(label),registryId),EVP_sha256());
}
std::array<std::uint8_t,64> citizenEntropy(const Fingerprint& secret,
                                          const Fingerprint& registryId,
                                          const std::string& citizenId) {
    static constexpr char label[]="MAAT/BBS/CITIZEN-ENTROPY/V1";
    auto input=prefix(label,sizeof(label),registryId);
    input.insert(input.end(),citizenId.begin(),citizenId.end());
    return mac<64>(secret,input,EVP_sha512());
}
void schema(sqlite3* db) {
    exec(db,"CREATE TABLE IF NOT EXISTS bbs_issuer_pin("
            "singleton INTEGER PRIMARY KEY CHECK(singleton=1),"
            "issuer_key BLOB NOT NULL CHECK(length(issuer_key)=96),"
            "entropy_tag BLOB NOT NULL CHECK(length(entropy_tag)=32))");
    exec(db,"CREATE TABLE IF NOT EXISTS bbs_citizen_anchor("
            "citizen_id TEXT PRIMARY KEY REFERENCES citizens(citizen_id),"
            "nym_anchor BLOB NOT NULL UNIQUE CHECK(length(nym_anchor)=48))");
}
void checkPin(sqlite3* db,const Fingerprint& registryId,
              const std::array<std::uint8_t,96>& key,const Fingerprint& tag) {
    Statement authority(db,"SELECT registry_id FROM registry_authority WHERE singleton=1");
    if (authority.step()!=SQLITE_ROW || sqlite3_column_bytes(authority.raw(),0)!=32 ||
        CRYPTO_memcmp(sqlite3_column_blob(authority.raw(),0),registryId.data(),32)!=0)
        throw std::runtime_error("Maât BBS: namespace not authorized");
    Statement pin(db,"SELECT issuer_key,entropy_tag FROM bbs_issuer_pin WHERE singleton=1");
    if (pin.step()!=SQLITE_ROW || sqlite3_column_bytes(pin.raw(),0)!=96 ||
        sqlite3_column_bytes(pin.raw(),1)!=32 ||
        CRYPTO_memcmp(sqlite3_column_blob(pin.raw(),0),key.data(),96)!=0 ||
        CRYPTO_memcmp(sqlite3_column_blob(pin.raw(),1),tag.data(),32)!=0)
        throw std::runtime_error("Maât BBS: signer identity or entropy secret changed");
}
void verifyHolder(const Fingerprint& key,const std::vector<std::uint8_t>& transcript,
                  const Ed25519Signature& signature) {
    EVP_PKEY* pub=EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519,nullptr,key.data(),key.size());
    if(!pub) throw std::runtime_error("Maât BBS: invalid holder key");
    EVP_MD_CTX* ctx=EVP_MD_CTX_new();
    if(!ctx){EVP_PKEY_free(pub);throw std::runtime_error("Maât BBS: signature context failed");}
    const bool good=EVP_DigestVerifyInit(ctx,nullptr,nullptr,nullptr,pub)==1 &&
        EVP_DigestVerify(ctx,signature.data(),signature.size(),transcript.data(),transcript.size())==1;
    EVP_MD_CTX_free(ctx);EVP_PKEY_free(pub);
    if(!good) throw std::runtime_error("Maât BBS: invalid holder request signature");
}
}

std::vector<std::uint8_t> bbsBoundRequestBytes(const Fingerprint& registryId,
                                                const BbsBoundIssueRequest& r) {
    nonzero(registryId);nonzero(r.citizenKey);nonzero(r.challenge);
    static constexpr char label[]="MAAT/BBS/BOUND-ISSUE-REQUEST/V1";
    auto bytes=prefix(label,sizeof(label),registryId);
    append(bytes,r.citizenKey);append(bytes,r.challenge);
    append(bytes,r.nymAnchor);append(bytes,r.commitment);append(bytes,r.bindingProof);
    return bytes;
}

void BbsBoundIssuer::bootstrap(CitizenRegistry& registry, const Fingerprint& registryId,
                               const Fingerprint& bbsSeed,const Fingerprint& entropyKey) {
    nonzero(registryId);nonzero(entropyKey);
    if (bbsSeed==entropyKey) throw std::invalid_argument("Maât BBS: issuer and PRF keys must differ");
    const auto pub=issuerKey(bbsSeed);
    const auto tag=entropyPin(entropyKey,registryId);
    exec(registry.db_,"BEGIN IMMEDIATE");
    try {
        schema(registry.db_);
        Statement put(registry.db_,"INSERT OR IGNORE INTO bbs_issuer_pin"
                                  "(singleton,issuer_key,entropy_tag) VALUES(1,?1,?2)");
        put.blob(1,pub);put.blob(2,tag);put.done();
        checkPin(registry.db_,registryId,pub,tag);
        exec(registry.db_,"COMMIT");
    } catch (...) {sqlite3_exec(registry.db_,"ROLLBACK",nullptr,nullptr,nullptr);throw;}
}

BbsBoundIssuer::BbsBoundIssuer(CitizenRegistry& registry,const Fingerprint& registryId,
                                const Fingerprint& bbsSeed,const Fingerprint& entropyKey)
  :registry_(registry),registryId_(registryId),bbsSeed_(bbsSeed),entropyKey_(entropyKey) {
    nonzero(registryId_);nonzero(entropyKey_);
    if (bbsSeed_==entropyKey_) throw std::invalid_argument("Maât BBS: reused signing secret");
    issuerPublicKey_=issuerKey(bbsSeed_);
    checkPin(registry_.db_,registryId_,issuerPublicKey_,entropyPin(entropyKey_,registryId_));
}
BbsBoundIssuer::~BbsBoundIssuer(){
    OPENSSL_cleanse(bbsSeed_.data(),bbsSeed_.size());
    OPENSSL_cleanse(entropyKey_.data(),entropyKey_.size());
}
Fingerprint BbsBoundIssuer::challenge() {
    Fingerprint value{};
    if(RAND_bytes(value.data(),static_cast<int>(value.size()))!=1)
        throw std::runtime_error("Maât BBS: OS randomness missing");
    auto now=std::int64_t(std::time(nullptr));
    std::lock_guard<std::mutex> lock(mutex_);
    for(auto it=challenges_.begin();it!=challenges_.end();) {
        if(it->second<now) it=challenges_.erase(it); else ++it;
    }
    if(challenges_.size()>=maxPending || !challenges_.emplace(value,now+challengeLifetime).second)
        throw std::runtime_error("Maât BBS: challenge budget/collision");
    return value;
}
BbsBoundCredential BbsBoundIssuer::issue(const BbsBoundIssueRequest& r) {
    const auto bytes=bbsBoundRequestBytes(registryId_,r);
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it=challenges_.find(r.challenge);
        if(it==challenges_.end()) throw std::runtime_error("Maât BBS: unknown or replayed challenge");
        const auto live=it->second >=std::int64_t(std::time(nullptr));
        challenges_.erase(it); // consume even if holder signature or binding is invalid
        if(!live) throw std::runtime_error("Maât BBS: expired challenge");
    }
    verifyHolder(r.citizenKey,bytes,r.citizenSignature);
    std::lock_guard<std::mutex> serializeIssuance(issueMutex_);
    exec(registry_.db_,"BEGIN IMMEDIATE");
    try {
        Statement eligible(registry_.db_,
            "SELECT k.citizen_id FROM citizen_keys k JOIN citizens c "
            "ON c.citizen_id=k.citizen_id WHERE k.public_key=?1 AND k.revoked=0 "
            "AND c.status=1 AND c.anonymous_permission=1");
        eligible.blob(1,r.citizenKey);
        if(eligible.step()!=SQLITE_ROW || sqlite3_column_bytes(eligible.raw(),0)!=64)
            throw std::runtime_error("Maât BBS: revoked/suspended/not enrolled");
        const auto* raw=sqlite3_column_text(eligible.raw(),0);
        if(!raw) throw std::runtime_error("Maât BBS: missing citizen ID");
        const std::string citizen(reinterpret_cast<const char*>(raw),64);
        // Pin must be checked at every issuance, not just on construction.
        checkPin(registry_.db_,registryId_,issuerPublicKey_,entropyPin(entropyKey_,registryId_));
        {
            Statement put(registry_.db_,
                "INSERT OR IGNORE INTO bbs_citizen_anchor(citizen_id,nym_anchor) VALUES(?1,?2)");
            put.text(1,citizen);put.blob(2,r.nymAnchor);put.done();
        }
        {
            Statement pinned(registry_.db_,
                "SELECT nym_anchor FROM bbs_citizen_anchor WHERE citizen_id=?1");
            pinned.text(1,citizen);
            if(pinned.step()!=SQLITE_ROW || sqlite3_column_bytes(pinned.raw(),0)!=48 ||
               CRYPTO_memcmp(sqlite3_column_blob(pinned.raw(),0),r.nymAnchor.data(),48)!=0)
                throw std::runtime_error("Maât BBS: citizen attempted to change hidden nym anchor");
        }
        auto entropy=citizenEntropy(entropyKey_,registryId_,citizen);
        BbsBoundCredential result{};
        const int ok=maat_bbs_bound_sign_v1(bbsSeed_.data(),entropy.data(),r.nymAnchor.data(),
                       r.commitment.data(),r.bindingProof.data(),registryId_.data(),
                       r.citizenKey.data(),r.challenge.data(),result.blindSignature.data());
        OPENSSL_cleanse(entropy.data(),entropy.size());
        if(ok!=1) throw std::runtime_error("Maât BBS: bad hidden nym binding/commitment");
        exec(registry_.db_,"COMMIT");
        return result;
    } catch (...) {sqlite3_exec(registry_.db_,"ROLLBACK",nullptr,nullptr,nullptr);throw;}
}

}} // namespace maat::identity
