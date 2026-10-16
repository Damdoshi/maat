#include "identity/replicated_trust.hpp"

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <sqlite3.h>

#include <algorithm>
#include <climits>
#include <cstring>
#include <limits>
#include <stdexcept>

namespace maat { namespace identity {
namespace {
constexpr char kDomain[] = "MAAT:REPLICATED-PUBLIC-TRUST:DELTA:V1";
constexpr std::int64_t kMaxValidity = 24 * 60 * 60;
constexpr std::int64_t kClockSkew = 5 * 60;
constexpr std::size_t kFixedSize = sizeof(kDomain) + 32 + 8 + 8 + 8 + 32 + 1 + 2;

void require(bool ok, const char* message) {
    if (!ok) throw std::runtime_error(message);
}

template<std::size_t N>
void append(std::vector<std::uint8_t>& out, const std::array<std::uint8_t,N>& data) {
    out.insert(out.end(),data.begin(),data.end());
}
void be(std::vector<std::uint8_t>& out, std::uint64_t x, int bytes) {
    for (int i=bytes-1; i>=0; --i)
        out.push_back(static_cast<std::uint8_t>(x >> (i*8)));
}
std::uint64_t readBe(const std::vector<std::uint8_t>& in, std::size_t& pos, int n) {
    require(pos + static_cast<std::size_t>(n) <= in.size(), "truncated trust delta");
    std::uint64_t result = 0;
    for (int i=0; i<n; ++i) result = (result<<8) | in[pos++];
    return result;
}
template<std::size_t N>
void take(const std::vector<std::uint8_t>& in, std::size_t& pos,
          std::array<std::uint8_t,N>& dst) {
    require(pos + N <= in.size(), "truncated trust delta field");
    std::copy_n(in.data()+pos,N,dst.data()); pos+=N;
}
bool allZero(const std::uint8_t* p, std::size_t n) {
    return std::all_of(p,p+n,[](std::uint8_t v){return v==0;});
}
std::size_t expectedKeySize(TrustOperation op) {
    switch (op) {
        case TrustOperation::heartbeat: return 0;
        case TrustOperation::add_citizen_key:
        case TrustOperation::revoke_citizen_key: return 32;
        case TrustOperation::add_bbs_issuer:
        case TrustOperation::revoke_bbs_issuer: return 96;
        default: throw std::invalid_argument("unknown trust delta operation");
    }
}
void canonical(const TrustDelta& d) {
    require(d.sequence > 0 && d.sequence <= INT64_MAX, "invalid trust sequence");
    require(d.issuedAt > 0 && d.validUntil > d.issuedAt &&
            d.validUntil-d.issuedAt <= kMaxValidity, "invalid trust validity interval");
    require(!allZero(d.registryId.data(),d.registryId.size()), "empty registry ID");
    const auto n = expectedKeySize(d.operation);
    require(d.publicKey.size()==n, "trust key size does not match operation");
    if (n) require(!allZero(d.publicKey.data(),n), "zero public key forbidden");
}
void sql(sqlite3* db,const char* statement) {
    require(sqlite3_exec(db,statement,nullptr,nullptr,nullptr)==SQLITE_OK,
            "trust database SQL error");
}
class Stmt final {
    sqlite3_stmt* p_=nullptr;
public:
    Stmt(sqlite3* db,const char* text) {
        require(sqlite3_prepare_v2(db,text,-1,&p_,nullptr)==SQLITE_OK,
                "trust SQL prepare failed");
    }
    ~Stmt(){sqlite3_finalize(p_);}
    sqlite3_stmt* get() const{return p_;}
    int step() const {return sqlite3_step(p_);}
    void blob(int idx,const void* ptr,std::size_t size) {
        require(sqlite3_bind_blob(p_,idx,ptr,static_cast<int>(size),SQLITE_TRANSIENT)==SQLITE_OK,
                "trust blob bind failure");
    }
    template<std::size_t N> void blob(int idx,const std::array<std::uint8_t,N>& v) {
        blob(idx,v.data(),v.size());
    }
    void key(const std::vector<std::uint8_t>& v) {blob(1,v.data(),v.size());}
    void int64(int idx,std::int64_t v) {
        require(sqlite3_bind_int64(p_,idx,v)==SQLITE_OK,"trust integer bind failure");
    }
    void done() {require(step()==SQLITE_DONE,"trust update rejected");}
};
class Transaction final {
    sqlite3* db_;
    bool committed_=false;
public:
    explicit Transaction(sqlite3* db):db_(db){sql(db_,"BEGIN IMMEDIATE");}
    ~Transaction(){if(!committed_) sqlite3_exec(db_,"ROLLBACK",nullptr,nullptr,nullptr);}
    void commit(){sql(db_,"COMMIT");committed_=true;}
};
struct Meta {
    std::uint64_t seq=0;
    TrustHash head{};
    std::int64_t issued=0;
    std::int64_t until=0;
    std::uint64_t highestSeen=0;
    bool forked=false;
};
Meta meta(sqlite3* db) {
    Stmt q(db,"SELECT sequence,head_hash,issued_at,valid_until,highest_seen FROM trust_metadata WHERE singleton=1");
    require(q.step()==SQLITE_ROW && sqlite3_column_bytes(q.get(),1)==32,
            "missing/corrupt trust metadata");
    Meta m;
    const auto signedSeq=sqlite3_column_int64(q.get(),0);
    require(signedSeq>=0,"corrupt trust sequence");
    m.seq=static_cast<std::uint64_t>(signedSeq);
    std::memcpy(m.head.data(),sqlite3_column_blob(q.get(),1),32);
    m.issued=sqlite3_column_int64(q.get(),2);
    m.until=sqlite3_column_int64(q.get(),3);
    const auto observed=sqlite3_column_int64(q.get(),4);
    require(observed>=0,"corrupt trust observed-sequence watermark");
    m.highestSeen=static_cast<std::uint64_t>(observed);
    Stmt fork(db,"SELECT 1 FROM trust_signed_forks LIMIT 1");
    m.forked=(fork.step()==SQLITE_ROW);
    Stmt proofs(db,"SELECT 1 FROM trust_fork_proofs LIMIT 1");
    m.forked=m.forked || (proofs.step()==SQLITE_ROW);
    return m;
}
bool active(sqlite3* db,const char* query,const std::uint8_t* key,
            std::size_t n) {
    Stmt s(db,query);
    s.blob(1,key,n);
    return s.step()==SQLITE_ROW && sqlite3_column_int(s.get(),0)==1;
}
void verifySignature(const TrustHash& authority,const TrustDelta& delta) {
    auto bytes=trustDeltaSigningBytes(delta);
    EVP_PKEY* key=EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519,nullptr,
                                               authority.data(),authority.size());
    require(key!=nullptr,"invalid trust authority public key");
    EVP_MD_CTX* ctx=EVP_MD_CTX_new();
    if (!ctx) {EVP_PKEY_free(key);throw std::runtime_error("trust signature context failure");}
    const bool ok=EVP_DigestVerifyInit(ctx,nullptr,nullptr,nullptr,key)==1 &&
        EVP_DigestVerify(ctx,delta.signature.data(),delta.signature.size(),
                         bytes.data(),bytes.size())==1;
    EVP_MD_CTX_free(ctx); EVP_PKEY_free(key);
    require(ok,"invalid public trust delta signature");
}
}

std::vector<std::uint8_t> trustDeltaSigningBytes(const TrustDelta& d) {
    canonical(d);
    std::vector<std::uint8_t> out;
    out.reserve(kFixedSize+d.publicKey.size());
    out.insert(out.end(),kDomain,kDomain+sizeof(kDomain)); // NUL is signed
    append(out,d.registryId);
    be(out,d.sequence,8);
    be(out,static_cast<std::uint64_t>(d.issuedAt),8);
    be(out,static_cast<std::uint64_t>(d.validUntil),8);
    append(out,d.previousHash);
    out.push_back(static_cast<std::uint8_t>(d.operation));
    be(out,d.publicKey.size(),2);
    out.insert(out.end(),d.publicKey.begin(),d.publicKey.end());
    return out;
}
std::vector<std::uint8_t> encodeTrustDelta(const TrustDelta& d) {
    auto encoded=trustDeltaSigningBytes(d);
    append(encoded,d.signature);
    return encoded;
}
TrustDelta decodeTrustDelta(const std::vector<std::uint8_t>& wire) {
    require(wire.size()>=kFixedSize+64 && wire.size()<=kFixedSize+96+64,
            "invalid trust delta length");
    require(std::equal(kDomain,kDomain+sizeof(kDomain),wire.begin()),
            "unknown trust delta domain/version");
    TrustDelta d;
    std::size_t pos=sizeof(kDomain);
    take(wire,pos,d.registryId);
    d.sequence=readBe(wire,pos,8);
    auto issued=readBe(wire,pos,8), until=readBe(wire,pos,8);
    require(issued<=INT64_MAX && until<=INT64_MAX,"trust time outside signed range");
    d.issuedAt=static_cast<std::int64_t>(issued);
    d.validUntil=static_cast<std::int64_t>(until);
    take(wire,pos,d.previousHash);
    d.operation=static_cast<TrustOperation>(readBe(wire,pos,1));
    const auto keyLen=static_cast<std::size_t>(readBe(wire,pos,2));
    require(keyLen==expectedKeySize(d.operation) && pos+keyLen+64==wire.size(),
            "invalid trust delta key/extension");
    d.publicKey.assign(wire.begin()+static_cast<std::ptrdiff_t>(pos),
                       wire.begin()+static_cast<std::ptrdiff_t>(pos+keyLen));
    pos+=keyLen;
    take(wire,pos,d.signature);
    canonical(d);
    return d;
}
TrustHash trustDeltaHash(const TrustDelta& d) {
    auto wire=encodeTrustDelta(d);
    TrustHash digest{};
    require(SHA256(wire.data(),wire.size(),digest.data())!=nullptr,"SHA256 failure");
    return digest;
}

ReplicatedTrust::ReplicatedTrust(const std::string& path,TrustHash registryId,
                                 TrustHash authorityPublicKey)
    :registryId_(registryId),authorityPublicKey_(authorityPublicKey) {
    require(!allZero(registryId.data(),registryId.size()) &&
            !allZero(authorityPublicKey.data(),authorityPublicKey.size()),
            "trust roots must be independently pinned");
    require(sqlite3_open_v2(path.c_str(),&db_,SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE,
                            nullptr)==SQLITE_OK,"cannot open trust database");
    try {
        sqlite3_busy_timeout(db_,5000);
        sql(db_,"PRAGMA journal_mode=WAL");
        sql(db_,"CREATE TABLE IF NOT EXISTS trust_metadata("
                "singleton INTEGER PRIMARY KEY CHECK(singleton=1),"
                "registry_id BLOB NOT NULL CHECK(length(registry_id)=32),"
                "authority_key BLOB NOT NULL CHECK(length(authority_key)=32),"
                "sequence INTEGER NOT NULL,head_hash BLOB NOT NULL CHECK(length(head_hash)=32),"
                "issued_at INTEGER NOT NULL,valid_until INTEGER NOT NULL,"
                "highest_seen INTEGER NOT NULL DEFAULT 0)");
        sql(db_,"CREATE TABLE IF NOT EXISTS trust_citizen_keys("
                "public_key BLOB PRIMARY KEY CHECK(length(public_key)=32),"
                "active INTEGER NOT NULL CHECK(active IN(0,1)))");
        // Immutable local history for bounded, independently verifiable peer catch-up.
        sql(db_,"CREATE TABLE IF NOT EXISTS trust_event_history("
                "sequence INTEGER PRIMARY KEY CHECK(sequence>0),"
                "event_hash BLOB NOT NULL CHECK(length(event_hash)=32),"
                "wire BLOB NOT NULL)");
        // A pair of valid authority signatures at the same sequence is
        // evidence of equivocation: permanently block authentication.
        sql(db_,"CREATE TABLE IF NOT EXISTS trust_signed_forks("
                "sequence INTEGER PRIMARY KEY,other_event BLOB NOT NULL)");
        sql(db_,"CREATE TABLE IF NOT EXISTS trust_fork_proofs("
                "sequence INTEGER PRIMARY KEY,"
                "first_event BLOB NOT NULL,second_event BLOB NOT NULL)");
        sql(db_,"CREATE TABLE IF NOT EXISTS trust_bbs_issuers("
                "public_key BLOB PRIMARY KEY CHECK(length(public_key)=96),"
                "active INTEGER NOT NULL CHECK(active IN(0,1)))");
        {
            Stmt ins(db_,"INSERT OR IGNORE INTO trust_metadata VALUES(1,?1,?2,0,?3,0,0,0)");
            ins.blob(1,registryId_); ins.blob(2,authorityPublicKey_);
            TrustHash zero{}; ins.blob(3,zero); ins.done();
        }
        Stmt m(db_,"SELECT registry_id,authority_key FROM trust_metadata WHERE singleton=1");
        require(m.step()==SQLITE_ROW && sqlite3_column_bytes(m.get(),0)==32 &&
                sqlite3_column_bytes(m.get(),1)==32 &&
                std::memcmp(sqlite3_column_blob(m.get(),0),registryId_.data(),32)==0 &&
                std::memcmp(sqlite3_column_blob(m.get(),1),authorityPublicKey_.data(),32)==0,
                "pinned trust roots changed");
        // Reject a journal whose tail is inconsistent with persisted trust.
        Stmt last(db_,"SELECT sequence,event_hash FROM trust_event_history "
                      "ORDER BY sequence DESC LIMIT 1");
        if (last.step()==SQLITE_ROW) {
            const Meta m=meta(db_);
            require(sqlite3_column_int64(last.get(),0)==static_cast<sqlite3_int64>(m.seq) &&
                    sqlite3_column_bytes(last.get(),1)==32 &&
                    std::memcmp(sqlite3_column_blob(last.get(),1),m.head.data(),32)==0,
                    "trust journal head mismatch");
        }
    } catch (...) {sqlite3_close(db_);db_=nullptr;throw;}
}
ReplicatedTrust::~ReplicatedTrust(){if(db_)sqlite3_close(db_);}

// Called with a SQLite write transaction and mutex already held. Every
// metadata, key and journal mutation succeeds together or rolls back.
static void appendTrustedDelta(sqlite3* db,const TrustDelta& d,const Meta& current) {
    require(d.sequence==current.seq+1 && d.previousHash==current.head &&
            d.issuedAt>=current.issued,"replayed/forked/out-of-order trust delta");
    if (d.operation!=TrustOperation::heartbeat) {
        const bool citizen=d.operation==TrustOperation::add_citizen_key ||
                           d.operation==TrustOperation::revoke_citizen_key;
        const bool add=d.operation==TrustOperation::add_citizen_key ||
                       d.operation==TrustOperation::add_bbs_issuer;
        const char* table=citizen ? "trust_citizen_keys" : "trust_bbs_issuers";
        if (add) {
            const std::string statement=std::string("INSERT INTO ")+table+
                "(public_key,active) VALUES(?1,1)";
            Stmt ins(db,statement.c_str()); ins.key(d.publicKey); ins.done();
            // SQLite PRIMARY KEY forbids reinsertion after a tombstone.
        } else {
            const std::string statement=std::string("INSERT INTO ")+table+
                "(public_key,active) VALUES(?1,0) ON CONFLICT(public_key) DO UPDATE SET active=0";
            Stmt rev(db,statement.c_str()); rev.key(d.publicKey); rev.done();
        }
    }
    const TrustHash hash=trustDeltaHash(d);
    {
        Stmt record(db,"INSERT INTO trust_event_history(sequence,event_hash,wire) "
                       "VALUES(?1,?2,?3)");
        auto wire=encodeTrustDelta(d);
        record.int64(1,static_cast<std::int64_t>(d.sequence));
        record.blob(2,hash);
        record.blob(3,wire.data(),wire.size());
        record.done();
    }
    {
        Stmt save(db,"UPDATE trust_metadata SET sequence=?1,head_hash=?2,"
                      "issued_at=?3,valid_until=?4 WHERE singleton=1");
        save.int64(1,static_cast<std::int64_t>(d.sequence));
        save.blob(2,hash); save.int64(3,d.issuedAt); save.int64(4,d.validUntil);
        save.done();
    }
}

void ReplicatedTrust::apply(const TrustDelta& d,std::int64_t now) {
    canonical(d);
    require(d.registryId==registryId_,"trust delta from another registry");
    require(now>0 && now<=INT64_MAX-kClockSkew &&
            d.issuedAt<=now+kClockSkew && d.validUntil>now,
            "expired/future trust delta");
    verifySignature(authorityPublicKey_,d);
    std::lock_guard<std::mutex> lock(mutex_);
    Transaction tx(db_);
    const Meta current=meta(db_);
    require(!current.forked,"signed trust fork: operator intervention required");
    if (d.sequence>current.seq+1 && d.issuedAt>=current.issued) {
        Stmt seen(db_,"UPDATE trust_metadata SET highest_seen=?1 WHERE singleton=1");
        seen.int64(1,static_cast<std::int64_t>(std::max(d.sequence,current.highestSeen)));
        seen.done(); tx.commit();
        throw std::runtime_error("signed trust delta gap: local verifier quarantined");
    }
    appendTrustedDelta(db_,d,current);
    tx.commit();
}

void ReplicatedTrust::applyHistoricalBatch(const std::vector<TrustDelta>& items,
                                           std::int64_t now) {
    require(!items.empty() && items.size()<=64,"invalid catch-up batch size");
    require(now>0 && now<=INT64_MAX-kClockSkew,"invalid catch-up clock");
    // A *historical* signed event may have expired. This does not make an
    // expired LOCAL HEAD fresh: fresh() still checks the last signed deadline.
    // Prevalidate the entire batch before touching SQLite.
    for (const auto& d:items) {
        canonical(d);
        require(d.registryId==registryId_ && d.issuedAt<=now+kClockSkew,
                "wrong registry or future event in catch-up");
        verifySignature(authorityPublicKey_,d);
    }
    std::lock_guard<std::mutex> lock(mutex_);
    Transaction tx(db_);
    Meta current=meta(db_);
    require(!current.forked,"signed trust fork: operator intervention required");
    for (const auto& d:items) {
        appendTrustedDelta(db_,d,current);
        current.seq=d.sequence;
        current.head=trustDeltaHash(d);
        current.issued=d.issuedAt;
        current.until=d.validUntil;
    }
    tx.commit();
}

// A signed event received as peer *evidence* must never be installed as a
// replacement branch. Persist fork evidence and fail closed, even on restart.
void ReplicatedTrust::validateSignedPeerEvent(const TrustDelta& d,std::int64_t now) const {
    canonical(d);
    require(d.registryId==registryId_ && now>0 && now<=INT64_MAX-kClockSkew &&
            d.issuedAt<=now+kClockSkew,"invalid peer evidence");
    verifySignature(authorityPublicKey_,d);
}
void ReplicatedTrust::observeSignedPeerEvent(const TrustDelta& d,std::int64_t now) {
    validateSignedPeerEvent(d,now);
    std::lock_guard<std::mutex> lock(mutex_);
    Transaction tx(db_);
    const Meta current=meta(db_);
    if (d.sequence<=current.seq) {
        TrustHash known{};
        bool have=false;
        if (d.sequence==current.seq) {known=current.head;have=true;}
        else {
            Stmt local(db_,"SELECT event_hash FROM trust_event_history WHERE sequence=?1");
            local.int64(1,static_cast<std::int64_t>(d.sequence));
            if (local.step()==SQLITE_ROW && sqlite3_column_bytes(local.get(),0)==32) {
                std::memcpy(known.data(),sqlite3_column_blob(local.get(),0),32);
                have=true;
            }
        }
        if (have && trustDeltaHash(d)!=known) {
            Stmt evidence(db_,"INSERT OR IGNORE INTO trust_signed_forks(sequence,other_event) "
                              "VALUES(?1,?2)");
            auto wire=encodeTrustDelta(d);
            evidence.int64(1,static_cast<std::int64_t>(d.sequence));
            evidence.blob(2,wire.data(),wire.size()); evidence.done();
            Stmt localWire(db_,"SELECT wire FROM trust_event_history WHERE sequence=?1");
            localWire.int64(1,static_cast<std::int64_t>(d.sequence));
            if(localWire.step()==SQLITE_ROW) {
                const auto* p=static_cast<const std::uint8_t*>(
                    sqlite3_column_blob(localWire.get(),0));
                const auto n=sqlite3_column_bytes(localWire.get(),0);
                if(p && n>0 && n<=512) {
                    Stmt add(db_,"INSERT OR IGNORE INTO trust_fork_proofs("
                                 "sequence,first_event,second_event) VALUES(?1,?2,?3)");
                    add.int64(1,static_cast<std::int64_t>(d.sequence));
                    add.blob(2,p,static_cast<std::size_t>(n));
                    add.blob(3,wire.data(),wire.size());
                    add.done();
                }
            }
            tx.commit();
            throw std::runtime_error("AUTHORITY EQUIVOCATION: signed fork quarantined");
        }
    } else if (d.sequence>current.seq+1 && d.issuedAt>=current.issued) {
        Stmt seen(db_,"UPDATE trust_metadata SET highest_seen=?1 WHERE singleton=1");
        seen.int64(1,static_cast<std::int64_t>(std::max(current.highestSeen,d.sequence)));
        seen.done();
    }
    tx.commit();
}

// The sync API never exposes private citizen attributes, only public signed
// authority events. If this DB predates alpha8, old events aren't fabricated:
// callers must bootstrap from a complete authenticated history instead.
std::vector<TrustDelta> ReplicatedTrust::historyAfter(std::uint64_t cursor,
                                                       const TrustHash& hash,
                                                       std::size_t limit) const {
    require(limit>0 && limit<=64 && cursor<=INT64_MAX,"invalid sync cursor/limit");
    std::lock_guard<std::mutex> lock(mutex_);
    const Meta current=meta(db_);
    require(!current.forked,"forked local register cannot serve trust");
    require(cursor<=current.seq,"remote cursor ahead of local register");
    if (cursor==0) require(hash==TrustHash{},"invalid genesis cursor");
    else if (cursor==current.seq) require(hash==current.head,"sync head conflict");
    else {
        Stmt pos(db_,"SELECT event_hash FROM trust_event_history WHERE sequence=?1");
        pos.int64(1,static_cast<std::int64_t>(cursor));
        require(pos.step()==SQLITE_ROW && sqlite3_column_bytes(pos.get(),0)==32,
                "sync history unavailable (legacy database or pruned events)");
        require(std::memcmp(sqlite3_column_blob(pos.get(),0),hash.data(),32)==0,
                "sync cursor fork");
    }
    std::vector<TrustDelta> events;
    Stmt query(db_,"SELECT sequence,wire FROM trust_event_history WHERE sequence>?1 "
                   "ORDER BY sequence ASC LIMIT ?2");
    query.int64(1,static_cast<std::int64_t>(cursor));
    query.int64(2,static_cast<std::int64_t>(limit));
    std::uint64_t next=cursor+1;
    while(query.step()==SQLITE_ROW) {
        require(sqlite3_column_int64(query.get(),0)==static_cast<sqlite3_int64>(next),
                "non-contiguous trust sync history");
        const auto* b=static_cast<const std::uint8_t*>(sqlite3_column_blob(query.get(),1));
        const auto n=sqlite3_column_bytes(query.get(),1);
        require(b && n>0 && n<=512,"malformed stored trust sync event");
        events.push_back(decodeTrustDelta({b,b+n}));
        ++next;
    }
    require(cursor==current.seq || !events.empty(),"sync history unavailable");
    return events;
}

bool ReplicatedTrust::historicalEvent(std::uint64_t sequence,TrustDelta& out) const {
    if(sequence==0 || sequence>INT64_MAX)return false;
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt query(db_,"SELECT wire FROM trust_event_history WHERE sequence=?1");
    query.int64(1,static_cast<std::int64_t>(sequence));
    if(query.step()!=SQLITE_ROW)return false;
    const auto* b=static_cast<const std::uint8_t*>(sqlite3_column_blob(query.get(),0));
    const auto n=sqlite3_column_bytes(query.get(),0);
    require(b && n>0 && n<=512,"corrupt stored trust event");
    out=decodeTrustDelta({b,b+n});
    return true;
}

void ReplicatedTrust::observeSignedForkPair(const TrustDelta& a,const TrustDelta& b,
                                            std::int64_t now) {
    validateSignedPeerEvent(a,now);
    validateSignedPeerEvent(b,now);
    require(a.sequence==b.sequence && trustDeltaHash(a)!=trustDeltaHash(b),
            "no cryptographically proven authority fork");
    std::lock_guard<std::mutex> lock(mutex_);
    Transaction tx(db_);
    Stmt proof(db_,"INSERT OR IGNORE INTO trust_fork_proofs("
                   "sequence,first_event,second_event) VALUES(?1,?2,?3)");
    const auto first=encodeTrustDelta(a),second=encodeTrustDelta(b);
    proof.int64(1,static_cast<std::int64_t>(a.sequence));
    proof.blob(2,first.data(),first.size());
    proof.blob(3,second.data(),second.size());
    proof.done();
    tx.commit();
}
bool ReplicatedTrust::forkProof(TrustDelta& first,TrustDelta& second) const {
    std::lock_guard<std::mutex> lock(mutex_);
    Stmt query(db_,"SELECT first_event,second_event FROM trust_fork_proofs "
                    "ORDER BY sequence ASC LIMIT 1");
    if(query.step()!=SQLITE_ROW)return false;
    auto decodeColumn=[&](int col)->TrustDelta {
        const auto* ptr=static_cast<const std::uint8_t*>(sqlite3_column_blob(query.get(),col));
        const auto n=sqlite3_column_bytes(query.get(),col);
        require(ptr && n>0 && n<=512,"corrupt signed fork proof");
        return decodeTrustDelta({ptr,ptr+n});
    };
    first=decodeColumn(0);
    second=decodeColumn(1);
    return true;
}

bool ReplicatedTrust::forked() const {
    std::lock_guard<std::mutex> lock(mutex_);return meta(db_).forked;
}

void ReplicatedTrust::applyEncoded(const std::vector<std::uint8_t>& data,std::int64_t now) {
    apply(decodeTrustDelta(data),now);
}
bool ReplicatedTrust::fresh(std::int64_t now) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (now<=0 || now>INT64_MAX-kClockSkew) return false;
    const Meta m=meta(db_);
    return m.until>now && m.issued<=now+kClockSkew && m.seq>=m.highestSeen && !m.forked;
}
bool ReplicatedTrust::citizenKeyActive(const TrustHash& key,std::int64_t now) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (now<=0 || now>INT64_MAX-kClockSkew) return false;
    const Meta m=meta(db_);
    return m.until>now && m.issued<=now+kClockSkew && m.seq>=m.highestSeen && !m.forked &&
       active(db_,"SELECT active FROM trust_citizen_keys WHERE public_key=?1",key.data(),key.size());
}
bool ReplicatedTrust::bbsIssuerActive(const BbsIssuerKey& key,std::int64_t now) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (now<=0 || now>INT64_MAX-kClockSkew) return false;
    const Meta m=meta(db_);
    return m.until>now && m.issued<=now+kClockSkew && m.seq>=m.highestSeen && !m.forked &&
       active(db_,"SELECT active FROM trust_bbs_issuers WHERE public_key=?1",key.data(),key.size());
}
std::uint64_t ReplicatedTrust::sequence() const {
    std::lock_guard<std::mutex> lock(mutex_); return meta(db_).seq;
}
TrustHash ReplicatedTrust::headHash() const {
    std::lock_guard<std::mutex> lock(mutex_); return meta(db_).head;
}

}} // namespace maat::identity
