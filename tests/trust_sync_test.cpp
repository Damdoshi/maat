#include "identity/trust_sync.hpp"
#include <openssl/evp.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <sstream>
#include <string>
#include <vector>
#include <memory>
using namespace maat::identity;
namespace {
void check(bool ok,const char* msg) {
    if(!ok){std::fprintf(stderr,"FAIL trust sync: %s\n",msg);std::exit(1);}
}
template<typename F> void rejects(F f,const char* why){
    try{f();}catch(const std::exception&){return;}
    check(false,why);
}
TrustHash value(unsigned seed) {
    TrustHash result{};
    for(std::size_t i=0;i<result.size();++i)
        result[i]=static_cast<std::uint8_t>((seed+i*29)%251+1);
    return result;
}
struct Signer {
    EVP_PKEY* p=nullptr;
    TrustHash pub{};
    Signer() {
        const auto secret=value(42);
        p=EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519,nullptr,
                                        secret.data(),secret.size());
        check(p!=nullptr,"Ed25519 test signer");
        std::size_t n=pub.size();
        check(EVP_PKEY_get_raw_public_key(p,pub.data(),&n)==1 && n==32,
              "Ed25519 test signer public key");
    }
    ~Signer(){EVP_PKEY_free(p);}
    void sign(TrustDelta& d)const {
        const auto msg=trustDeltaSigningBytes(d);
        EVP_MD_CTX* ctx=EVP_MD_CTX_new();
        check(ctx!=nullptr,"Ed25519 context");
        std::size_t size=d.signature.size();
        const bool ok=EVP_DigestSignInit(ctx,nullptr,nullptr,nullptr,p)==1 &&
            EVP_DigestSign(ctx,d.signature.data(),&size,msg.data(),msg.size())==1 &&
            size==d.signature.size();
        EVP_MD_CTX_free(ctx);check(ok,"Ed25519 signature");
    }
};
TrustDelta signedNext(const TrustHash& registry,const Signer& signer,
                      const TrustDelta* prev,std::int64_t at,
                      TrustOperation op,const std::vector<std::uint8_t>& key) {
    TrustDelta d;
    d.registryId=registry;
    d.sequence=prev ? prev->sequence+1 : 1;
    d.previousHash=prev ? trustDeltaHash(*prev) : TrustHash{};
    d.issuedAt=at;
    d.validUntil=at+3600;
    d.operation=op;
    d.publicKey=key;
    signer.sign(d);
    return d;
}
std::string path(const std::string& dir,const char* name){return dir+"/"+name+".sqlite";}
TrustSyncResponse roundtrip(ReplicatedTrust& source,const TrustSyncRequest& req,
                            std::int64_t now) {
    std::stringstream pipe(std::ios::in|std::ios::out|std::ios::binary);
    writeTrustSyncRequest(pipe,req);
    TrustSyncRequest decoded;
    check(readTrustSyncRequest(pipe,decoded),"decode request");
    check(decoded.cursor==req.cursor && decoded.cursorHash==req.cursorHash,
          "request round trip");
    const auto reply=answerTrustSync(source,decoded,now);
    std::stringstream back(std::ios::in|std::ios::out|std::ios::binary);
    writeTrustSyncResponse(back,reply);
    return readTrustSyncResponse(back);
}
}
int main() {
    constexpr std::int64_t now=1792166400;
    Signer signer;
    const TrustHash registry=value(10),alice=value(31);
    char tmp[]="/tmp/maat-trust-sync-XXXXXX";
    check(mkdtemp(tmp)!=nullptr,"temporary directory");
    const std::string dir(tmp),src=path(dir,"source"),dst=path(dir,"dest"),
                      forkdb=path(dir,"fork");
    {
        ReplicatedTrust source(src,registry,signer.pub),client(dst,registry,signer.pub);
        // A long initial history, most of it expired: first and intermediate
        // pages MUST NOT turn a verifier into an authenticated node.
        std::vector<TrustDelta> batch;
        TrustDelta previous;
        bool have=false;
        for(unsigned i=0;i<171;++i) {
            const bool last=i==170;
            const auto at=last ? now-2 : now-172800;
            std::vector<std::uint8_t> key;
            if(i==0)key={alice.begin(),alice.end()};
            auto d=signedNext(registry,signer,have ? &previous : nullptr,at,
                              i==0 ? TrustOperation::add_citizen_key : TrustOperation::heartbeat,key);
            batch.push_back(d);previous=d;have=true;
            if(batch.size()==64 || last){
                source.applyHistoricalBatch(batch,now);
                batch.clear();
            }
        }
        check(source.sequence()==171 && source.fresh(now),"source built from signed history");
        check(source.citizenKeyActive(alice,now),"source key lookup");
        check(!client.fresh(now),"unbootstrapped client fails closed");
        {
            auto req=makeTrustSyncRequest(client);
            auto bad=roundtrip(source,req,now);
            check(bad.events.size()==64,"first page bounded to 64");
            // Fake one event's signature; batch must not partially apply.
            bad.events[10].back()^=1;
            rejects([&]{acceptTrustSync(client,req,bad,now);},"poisoned batch denied");
            check(client.sequence()==0,"poisoned batch transactional rollback");
        }
        // A valid signed tip advertises 171 events, but the peer deliberately
        // sends only a short page. The client must be able to persist and
        // resume that exact verified prefix, even after process restart.
        const auto resumeDb=path(dir,"resumable");
        {
            ReplicatedTrust resume(resumeDb,registry,signer.pub);
            auto r=makeTrustSyncRequest(resume);
            auto partial=roundtrip(source,r,now);
            check(partial.events.size()==64,"signed tip for partial-page test");
            partial.events.resize(7);
            check(acceptTrustSync(resume,r,partial,now)==7,
                  "short authentic page commits just seven events");
            check(resume.sequence()==7 && !resume.fresh(now),
                  "partial historical replay cannot authorize identity");
            // A peer knows a fresh signed head but withholds every event.
            auto withheld=roundtrip(source,makeTrustSyncRequest(resume),now);
            withheld.events.clear();
            auto stalledRequest=makeTrustSyncRequest(resume);
            rejects([&]{acceptTrustSync(resume,stalledRequest,withheld,now);},
                    "signed advanced tip with empty page is a stall");
            check(resume.sequence()==7,"stalled peer cannot alter committed prefix");
            // Truncated binary response: decode fails before touching SQLite.
            auto valid=roundtrip(source,stalledRequest,now);
            std::stringstream serialized(std::ios::in|std::ios::out|std::ios::binary);
            writeTrustSyncResponse(serialized,valid);
            const std::string wire=serialized.str();
            std::istringstream truncated(wire.substr(0,wire.size()-3),std::ios::binary);
            rejects([&]{(void)readTrustSyncResponse(truncated);},
                    "truncated on-wire frame cannot be applied");
            check(resume.sequence()==7,"broken stream keeps last committed cursor");
        }
        {
            ReplicatedTrust recovered(resumeDb,registry,signer.pub);
            check(recovered.sequence()==7 && recovered.headHash()!=TrustHash{},
                  "SQLite cursor persisted across interrupted SSH session");
            unsigned roundCount=0;
            while(recovered.sequence()<source.sequence()) {
                auto req=makeTrustSyncRequest(recovered);
                auto response=roundtrip(source,req,now);
                check(acceptTrustSync(recovered,req,response,now)>0,
                      "resume continues from verified cursor");
                check(++roundCount<=3,"bounded resume pagination");
            }
            check(recovered.sequence()==171 && recovered.headHash()==source.headHash() &&
                  recovered.fresh(now) && recovered.citizenKeyActive(alice,now),
                  "recovery reaches exact authority head after interruption");
        }
        // A server supplies two contradictory REAL signatures at sequence 64:
        // one inside the page and another as its purported signed tip.
        // Preserve the authority fork proof and do not install the page.
        const auto forkTipDb=path(dir,"fork-tip");
        {
            ReplicatedTrust forkTip(forkTipDb,registry,signer.pub);
            const auto r=makeTrustSyncRequest(forkTip);
            auto response=roundtrip(source,r,now);
            auto alternative=decodeTrustDelta(response.events.back());
            alternative.issuedAt=now-1;
            alternative.validUntil=now+3600;
            signer.sign(alternative);
            response.tipEvidence=encodeTrustDelta(alternative);
            response.peerSequence=alternative.sequence;
            response.peerHead=trustDeltaHash(alternative);
            rejects([&]{acceptTrustSync(forkTip,r,response,now);},
                    "genuinely signed conflicting page tip quarantined");
            check(forkTip.forked() && forkTip.sequence()==0 && !forkTip.fresh(now),
                  "signed tip fork rejects atomic batch and quarantines");
        }
        {
            ReplicatedTrust after(forkTipDb,registry,signer.pub);
            TrustDelta a,b;
            check(after.forked() && after.forkProof(a,b) &&
                  a.sequence==64 && b.sequence==64 && trustDeltaHash(a)!=trustDeltaHash(b),
                  "signed tip fork proof durable across restart");
        }
        std::size_t rounds=0;
        while(client.sequence()<source.sequence()) {
            auto request=makeTrustSyncRequest(client);
            auto response=roundtrip(source,request,now);
            check(response.status==TrustSyncStatus::events,"valid page status");
            check(acceptTrustSync(client,request,response,now)>0,"valid page advances");
            ++rounds;
            if(client.sequence()<171)
                check(!client.fresh(now),"expired/incomplete catch-up denies identity");
            check(rounds<=3,"sync completes in three pages");
        }
        check(rounds==3 && client.sequence()==171 && client.headHash()==source.headHash(),
              "same signed state after pagination");
        check(client.fresh(now) && client.citizenKeyActive(alice,now),
              "local public key active only after fresh signed tip");
        auto request=makeTrustSyncRequest(client);
        auto reply=roundtrip(source,request,now);
        check(reply.events.empty() && acceptTrustSync(client,request,reply,now)==0,
              "idempotent sync at common head");
        {
            // An untrusted number/hash alone cannot quarantine or raise trust.
            TrustSyncResponse fake;
            fake.peerSequence=500;
            fake.peerHead=value(99);
            rejects([&]{acceptTrustSync(client,request,fake,now);},
                    "unsigned high-water hint rejected, not accepted as completion");
            check(client.fresh(now),"unsigned high-water does not poison pool");
        }
        {
            const auto wrongReq=request;
            auto poisoned=reply;
            poisoned.tipEvidence.push_back(0);
            rejects([&]{acceptTrustSync(client,wrongReq,poisoned,now);},
                    "malformed peer tip denied");
            check(client.fresh(now),"malformed tip leaves trust unchanged");
        }
        {
            auto badRoot=request;badRoot.registryId=value(255);
            check(roundtrip(source,badRoot,now).status==TrustSyncStatus::wrong_registry,
                  "wrong registry refuses to supply events");
            auto falseCursor=request;falseCursor.cursorHash=value(5);
            falseCursor.cursorEvidence.clear();
            check(roundtrip(source,falseCursor,now).status==TrustSyncStatus::cursor_conflict,
                  "untrusted cursor mismatch gets signed evidence, not replacement");
            check(!source.forked(),"hash claim alone cannot poison provider");
        }
        {
            // A signed revocation received from a peer takes effect locally
            // without any call to the authority while authenticating.
            std::vector<std::uint8_t> key(alice.begin(),alice.end());
            auto revoke=signedNext(registry,signer,&previous,now-1,
                                   TrustOperation::revoke_citizen_key,key);
            source.apply(revoke,now);
            auto r=makeTrustSyncRequest(client);
            auto response=roundtrip(source,r,now);
            check(acceptTrustSync(client,r,response,now)==1,
                  "one signed revocation synced from peer");
            check(!client.citizenKeyActive(alice,now) && client.fresh(now),
                  "replicated revocation immediately denies local key");
            request=makeTrustSyncRequest(client);
            reply=roundtrip(source,request,now);
            previous=revoke;
        }
        {
            // Same authority signs DIFFERENT event at the same sequence:
            // both are validly signed; fail closed and preserve evidence.
            TrustDelta other=previous;
            other.issuedAt=now;
            other.validUntil=now+3600;
            signer.sign(other);
            check(trustDeltaHash(other)!=source.headHash(),"genuine alternative branch");
            auto conflict=reply;
            conflict.status=TrustSyncStatus::cursor_conflict;
            conflict.peerSequence=other.sequence;
            conflict.peerHead=trustDeltaHash(other);
            conflict.tipEvidence=encodeTrustDelta(other);
            rejects([&]{acceptTrustSync(client,request,conflict,now);},
                    "authority equivocation triggers quarantine");
            check(client.forked() && !client.fresh(now) &&
                  !client.citizenKeyActive(alice,now),
                  "forked verifier never authenticates");
            rejects([&]{client.applyHistoricalBatch({other},now);},
                    "forked verifier cannot replace its branch");
        }
        {
            // A source presented with a contradictory signed cursor also
            // quarantines. Replication propagates EVIDENCE, not a poison pool.
            ReplicatedTrust alternative(forkdb,registry,signer.pub);
            alternative.applyHistoricalBatch({source.historyAfter(0,TrustHash{},1)[0]},now);
            // Malicious unsigned hashes do not become fork proofs.
            auto falseReq=makeTrustSyncRequest(source);
            falseReq.cursorHash=value(9);
            falseReq.cursorEvidence.clear();
            auto res=answerTrustSync(alternative,falseReq,now);
            check(!alternative.forked() && res.status==TrustSyncStatus::peer_behind,
                  "unsigned remote cursor ignored");
            // An already quarantined peer gossips BOTH independently signed
            // conflicting events. Even a node on neither branch can check
            // them and permanently refuse trust without consulting authority.
            auto witnessRequest=makeTrustSyncRequest(alternative);
            auto forkReply=roundtrip(client,witnessRequest,now);
            check(forkReply.status==TrustSyncStatus::fork_quarantine &&
                  !forkReply.forkA.empty() && !forkReply.forkB.empty(),
                  "quarantined peer supplies pair of signed events");
            auto corrupted=forkReply;
            corrupted.forkB.back()^=1;
            rejects([&]{acceptTrustSync(alternative,witnessRequest,corrupted,now);},
                    "forged fork witness rejected");
            check(!alternative.forked(),"invalid gossip proof cannot poison third node");
            rejects([&]{acceptTrustSync(alternative,witnessRequest,forkReply,now);},
                    "real fork evidence propagated without accepting branch");
            check(alternative.forked() && !alternative.fresh(now),
                  "third node quarantines from two authentic signatures");
        }
    }
    {
        ReplicatedTrust after(dst,registry,signer.pub);
        check(after.forked() && !after.fresh(now),"signed fork quarantine durable on restart");
        check(after.sequence()==172,"quarantine never rewrites trusted head");
        TrustDelta first,second;
        check(after.forkProof(first,second) && first.sequence==second.sequence &&
              trustDeltaHash(first)!=trustDeltaHash(second),
              "signed fork evidence persists for further peer gossip");
    }
    {
        ReplicatedTrust after(forkdb,registry,signer.pub);
        check(after.forked(),"gossip fork quarantine survives restart");
    }
    // Decode framing edge cases without relying on a live SSH daemon.
    {
        std::stringstream bad(std::ios::in|std::ios::out|std::ios::binary);
        bad<<"MAATS8Q"; TrustSyncRequest req;
        rejects([&]{readTrustSyncRequest(bad,req);},"truncated request rejected");
        std::stringstream absent(std::ios::in|std::ios::out|std::ios::binary);
        check(!readTrustSyncRequest(absent,req),"clean EOF terminates SSH channel");
    }
    for(const auto& db:{src,dst,forkdb,path(dir,"resumable"),path(dir,"fork-tip")}){
        std::remove(db.c_str());std::remove((db+"-wal").c_str());
        std::remove((db+"-shm").c_str());
    }
    rmdir(dir.c_str());
    std::puts("PASS authenticated P2P cursor, bounded replay, expired history, "
              "atomic poison rejection, local indexed pool, durable signed-fork quarantine");
}
