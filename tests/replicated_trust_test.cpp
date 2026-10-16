#include "identity/replicated_trust.hpp"

#include <openssl/evp.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

using namespace maat::identity;
namespace {
void check(bool value,const char* text) {
    if (!value) {std::fprintf(stderr,"FAIL public replica: %s\n",text);std::exit(1);}
}
template<typename F> void rejects(F work,const char* why) {
    try{work();}catch(const std::exception&){return;}check(false,why);
}
TrustHash value(unsigned seed) {
    TrustHash out{};
    for (unsigned i=0;i<32;++i) out[i]=static_cast<std::uint8_t>((i*5+seed)%255+1);
    out[0]=static_cast<std::uint8_t>(seed);
    out[1]=static_cast<std::uint8_t>(seed>>8);
    out[2]=static_cast<std::uint8_t>(seed>>16);
    out[3]=static_cast<std::uint8_t>(seed>>24);
    return out;
}
BbsIssuerKey issuer(unsigned seed) {
    BbsIssuerKey out{};
    for (unsigned i=0;i<96;++i) out[i]=static_cast<std::uint8_t>((i*7+seed)%255+1);
    return out;
}
struct Signer {
    EVP_PKEY* privateKey=nullptr;
    TrustHash pub{};
    explicit Signer(unsigned seed) {
        auto secret=value(seed);
        privateKey=EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519,nullptr,
                                                secret.data(),secret.size());
        check(privateKey!=nullptr,"test Ed25519 secret");
        std::size_t n=pub.size();
        check(EVP_PKEY_get_raw_public_key(privateKey,pub.data(),&n)==1 && n==32,
              "test Ed25519 public");
    }
    ~Signer(){EVP_PKEY_free(privateKey);}
    void sign(TrustDelta& delta) const {
        auto bytes=trustDeltaSigningBytes(delta);
        auto* ctx=EVP_MD_CTX_new();
        check(ctx!=nullptr,"signing context");
        std::size_t len=delta.signature.size();
        const bool ok=EVP_DigestSignInit(ctx,nullptr,nullptr,nullptr,privateKey)==1 &&
            EVP_DigestSign(ctx,delta.signature.data(),&len,bytes.data(),bytes.size())==1 &&
            len==delta.signature.size();
        EVP_MD_CTX_free(ctx);
        check(ok,"test signed event");
    }
};
TrustDelta next(ReplicatedTrust& store,const Signer& signer,const TrustHash& registry,
                TrustOperation op,const std::vector<std::uint8_t>& key,
                std::int64_t now) {
    TrustDelta d;
    d.registryId=registry;
    d.sequence=store.sequence()+1;
    d.previousHash=store.headHash();
    d.issuedAt=now-2;
    d.validUntil=now+3600;
    d.operation=op;
    d.publicKey=key;
    signer.sign(d);
    return d;
}
template<std::size_t N> std::vector<std::uint8_t> vect(const std::array<std::uint8_t,N>& arr) {
    return {arr.begin(),arr.end()};
}
}
int main() {
    constexpr std::int64_t now=1792166400;
    const TrustHash registry=value(1);
    Signer signer(21), evil(22);
    char temp[]="/tmp/maat-public-trust-XXXXXX";
    check(mkdtemp(temp)!=nullptr,"temporary test directory");
    const std::string db=std::string(temp)+"/state.sqlite";
    const auto alice=value(31),bob=value(32);
    const auto bbs=issuer(45),bbs2=issuer(46);
    {
        ReplicatedTrust store(db,registry,signer.pub);
        check(!store.fresh(now),"no signed heartbeat -> fail closed");
        check(!store.citizenKeyActive(alice,now),"unknown citizen denied");
        check(!store.bbsIssuerActive(bbs,now),"unknown BBS issuer denied");
        auto init=next(store,signer,registry,TrustOperation::heartbeat,{},now);
        auto encoded=encodeTrustDelta(init);
        check(decodeTrustDelta(encoded).signature==init.signature,"wire roundtrip");
        auto corrupt=encoded; corrupt[corrupt.size()-1]^=1;
        rejects([&]{store.applyEncoded(corrupt,now);},"bad signature rejects");
        corrupt=encoded;corrupt.push_back(0);
        rejects([&]{store.applyEncoded(corrupt,now);},"wire trailing bytes reject");
        corrupt=encoded;corrupt[0]^=1;
        rejects([&]{store.applyEncoded(corrupt,now);},"wrong wire version reject");
        auto wrong=init;wrong.registryId=value(3);signer.sign(wrong);
        rejects([&]{store.apply(wrong,now);},"other registry rejects");
        evil.sign(init);
        rejects([&]{store.apply(init,now);},"wrong signer rejects");
        init=decodeTrustDelta(encoded);
        store.applyEncoded(encoded,now);
        check(store.sequence()==1 && store.fresh(now),"initial signed heartbeat accepted");
        rejects([&]{store.apply(init,now);},"replay rejects");
        rejects([&]{store.apply(init,now+4000);},"expired replay rejects");
        auto key=next(store,signer,registry,TrustOperation::add_citizen_key,vect(alice),now);
        auto gap=key;gap.sequence+=1;signer.sign(gap);
        rejects([&]{store.apply(gap,now);},"missing delta forbidden");
        check(!store.fresh(now),"signed missing-sequence hint quarantines stale replica");
        auto fork=key;fork.previousHash=value(4);signer.sign(fork);
        rejects([&]{store.apply(fork,now);},"fork denied");
        auto future=key;future.issuedAt=now+301;future.validUntil=now+3601;signer.sign(future);
        rejects([&]{store.apply(future,now);},"far future rejected");
        auto tooLong=key;tooLong.validUntil=now+90000;
        rejects([&]{signer.sign(tooLong);store.apply(tooLong,now);},"excessive freshness window denied");
        auto badKey=key;badKey.publicKey.resize(31);
        rejects([&]{store.apply(badKey,now);},"short citizen key denied");
        store.apply(key,now);
        check(!store.citizenKeyActive(alice,now),"gap quarantine persists until missing events arrive");
        check(!store.citizenKeyActive(alice,now+3600),"stale replica fails closed");
        auto addIssuer=next(store,signer,registry,TrustOperation::add_bbs_issuer,vect(bbs),now);
        store.apply(addIssuer,now);
        check(store.bbsIssuerActive(bbs,now),"BBS issuer activated locally");
        check(store.citizenKeyActive(alice,now),"gap quarantine clears at observed sequence");
        check(!store.bbsIssuerActive(bbs2,now),"untrusted issuer denied");
        auto revoked=next(store,signer,registry,TrustOperation::revoke_citizen_key,vect(alice),now);
        store.apply(revoked,now);
        check(!store.citizenKeyActive(alice,now),"citizen key revoked locally");
        auto resurrect=next(store,signer,registry,TrustOperation::add_citizen_key,vect(alice),now);
        rejects([&]{store.apply(resurrect,now);},"revoked public key permanently tombstoned");
        check(store.sequence()==4,"failed update atomic no sequence advance");
        auto revokeIssuer=next(store,signer,registry,TrustOperation::revoke_bbs_issuer,vect(bbs),now);
        store.apply(revokeIssuer,now);
        check(!store.bbsIssuerActive(bbs,now),"BBS issuer revocation enforced");
        // A revocation of a key not seen yet creates a tombstone; re-add denied.
        auto unknownRevoke=next(store,signer,registry,TrustOperation::revoke_citizen_key,vect(bob),now);
        store.apply(unknownRevoke,now);
        auto disallowedAdd=next(store,signer,registry,TrustOperation::add_citizen_key,vect(bob),now);
        rejects([&]{store.apply(disallowedAdd,now);},"revoked unknown key cannot resurrect");
        auto heartbeat=next(store,signer,registry,TrustOperation::heartbeat,{},now+1800);
        store.apply(heartbeat,now+1800);
        check(store.fresh(now+3700),"signed heartbeat renews offline trust freshness");
        check(!store.fresh(now+5400),"heartbeat validity eventually expires");
        check(!store.citizenKeyActive(alice,now+3700),"heartbeat cannot restore revoked key");
        auto lastSeq=store.sequence();
        for (unsigned i=0;i<256;++i) {
            auto person=value(75+i);
            auto d=next(store,signer,registry,TrustOperation::add_citizen_key,vect(person),now+1800);
            store.apply(d,now+1800);
            check(store.citizenKeyActive(person,now+1800),"indexed local key lookup");
        }
        check(store.sequence()==lastSeq+256,"incremental pool accepts 256 signed keys");
    }
    {
        ReplicatedTrust restored(db,registry,signer.pub);
        check(restored.sequence()==263,"signed head persists across restart");
        check(restored.citizenKeyActive(value(75),now+1800),"pool survives restart");
        check(!restored.citizenKeyActive(alice,now+1800),"revocation survives restart");
        check(!restored.bbsIssuerActive(bbs,now+1800),"revoked BBS issuer survives restart");
        rejects([&]{ReplicatedTrust wrong(db,registry,evil.pub);},"authority pin survives restart");
        rejects([&]{ReplicatedTrust wrong(db,value(5),signer.pub);},"registry pin survives restart");
    }
    std::remove(db.c_str());
    std::remove((db+"-wal").c_str());
    std::remove((db+"-shm").c_str());
    rmdir(temp);
    std::puts("PASS signed hash-chained gossip, strict wire format, offline indexed pool, "
              "authority/root pin, monotone replay, tamper/fork/staleness rejection, "
              "revoke/tombstone and persistent restart");
}
