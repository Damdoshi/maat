#include "identity/trust_sync.hpp"

#include <algorithm>
#include <array>
#include <climits>
#include <cstring>
#include <istream>
#include <ostream>
#include <stdexcept>

namespace maat { namespace identity {
namespace {
constexpr std::array<char,8> requestMagic={'M','A','A','T','S','8','Q','\0'};
constexpr std::array<char,8> responseMagic={'M','A','A','T','S','8','R','\0'};
void require(bool ok,const char* msg){if(!ok)throw std::runtime_error(msg);}
void write(std::ostream& out,const void* p,std::size_t size) {
    out.write(static_cast<const char*>(p),static_cast<std::streamsize>(size));
    require(static_cast<bool>(out),"trust sync write failure");
}
void read(std::istream& in,void* p,std::size_t size) {
    in.read(static_cast<char*>(p),static_cast<std::streamsize>(size));
    require(static_cast<bool>(in),"truncated trust sync frame");
}
void put(std::ostream& out,std::uint64_t value,int n) {
    for(int i=n-1;i>=0;--i){const char c=static_cast<char>((value>>(i*8))&255);write(out,&c,1);}
}
std::uint64_t get(std::istream& in,int n) {
    std::uint64_t v=0;
    for(int i=0;i<n;++i){unsigned char c=0;read(in,&c,1);v=(v<<8)|c;}
    return v;
}
void bytes(std::ostream& out,const std::vector<std::uint8_t>& wire) {
    require(wire.size()<=512,"oversized trust sync event");
    put(out,wire.size(),2);
    if(!wire.empty())write(out,wire.data(),wire.size());
}
std::vector<std::uint8_t> bytes(std::istream& in) {
    const auto n=get(in,2);
    require(n<=512,"oversized trust sync event");
    std::vector<std::uint8_t> result(static_cast<std::size_t>(n));
    if(n)read(in,result.data(),result.size());
    return result;
}
void validateRequest(const TrustSyncRequest& req) {
    require(req.cursor<=INT64_MAX && req.maxEvents>0 &&
            req.maxEvents<=kTrustSyncMaxEvents,"invalid trust sync cursor/limit");
    if(req.cursor==0)
        require(req.cursorHash==TrustHash{} && req.cursorEvidence.empty(),
                "invalid genesis trust sync cursor");
    require(req.cursorEvidence.size()<=512,"oversized cursor evidence");
    if(!req.cursorEvidence.empty()) {
        const auto witness=decodeTrustDelta(req.cursorEvidence);
        require(witness.sequence==req.cursor && trustDeltaHash(witness)==req.cursorHash,
                "cursor evidence does not match cursor");
    }
}
void validateResponse(const TrustSyncResponse& res) {
    require(static_cast<unsigned>(res.status)<=static_cast<unsigned>(TrustSyncStatus::fork_quarantine),
            "invalid trust sync status");
    require(res.peerSequence<=INT64_MAX &&
            res.events.size()<=kTrustSyncMaxEvents && res.tipEvidence.size()<=512 &&
            res.forkA.size()<=512 && res.forkB.size()<=512,
            "oversized trust sync response");
    if(!res.tipEvidence.empty()) {
        const auto tip=decodeTrustDelta(res.tipEvidence);
        require(tip.sequence==res.peerSequence && trustDeltaHash(tip)==res.peerHead,
                "invalid trust sync signed tip binding");
    }
    if(res.status!=TrustSyncStatus::events)
        require(res.events.empty(),"non-event trust response has events");
    require(res.forkA.empty()==res.forkB.empty(),"incomplete signed fork evidence");
    require(res.status==TrustSyncStatus::fork_quarantine || res.forkA.empty(),
            "fork evidence in unrelated trust response");
    if(!res.forkA.empty()) {
        const auto a=decodeTrustDelta(res.forkA),b=decodeTrustDelta(res.forkB);
        require(a.sequence==b.sequence && a.registryId==b.registryId &&
                trustDeltaHash(a)!=trustDeltaHash(b),"invalid fork evidence shape");
    }
    for(const auto& wire:res.events){
        require(!wire.empty() && wire.size()<=512,"oversized trust event");
        (void)decodeTrustDelta(wire);
    }
}
}

TrustSyncRequest makeTrustSyncRequest(const ReplicatedTrust& local,std::uint16_t limit) {
    TrustSyncRequest req;
    req.registryId=local.registryId();
    req.cursor=local.sequence();
    req.cursorHash=local.headHash();
    req.maxEvents=limit;
    if(req.cursor) {
        TrustDelta last;
        if(local.historicalEvent(req.cursor,last))
            req.cursorEvidence=encodeTrustDelta(last);
    }
    validateRequest(req);
    return req;
}
static void attachForkProof(ReplicatedTrust& local,TrustSyncResponse& res) {
    TrustDelta a,b;
    if(local.forkProof(a,b)) {
        res.forkA=encodeTrustDelta(a);
        res.forkB=encodeTrustDelta(b);
    }
}
TrustSyncResponse answerTrustSync(ReplicatedTrust& local,const TrustSyncRequest& req,
                                  std::int64_t now) {
    validateRequest(req);
    TrustSyncResponse res;
    res.peerSequence=local.sequence();
    res.peerHead=local.headHash();
    TrustDelta tip;
    if(res.peerSequence && local.historicalEvent(res.peerSequence,tip))
        res.tipEvidence=encodeTrustDelta(tip);
    if(req.registryId!=local.registryId()) {
        res.status=TrustSyncStatus::wrong_registry;
        return res;
    }
    // A malicious *claim* of a different head is harmless. A conflicting
    // signed cursor witness, however, is permanent authority fork evidence.
    if(!req.cursorEvidence.empty()) {
        try {local.observeSignedPeerEvent(decodeTrustDelta(req.cursorEvidence),now);}
        catch(const std::exception&) {
            if(local.forked()) {
                res.status=TrustSyncStatus::fork_quarantine;
                attachForkProof(local,res);
            }
            else throw;
            return res;
        }
    }
    if(local.forked()) {
        res.status=TrustSyncStatus::fork_quarantine;
        attachForkProof(local,res);
        return res;
    }
    if(req.cursor>res.peerSequence) {res.status=TrustSyncStatus::peer_behind;return res;}
    try {
        const auto deltas=local.historyAfter(req.cursor,req.cursorHash,req.maxEvents);
        for(const auto& delta:deltas)res.events.push_back(encodeTrustDelta(delta));
    } catch(const std::exception&) {
        // No local branch is ever replaced on a cursor mismatch. Offer
        // signed evidence at exactly that sequence if retained in history.
        TrustDelta evidence;
        if(req.cursor && local.historicalEvent(req.cursor,evidence)) {
            res.status=TrustSyncStatus::cursor_conflict;
            res.tipEvidence=encodeTrustDelta(evidence);
            // Conflict evidence is at req.cursor, not at remote tip. In this
            // status, these two fields name the *witness* (not latest head).
            res.peerSequence=evidence.sequence;
            res.peerHead=trustDeltaHash(evidence);
        } else res.status=TrustSyncStatus::history_unavailable;
    }
    return res;
}

std::size_t acceptTrustSync(ReplicatedTrust& local,const TrustSyncRequest& req,
                            const TrustSyncResponse& res,std::int64_t now) {
    validateRequest(req);validateResponse(res);
    require(req.registryId==local.registryId(),"local sync registry changed");
    require(req.cursor==local.sequence() && req.cursorHash==local.headHash(),
            "local sync cursor changed (retry required)");
    if(res.status==TrustSyncStatus::wrong_registry)
        throw std::runtime_error("remote trust root mismatch");
    if(res.status==TrustSyncStatus::fork_quarantine) {
        // A self-reported fork is untrusted. Two genuine authority-signed
        // contradictory events, independently checked, are decisive.
        if(!res.forkA.empty())
            local.observeSignedForkPair(decodeTrustDelta(res.forkA),
                                        decodeTrustDelta(res.forkB),now);
        throw std::runtime_error("peer reports signed trust fork/quarantine");
    }
    if(res.status==TrustSyncStatus::cursor_conflict) {
        require(!res.tipEvidence.empty(),"unsigned conflict claim");
        auto evidence=decodeTrustDelta(res.tipEvidence);
        require(evidence.sequence==req.cursor,"wrong conflict sequence");
        local.observeSignedPeerEvent(evidence,now);
        throw std::runtime_error("unsigned or unprovable peer conflict");
    }
    if(res.status==TrustSyncStatus::history_unavailable)
        throw std::runtime_error("peer cannot supply authenticated history");
    if(res.status==TrustSyncStatus::peer_behind) {
        if(!res.tipEvidence.empty())
            local.observeSignedPeerEvent(decodeTrustDelta(res.tipEvidence),now);
        return 0;
    }
    require(res.events.size()<=req.maxEvents,"peer exceeded sync page limit");
    std::vector<TrustDelta> deltas;
    deltas.reserve(res.events.size());
    auto previous=req.cursorHash;
    auto expected=req.cursor+1;
    for(const auto& wire:res.events) {
        auto delta=decodeTrustDelta(wire);
        require(delta.registryId==req.registryId && delta.sequence==expected &&
                delta.previousHash==previous,"noncontiguous or foreign trust sync response");
        previous=trustDeltaHash(delta);
        ++expected;
        deltas.push_back(delta);
    }
    // A server snapshot MUST be backed by its authority-signed last event.
    // Peer sequence counters alone are never proof of additional history.
    require(!res.tipEvidence.empty() || (res.peerSequence==0 && deltas.empty()),
            "unsigned trust sync snapshot");
    if(!res.tipEvidence.empty()) {
        const auto tip=decodeTrustDelta(res.tipEvidence);
        // Verify before any mutation, including the case of an empty page.
        local.validateSignedPeerEvent(tip,now);
        require(tip.sequence>=req.cursor &&
                (deltas.empty() || tip.sequence>=deltas.back().sequence),
                "trust sync snapshot predates returned events");
        if(!deltas.empty() && tip.sequence==deltas.back().sequence &&
           trustDeltaHash(tip)!=trustDeltaHash(deltas.back())) {
            // Two *signed* events at the same sequence are real evidence,
            // not a peer's unverified allegation: persist quarantine.
            local.observeSignedForkPair(tip,deltas.back(),now);
            throw std::runtime_error("signed trust fork in sync response");
        }
        require(!deltas.empty() || tip.sequence<=req.cursor,
                "peer withheld events despite signed newer head");
    }
    if(!deltas.empty()) local.applyHistoricalBatch(deltas,now);
    // Only authentic signed evidence can trigger quarantine. A fabricated
    // peerSequence/peerHead is never an authorization or quarantine signal.
    if(!res.tipEvidence.empty())
        local.observeSignedPeerEvent(decodeTrustDelta(res.tipEvidence),now);
    return deltas.size();
}

void writeTrustSyncRequest(std::ostream& out,const TrustSyncRequest& req) {
    validateRequest(req);
    write(out,requestMagic.data(),requestMagic.size());
    write(out,req.registryId.data(),req.registryId.size());
    put(out,req.cursor,8);
    write(out,req.cursorHash.data(),req.cursorHash.size());
    put(out,req.maxEvents,2);
    bytes(out,req.cursorEvidence);
    out.flush(); require(static_cast<bool>(out),"trust sync request flush failure");
}
bool readTrustSyncRequest(std::istream& in,TrustSyncRequest& req) {
    std::array<char,8> magic{};
    in.read(magic.data(),magic.size());
    if(in.eof() && in.gcount()==0)return false;
    require(in.gcount()==static_cast<std::streamsize>(magic.size()) &&
            magic==requestMagic,"unknown/partial trust sync request");
    TrustSyncRequest next;
    read(in,next.registryId.data(),next.registryId.size());
    next.cursor=get(in,8);
    read(in,next.cursorHash.data(),next.cursorHash.size());
    next.maxEvents=static_cast<std::uint16_t>(get(in,2));
    next.cursorEvidence=bytes(in);
    validateRequest(next);
    req=next;
    return true;
}
void writeTrustSyncResponse(std::ostream& out,const TrustSyncResponse& res) {
    validateResponse(res);
    write(out,responseMagic.data(),responseMagic.size());
    put(out,static_cast<unsigned>(res.status),1);
    put(out,res.peerSequence,8);
    write(out,res.peerHead.data(),res.peerHead.size());
    bytes(out,res.tipEvidence);
    bytes(out,res.forkA);
    bytes(out,res.forkB);
    put(out,res.events.size(),2);
    for(const auto& item:res.events)bytes(out,item);
    out.flush();require(static_cast<bool>(out),"trust sync response flush failure");
}
TrustSyncResponse readTrustSyncResponse(std::istream& in) {
    std::array<char,8> magic{};
    read(in,magic.data(),magic.size());
    require(magic==responseMagic,"unknown trust sync response version");
    TrustSyncResponse res;
    res.status=static_cast<TrustSyncStatus>(get(in,1));
    res.peerSequence=get(in,8);
    read(in,res.peerHead.data(),res.peerHead.size());
    res.tipEvidence=bytes(in);
    res.forkA=bytes(in);
    res.forkB=bytes(in);
    const auto count=get(in,2);
    require(count<=kTrustSyncMaxEvents,"oversized trust sync event count");
    for(std::size_t i=0;i<count;++i)res.events.push_back(bytes(in));
    validateResponse(res);
    return res;
}

}} // namespace maat::identity
