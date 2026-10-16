//! Alpha6 research issuer: blind BBS with *bound* prover contribution.
//!
//! Issuer checks that the hidden nym contribution is the one pinned at first
//! enrolment, without ever receiving that scalar. The binding anchor is
//! globally linkable and MUST remain exclusively inside the private issuer.
//! The service sees ONLY BBS pseudonyms and proofs from the presentation gate.
//! This code implements a Schnorr proof over BBS's exact blind generators;
//! it is a research protocol extension requiring external review.
use affinidi_bbs::{
    Ciphersuite, Scalar, blind_sign_with_nym, keygen, nym_commit, sk_to_pk,
};
#[cfg(test)]
use affinidi_bbs::{PublicKey, Signature};
use affinidi_bbs::generators::{
    create_generators_with_api_id, point_from_bytes, point_to_bytes,
};
use affinidi_bbs::hash::{hash_to_scalar, scalar_from_bytes, scalar_to_bytes};
use std::io::Read;

const HEADER: &[u8] = b"MAAT-BBS-NYM-ISSUANCE-V1";
const ACTIVE: &[u8] = b"MAAT-CITIZEN-ACTIVE-V1";
const BIND_DST: &[u8] = b"MAAT-BBS-BINDING-SCHNORR-V1-H2S";
const ENTROPY_DST: &[u8] = b"MAAT-BBS-CITIZEN-ENTROPY-V1-H2S";
const BIND_DOMAIN: &[u8] = b"MAAT-BBS-BINDING-V1\0";
const CS: Ciphersuite = Ciphersuite::Bls12381Sha256;

fn bases() -> Option<Vec<bls12_381_plus::G1Projective>> {
    let mut id = b"BLIND_".to_vec();
    id.extend_from_slice(&CS.pseudonym_api_id());
    create_generators_with_api_id(2, &id, CS).ok()
}

fn decode_point(b: &[u8;48]) -> Option<bls12_381_plus::G1Projective> {
    let p = point_from_bytes(b)?;
    if bool::from(p.is_identity()) { None } else { Some(p) }
}

fn binding_challenge(
    anchor: &[u8;48], commitment: &[u8;144], t: &[u8;48],
    registry: &[u8;32], citizen_key: &[u8;32], nonce: &[u8;32],
) -> Option<Scalar> {
    let mut transcript = Vec::with_capacity(20+48+144+48+96);
    transcript.extend_from_slice(BIND_DOMAIN);
    transcript.extend_from_slice(registry);
    transcript.extend_from_slice(citizen_key);
    transcript.extend_from_slice(nonce);
    transcript.extend_from_slice(anchor);
    transcript.extend_from_slice(commitment);
    transcript.extend_from_slice(t);
    hash_to_scalar(&transcript, BIND_DST, CS).ok()
}

pub fn holder_commit(prover: Scalar) -> Option<([u8;144], Scalar)> {
    if prover == Scalar::ZERO { return None; }
    let (c, blind) = nym_commit(prover, &[], CS).ok()?;
    let arr: [u8;144] = c.try_into().ok()?;
    Some((arr, blind))
}

/// The holder proves knowledge of the blinding scalar r such that
/// C - anchor = Q_2*r. The issuer also validates BBS's original nym_commit
/// PoK before issuing. This binds its hidden nym to the pinned anchor.
/// Domain separated and bound to the *server-issued* challenge and citizen key.
pub fn holder_binding(
    prover: Scalar, blind: Scalar, commitment: &[u8;144],
    registry: &[u8;32], citizen_key: &[u8;32], nonce: &[u8;32],
) -> Option<([u8;48], [u8;80])> {
    let g = bases()?;
    let anchor = point_to_bytes(&(&g[1] * prover));
    let c_bytes: [u8;48] = commitment[0..48].try_into().ok()?;
    let c = decode_point(&c_bytes)?;
    if c != &g[0]*blind + &g[1]*prover { return None; }
    // Linux OS entropy; no deterministic witness nonce, even for repeated proofs.
    let mut random = [0u8; 48];
    std::fs::File::open("/dev/urandom").ok()?.read_exact(&mut random).ok()?;
    let witness = hash_to_scalar(&random, b"MAAT-BBS-BIND-WITNESS-V1-H2S", CS).ok()?;
    if witness == Scalar::ZERO { return None; }
    let t = point_to_bytes(&(&g[0]*witness));
    let cp = binding_challenge(&anchor, commitment, &t, registry, citizen_key, nonce)?;
    let response = scalar_to_bytes(&(witness + cp * blind));
    let mut proof = [0u8;80];
    proof[..48].copy_from_slice(&t);
    proof[48..].copy_from_slice(&response);
    Some((anchor, proof))
}

pub fn check_binding(
    anchor: &[u8;48], commitment: &[u8;144], proof: &[u8;80],
    registry: &[u8;32], citizen_key: &[u8;32], nonce: &[u8;32],
) -> bool {
    let Some(g) = bases() else { return false; };
    let Some(a) = decode_point(anchor) else { return false; };
    let Ok(c_bytes): Result<[u8;48],_> = commitment[..48].try_into() else {return false};
    let Some(c) = decode_point(&c_bytes) else {return false};
    let Ok(t_bytes): Result<[u8;48],_> = proof[..48].try_into() else {return false};
    let Some(t) = decode_point(&t_bytes) else {return false};
    let Ok(z_bytes): Result<[u8;32],_> = proof[48..].try_into() else {return false};
    let Some(z) = scalar_from_bytes(&z_bytes) else {return false};
    let Some(challenge) = binding_challenge(anchor, commitment, &t_bytes, registry, citizen_key, nonce) else {return false};
    &g[0]*z == t + (c-a)*challenge
}

/// `entropy_material` is a 64-byte HMAC-SHA512, keyed by the private issuer
/// master secret over the registry namespace and *private* citizen ID.
/// Using the same pinned secret and citizen ID reproduces exactly the same
/// contribution across certificate and SSH-key rotations.
pub fn citizen_entropy(entropy_material: &[u8;64]) -> Option<Scalar> {
    let e = hash_to_scalar(entropy_material, ENTROPY_DST, CS).ok()?;
    if e == Scalar::ZERO { None } else { Some(e) }
}

pub fn issuer_public_key(key_material: &[u8;32]) -> Option<[u8;96]> {
    let sk = keygen(key_material, b"MAAT-BBS-ISSUER-V1").ok()?;
    Some(sk_to_pk(&sk).to_bytes())
}

pub fn sign_bound(
    key_material: &[u8;32], entropy_material: &[u8;64],
    anchor: &[u8;48], commitment: &[u8;144], binding: &[u8;80],
    registry: &[u8;32], citizen_key: &[u8;32], nonce: &[u8;32],
) -> Option<[u8;80]> {
    if !check_binding(anchor,commitment,binding,registry,citizen_key,nonce) { return None; }
    let sk = keygen(key_material, b"MAAT-BBS-ISSUER-V1").ok()?;
    let pk = sk_to_pk(&sk);
    let entropy = citizen_entropy(entropy_material)?;
    let sig = blind_sign_with_nym(&sk,&pk,commitment,entropy,HEADER,&[ACTIVE],CS).ok()?;
    Some(sig.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_bbs::{blind_verify_with_nym,proof_gen_with_nym,proof_verify_with_nym};

    fn run() -> (Scalar, Scalar, [u8;96], [u8;48]) {
        let sk_material = [70u8;32];
        let reg = [1u8;32]; let citizen=[2u8;32]; let nonce=[3u8;32];
        let prover = Scalar::from(42u64);
        let entropy_material = [17u8;64];
        let entropy = citizen_entropy(&entropy_material).unwrap();
        let pk = issuer_public_key(&sk_material).unwrap();
        let mut known_nym = None;
        for i in 0..3 {
            let (commitment,blind) = holder_commit(prover).unwrap();
            let (anchor,binding)=holder_binding(prover,blind,&commitment,&reg,&citizen,&nonce).unwrap();
            assert!(check_binding(&anchor,&commitment,&binding,&reg,&citizen,&nonce));
            let signature = sign_bound(&sk_material,&entropy_material,&anchor,&commitment,&binding,
                                       &reg,&citizen,&nonce).unwrap();
            let public_key=PublicKey::from_bytes(&pk).unwrap();
            let signature=Signature::from_bytes(&signature).unwrap();
            assert!(blind_verify_with_nym(&public_key,&signature,HEADER,&[ACTIVE],&[],
                                           prover,entropy,blind,CS).unwrap());
            let ctx=b"MAAT:BBS-NYM:SERVICE:example.com";
            let (proof,nym)=proof_gen_with_nym(&public_key,&signature,HEADER,b"nonce123",prover+entropy,
                ctx,&[ACTIVE],&[0],&[],&[],blind,CS).unwrap();
            assert!(proof_verify_with_nym(&public_key,&proof,HEADER,b"nonce123",&nym,
                ctx,1,&[ACTIVE],&[0],&[],&[],CS).unwrap());
            if let Some(prior) = known_nym {assert_eq!(nym.to_bytes(),prior);}
            known_nym=Some(nym.to_bytes());
            if i==0 {
                let (bad_commitment,bad_blind)=holder_commit(Scalar::from(43u64)).unwrap();
                let (bad_anchor,bad_proof)=holder_binding(Scalar::from(43u64),bad_blind,&bad_commitment,
                                                        &reg,&citizen,&nonce).unwrap();
                assert_ne!(anchor,bad_anchor);
                assert!(!check_binding(&anchor,&bad_commitment,&bad_proof,&reg,&citizen,&nonce));
                assert!(sign_bound(&sk_material,&entropy_material,&anchor,&bad_commitment,&bad_proof,
                                   &reg,&citizen,&nonce).is_none());
                assert!(!check_binding(&anchor,&commitment,&binding,&reg,&citizen,&[4u8;32]));
                let mut tampered=binding;tampered[79]^=1;
                assert!(!check_binding(&anchor,&commitment,&tampered,&reg,&citizen,&nonce));
            }
        }
        (prover, entropy, pk, known_nym.unwrap())
    }
    #[test] fn pinned_issuer_and_holder_survive_reissuance() { run(); }
    #[test] fn different_service_yields_different_pseudonym() {
        let (_,_,_,_) = run();
        let cs=CS;let prover=Scalar::from(99u64);let ent=citizen_entropy(&[11u8;64]).unwrap();
        let (commitment,blind)=holder_commit(prover).unwrap();
        let (anchor,binding)=holder_binding(prover,blind,&commitment,&[1u8;32],&[2u8;32],&[3u8;32]).unwrap();
        let key=[71u8;32];
        let sig=sign_bound(&key,&[11u8;64],&anchor,&commitment,&binding,&[1u8;32],&[2u8;32],&[3u8;32]).unwrap();
        let pk=PublicKey::from_bytes(&issuer_public_key(&key).unwrap()).unwrap();
        let sig=Signature::from_bytes(&sig).unwrap();
        let (_,a)=proof_gen_with_nym(&pk,&sig,HEADER,b"chal",prover+ent,b"service-a",
            &[ACTIVE],&[0],&[],&[],blind,cs).unwrap();
        let (_,b)=proof_gen_with_nym(&pk,&sig,HEADER,b"chal",prover+ent,b"service-b",
            &[ACTIVE],&[0],&[],&[],blind,cs).unwrap();
        assert_ne!(a.to_bytes(),b.to_bytes());
    }
}
