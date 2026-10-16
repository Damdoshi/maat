//! Narrow C ABI for verification only. No key issuance and no SSH integration.
//! Does not decide civic identity or revocation; caller must enforce its policy.
use affinidi_bbs::{Ciphersuite, Proof, PublicKey, Pseudonym, proof_verify_with_nym};
use std::os::raw::c_int;

const MAX_PROOF: usize = 64 * 1024;
const MAX_CONTEXT: usize = 1024;
const MAX_PH: usize = 4096;
const ISSUER_HEADER: &[u8] = b"MAAT-BBS-NYM-ISSUANCE-V1";
const ACTIVE_MESSAGE: &[u8] = b"MAAT-CITIZEN-ACTIVE-V1";

/// Returns 1 on a valid BBS nym proof; 0 for every other outcome.
///
/// `context` and `presentation_header` MUST be supplied by the verifier,
/// never accepted from the prover. `public_key` must be pinned by policy.
/// Exactly one public signed message (ACTIVE_MESSAGE) is disclosed; no
/// holder-committed messages are disclosed. The holder nym is hidden.
#[no_mangle]
pub unsafe extern "C" fn maat_bbs_nym_verify_v1(
    public_key: *const u8,
    public_key_len: usize,
    proof: *const u8,
    proof_len: usize,
    pseudonym: *const u8,
    pseudonym_len: usize,
    context: *const u8,
    context_len: usize,
    presentation_header: *const u8,
    presentation_header_len: usize,
) -> c_int {
    if public_key.is_null() || proof.is_null() || pseudonym.is_null() ||
       context.is_null() || presentation_header.is_null() ||
       public_key_len != 96 || pseudonym_len != 48 ||
       proof_len < 272 || proof_len > MAX_PROOF || (proof_len - 272) % 32 != 0 ||
       context_len == 0 || context_len > MAX_CONTEXT ||
       presentation_header_len == 0 || presentation_header_len > MAX_PH {
        return 0;
    }
    let result = std::panic::catch_unwind(|| {
        // SAFETY: FFI callers promise valid readable buffers for lengths.
        // Pointer ownership/lifetime is never retained by the verifier.
        let pk_bytes: &[u8] = unsafe { std::slice::from_raw_parts(public_key, public_key_len) };
        let nym_bytes: &[u8] = unsafe { std::slice::from_raw_parts(pseudonym, pseudonym_len) };
        let proof_bytes: &[u8] = unsafe { std::slice::from_raw_parts(proof, proof_len) };
        let ctx: &[u8] = unsafe { std::slice::from_raw_parts(context, context_len) };
        let ph: &[u8] = unsafe { std::slice::from_raw_parts(presentation_header, presentation_header_len) };
        let Ok(pk_arr): Result<&[u8; 96], _> = pk_bytes.try_into() else { return false };
        let Ok(nym_arr): Result<&[u8; 48], _> = nym_bytes.try_into() else { return false };
        let Ok(pk) = PublicKey::from_bytes(pk_arr) else { return false };
        let Ok(nym) = Pseudonym::from_bytes(nym_arr) else { return false };
        let proof = Proof::from_bytes(proof_bytes);
        proof_verify_with_nym(
            &pk, &proof, ISSUER_HEADER, ph, &nym, ctx,
            1, &[ACTIVE_MESSAGE], &[0], &[], &[], Ciphersuite::Bls12381Sha256,
        ).unwrap_or(false)
    });
    if result.unwrap_or(false) { 1 } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_bbs::{Scalar, keygen, sk_to_pk, nym_commit,
                       blind_sign_with_nym, proof_gen_with_nym};

    fn demo(context: &[u8], challenge: &[u8], prover: Scalar, issuer: Scalar)
       -> ([u8; 96], Vec<u8>, [u8; 48]) {
        let cs = Ciphersuite::Bls12381Sha256;
        let sk = keygen(b"MAAT-TEST-KEY-MATERIAL-NOT-FOR-USE-00001", b"").unwrap();
        let pk = sk_to_pk(&sk);
        let (commitment, blinding) = nym_commit(prover, &[], cs).unwrap();
        let sig = blind_sign_with_nym(&sk, &pk, &commitment, issuer,
                                     ISSUER_HEADER, &[ACTIVE_MESSAGE], cs).unwrap();
        let (proof, nym) = proof_gen_with_nym(
            &pk, &sig, ISSUER_HEADER, challenge, prover + issuer,
            context, &[ACTIVE_MESSAGE], &[0], &[], &[], blinding, cs).unwrap();
        (pk.to_bytes(), proof.to_bytes().to_vec(), nym.to_bytes())
    }

    fn check(pk: &[u8;96], proof: &[u8], nym: &[u8;48], ctx: &[u8], ph: &[u8]) -> bool {
        unsafe { maat_bbs_nym_verify_v1(pk.as_ptr(), pk.len(),
            proof.as_ptr(), proof.len(), nym.as_ptr(), nym.len(),
            ctx.as_ptr(), ctx.len(), ph.as_ptr(), ph.len()) == 1 }
    }

    #[test]
    fn bbs_valid_and_invalid_presentations() {
        let context = b"MAAT:BBS-NYM:SERVICE:forum.example";
        let ph = b"MAAT:BBS-PRESENTATION-V1:server-owned-challenge-00000001";
        let (pk, proof, nym) = demo(context, ph, Scalar::from(42u64), Scalar::from(9u64));
        assert!(check(&pk, &proof, &nym, context, ph));
        assert!(!check(&pk, &proof, &nym, context, b"other-challenge"));
        assert!(!check(&pk, &proof, &nym, b"other-service", ph));
        let mut changed = proof.clone(); changed[0] ^= 1;
        assert!(!check(&pk, &changed, &nym, context, ph));
        assert!(!check(&pk, &[], &nym, context, ph));
    }

    #[test]
    fn pseudonym_scope_and_renewal() {
        let base = Scalar::from(42u64);
        let entropy = Scalar::from(9u64);
        let a = demo(b"scope-a", b"nonce-a", base, entropy);
        let b = demo(b"scope-a", b"nonce-b", base, entropy);
        let c = demo(b"scope-b", b"nonce-c", base, entropy);
        assert_eq!(a.2, b.2); // Reissued with the SAME secrets.
        assert_ne!(a.2, c.2);
        let switched_prover = demo(b"scope-a", b"nonce-d", Scalar::from(43u64), entropy);
        let switched_issuer = demo(b"scope-a", b"nonce-e", base, Scalar::from(10u64));
        assert_ne!(a.2, switched_prover.2); // CRITICAL: issuance policy must prevent this.
        assert_ne!(a.2, switched_issuer.2);
    }
}

// Alpha6: private registry-bound blind issuer, NOT a web/SSH authentication API.
// Fixed-size ABI; no strings or remote-supplied pointers retained.
pub mod bound_issue;

#[no_mangle]
pub unsafe extern "C" fn maat_bbs_issuer_public_key_v1(
    seed: *const u8, out_pk: *mut u8,
) -> c_int {
    if seed.is_null() || out_pk.is_null() {return 0;}
    let result=std::panic::catch_unwind(|| {
        let material: [u8;32]=unsafe{std::slice::from_raw_parts(seed,32)}.try_into().ok()?;
        let pk=bound_issue::issuer_public_key(&material)?;
        unsafe {std::ptr::copy_nonoverlapping(pk.as_ptr(),out_pk,96)};
        Some(1)
    });
    result.ok().flatten().unwrap_or(0)
}

#[no_mangle]
pub unsafe extern "C" fn maat_bbs_holder_commit_v1(
    scalar: *const u8, commitment_out: *mut u8, blind_out: *mut u8,
) -> c_int {
    if scalar.is_null() || commitment_out.is_null() || blind_out.is_null(){return 0;}
    let result=std::panic::catch_unwind(|| {
        let bs: [u8;32] = unsafe{std::slice::from_raw_parts(scalar,32)}.try_into().ok()?;
        let prover=affinidi_bbs::hash::scalar_from_bytes(&bs)?;
        let (commit,blind)=bound_issue::holder_commit(prover)?;
        unsafe {
            std::ptr::copy_nonoverlapping(commit.as_ptr(),commitment_out,144);
            std::ptr::copy_nonoverlapping(affinidi_bbs::hash::scalar_to_bytes(&blind).as_ptr(),blind_out,32);
        }
        Some(1)
    });
    result.ok().flatten().unwrap_or(0)
}

#[no_mangle]
pub unsafe extern "C" fn maat_bbs_holder_binding_v1(
    scalar: *const u8, blind: *const u8, commitment: *const u8,
    registry: *const u8, citizen_key: *const u8, nonce: *const u8,
    anchor_out: *mut u8, proof_out: *mut u8,
) -> c_int {
    if scalar.is_null() || blind.is_null() || commitment.is_null() || registry.is_null() ||
       citizen_key.is_null() || nonce.is_null() || anchor_out.is_null() || proof_out.is_null() {return 0;}
    let result=std::panic::catch_unwind(|| {
        let sk: [u8;32]=unsafe{std::slice::from_raw_parts(scalar,32)}.try_into().ok()?;
        let sb: [u8;32]=unsafe{std::slice::from_raw_parts(blind,32)}.try_into().ok()?;
        let prover=affinidi_bbs::hash::scalar_from_bytes(&sk)?;
        let blinder=affinidi_bbs::hash::scalar_from_bytes(&sb)?;
        let c: [u8;144]=unsafe{std::slice::from_raw_parts(commitment,144)}.try_into().ok()?;
        let r: [u8;32]=unsafe{std::slice::from_raw_parts(registry,32)}.try_into().ok()?;
        let u: [u8;32]=unsafe{std::slice::from_raw_parts(citizen_key,32)}.try_into().ok()?;
        let n: [u8;32]=unsafe{std::slice::from_raw_parts(nonce,32)}.try_into().ok()?;
        let (anchor, proof)=bound_issue::holder_binding(prover,blinder,&c,&r,&u,&n)?;
        unsafe {
            std::ptr::copy_nonoverlapping(anchor.as_ptr(),anchor_out,48);
            std::ptr::copy_nonoverlapping(proof.as_ptr(),proof_out,80);
        }
        Some(1)
    });
    result.ok().flatten().unwrap_or(0)
}

#[no_mangle]
pub unsafe extern "C" fn maat_bbs_bound_sign_v1(
    seed: *const u8, entropy_material: *const u8, anchor: *const u8,
    commitment: *const u8, proof: *const u8, registry: *const u8,
    citizen_key: *const u8, nonce: *const u8, signature_out: *mut u8,
) -> c_int {
    if seed.is_null() || entropy_material.is_null() || anchor.is_null() ||
       commitment.is_null() || proof.is_null() || registry.is_null() ||
       citizen_key.is_null() || nonce.is_null() || signature_out.is_null() {return 0;}
    let result=std::panic::catch_unwind(|| {
        let s: [u8;32]=unsafe{std::slice::from_raw_parts(seed,32)}.try_into().ok()?;
        let e: [u8;64]=unsafe{std::slice::from_raw_parts(entropy_material,64)}.try_into().ok()?;
        let a: [u8;48]=unsafe{std::slice::from_raw_parts(anchor,48)}.try_into().ok()?;
        let c: [u8;144]=unsafe{std::slice::from_raw_parts(commitment,144)}.try_into().ok()?;
        let p: [u8;80]=unsafe{std::slice::from_raw_parts(proof,80)}.try_into().ok()?;
        let r: [u8;32]=unsafe{std::slice::from_raw_parts(registry,32)}.try_into().ok()?;
        let u: [u8;32]=unsafe{std::slice::from_raw_parts(citizen_key,32)}.try_into().ok()?;
        let n: [u8;32]=unsafe{std::slice::from_raw_parts(nonce,32)}.try_into().ok()?;
        let sig=bound_issue::sign_bound(&s,&e,&a,&c,&p,&r,&u,&n)?;
        unsafe {std::ptr::copy_nonoverlapping(sig.as_ptr(),signature_out,80)};
        Some(1)
    });
    result.ok().flatten().unwrap_or(0)
}
