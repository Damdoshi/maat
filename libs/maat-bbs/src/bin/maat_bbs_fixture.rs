//! TEST ONLY: deterministic BBS issuer and proof generator for C++ ABI tests.
//! This binary MUST NOT be distributed as a Maât credential issuer.
//! The key below is public test material, never suitable for production.
use affinidi_bbs::{
    Ciphersuite, Scalar, blind_sign_with_nym, keygen, nym_commit,
    proof_gen_with_nym, sk_to_pk,
};
use std::env;

const TEST_KEY: &[u8] = b"MAAT-TEST-KEY-MATERIAL-NOT-FOR-USE-00001";
const HEADER: &[u8] = b"MAAT-BBS-NYM-ISSUANCE-V1";
const ACTIVE: &[u8] = b"MAAT-CITIZEN-ACTIVE-V1";

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 { return Err("odd hex length".into()); }
    let digit = |b: u8| -> Result<u8, String> {
        match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            _ => Err("invalid hex".into()),
        }
    };
    s.as_bytes().chunks_exact(2).map(|pair| {
        Ok((digit(pair[0])? << 4) | digit(pair[1])?)
    }).collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes { write!(&mut out, "{b:02x}").expect("write to string"); }
    out
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let service = args.next().ok_or("missing service")?;
    let challenge_hex = args.next().ok_or("missing challenge")?;
    let prover: u64 = args.next().ok_or("missing prover")?
        .parse().map_err(|_| "invalid prover number")?;
    let issuer: u64 = args.next().ok_or("missing issuer")?
        .parse().map_err(|_| "invalid issuer number")?;
    if args.next().is_some() { return Err("too many arguments".into()); }
    if service.is_empty() || service.len() > 200 ||
       !service.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-') {
        return Err("invalid service".into());
    }
    let challenge = decode_hex(&challenge_hex)?;
    if challenge.len() != 32 { return Err("challenge must be 32 bytes".into()); }

    let cs = Ciphersuite::Bls12381Sha256;
    let sk = keygen(TEST_KEY, b"").map_err(|e| e.to_string())?;
    let pk = sk_to_pk(&sk);
    let (commitment, blinding) = nym_commit(Scalar::from(prover), &[], cs)
        .map_err(|e| e.to_string())?;
    let sig = blind_sign_with_nym(&sk, &pk, &commitment, Scalar::from(issuer),
                                  HEADER, &[ACTIVE], cs).map_err(|e| e.to_string())?;
    let mut context = b"MAAT:BBS-NYM:SERVICE:".to_vec();
    context.extend_from_slice(service.as_bytes());
    let mut presentation_header = b"MAAT:BBS-PRESENTATION-V1:".to_vec();
    presentation_header.extend_from_slice(&challenge);
    let (proof, pseudonym) = proof_gen_with_nym(
        &pk, &sig, HEADER, &presentation_header, Scalar::from(prover) + Scalar::from(issuer),
        &context, &[ACTIVE], &[0], &[], &[], blinding, cs,
    ).map_err(|e| e.to_string())?;
    println!("PK={}", encode_hex(&pk.to_bytes()));
    println!("PROOF={}", encode_hex(proof.to_bytes()));
    println!("NYM={}", encode_hex(&pseudonym.to_bytes()));
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("BBS TEST FIXTURE ERROR: {e}");
        std::process::exit(2);
    }
}
