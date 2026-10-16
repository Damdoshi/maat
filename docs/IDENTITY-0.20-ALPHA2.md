# Maât 0.20.0-alpha2 — Signed registry authority boundary

## State and scope

This alpha introduces **Ed25519-signed registry administration** on top of
0.20.0-alpha1's citizen uniqueness, key-rotation, revocation and per-service
ban storage. This is a C++17 / SQLite *library*: it does **not** expose an
administrative daemon, network endpoint, anonymous credential issuer, ZKP
verifier, civil registration service or judicial deanonymization machinery.

The existing SSH -> broker -> Apache -> PHP transport is unchanged. Its
`identity_verified` field is **always false**. This alpha is NOT approved
for a national registry, public deployment or Internet-facing operation.

## API and trust boundary

The new `identity/authority_commands.hpp` provides:

* `AuthorityInstruction`: immutable-for-signature command values, containing
  a random registry namespace, a strict 64-bit monotonic sequence, an action,
  and the action's exactly required fields.
* `authoritySigningBytes(instruction)`: a deterministic, domain-separated
  binary message, with `MAAT/REGISTRY/AUTHORITY-COMMAND/V1` and a trailing NUL.
  Includes registry namespace, 1-byte action, 1-byte permission, 8-byte
  big-endian sequence, 32-byte citizen ID slot, 32-byte subject commitment,
  32-byte Ed25519 public key slot. Unused fields **must** be empty/zero.
* `RegistryAuthority::bootstrap(registry, publicKey, registryId)`: an explicit
  *trusted offline provisioning* operation. Provision an unpredictable 256-bit
  registry ID and an authority Ed25519 public key into a private, owned
  SQLite database. The pin cannot be changed by calling `bootstrap` again.
* `RegistryAuthority(registry, publicKey, registryId)`: refuses missing or
  mismatched pins; never automatically enrolls a new authority.
* `RegistryAuthority::apply(instruction, signature)`: verifies the Ed25519
  signature, requires the signed registry namespace, then performs a single
  SQLite `BEGIN IMMEDIATE` transaction that checks `sequence = last+1`, applies
  the citizen change, advances the counter and inserts an audit record.
  Domain operations that need nested atomicity use SQLite savepoints. A
  failure rolls back both mutation and counter.

A successful, signed no-op (e.g. an already revoked key) is still recorded and
consumes its assigned sequence. A failed command consumes none. The audit
record contains a SHA-256 hash of the signed bytes, the signature, action,
sequence and change flag (not civil identifiers). Audit entries are ordinary
SQLite rows; they are **not** immutable evidence against privileged DB owners.

Only `RegistryAuthority` may call the citizen store's mutation methods (now
C++-private). `CitizenRegistry::lookup` and `activeKeyOwner` are still trusted
*administrative* queries, NOT client-accessible lookups. `ServiceBanLedger`
remains independent; the signature gate does not authorize or attest service
nullifiers.

**Provisioning requirements:** the registry DB and its directory must belong
exclusively to a trusted OS principal. The signing private key must remain
outside the registry process/database, ideally in dedicated hardware. The
`bootstrap` method is NOT a public endpoint; whoever gains write access to an
uninitialized database can provision their key. It is the deployment's
responsibility to authenticate and constrain provisioning (e.g. offline
installation tooling and OS-level controls).

The current signing key is a **single authority**, not a threshold authority.
The public-key pin is intentionally immutable in this alpha; governance,
rotation, quorum approval, appeals and recovery require a future design.
These APIs do NOT check a person's legal identity or possession of a newly
registered citizen's private key. Those are separate issuer obligations.

## Replay and rollback limitations

An already applied sequence is rejected even across process restarts and under
concurrent, independently opened SQLite connections. Commands are also bound
to the randomly provisioned registry ID, preventing unintended execution in a
different registry with the same signing key.

However, **restoring an old database snapshot restores its sequence counter**.
A security-sensitive deployment requires anti-rollback continuity beyond the
SQLite database (independent append-only log, quorum, tamper-evident external
checkpoints) and backups protected against rollback. A malicious privileged
registry owner or compromised authority is outside this alpha's protections.

## Anonymity and bans: still NOT cryptographically enforced

The existing `AnonymousPermission` is a stored authorization decision, not a
cryptographically anonymous credential. The ban ledger stores `(service,
nullifier)` and is still ignorant of a user's civil identity, but it cannot
verify that a user supplied a valid, stable nullifier rather than a chosen
random value. Do not expose `ban/isBanned` to public proof flows yet.

Before any anonymous use we still need a vetted, unlinkable anonymous
credential scheme with holder-binding, non-revocation proofs, deterministic
service-scoped nullifiers, renewal stability and carefully governed, separate
opening capability where legally justified. A scoped nullifier prevents
multiple identities *within that service scope*, not automated requests from
one person. The service will also need abuse limits.

The 20-witness idea and optional anonymous relays remain **unimplemented** and
must not be conflated with cryptographic identity attestation.

## Tests

* CTest `maat-citizen-registry-tests` exercises Ed25519 signatures; wrong and
  tampered signatures; unprovisioned/wrong authority; immutable pin and
  registry namespace; malformed command encoding; wrong/replayed/out-of-order
  sequences; restart persistence; failed-command rollback; citizen uniqueness;
  rotation/revocation and anonymous permission; independent service bans;
  parallel signed enrollment racing for the same sequence (one succeeds);
  cross-registry replay rejection; file ownership and symlink refusal.
* The tests themselves sign with disposable local Ed25519 test keys. There are
  no embedded production private keys in the library.
* CTest and targeted ASan/UBSan passed locally. Docker/QEMU must be run again
  on this exact alpha2 artifact; passing alpha1 logs is not an alpha2 test.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j4
ctest --test-dir build --output-on-failure
sudo ./tests/docker/run-e2e.sh
```
