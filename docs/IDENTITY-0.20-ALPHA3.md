# Maât 0.20.0-alpha3 — Scoped, issuer-mediated credentials

## Status and precisely scoped guarantee

This release adds a **real cryptographically verifiable, short-lived, service-scoped
credential** with Ed25519 signatures, deterministic issuer-secret-derived
service nullifiers and signed one-time holder challenges. This is an isolated
C++17 library on top of the private citizen registry from alpha1/alpha2.

**It is NOT an anonymous credential protocol.** The trusted issuer necessarily
learns which registered citizen requests access to which named service; it can
correlate service usage, and it could disclose this mapping. The service only
sees a PRF-derived stable nullifier, a distinct holder session key and an
issuer signature, not the citizen ID or permanent SSH key. Different services
get cryptographically distinct nullifiers *if* the long-term HMAC secret is
not leaked and the service-specific holder keys are not reused. IP addresses,
traffic metadata, cookies and applications can still identify users.

No ZKP, blind issuance, group signature, judicial threshold opening, anonymous
network routing, national civil identity verification, revocation distribution
or production-grade issuer daemon is included. The SSH/Apache/PHP bridge remains
unchanged and `identity_verified=false` is still mandatory. These credentials
MUST NOT be accepted by `maatd`, its broker or `$_AUTH` as verified civil identity.

## Offline/private authority and issuer boundary

`RegistryAuthority` from alpha2 remains responsible for the only way to add a
citizen or modify their anonymity permission. The new
`ScopedCredentialIssuer` is a **distinct privileged, private service** requiring:

- A pre-bootstrapped and *signed-command-administered* citizen registry.
- A different 32-byte Ed25519 signing seed for credentials (NOT the authority
  command-signing seed). The corresponding public key is distributed to
  verifiers.
- A separate uniformly random 256-bit HMAC-SHA256 nullifier secret, stored and
  backed up exclusively outside SQLite and outside the public verifier.
- An explicit trusted `ScopedCredentialIssuer::bootstrap(...)` pin to the
  existing registry namespace. The SQLite anchor stores the issuer public key
  and a SHA-256 commitment to the HMAC secret; it cannot silently change.

The registry is owner-only SQLite. Bootstrap requires operating-system
provisioning access and is NOT a publicly callable operation. The issuer
contains secrets in memory while running; the two seed buffers are cleansed
at normal object destruction. Production needs a dedicated key-management
service/HSM, authenticated administration, secure recovery, rate limiting and
isolation of the online issuer from the offline identity authority.

**Keep the HMAC secret across key rotations and service restarts.** Losing it
means new nullifiers will not match existing bans; alpha3 deliberately rejects
a different HMAC secret against an existing anchor. A future *deliberate*
rotation needs a migration/overlap protocol preserving bans.

## Issuance (trusted issuer sees permanent key and service)

1. The issuer generates a random 32-byte, 60-second, one-use challenge.
2. The citizen signs a domain-separated `MAAT/CREDENTIAL/ISSUE-REQUEST/V1`
   transcript containing registry namespace, service scope, registered
   Ed25519 public key, independent holder public key and challenge.
3. The issuer verifies the Ed25519 signature and atomically checks through
   one SQL snapshot that the citizen's registered key is not revoked, their
   identity is active, the anonymously scoped permission is explicitly
   `allowed`, and the proposed holder key is not in the registry.
4. The issuer derives `nullifier = HMAC-SHA256(secret,
   domain || registry_id || citizen_id || service_scope)` and signs a canonical
   `MAAT/CREDENTIAL/SCOPED-ASSERTION/V1` containing registry ID, service scope,
   random serial, scoped nullifier, holder public key and validity timestamps.
   **No citizen ID, permanent key or legal identity is in the credential.**
5. Credential validity lasts **at most 300 seconds** from issuance. Future
   and expired assertions are refused by the service.

The input citizen credential must be bound to an actual person by a future
civil-registration and device-protection process. This alpha proves
possession of a *registered Ed25519 key*, not unique human presence.

The issuer-side random challenge is one-use and in-memory. Reopening an issuer
loses pending challenges (safe failure). Only locally generated challenges
may be consumed. Key registration and anonymous permission validation are
observed together in one SQL statement; a concurrent revocation after that
snapshot does not invalidate an already issued credential (see below).

## Verification (service has no citizen registry)

A service configures `ScopedCredentialVerifier` with **only** the pinned issuer
public key, registry ID, its canonical scope name and its private
`ServiceBanLedger`. It generates a fresh, unpredictable one-use challenge.
The short-lived holder signs `MAAT/CREDENTIAL/HOLDER-PRESENTATION/V1`, covering
the entire signed credential, issuer signature and verifier challenge.

The service checks the issuer signature, registry and service scope, lifetime,
local ban ledger and holder signature. A failed attempt consumes its challenge.
No public API can turn a self-chosen nullifier into a successful presentation.
Tests confirm tampering and replay are rejected and that a different scope
cannot accept the assertion.

For a given registry/citizen/scope, issuer-derived nullifiers are stable across
holder-key renewals and **registered citizen SSH key rotations**, as long as
the HMAC key and citizen record are unchanged. Two services receive different
nullifiers. A service-local ban therefore survives credential renewal.

As with any scoped stable pseudonym, **the service can track visits made under
that same nullifier**; use this flow only where a per-service identity is
needed (accounts, writing or other regulated operations), not as a mandatory
check for merely viewing a website.

## Revocation and privacy gaps for future versions

When a citizen key is revoked or anonymity permission is suspended, the issuer
refuses **new issuance**. Already issued credentials can continue to work for
up to five minutes. This is **not immediate revocation**. Future work needs an
authenticated, freshness-bounded, verifiable revocation feed or an equivalent
mechanism without a nominal per-visit central registry query. The verifier's
trusted system clock must be sane. Neither global revocation nor scope bans
constitute a substitution for application rate limiting.

The issuer knows both the citizen and service and could correlate across
sites. A later *vetted* blind/ZK credential protocol is necessary to remove
this trust and guarantee unlinkable issuance. Secret-keyed nullifiers alone
are not enough. A service can still correlate two sessions if a holder reuses
the same holder key across scopes; applications must generate independent keys.

Service policies, authority appeals, threshold judicial opening, cryptographic
anti-rollback for the registry database, issuer-side attestation and anti-
collusion must be separately designed. This release is **NOT for public
deployment**.

## Tests

`tests/scoped_credentials_test.cpp` includes signed authority administration;
anonymity default-deny; issuer pinning and HMAC secret change refusal; citizen
key possession; wrong holder, forged issuer, tampered timestamps/nullifiers;
challenge replay; wrong registry and scope; 300-second expiration bound;
renewed holder and permanent keys preserving nullifiers; independent service
scopes; persisted service bans; suspension and key/citizen revocation blocking
new issuance. It also explicitly tests the known current limitation where a
previously issued credential remains valid until its expiry.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j4
ctest --test-dir build --output-on-failure
sudo ./tests/docker/run-e2e.sh
./tests/qemu/run-e2e.sh /path/to/verified-ubuntu-22.04-server-cloudimg-amd64.img
```
