# Maât 0.19 — release gates

## Passed in user-supplied traces (2026-10-13)

* Docker: positive SSH → root broker → Apache → PHP `$_AUTH`, concurrency,
  negative/forged requests, fail-closed behavior, HTTP persistence.
* QEMU Ubuntu 22.04 (Linux 5.15.0-198-generic): same E2E suite on its own
  guest kernel, positive and adversarial HTTP/1.1 persistent tests, UID
  separation and `/proc` isolation, broker shutdown.
* This RC consolidates alpha1 (adversarial tests and SQLite/GCC fixes),
  alpha2 (bounded multiple broker grants) and alpha3 (persistent bridge).

## Still necessary before a stable production claim

* Re-run this **exact 0.19.0-rc1** source archive under Docker and QEMU;
  it has new metadata/version/packaging but unchanged authentication logic.
* Security review and fuzzing of HTTP framing, RPC parsing and privilege
  boundaries; production operating conditions not yet validated.
* Actual citizen register and civil-identity validation, revocation,
  accountable key uniqueness and renewal; `identity_verified` is false.
* Host-wide UID reservation, NSS and SQLite ledger rollback procedures.
* Reproducible pinned dependencies/base images, package building and
  deployment tests, compatibility matrix for Apache/PHP ABI.

**Status:** integration-tested research release candidate, NOT production.
