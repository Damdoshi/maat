# Maât 0.19.0-rc1 — observed E2E evidence

**Date:** 2026-10-13. Integration-validated prototype; no formal security
certification, production claim or legally attested civil identity.

## User-supplied test results, prior to RC packaging

* **Docker 0.19-alpha3:** the earlier user trace ended in the positive and
  adversarial `E2E HTTP PASS`, including HTTP keep-alive and broker failure.
* **QEMU 0.19-alpha3 + QEMU permissions patch:** the uploaded output ended
  in `E2E HTTP PASS` and `PASS QEMU isolated-kernel Maât native E2E`.
  VM was Ubuntu 22.04, Linux 5.15.0-198-generic, 4096 MiB RAM, 12 GiB disk.
* QEMU CTest: **12 passed, one skipped** (`maat-bind-tests`, which requires
  privileged environment); aggregate `100% tests passed, 0 tests failed out
  of 13` includes that skip. PHP PHPT: 7 passed.

## Verified in native QEMU E2E

* Twelve alternating authenticated SSH requests under one Unix login with
  two different Ed25519 keys; exact Alice/Bob key isolation maintained.
* Eight simultaneous requests, 32 requests / eight workers; 32 unbound or
  forged direct TCP requests rejected.
* Three pipelined HTTP requests per SSH session; live sequential keep-alive
  for both identities; independent TCP proof for each request.
* Ambiguous, malformed, oversized, fragmented and truncated HTTP messages;
  abandoned requests did not contaminate a later session.
* Ephemeral UIDs 1000000021 and 1000000022 for simultaneous sessions,
  verified cross-session /proc isolation within guest.
* Wrong SSH key, untrusted UID, and interrupted broker fail closed.
* Indicative five-request latency median 137.1ms, mean 130.0ms,
  maximum 161.1ms (loopback; sample not a performance benchmark).

## Explicit limitations

* No proof of citizen civil identity. `identity_verified=false`.
* No demonstration of safety against hostile root, other kernel versions,
  broader HTTP smuggling variants or unknown races.
* No release image pinning, package installation validation, deployment
  behind proxy/TLS, or Apache/PHP ABI portability guarantees.
* The new **RC archive itself** has NOT yet been tested in Docker or QEMU;
  changes from the tested code are metadata, docs and package version only.
