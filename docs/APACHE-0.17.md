# Maât 0.17 — Single, direct Apache verification path

**Security status:** experimental; NOT for public production.

## Design and invariants

* An OpenSSH monitor-authenticated key enters the privileged broker through
  the trusted monitor chain; the isolated HTTP bridge receives a single-use
  ticket using an inherited session-bound Unix socket descriptor.
* `mod_maat` owns the `MAATCHECK1` consumption. Every candidate `X-Maat-Ticket`
  is stripped before PHP. Header variants `X_Maat_*` are also stripped.
* `mod_maat` accepts a broker identity only after `SO_PEERCRED` validates the
  root-owned broker process and the exact SSH Ed25519 blob is parsed.
* The broker response is stored in Apache's `request_config` (per-request).
* `php-maat` asks the Apache optional function `maat_request_identity` for
  that request; it has **no fallback to `$_SERVER`**, bearer strings or environment.
* The PHP 8.1 native extension is currently limited to `apache2handler`.
  Other SAPIs and instances without the optional function return `$_AUTH = NULL`.
* `identity_verified` is **false**: nothing asserts civil or citizenship identity.

`MaatDirectVerify` and the legacy two-stage PHP->broker flow are removed.
This is a **breaking pre-release change**: rebuild both modules, do not mix
0.16 and 0.17 binaries. `MaatIngress On` remains an explicit flag for the
private Apache listener only; it is not a legacy compatibility switch.

## Test sequence (Ubuntu PHP 8.1)

Run as an ordinary user, never sudo:

```sh
./build.sh --skip-vendored-apache
# or:
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j4
ctest --test-dir build --output-on-failure
./tools/build-mod-maat.sh
./tests/smoke_mod_maat.sh
./tests/smoke_mod_maat_direct.sh
./php-ext/build.sh
./tests/native_apache_smoke.sh
```

The native Apache smoke deliberately has no broker. It asserts that 40
requests are anonymous or denied, including forged 64-character tickets.
It **cannot** demonstrate a positive SSH-authenticated identity.

Positive SSH / Apache / native $_AUTH verification requires **root in a
throwaway VM/container** (it modifies local accounts, root-owned paths and
runtime sockets):

```sh
MAAT_CONFIRM_DISPOSABLE_VM=yes tests/e2e_native_apache.sh
```

The positive E2E test alternates two Ed25519 SSH keys under the same technical
account and interleaves anonymous requests; it checks the exact public keys.
It has not been executed in the current artifact-building environment.

## Remaining trust limits

* The bridge currently transports a bearer ticket over loopback TCP to Apache.
  Any untrusted local process with access to that listener remains relevant to
  the threat model. Replace with a strict Unix socket / descriptor handoff in
  a subsequent change, or apply a strong host-level network/access boundary.
* The PHP 8.1 adapter uses the **private** `php_struct` layout from
  `sapi/apache2handler/php_apache.h` (`int state; request_rec *r; ...`). That
  layout is not a public, stable PHP extension ABI. Reverify for other versions.
* Neither a credential registry nor proof of unique French citizenship exists.
* No code path in 0.17 returns `identity_verified=true`.
