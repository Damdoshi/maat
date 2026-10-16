# Native PHP positive SSH -> Apache validation (0.14 follow-up)

This test complements `tests/native_apache_smoke.sh` (unprivileged, anonymous only).
It must run **exclusively in a disposable VM/container** with root. The existing
`tests/e2e_apache.sh` temporarily modifies the `maatweb` account and files in
`/usr/lib/maat`, and binds privileged IPC sockets. **Do not run on a production
host or the regular EFRITS server.**

## Preconditions

- Build the C++ tree and bundled patched OpenSSH binaries.
- Install PHP development headers, `mod_php` matching the compiled extension,
  Apache 2.4, SQLite and build/test dependencies inside the disposable VM.
- Create the test-only Unix accounts and test socket directories as described
  by `tests/e2e_apache.sh` (or use an image built from the Maât test .deb).
- Build `php-ext/modules/maat.so` and pass its PHPT suite.
- Verify `sshd` is run only with the disposable loopback test configuration.
- Ensure no other Maât or Apache test is using `/run/maat*`, TCP 18081 or the
  temporary system account.

## Commands (INSIDE disposable root VM/container only)

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j4
./php-ext/build.sh
MAAT_CONFIRM_DISPOSABLE_VM=yes tests/e2e_native_apache.sh
```

`MAAT_NATIVE_EXTENSION` may point to another already-tested `maat.so`.
Do not enable `maat.so` globally or restart the machine's existing Apache.

## Assertions

1. `maat.so` loads, and `_AUTH` is a native superglobal initialized to NULL
   outside an authenticated Maât request.
2. OpenSSH accepts a real Ed25519 key, the monitor informs the privileged broker,
   and the **native PHP extension** consumes a one-use broker assertion.
3. The returned public-key bytes match the Ed25519 key actually used by SSH.
4. Two different Ed25519 identities using the **same Unix login** alternate
   over twelve real SSH requests, and PHP never attributes the wrong key.
5. Twelve interleaved HTTP accesses (some with forged identity headers) remain
   anonymous. No `auto_prepend_file` PHP bootstrap runs in native mode.
6. A wrong SSH key is rejected, the broker fails closed, and two simultaneous
   SSH sessions still receive distinct ephemeral kernel UIDs.

These are integration **tests**, not a proof against host-root compromise or
credentials held by an untrusted privileged process. `identity_verified` remains
false until a citizen registry is implemented.

## Bundled Apache?

Bundling `httpd` sources in `libs/apache-httpd/` is compatible with this design,
but Apache should remain a **separate Unix process**. Avoid shipping a fork of
Apache just to load `maat.so` while the stock server already supports mod_php.
The E2E test purposefully uses an isolated Apache configuration with the host's
installed Apache 2.4. If an Apache source tree is vendored later, pin a released
version, document its license and origin, check ABI compatibility with mod_php
and APR, and run the same test against both host Apache and the vendored build.
