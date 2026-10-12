# Maât 0.9 — validation report (2026-10-12)

Environment: Debian GNU/Linux 13 (Trixie), amd64, GCC 14, C++17,
OpenSSH 10.6p1 from supplied openssh-portable-master.zip, OpenSSL
headers 3.5.7 / shared library 3.5.5. Configuration was made with the
explicit OpenSSL header-check override because of this mismatch.

## Completed

- Privileged monitor modification compiled into `sshd`, `sshd-auth`, and
  `sshd-session` (the fork's split-server architecture).
- Fork client `ssh` and generator `ssh-keygen` also built for testing.
- DDD C++ library, real receiver and SQLite store compiled in Debug and Release.
- 32 checks for protocol serialization, malformed messages, incompatible keys,
  Unix peer UID, duplicate rejection, and SQLite persistence after reopening.
- 5,000 deterministic malformed packets parsed without crashes; tests also ran
  under AddressSanitizer + UndefinedBehaviorSanitizer with no reported error.
- True root-isolated localhost OpenSSH E2E (tests/e2e.sh): real Ed25519
  signature accepted, key bytes in SQLite exactly matched the client's public
  key, wrong public key rejected, authenticated RSA key rejected by Maât,
  clean receiver restart and reauthentication, missing receiver fail-closed.
- Full SSH local handshake profile (eight successive logins): median 125.7 ms,
  mean 125.9 ms, max 127.9 ms. Figures describe this container, not production.
- SQLite profile: 500 `synchronous=FULL` WAL writes in 6.0 ms (~82,943/s)
  on this virtual filesystem; not representative of real durable media latency.
- Patch `docs/0001-privileged-monitor-maatmon2.patch` applied to a clean
  `monitor.c` taken from the user's supplied ZIP and yielded byte-identical
  modified source.
- Debian `.deb` built successfully, metadata checked, APT install simulated,
  **actually installed and removed** in disposable container. `sshd -t`
  passed on the installed config after the postinst generated the host key;
  host key mode was 0600, protected directories were 0700.

## Not completed / not claimed

- No upstream OpenSSH complete regression suite, no external security audit.
- No real citizen identification/attestation or key revocation.
- No HTTP, Apache/PHP, `$_AUTH`, or browser integration in this release.
- No cross-distro build validation (Debian 12 or other architectures).
- No failover/load testing under sustained concurrency or crash-injection
  beyond receiver restart and missing-receiver tests.
- Server assumes a trusted root privilege domain. `SO_PEERCRED` cannot defend
  against a compromised root process on the same host.
- Current proof is authenticated SSH key ownership, **not** citizenship.

## Test caution

`tests/e2e.sh` requires root and modifies the test machine: a temporary
`maat_e2e` Unix account is created/removed, `/run/maat/monitor.sock` used,
`/usr/lib/maat/sshd-auth` and `sshd-session` expected, and a persistent SQLite
record written into `/var/lib/maat/monitor.db`. Run only in a disposable VM
or container dedicated to testing Maât; never on an administration host.
