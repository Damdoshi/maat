# Maât 0.13 — trust-boundary review

## What the 0.13 isolation DOES guarantee under its assumptions

- The key originates from OpenSSH's privileged monitor after signature
  validation; the bridge cannot assert its own SSH identity.
- Only a root-credentialed registrar can supply the broker with a socket
  descriptor and the authenticated KEX session identifier.
- `MAATBIND3` is bound transactionally and issues a monotonically increasing,
  never-recycled UID in the reserved host UID range.
- The assigned UID is sent only over a root-only socket and an OpenSSH monitor
  IPC channel, not a client-provided HTTP or SSH argument.
- OpenSSH drops to the ephemeral UID before handling post-auth client session
  requests; subsequent bridge exec runs with the same unique UID.
- A different UID cannot inspect the bridge's inherited fd 3 through the
  Linux procfs ptrace access checks under the tested kernel configuration.
- Wrong SSH keys, forged HTTP headers, used bearer tickets and absence of
  the broker are rejected by live end-to-end tests.

## Preconditions / out of scope

1. Linux kernel procfs and ptrace access semantics must be verified on each
   supported kernel; LSM policies and namespaces affect observable behaviour.
2. Host administrators MUST prevent all other privileged services from using
   UIDs 1800000000..1899999999. Checking NSS is not enough to guarantee this.
3. `/var/lib/maat/monitor.db` must remain unique, durable, non-rollbackable,
   unmodified by non-root, and allocated before any sessions run.
4. Host root, kernel, sshd monitor, broker, Apache/php privileged setup and
   package supply chain are trusted for their respective purposes.
5. A process under the same ephemeral UID (e.g. forked malicious subprocess)
   is in the same session security domain; no code from clients is executed.
6. One Unix UID is allocated per SSH connection rather than per HTTP request;
   multi-request support would require revisiting FD lifetime and tickets.
7. Repeated new authentications exhaust the UID range over time; the service
   must fail closed on exhaustion and monitor growth/rate limits.
8. A database rollback or reassignment by a privileged administrator defeats
   the never-reuse guarantee. Enforce monotonic provisioning in production.
9. No guarantees about citizen uniqueness or civil identity yet.

## Tests executed in development container

- CTest: maat-monitor-tests, maat-http-tests, maat-bind-tests (Debug and
  ASan/UBSan).
- Real OpenSSH authentication with Apache mod_php and PHP built-in origin.
- Two simultaneous authenticated SSH sessions under `maatweb`: different
  process kernel UIDs and cross-session procfs descriptor inspection denied.
- Reopening SQLite: UID allocation strictly increasing, binding replay denied.
- Wrong key, user-origin forged ticket, broker outage, cross-UID denied.
- Kernel positive control (same UID+dumpable can inspect fd 3), negative
  control (dumpable=0 denies): separate root-only isolation test.

These tests prove functionality in this single environment, not security for
arbitrary hosts or attack scenarios.
