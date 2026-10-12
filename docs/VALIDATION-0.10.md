# Validation — Maât 0.10.0 (2026-10-12)

Environment: Debian 13 amd64, GCC 14, C++17, PHP 8.4, OpenSSH Portable
10.6p1 fork compiled with MAAT_MONITOR_SOCKET.

Results:
- OpenSSH `sshd`, `sshd-auth`, `sshd-session`, client and ssh-keygen built.
  The OpenSSH build reused already-tested 0.9 object files because the
  cold build exceeded execution limits; changed `session.c` compiled and
  binaries were linked. A clean full rebuild remains outstanding.
- Two CTest suites passed normally and under ASan/UBSan.
- Parser rejects duplicate Host and Content-Length, unsupported chunked
  transfer, hop-by-hop headers, pipelining and invalid framing.
- Durable SQLite unique issuance and one-shot ticket consumption tested.
- Actual SSH client authenticated via modified privileged monitor, matched
  persisted exact Ed25519 key in PHP, traversing SSH -> receiver -> broker
  -> forced HTTP command -> PHP dev server.
- Ordinary HTTP and a direct forged X-Maat-Ticket request returned `null`.
- Incorrect SSH client key was rejected.
- Five measured *complete* SSH -> PHP requests on loopback (not production
  numbers): median about 144 ms, mean about 143 ms, max about 151 ms.
- PHP example scripts passed `php -l`.
- Debian `.deb` generated and contents/control metadata inspected.

Not validated: actual Apache mod_php request path (test used PHP built-in
HTTP server), installation/removal of THIS 0.10 package on a clean VM,
native extension/superglobal, civil identity, production security, SSH
upstream full regression suite, cold build from scratch or multi-client
stress testing.
