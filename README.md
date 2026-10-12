# Maât 0.14.0 — isolated Unix credentials per authenticated SSH/HTTP session

**Security research prototype; NOT approved for Internet-facing production.**

C++17, bundled OpenSSH Portable 10.6p1 (`libs/openssh-portable/`), a
privileged monitor receiver, a broker, a forced HTTP bridge, SQLite and a PHP
demonstrator. No citizen registry exists; `identity_verified` remains `false`.

## Security change in 0.13

Version 0.12 protected shared-UID processes with `PR_SET_DUMPABLE(0)`, but
`execve()` can reset dumpability. In 0.13, **each SSH connection** is given a
**distinct Linux kernel UID**, before OpenSSH's post-auth privilege drop.

1. The OpenSSH privileged monitor validates the real Ed25519 SSH key and
   records a `MAATMON2` assertion via a root-owned Unix socket.
2. Before dropping privileges, the post-auth child requests a `MAATBIND3`
   session capability via the privileged monitor. The monitor registers the
   session with the root broker using `SOCK_SEQPACKET` and `SCM_RIGHTS`.
3. Inside one SQLite `BEGIN IMMEDIATE` transaction, the broker binds that
   previously verified session and allocates an unused ephemeral UID from the
   **host-reserved range `1800000000..1899999999`**.
4. The privileged monitor receives the UID in an `MAATBOUND3` reply and
   conveys it to the post-auth child over OpenSSH's internal monitor IPC.
5. The post-auth child applies the assigned UID through OpenSSH's normal
   `do_setusercontext()` **before parsing further client session requests**.
   The login account must be `maatweb`; no shell or user-controlled command
   runs. An administrative `ForceCommand` launches `maat-http-bridge` directly.
6. The bridge holds only its inherited per-session socket descriptor (fd 3).
   It requests one use-once ticket over it. Apache/PHP redeems the ticket
   against a separate Unix verification socket. Web applications never get
   to declare the identity themselves.

The ledger `maat_ephemeral_uids` is durable. UIDs are **never reused**, even
if a session is abandoned, has ended, or the broker restarts. Collisions,
replays, SQLite failures and UID range exhaustion fail closed. The code
refuses an UID found by NSS (`getpwuid_r`) but **this is not a complete
host-wide collision check**.

### REQUIRED host-level UID reservation

**Do not deploy until the entire range `1800000000..1899999999` is
administratively reserved exclusively for Maât**, including every relevant
NSS source, systemd service, container, privileged runtime and UID allocator.
The package does **not** automatically enforce a reservation with all other
root processes. Linux does not offer a general exclusive UID allocator;
privileged software elsewhere can still adopt an overlapping UID. For a
production release, create an auditable machine-level reservation/preflight
policy or move sessions into separately controlled user namespaces.

The SQLite database is part of the security perimeter: never delete, truncate,
restore to an earlier version or copy it between independent active machines.
An attacker with host root access can forge this local chain.

## Build

Debian 13 amd64 requirements: g++, cmake, sqlite3 development headers,
OpenSSL and zlib development headers, autoconf/automake, OpenSSH build tools,
Apache 2.4 with mod_php and PHP 8.4 for Apache end-to-end tests.

```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j4
ctest --test-dir build --output-on-failure

cd libs/openssh-portable
./configure --prefix=/usr --sysconfdir=/etc/maat \
 --libexecdir=/usr/lib/maat --with-privsep-user=maatsshd \
 --with-privsep-path=/var/empty/maat --without-pam \
 --without-kerberos5 --without-selinux \
 --without-security-key-builtin CFLAGS='-O2 -g -DMAAT_MONITOR_SOCKET'
make -j4 sshd sshd-auth sshd-session ssh ssh-keygen
```

Build this with matching OpenSSL headers and libraries. The validation
container's system OpenSSL headers and shared library versions differ, so
**only for the test build** the `--without-openssl-header-check` override was
necessary. This mismatch must be fixed before production.

**Disposable root VM/container ONLY:**

```
tests/e2e_apache.sh
# Or for the PHP built-in server:
tests/e2e_http.sh
./build/maat-isolation-tests
```

The tests temporarily modify the `maatweb` test account's shell/password,
restore them on exit, and use dedicated local sockets, keys and ports.
Never run them on a production host. The Apache E2E verifies two concurrent
sessions sharing the same SSH account but assigned distinct UIDs, and probes
`/proc/<pid>/fd/3` from the original account and another session UID.

To build an amd64 Debian package from sources:

```
MAAT_OUTPUT_DIRECTORY=dist packaging/build-deb.sh
```

The build deliberately fails when OpenSSL headers/library don't match, unless
`MAAT_ALLOW_OPENSSL_HEADER_MISMATCH=1` is explicitly set for a test build.
The `.deb` never enables SSH or Apache services automatically. The included
SSH HTTP example configuration is loopback-only and denies all users until
an administrator explicitly permits appropriate test credentials.

## Remaining work / non-guarantees

- No citizen authority, birth records, unique-human identity, card, revocation
  or selective disclosure. The `maatweb` Unix account is NOT a civil identity.
- `_AUTH` native PHP extension is included in `php-ext/` but not compiled or
  runtime-tested (the test environment lacks `php8.4-dev` / `phpize`). Apache
  E2E still uses `php/maat_auth.php` bootstrap, not a PHP superglobal.
- HTTP proxy supports one bounded HTTP/1.1 GET/POST/HEAD request per SSH
  connection; not HTTP/2, WebSockets, streaming, or production browser use.
- Global UID reservation across root-managed services is NOT yet enforced.
  No independent security audit or penetration test has been done.
- Monitor and broker are root-trusted, and SQLite files are root-controlled.
  The UID ledger grows monotonically and needs operational limits/monitoring.
- No automatic database disaster recovery, secure upgrade/rollback policy,
  workload profiling beyond short local loopback measurements, or load testing.

See `docs/SECURITY-0.13.md` for the trust model and failure cases.

### 0.14: UID allocation configuration and PHP extension testing

See `docs/UID-RANGE.md` for the root-owned Dabsic-subset range configuration.
The PHP native module is not built into the `maat-sshd` package unless PHP development
headers are available and its compilation / PHPT tests have passed.
