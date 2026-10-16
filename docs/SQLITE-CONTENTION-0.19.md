# Maât 0.19 alpha1 — concurrent SSH assertion writes

The privileged OpenSSH monitor receiver and the HTTP identity broker write to
**the same** SQLite database (`/var/lib/maat/monitor.db`). The broker uses
`BEGIN IMMEDIATE` for a session binding and ephemeral UID allocation. The
receiver must durably commit each authenticated SSH assertion *before*
acknowledging it to OpenSSH.

Previously `ReplayStore` opened a SQLite connection without a busy handler. A
valid concurrent assertion could immediately fail `SQLITE_BUSY` during the
broker's write transaction, despite the broker being healthy. In the Docker
stress run this manifested as an SSH exit 255 and a single `Maât SSH assertion
rejected` in the monitor log. The logs alone do not prove which operation
returned `SQLITE_BUSY`; this fix addresses a reproducible race matching those
symptoms.

`ReplayStore` now waits **up to 1200 milliseconds** for a competing SQLite
writer. The wait is bounded below OpenSSH's 2-second root-monitor IPC timeout.
SQLite's uniqueness constraint remains authoritative: already accepted
sessions are still rejected. No assertion is acknowledged until it is
committed; a persistent lock still fails closed.

`maat-monitor-tests` exercises both scenarios using a second SQLite writer:

- Transaction released after ~180 ms: valid assertion succeeds; replay fails.
- Transaction held past the 1200 ms timeout: assertion is denied, and can be
  accepted normally on a fresh attempt after release.

The stress test is **not** weakened: 32 positive SSH connections still run with
8 worker threads, alongside identity, framing, replay and interruption tests.
When a stress test fails, logs now include fatal/transport diagnostics from
the isolated sshd. Run these checks only with the disposable Docker harness.

This does not claim that the Docker E2E stress now passes: it must be rerun on
the user's machine. Other resource limits and high-concurrency issues may
still exist and should be diagnosed from that run rather than adding retries.
