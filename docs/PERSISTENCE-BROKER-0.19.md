# Maât 0.19-alpha2 — bounded repeated descriptor grants

This stage modifies **only the session capability lifecycle** of the root
HTTP broker. It does **not** make SSH/HTTP persistent yet. The forced-command
bridge still accepts one HTTP/1.1 request, establishes one TCP connection,
passes one descriptor (`MAATLINK1`), and exits. All 0.18 requests therefore
continue through the exact same per-request verification.

## Broker behavior

* After `RootSessionBinder` acknowledges a genuine OpenSSH session, the broker
  keeps its unique `SOCK_SEQPACKET` session capability until EOF, error, quota,
  or expiry instead of closing it immediately after the first successful FD.
* Each incoming `MAATLINK1` packet must contain exactly one transferred live
  TCP descriptor (`SCM_RIGHTS`). `SessionConnectionChannel` continues to check
  the bound SSH session in SQLite and registers a new, independent kernel TCP
  connection proof. Apache must redeem each proof independently, one time.
* A `SessionRegistrationBudget` limits each capability to 100 **successful**
  grants, 60 seconds of idle time between grants, and five minutes since the
  capability was bound. The limits are monotonic-clock based. A failed
  registration, malformed FD, or failed acknowledgement closes the capability.
* No SSH username, public key or verified identity is cached by Apache. All
  per-request lookups continue through the root broker, including after a
  previous request on the same SSH channel.
* This stage does not purge an already-registered in-flight FD immediately
  if SSH closes its capability. Such proof has a 15-second timeout and remains
  redeemable once, matching the previous one-shot behavior. It does not grant
  a new proof once its session capability has closed.

## Tests and remaining gate

`maat-session-budget-tests` exercises quota and expiry (including boundary
conditions). `maat-descriptor-e2e-tests` sends two separate kernel TCP FDs
through the *same* Unix session capability and uses the C Apache broker client
to redeem both individually. Each old accepted FD is still single-use.

**HTTP keep-alive is not implemented**: the bridge must still gain a bounded,
correctly framed HTTP/1.1 request/response loop with an independent TCP proof
per request. Do not relax the one-request restriction in `HTTPRequest::read`
without adding safe framing and multi-request Docker negative tests. Run the
new positive 2-request SSH test only once the bridge is actually updated, and
re-run the QEMU suite before making 0.19 stable.
