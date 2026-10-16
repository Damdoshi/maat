# Maât 0.19-alpha3 — Persistent HTTP over one SSH session

## Implementation status

The alpha2 broker keeps a strictly bounded, root-attested SSH session
capability: up to 100 successful `MAATLINK1` registrations, 60 seconds of
inactivity, five minutes of total lifetime. It does **not** cache identities
in Apache or PHP.

Alpha3 changes the **forced-command bridge** to accept multiple complete
HTTP/1.1 request frames on that same SSH channel. Pipelined requests are
processed strictly in order; sequential requests may be sent after each
response, without reopening SSH. This is an **alpha candidate**, pending the
positive Docker and QEMU E2E tests.

For **each** HTTP message, independently:

1. Parse the next bounded request frame from a stream. Reject duplicated or
   ambiguous framing (`Transfer-Encoding`, `Expect`, `Upgrade`, duplicate
   `Content-Length`, headers with folding/controls, invalid content lengths,
   incomplete bodies). Never infer identity from those headers.
2. Open a **new** loopback TCP socket to a private Apache instance.
3. Register that exact live client FD with the broker on the SSH-bound
   `SOCK_SEQPACKET` capability (`SCM_RIGHTS` / `MAATLINK1`). Wait for the
   broker's `MAATREADY1` acknowledgement *before* forwarding any HTTP bytes.
4. Forward a sanitized request with `Connection: close`. Apache receives a
   **new** accepted socket for every request and independently redeems the
   matching proof once. `mod_maat` populates the request-local Apache context
   and `php-maat` exposes it as `$_AUTH`.
5. Consume the finite Apache response up to EOF, with an 8 MiB response cap
   and a five-second backend receive timeout. Reject ambiguous or malformed
   `Content-Length` / `Transfer-Encoding` combinations. Decode simple
   `chunked` encoding (without extensions or trailers), then send an
   HTTP/1.1 response with freshly computed `Content-Length` and
   `Connection: keep-alive`. HEAD, 204 and 304 responses are bodyless.
6. Continue with the next frame. On any framing, broker, TCP or response
   error, stop rather than reusing the previous request's context. The
   capability itself cannot authorize a request without a new proof.

The bridge imposes a 15-second framing deadline after the first byte of an
incomplete request and a 60-second inter-request idle limit. The broker has
its own independent quota/expiry checks. Input bodies are capped at 1 MiB,
request headers at 16 KiB.

## Security / compatibility restrictions

* HTTP/1.1 only; no client-chosen `Connection`, `Expect`, `Upgrade` or
  `Transfer-Encoding`, and no HTTP/2, CONNECT or WebSocket support yet.
* Request pipelining is processed in order (no parallel dispatch within a
  single SSH channel). Failure of a later pipelined request does not undo
  an earlier completed, independently authenticated request.
* Each response is **buffered** (up to 8 MiB) before being sent, to guarantee
  exact framing and detect mismatches prior to forwarding. This is not yet
  suitable for streaming video, SSE or large downloads.
* Neither authentication success nor `identity_verified` establishes French
  citizen identity; the latter stays false pending a real identity registry.
* A previously registered in-flight descriptor can outlive the SSH capability
  briefly (15 seconds), as documented in `PERSISTENCE-BROKER-0.19.md`. No new
  descriptor can be registered after the capability closes.
* A `Connection: keep-alive` HTTP response by itself is not proof of a safe
  request. The actual new TCP descriptor must still be registered and
  consumed for **every** subsequent message.

## Validation ladder

1. `maat-http-stream-tests`: frame splitting, POST, fragmentation, truncated
   request and malformed Apache responses.
2. `maat-bridge-persistence-smoke`: launches real `maat-http-bridge` with an
   unprivileged mock broker via FD3 plus a loopback backend, checking three
   distinct `SCM_RIGHTS` grants and three separately framed responses.
3. Docker positive E2E: real OpenSSH → broker → Apache → PHP, three pipelined
   requests followed by live sequential requests for **both** Ed25519 keys.
4. Docker negatives: malformed requests, forged direct connections, concurrent
   sessions, broker interruption and replay.
5. QEMU: repeat the positive and negative E2E on an independent kernel.

**Only 1–2 are confirmed by the local alpha3 build.** Docker and QEMU
remain external validation gates. Do not enable a production deployment or
mark 0.19 stable until those real tests and a security review succeed.
