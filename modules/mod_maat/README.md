# mod_maat — descriptor-bound authentication (0.18)

An Apache instance configured with `MaatIngress On` is *private SSH ingress*:
every request must match an active, broker-registered TCP connection through
Linux `SCM_RIGHTS` descriptor transfer. A direct anonymous request to this
private listener is rejected with 403, even on loopback. Apache never reads a
client-supplied identity or bearer token from HTTP; all `X-Maat-*` variants
are stripped before the request reaches PHP.

`MaatIngress Off` preserves ordinary anonymous HTTP (`$_AUTH = NULL`). Run it
on a **separate Apache instance** from the Maât ingress. Avoid using mixed
vhosts on one listener because `MaatIngress` is server-level.

On the private instance, the SSH bridge registers the client half of a live
TCP connection via its inherited, session-specific Unix capability. Apache
transmits its accepted TCP descriptor to the broker. The broker checks the
kernel local/peer addresses of BOTH live TCP endpoints, consumes the match
once, and returns the Ed25519 key previously attested by OpenSSH. That
request-local structure is read by the native `php-maat` Apache hook.

No TCP tuple, key, session ID or nonce is accepted as a client claim. The
broker holds the client descriptor to prevent premature TCP tuple reuse and
expires unclaimed registrations in 15 seconds.

**Security assumptions:** broker root, OpenSSH privileged monitor, exclusive
non-reused session UIDs, protected `/run/maat-http` directory, isolated Apache
workers, and no privileged local attacker. HTTP ingress must never be
forwarded through an unaudited proxy that changes TCP endpoints. The channel
currently handles one request per SSH connection and local IPv4 loopback only.
