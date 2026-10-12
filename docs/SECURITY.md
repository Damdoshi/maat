# Trust boundary and policy — Maât 0.9

The authenticated SSH key is obtained from OpenSSH's **privileged**
`Authctxt::prev_keys[0]`, populated after a signature was successfully verified
in `mm_answer_keyverify()`. The final authentication path insists on one
successful raw Ed25519 publickey login, excluding certificates and other
methods until they are explicitly defined and validated.

The root monitor writes an SSH-string-framed binary packet to a root-only
`SOCK_SEQPACKET` socket and waits for the exact `MAATOK2` acknowledgement.
The C++ receiver validates its UID using `SO_PEERCRED`, parses the key blob,
and atomically registers the KEX session ID in SQLite (`FULL` durability).
Only a successful insert yields ACK. If the receiver is missing, rejects the
packet, or never responds, the Maât SSH login fails.

**Threat model:** Unix uid 0 and privileged OpenSSH processes are trusted.
An attacker with uid 0 can forge the IPC; a local Unix socket is not a
cryptographic attestation against a compromised kernel/root account. The
connection is not yet bound to an HTTP stream: a session-to-HTTP capability
must be introduced before delivering any `$_AUTH` value.

The root-only SQLite DB stores accepted key blobs and Unix usernames, not
identity documents. It is currently unbounded, and has no retention or
replication policy. Its replay uniqueness survives daemon restart but not
malicious deletion/rollback of the local database by root.

**Never enable `maat-sshd.service` to serve real users yet.** The supplied
`sshd_config` contains `DenyUsers *`, `AuthorizedKeysFile none`, forwarding
disabled and a localhost-only listener for an intentionally inert setup.
