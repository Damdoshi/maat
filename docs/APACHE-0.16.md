# Maât 0.16 — direct request context (EXPERIMENTAL)

This revision is opt-in and is NOT a production-ready replacement for the
validated 0.15 path. **Do not remove maat-http-bridge or check.sock.**

## Why this design

The privileged OpenSSH monitor authenticates an SSH public key and creates
an isolated per-session capability. The bridge still converts a single SSH
HTTP request to HTTP/1.1 and places its one-use ticket on the loopback-only
Apache hop. `mod_maat` now has an *optional* verifier instead of forwarding
that ticket into PHP. Verification is done over the socket in the root-controlled
`/run/maat-http/` directory (socket owner is the Apache service UID): it requires `SO_PEERCRED` uid=0, a strictly
well-formed reply, and a valid 51-byte Ed25519 SSH public-key blob.

`mod_maat` stores the verified identity in **request_rec->request_config**.
The input ticket is removed from the HTTP request before PHP sees it, and
Apache provides an optional native API `maat_request_identity(request_rec*)`.
No authenticated identity is inferred from HTTP headers. No PHP HTTP header
or subprocess environment field is used to convey this identity.

**Two modes are intentionally mutually exclusive:**

- Default (`MaatDirectVerify Off`): 0.15 behavior, PHP consumes the broker
  ticket and produces `$_AUTH`; retained as the working path.
- Experimental (`MaatDirectVerify On`): the Apache module consumes the ticket
  and stores the verified identity, then a specially built PHP 8.1 extension
  reads it using Apache's optional-function registry. Without that extension,
  PHP receives NULL. Never assume that HTTP 200 implies authenticated PHP.

This **does not** create an identity/citizenship registry. Even in the new
mode `identity_verified` remains false and no civil attributes are supplied.

## Compiling and nonprivileged tests (Ubuntu 22.04, PHP 8.1, tcsh)

From the repository root:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j4
ctest --test-dir build --output-on-failure
./tools/build-mod-maat.sh
./tests/smoke_mod_maat.sh
./tests/smoke_mod_maat_direct.sh
```

The second smoke test runs a private Apache and deliberately has no trusted
broker: forged candidates **must fail closed** (HTTP 403). Neither test
installs/enables Apache globally.

Build the **experimental** PHP SAPI adapter explicitly:

```sh
env MAAT_EXPERIMENTAL_APACHE_ABI=yes ./php-ext/build.sh
./tests/native_apache_smoke.sh
```

This special build depends on the **private** layout of
`php_struct` in the PHP 8.1 `apache2handler` SAPI. It uses
`SG(server_context)` and `apr_dynamic_fn_retrieve` to get the Apache
request-scoped identity without touching `$_SERVER` or any HTTP header.
It is not a supported public PHP API and **must not be enabled for PHP
8.2+ or production without ABI validation**.

The ordinary extension can always be rebuilt with:

```sh
env MAAT_EXPERIMENTAL_APACHE_ABI=no ./php-ext/build.sh
```

For the real SSH → Apache → native PHP positive path, run **ONLY in a
root disposable container/VM with a snapshot**:

```sh
env MAAT_CONFIRM_DISPOSABLE_VM=yes tests/e2e_native_apache_direct.sh
```

This script modifies the local test account, privileged binary paths and
runtime sockets. **Never run it on your personal Ubuntu machine or any
server with production accounts.** A success requires two distinct SSH
identities, interleaved anonymous traffic, and broker-outage rejection.

## Security boundaries and open items

- The check socket lives in a root-controlled directory and is owned by the Apache UID;
  another compromised Apache worker could race stolen bearer tickets. We have
  not yet replaced the loopback TCP hop with a credential-checked Unix domain
  socket or a broker-controlled file-descriptor handoff.
- The strict `SO_PEERCRED` check protects the Apache->broker connection only
  against non-root impersonation. A compromised root process is in the TCB.
- This implementation is an Apache module and requires `mod_php`; PHP-FPM
  deliberately falls back to the older broker path, not to Apache request
  pointer inspection.
- PHP applications can still overwrite the mutable `$_AUTH` superglobal after
  it is created; this feature cannot prevent a trusted PHP application from
  modifying its own variables.
- The private PHP/apache2handler ABI binding is preliminary: positive native
  integration must be executed on the exact target PHP build before shipping.
- The new broker path blocks at most two seconds per rejected candidate,
  and the current broker is still single-threaded. Stress/load tests and an
  effective per-client request limit are needed before public deployment.
- DDD remains in the C++ broker; `mod_maat` is a C adapter with explicit
  identity/transport structures.
- Old Apache `MaatIngress On` is not a certificate of civil identity.
