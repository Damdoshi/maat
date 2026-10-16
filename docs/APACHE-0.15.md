# Apache HTTP Server / Maât 0.15

## Upstream source and provenance

Target: **Apache HTTP Server 2.4.69** (released 2026-10-01).

- https://downloads.apache.org/httpd/httpd-2.4.69.tar.gz
- SHA-256: `c551b9861e26f146f57e1b1765e69c89a60b3db0ec252ccab0d36283487016bb`
- Source license: Apache License 2.0; preserve `LICENSE` and `NOTICE` in the tree.

The `libs/apache-httpd/` directory is populated by `tools/vendor-httpd.sh`.
The script first verifies the complete upstream archive against the above
pinned official digest and **refuses mismatches**. It never overwrites sources.
It may also be supplied a local archive for fully offline builds:

```sh
tools/vendor-httpd.sh /path/to/httpd-2.4.69.tar.gz
```

**Current distribution note**: the build environment preparing this delivery
could not resolve `downloads.apache.org`, so its archived source snapshot does
not include the upstream httpd tree. The vendor script is included instead.
Do not infer that Apache 2.4.69 was built or tested here.

## Build a private Apache

On Debian 13:

```sh
sudo apt install gcc make perl libapr1-dev libaprutil1-dev libpcre2-dev \
    libssl-dev zlib1g-dev curl
./tools/vendor-httpd.sh
./tools/build-vendored-httpd.sh
```

On Ubuntu 22.04 with PHP 8.1, APR/APR-util/PCRE2 `-dev` packages are likewise
required. The resulting Apache is installed only under
`build/httpd-prefix/`. The custom Apache is *not* automatically started,
registered with systemd or substituted for the distribution Apache.
The project OpenSSH fork remains independent under `libs/openssh-portable/`.

If you prefer to use the distro Apache to develop `mod_maat`:

```sh
sudo apt install apache2-dev
./tools/build-mod-maat.sh
```

The module is deliberately not loaded or enabled globally. Build results
are in `modules/mod_maat/.libs/mod_maat.so`.

## What mod_maat does and does NOT do

At the `post_read_request` Apache hook, the module examines all request
headers whose name normalizes to the `X-Maat-` prefix (including underscore
aliases that PHP would expose under the same `HTTP_X_MAAT_*` name).

- Default `MaatIngress Off`: removes **all** untrusted `X-Maat-*` fields.
- `MaatIngress On`: for an explicitly selected private Apache instance, a
  single strict 64-character lowercase hexadecimal `X-Maat-Ticket` is
  passed through only when the immediate connection peer is loopback.
- Duplicate, malformed or non-loopback bearer submissions are rejected.
- All other client-supplied `X-Maat-*` fields are removed, even in Maât mode.

**The ticket is not an identity.** The existing native `php-maat` extension
must still atomically consume that token through the protected broker socket,
and the broker must still verify the Apache/PHP peer credentials. No PHP code
may trust HTTP header contents as a claim of citizenship.

A dedicated private Apache instance must listen on `127.0.0.1:18081`, not on
external interfaces. Add to that instance's config only:

```apache
LoadModule maat_module /ABSOLUTE/PATH/maat/modules/mod_maat/.libs/mod_maat.so
MaatIngress On
```

**Threat limitation:** loopback is not an authenticated IPC endpoint. Other
local processes could potentially access the HTTP listener, and a stolen
short-lived bearer ticket could be raced. `mod_maat` does not eliminate this
risk. It adds filtering and keeps the unchanged SSH monitor -> broker ->
Apache/PHP proof chain. A later revision should use a Unix-domain listener
with verifiable peer credentials or a broker-controlled connection handoff,
and remove the bridge/ticket design only *after* end-to-end adversarial tests.

## Tests

Run without privilege:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j4
ctest --test-dir build --output-on-failure
```

The pure-C policy tests and the simulated Apache hook execute even without
Apache developer headers. Their passing does **not** prove the module builds
against real Apache.

After building the real DSO, run the isolated `tests/smoke_mod_maat.sh`
with `MAAT_APACHE_MODULE=/absolute/path/to/mod_maat.so`. The positive
SSH -> Apache -> PHP `$_AUTH` E2E still requires a disposable privileged VM;
never execute it on the personal development machine or a production server.

## Why avoid patching Apache internals?

Apache remains an ordinary 2.4 server; `mod_maat` is a replaceable adapter.
The sources may be bundled for reproducible builds, while preserving the
upstream module ABI, virtual hosts, and ordinary non-Maât deployments. This
is less expensive to maintain than an invasive fork of Apache itself.
