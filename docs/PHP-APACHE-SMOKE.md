# Native php-maat on Ubuntu / Apache mod_php

The extension was built successfully on Ubuntu PHP 8.1 (PHP API 20210902).
This document separates **isolated anonymous Apache validation** from the
privileged, positive SSH -> Apache -> PHP end-to-end test.

## 1. Isolated mod_php smoke test (safe on a workstation)

From the repository root, after `./php-ext/build.sh`:

```sh
tests/native_apache_smoke.sh
```

The test runs as your normal Unix user and **must not be run with sudo**. It
starts a temporary Apache instance listening only on a random
`127.0.0.1` port. It loads your local `php-ext/modules/maat.so` through a
private `PHP_INI_SCAN_DIR`, and neither changes the system Apache settings
nor installs any Debian package. The process and temporary files are removed
at the end; use `MAAT_KEEP_SMOKE_LOGS=1` to retain its diagnostics.

The test checks the loaded native extension, nested access to `$_AUTH`,
`$_AUTH === NULL` for normal HTTP, rejection of fabricated identity/ticket
headers, and request-to-request isolation over repeated requests.
**It does not test a positive SSH identity.**

## 2. Positive SSH -> Apache -> native $_AUTH (disposable VM only)

`tests/e2e_apache.sh` modifies the test `maatweb` account and installs test
OpenSSH executables into `/usr/lib/maat`. It also starts root-owned Maât
sockets and a broker. **Never run it on EFRITS's production server or on a
workstation you need to preserve.** It refuses to run unless you explicitly
confirm you are inside a disposable VM/container:

```sh
sudo env MAAT_CONFIRM_DISPOSABLE_VM=yes \
    MAAT_NATIVE_EXTENSION="$PWD/php-ext/modules/maat.so" \
    tests/e2e_apache.sh
```

The script now detects `/usr/lib/apache2/modules/libphpX.Y.so` from
`php-config` rather than assuming PHP 8.4. Install `libapache2-mod-php8.1`
for an Ubuntu PHP 8.1 VM, along with the server's other test prerequisites.
Run this only with a freshly provisioned test account, isolated sockets and
no other Maât services running. No production modifications are permissible.

## 3. Packaging

The `.deb` produced by `./packaging/build-php-deb.sh` does not activate the
extension automatically; `/etc/php/X.Y/mods-available/maat.ini` is installed
with mode 0644. Enable it for an Apache SAPI **only after** the two tests
above pass. This preserves existing websites while iterating.
