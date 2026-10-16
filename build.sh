#!/usr/bin/env bash
# Build every Maât component without installing or activating host services.
set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd "$ROOT"
JOBS=${MAAT_BUILD_JOBS:-4}
[[ $JOBS =~ ^[1-9][0-9]*$ ]] || { echo 'MAAT_BUILD_JOBS must be positive' >&2; exit 2; }
command -v cargo >/dev/null || { echo 'Missing cargo (offline BBS build)' >&2; exit 2; }
cmake -S . -B build -DMAAT_BUILD_BBS_BRIDGE=ON -DBUILD_TESTING=ON -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build --parallel "$JOBS"

# Native Apache 2 module: Apache provides the ABI and compile flags through apxs2.
command -v apxs2 >/dev/null || { echo 'Missing apxs2 (apache2-dev)' >&2; exit 2; }
(cd modules/mod_maat && apxs2 -c -Wc,-Wall -Wc,-Wextra -lcrypto -lsqlite3 \
    mod_maat.c maat_broker_client.c ingress_policy.c)
test -s modules/mod_maat/.libs/mod_maat.so || { echo 'mod_maat.so was not built' >&2; exit 1; }

# Native PHP extension: must match installed development headers and Apache ABI.
command -v phpize >/dev/null || { echo 'Missing phpize (php-dev)' >&2; exit 2; }
command -v php-config >/dev/null || { echo 'Missing php-config (php-dev)' >&2; exit 2; }
command -v php >/dev/null || { echo 'Missing php CLI' >&2; exit 2; }
PHP_MAJOR_MINOR=$(php -r 'echo PHP_MAJOR_VERSION,".",PHP_MINOR_VERSION;')
PHP_HEADERS=$(php-config --version | cut -d. -f1,2)
[[ "$PHP_MAJOR_MINOR" == "$PHP_HEADERS" ]] || { echo 'PHP CLI/development header mismatch' >&2; exit 2; }
[[ "$PHP_MAJOR_MINOR" == 8.1 ]] || { echo 'Native PHP ABI currently supports PHP 8.1 only' >&2; exit 2; }
(cd php-ext && phpize && ./configure --enable-maat --enable-maat-apache-abi && make -j"$JOBS")
test -s php-ext/modules/maat.so || { echo 'PHP maat.so was not built' >&2; exit 1; }

# Private OpenSSH fork. Builds binaries, never calls 'make install'.
# This define activates Maât's authenticated session binder and direct bridge
# execution. An ordinary OpenSSH build is NOT a valid Maât build.
MAAT_SSH_CFLAGS="${CFLAGS:--O2 -g} -DMAAT_MONITOR_SOCKET"
(cd libs/openssh-portable &&
  # The privsep helpers are installed under /usr/lib/maat by the E2E tests
  # and deployment layout. Their paths are compiled into sshd itself.
  # Reconfigure older build trees as well, not just fresh checkouts.
  if [[ ! -f Makefile ]] ||
     ! grep -Eq '^libexecdir[[:space:]]*=[[:space:]]*/usr/lib/maat[[:space:]]*$' Makefile ||
     ! grep -Eq '^CFLAGS[[:space:]]*=.*-DMAAT_MONITOR_SOCKET([[:space:]]|$)' Makefile; then
    if [[ -f Makefile ]]; then
      make clean
    fi
    ./configure --prefix=/usr/local --libexecdir=/usr/lib/maat \
      --sysconfdir=/etc/maat/ssh \
      --with-privsep-path=/var/empty/maat --with-privsep-user=maatsshd \
      CFLAGS="$MAAT_SSH_CFLAGS"
  fi
  # Fail closed: the unmodified SSH authentication path must never masquerade
  # as a successful Maât build.
  grep -Eq '^CFLAGS[[:space:]]*=.*-DMAAT_MONITOR_SOCKET([[:space:]]|$)' Makefile || {
    echo 'FATAL: OpenSSH was built without -DMAAT_MONITOR_SOCKET' >&2
    exit 1
  }
  make -j"$JOBS" ssh sshd sshd-auth sshd-session ssh-keygen)
for f in ssh sshd sshd-auth sshd-session ssh-keygen; do
  test -x "libs/openssh-portable/$f" || { echo "OpenSSH executable missing: $f" >&2; exit 1; }
done
printf '\nPASS: all Maât build components compiled; nothing installed or started.\n'
