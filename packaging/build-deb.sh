#!/bin/sh
# Scripted from-source package assembly for Debian 13 (amd64).
# Requires: g++, cmake, libsqlite3-dev, libssl-dev, zlib1g-dev, autoconf,
# automake, libtool, dpkg-dev and usual OpenSSH Portable build dependencies.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OPENSSH="$ROOT/libs/openssh-portable"
case "$(dpkg --print-architecture)" in amd64) ;; *) echo 'Only tested for amd64' >&2; exit 1;; esac
if [ ! -f "$OPENSSH/Makefile" ]; then
  (cd "$OPENSSH"; autoreconf -fi)
fi
EXTRA=''
if [ "${MAAT_ALLOW_OPENSSL_HEADER_MISMATCH:-0}" = 1 ]; then
  EXTRA='--without-openssl-header-check'
fi
(cd "$OPENSSH"
 ./configure --prefix=/usr --sysconfdir=/etc/maat --libexecdir=/usr/lib/maat \
    --with-privsep-user=maatsshd --with-privsep-path=/var/empty/maat \
    --without-pam --without-kerberos5 --without-selinux \
    --without-security-key-builtin $EXTRA CFLAGS='-O2 -g -DMAAT_MONITOR_SOCKET'
 make -j2 sshd sshd-auth sshd-session ssh-keygen)
cmake -S "$ROOT" -B "$ROOT/build-deb" -DCMAKE_BUILD_TYPE=Release
cmake --build "$ROOT/build-deb" -j2
OUT="${MAAT_OUTPUT_DIRECTORY:-$ROOT/dist}"
mkdir -p "$OUT"
PKG="$ROOT/.maat-package-root"
rm -rf "$PKG"
mkdir -p "$PKG/DEBIAN" "$PKG/usr/lib/maat" "$PKG/usr/sbin" \
 "$PKG/etc/maat" "$PKG/lib/systemd/system" "$PKG/usr/share/doc/maat-sshd"
install -m 0755 "$OPENSSH/sshd" "$PKG/usr/lib/maat/sshd"
install -m 0755 "$OPENSSH/sshd-auth" "$PKG/usr/lib/maat/sshd-auth"
install -m 0755 "$OPENSSH/sshd-session" "$PKG/usr/lib/maat/sshd-session"
install -m 0755 "$OPENSSH/ssh-keygen" "$PKG/usr/lib/maat/ssh-keygen"
install -m 0755 "$ROOT/build-deb/maat-monitor-receiver" "$PKG/usr/sbin/maat-monitor-receiver"
install -m 0755 "$ROOT/build-deb/maat-http-bridge" "$PKG/usr/sbin/maat-http-bridge"
install -m 0755 "$ROOT/build-deb/maat-http-broker" "$PKG/usr/sbin/maat-http-broker"
install -m 0755 "$ROOT/build-deb/maat-check-config" "$PKG/usr/sbin/maat-check-config"
install -d -m 0755 "$PKG/usr/share/maat/php"
install -m 0644 "$ROOT/php/maat_auth.php" "$PKG/usr/share/maat/php/maat_auth.php"
install -m 0644 "$ROOT/php/whoami.php" "$PKG/usr/share/maat/php/whoami.php"
install -d -m 0755 "$PKG/usr/src/maat/php-ext"
install -m 0644 "$ROOT/php-ext/maat.c" "$PKG/usr/src/maat/php-ext/maat.c"
install -m 0644 "$ROOT/php-ext/config.m4" "$PKG/usr/src/maat/php-ext/config.m4"
install -m 0755 "$ROOT/php-ext/build.sh" "$PKG/usr/src/maat/php-ext/build.sh"
install -d -m 0755 "$PKG/usr/src/maat/php-ext/tests"
install -m 0644 "$ROOT/php-ext/tests/"*.phpt "$PKG/usr/src/maat/php-ext/tests/"
install -m 0644 "$ROOT/etc/maat/sshd_http.conf" "$PKG/etc/maat/sshd_http.conf"
install -m 0644 "$ROOT/systemd/maat-http-broker.service" "$PKG/lib/systemd/system/maat-http-broker.service"
install -m 0644 "$ROOT/systemd/maat-sshd-http.service" "$PKG/lib/systemd/system/maat-sshd-http.service"
install -m 0644 "$ROOT/etc/maat/uid_range.dab" "$PKG/etc/maat/uid_range.dab"
install -m 0644 "$ROOT/etc/maat/sshd_config" "$PKG/etc/maat/sshd_config"
install -m 0644 "$ROOT/systemd/maat-sshd.service" "$PKG/lib/systemd/system/maat-sshd.service"
install -m 0644 "$ROOT/systemd/maat-monitor-receiver.service" "$PKG/lib/systemd/system/maat-monitor-receiver.service"
install -m 0644 "$ROOT/README.md" "$PKG/usr/share/doc/maat-sshd/README"
install -m 0644 "$OPENSSH/LICENCE" "$PKG/usr/share/doc/maat-sshd/copyright"
cat > "$PKG/DEBIAN/control" <<'CONTROL'
Package: maat-sshd
Version: 0.14.0-1
Section: net
Priority: optional
Architecture: amd64
Maintainer: Maât Project <maintainers@localhost.invalid>
Depends: libc6 (>= 2.38), libstdc++6, libsqlite3-0, libssl3t64, libcrypt1, libzstd1, zlib1g, passwd, php8.4-common
Description: Experimental Maât OpenSSH with SSH-to-HTTP identity bridge
 Dedicated sshd, durable Unix receiver, single-use identity broker and HTTP bridge.
 Not a citizen identity validator. Services are not enabled automatically.
CONTROL
cat > "$PKG/DEBIAN/conffiles" <<'CONFFILES'
/etc/maat/sshd_config
/etc/maat/sshd_http.conf
/etc/maat/uid_range.dab
CONFFILES
cat > "$PKG/DEBIAN/postinst" <<'POSTINST'
#!/bin/sh
set -e
if [ "$1" = configure ]; then
    if ! getent passwd maatweb >/dev/null; then
        useradd --system --no-create-home --home-dir /nonexistent \
            --shell /bin/false maatweb
    fi
    if ! getent passwd maatsshd >/dev/null; then
        useradd --system --no-create-home --home-dir /var/empty/maat \
            --shell /usr/sbin/nologin maatsshd
    fi
    install -d -m 0755 -o root -g root /var/empty/maat
    install -d -m 0700 -o root -g root /etc/maat /var/lib/maat
    if [ ! -e /etc/maat/ssh_host_ed25519_key ]; then
        /usr/lib/maat/ssh-keygen -q -t ed25519 -N '' -f /etc/maat/ssh_host_ed25519_key
    fi
    /usr/sbin/maat-check-config /etc/maat/uid_range.dab >/dev/null
    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload >/dev/null 2>&1 || :
    fi
fi
exit 0
POSTINST
chmod 0755 "$PKG/DEBIAN/postinst"
chmod 0755 "$PKG/DEBIAN"
chmod g-s "$PKG/DEBIAN"
# Intentionally do not enable or start SSH services in maintainer scripts.
find "$PKG" -type d -exec chmod g-s {} +
dpkg-deb --build --root-owner-group "$PKG" "$OUT/maat-sshd_0.14.0-1_amd64.deb"
printf 'Wrote %s\n' "$OUT/maat-sshd_0.14.0-1_amd64.deb"
