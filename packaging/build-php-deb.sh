#!/bin/sh
# Compile and test native module before creating php8.4-maat.deb.
# Requires php8.4-dev, php8.4-cli, phpize8.4, php-config8.4, dpkg-deb.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
"$ROOT/php-ext/build.sh"
API=$(php-config8.4 --phpapi)
[ -n "$API" ] || { echo 'Missing PHP API version' >&2; exit 2; }
PKG="$ROOT/.maat-php-package-root"
rm -rf "$PKG"
install -d "$PKG/DEBIAN" "$PKG/usr/lib/php/$API" "$PKG/etc/php/8.4/mods-available"
install -m 0644 "$ROOT/php-ext/modules/maat.so" "$PKG/usr/lib/php/$API/maat.so"
printf 'extension=maat.so\n' > "$PKG/etc/php/8.4/mods-available/maat.ini"
cat > "$PKG/DEBIAN/control" <<'EOF'
Package: php8.4-maat
Version: 0.14.0-1
Section: php
Priority: optional
Architecture: amd64
Maintainer: Maât Project <maintainers@localhost.invalid>
Depends: php8.4-common, maat-sshd (>= 0.14.0)
Description: Experimental native Maât $_AUTH superglobal for PHP 8.4
 Native module registers request-scoped _AUTH and verifies SSH tickets.
 Not a national civil identity validator. Enable manually after testing.
EOF
OUT="${MAAT_OUTPUT_DIRECTORY:-$ROOT/dist}"
mkdir -p "$OUT"
dpkg-deb --build --root-owner-group "$PKG" "$OUT/php8.4-maat_0.14.0-1_amd64.deb"
