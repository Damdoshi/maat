#!/bin/sh
# Fetch/verify official httpd 2.4.69; never trust an unverified source tarball.
# Optional argument: pre-downloaded httpd-2.4.69.tar.gz for offline machines.
set -eu
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
VERSION=2.4.69
EXPECTED=c551b9861e26f146f57e1b1765e69c89a60b3db0ec252ccab0d36283487016bb
TARGET="$ROOT/libs/apache-httpd"
[ ! -e "$TARGET" ] || {
    echo "Apache already present at $TARGET; refusing overwrite" >&2
    exit 2
}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT HUP INT TERM
if [ "$#" -gt 0 ]; then
    [ "$#" -eq 1 ] || { echo 'Provide one archive only' >&2; exit 2; }
    cp -- "$1" "$WORK/httpd.tar.gz"
else
    command -v curl >/dev/null || { echo 'curl missing' >&2; exit 2; }
    curl --fail --location --proto '=https' --tlsv1.2 --retry 2 \
        --connect-timeout 8 --max-time 120 \
        'https://downloads.apache.org/httpd/httpd-2.4.69.tar.gz' \
        -o "$WORK/httpd.tar.gz"
fi
ACTUAL=$(sha256sum "$WORK/httpd.tar.gz" | cut -d' ' -f1)
[ "$ACTUAL" = "$EXPECTED" ] || {
    echo "FAIL Apache hash mismatch: got $ACTUAL, expected $EXPECTED" >&2
    exit 3
}
# Archive paths are covered by the cryptographic upstream digest.
mkdir "$WORK/unpack"
tar -xzf "$WORK/httpd.tar.gz" -C "$WORK/unpack"
[ -f "$WORK/unpack/httpd-$VERSION/configure" ] || {
    echo 'Invalid upstream tree' >&2; exit 4;
}
mv "$WORK/unpack/httpd-$VERSION" "$TARGET"
printf '%s  %s\n' "$EXPECTED" "httpd-$VERSION.tar.gz" > "$TARGET/.maat-upstream.sha256"
echo "PASS verified upstream Apache HTTP Server $VERSION in libs/apache-httpd"
