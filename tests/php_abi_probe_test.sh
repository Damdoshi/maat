#!/usr/bin/env bash
# Reproduces early-match SIGPIPE in `php -i | grep -q` with pipefail.
# This runs without PHP development headers, Apache or root.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
printf 'dummy\n' > "$TMP/maat.so"
cat > "$TMP/php-good" <<'SH'
#!/bin/sh
printf 'Apache request ABI => native enabled (PHP 8.1 only)\n'
sleep 0.04
python3 -c 'import sys; sys.stdout.write("Z" * 500000); sys.stdout.flush()'
SH
cat > "$TMP/php-no-abi" <<'SH'
#!/bin/sh
printf 'Apache request ABI => disabled\n'
SH
cat > "$TMP/php-broken" <<'SH'
#!/bin/sh
printf 'Apache request ABI => native enabled\n'
exit 17
SH
chmod +x "$TMP/php-good" "$TMP/php-no-abi" "$TMP/php-broken"
PHP_BIN="$TMP/php-good" "$ROOT/tools/check-php-maat-abi.sh" "$TMP/maat.so" || {
    echo 'FAIL: false-negative from early match / SIGPIPE' >&2
    exit 1
}
if PHP_BIN="$TMP/php-no-abi" "$ROOT/tools/check-php-maat-abi.sh" "$TMP/maat.so" >/dev/null 2>&1; then
    echo 'FAIL: accepted a module without native ABI' >&2
    exit 1
fi
if PHP_BIN="$TMP/php-broken" "$ROOT/tools/check-php-maat-abi.sh" "$TMP/maat.so" >/dev/null 2>&1; then
    echo 'FAIL: accepted a failed PHP process' >&2
    exit 1
fi
printf 'PASS ABI probe drains phpinfo, rejects missing ABI and propagates PHP errors\n'
