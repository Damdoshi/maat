#!/usr/bin/env bash
# Ensure the native module exposes mod_maat's verified Apache request context.
# Consume ALL phpinfo output: grep -q can SIGPIPE PHP when pipefail is set.
set -euo pipefail

if [ "$#" -ne 1 ] || [ ! -s "$1" ]; then
    echo 'ERROR: expected an existing non-empty maat.so argument' >&2
    exit 2
fi
PHP_BIN=${PHP_BIN:-php}
command -v "$PHP_BIN" >/dev/null 2>&1 || {
    echo "ERROR: PHP binary not found: $PHP_BIN" >&2
    exit 2
}
if ! "$PHP_BIN" -n -d "extension=$1" -i | \
    grep -F 'Apache request ABI => native enabled' >/dev/null; then
    echo 'ERROR: php-maat native Apache request ABI is unavailable (or PHP failed)' >&2
    exit 2
fi
