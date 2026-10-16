#!/usr/bin/env bash
# EXPERIMENTAL. Disposable root VM/container ONLY; modifies Maât test account.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
if [ "${MAAT_CONFIRM_DISPOSABLE_VM:-}" != yes ] || [ "$(id -u)" -ne 0 ]; then
    echo 'SKIP: use disposable VM/container root with MAAT_CONFIRM_DISPOSABLE_VM=yes' >&2
    exit 77
fi
MODULE=${MAAT_NATIVE_EXTENSION:-"$ROOT/php-ext/modules/maat.so"}
[ -s "$MODULE" ] || { echo 'Missing native maat.so' >&2; exit 2; }
[ -s "$ROOT/modules/mod_maat/.libs/mod_maat.so" ] || {
    echo 'Missing mod_maat DSO' >&2; exit 2;
}
"$ROOT/tools/check-php-maat-abi.sh" "$MODULE"
MAAT_NATIVE_EXTENSION="$(realpath "$MODULE")" \
    "$ROOT/tests/e2e_native_apache.sh"
