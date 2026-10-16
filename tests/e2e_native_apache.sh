#!/usr/bin/env bash
# Root-only IN A DISPOSABLE VM/CONTAINER. This delegates to e2e_apache.sh,
# which temporarily changes a Unix account and root-owned test files.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
if [ "${MAAT_CONFIRM_DISPOSABLE_VM:-}" != yes ] || [ "$(id -u)" -ne 0 ]; then
    echo 'SKIP: native SSH-to-Apache E2E requires disposable root VM/container and MAAT_CONFIRM_DISPOSABLE_VM=yes' >&2
    exit 77
fi
PHP_BIN=${PHP_BIN:-php}
PHP_CONFIG_BIN=${PHP_CONFIG_BIN:-php-config}
SO=${MAAT_NATIVE_EXTENSION:-"$ROOT/php-ext/modules/maat.so"}
for command in "$PHP_BIN" "$PHP_CONFIG_BIN" realpath; do
    command -v "$command" >/dev/null 2>&1 || { echo "Missing $command" >&2; exit 2; }
done
[ -s "$SO" ] || { echo "Missing native PHP extension: $SO" >&2; exit 2; }
SO=$(realpath "$SO")
cli_version=$("$PHP_BIN" -r 'echo PHP_MAJOR_VERSION,".",PHP_MINOR_VERSION;')
dev_version=$("$PHP_CONFIG_BIN" --version | cut -d. -f1,2)
[ "$cli_version" = "$dev_version" ] || {
    echo "PHP CLI ($cli_version) != header ABI ($dev_version)" >&2; exit 2;
}
if ! "$PHP_BIN" -n -d "extension=$SO" -r '
    if (!extension_loaded("maat")) exit(10);
    function check_native_maat() { return array_key_exists("_AUTH", $GLOBALS) && $_AUTH === NULL; }
    if (!check_native_maat()) exit(11);
'; then
    echo 'Native maat.so failed CLI load/anonymous superglobal preflight' >&2; exit 2
fi
printf 'PASS native extension PHP %s preflight, launching disposable SSH/Apache E2E\n' "$cli_version"
MAAT_E2E_APACHE_DIRECT=1 MAAT_NATIVE_EXTENSION="$SO" PHP_CONFIG_BIN="$PHP_CONFIG_BIN" "$ROOT/tests/e2e_apache.sh"
