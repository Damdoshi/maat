#!/usr/bin/env bash
# Smoke test for the native PHP Maât extension under PRIVATE mod_php Apache.
# No root, no system service restart, no changes to the host's Apache config.
set -euo pipefail

if [ "$(id -u)" -eq 0 ]; then
    echo 'ERROR: run as an ordinary user; this test never needs sudo.' >&2
    exit 2
fi

ROOT=$(cd "$(dirname "$0")/.." && pwd)
EXTENSION=${MAAT_NATIVE_EXTENSION:-"$ROOT/php-ext/modules/maat.so"}
PHP_CONFIG_BIN=${PHP_CONFIG_BIN:-php-config}
PHP_BIN=${PHP_BIN:-php}
for tool in apache2 "$PHP_CONFIG_BIN" "$PHP_BIN" python3; do
    command -v "$tool" >/dev/null 2>&1 || { echo "Missing: $tool" >&2; exit 2; }
done
[ -s "$EXTENSION" ] || { echo "Missing extension: $EXTENSION" >&2; exit 2; }
EXTENSION=$(realpath "$EXTENSION")
MAAT_MOD="$ROOT/modules/mod_maat/.libs/mod_maat.so"
[ -s "$MAAT_MOD" ] || { echo "Missing mod_maat.so: $MAAT_MOD" >&2; exit 2; }
MAAT_MOD=$(realpath "$MAAT_MOD")
# The helper drains all phpinfo output, so pipefail cannot mistake a
# successful grep -q match for an extension failure due to SIGPIPE.
PHP_BIN="$PHP_BIN" "$ROOT/tools/check-php-maat-abi.sh" "$EXTENSION"

CLI_VER=$($PHP_BIN -r 'echo PHP_MAJOR_VERSION,".",PHP_MINOR_VERSION;')
DEV_VER=$($PHP_CONFIG_BIN --version | cut -d. -f1,2)
[ "$CLI_VER" = "$DEV_VER" ] || {
    echo "PHP CLI ($CLI_VER) and development headers ($DEV_VER) differ" >&2; exit 2;
}
MOD_PHP="/usr/lib/apache2/modules/libphp${CLI_VER}.so"
[ -r "$MOD_PHP" ] || {
    echo "Missing mod_php: $MOD_PHP" >&2; exit 2;
}

TMP=$(mktemp -d /tmp/maat-native-apache-XXXXXXXX)
APACHE_PID=''
cleanup() {
    if [ -n "$APACHE_PID" ]; then
        kill "$APACHE_PID" 2>/dev/null || true
        wait "$APACHE_PID" 2>/dev/null || true
    fi
    if [ "${MAAT_KEEP_SMOKE_LOGS:-0}" = 1 ]; then
        echo "Retained private Apache diagnostics: $TMP"
    else
        rm -rf "$TMP"
    fi
}
trap cleanup EXIT
mkdir -p "$TMP/htdocs" "$TMP/php-scan"

cat > "$TMP/htdocs/whoami.php" <<'PHP'
<?php
header('Content-Type: application/json');
function nested_auth_maat_smoke() { return $_AUTH; }
$auth = nested_auth_maat_smoke();
echo json_encode([
    'extension_loaded' => extension_loaded('maat'),
    'php_version' => PHP_VERSION,
    'auth' => $auth,
    'superglobal_exists' => array_key_exists('_AUTH', $GLOBALS),
    'ticket_visible' => isset($_SERVER['HTTP_X_MAAT_TICKET']),
], JSON_THROW_ON_ERROR), "\n";
PHP
printf 'extension=%s\n' "$EXTENSION" > "$TMP/php-scan/maat.ini"

PORT=$(python3 - <<'PY'
import socket
with socket.socket() as s:
    s.bind(('127.0.0.1', 0))
    print(s.getsockname()[1])
PY
)
cat > "$TMP/apache.conf" <<EOF_APACHE
ServerRoot /etc/apache2
ServerName 127.0.0.1
Listen 127.0.0.1:$PORT
PidFile $TMP/apache.pid
ErrorLog $TMP/apache-error.log
LogLevel warn
LoadModule mpm_prefork_module /usr/lib/apache2/modules/mod_mpm_prefork.so
LoadModule authz_core_module /usr/lib/apache2/modules/mod_authz_core.so
LoadModule php_module $MOD_PHP
LoadModule maat_module $MAAT_MOD
MaatIngress Off
User $(id -un)
Group $(id -gn)
DocumentRoot "$TMP/htdocs"
<Directory "$TMP/htdocs">
    Require all granted
    Options -Indexes -FollowSymLinks
    <FilesMatch "\\.php$">
        SetHandler application/x-httpd-php
    </FilesMatch>
</Directory>
EOF_APACHE
apache2 -t -f "$TMP/apache.conf" > "$TMP/config-check.out" 2>&1 || {
    cat "$TMP/config-check.out" >&2; exit 1;
}

# Leading ':' also scans the normal Apache PHP ini configuration, then our
# disposable extension declaration. No a2enmod/phpenmod or service restart.
PHP_INI_SCAN_DIR="${PHP_INI_SCAN_DIR:-}:$TMP/php-scan" apache2 -X -f "$TMP/apache.conf" > "$TMP/apache-stdout.log" 2>&1 &
APACHE_PID=$!

python3 - "$PORT" "$TMP/apache-error.log" "$TMP/apache-stdout.log" <<'PY'
import json
import sys
import time
from urllib.request import Request, urlopen
from urllib.error import HTTPError

port, errfile, stdoutfile = sys.argv[1:]
url = f'http://127.0.0.1:{port}/whoami.php'

def fetch(headers):
    try:
        with urlopen(Request(url, headers=headers), timeout=3) as res:
            assert res.status == 200, res.status
            return json.loads(res.read())
    except HTTPError as exc:
        return {'http_error': exc.code}

for attempt in range(40):
    try:
        fetch({})
        break
    except Exception:
        if attempt == 39:
            for p in (stdoutfile, errfile):
                try:
                    print(open(p).read(), file=sys.stderr)
                except OSError:
                    pass
            raise
        time.sleep(.075)

# With no valid broker capability, even a 64-char spoofed ticket must not
# authenticate. Repetition detects potential request-to-request state leaks.
for n in range(40):
    headers = {} if n % 2 == 0 else {
        'X-Maat-Ticket': 'f' * 64,
        'X-Maat-User': 'forged',
    }
    result = fetch(headers)
    assert result['extension_loaded'] is True, result
    assert result['superglobal_exists'] is True, result
    assert result['auth'] is None, result
    assert result['ticket_visible'] is False, result
print('PASS mod_maat + native maat.so loaded into isolated mod_php Apache')
print('PASS $_AUTH available from nested function and NULL without Maât')
print('PASS 40 ordinary/forged requests with no cross-request identity leakage')
print('NOTE: true authenticated SSH -> Apache -> $_AUTH is the disposable-root E2E test')
PY
