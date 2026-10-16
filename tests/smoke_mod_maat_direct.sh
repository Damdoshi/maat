#!/usr/bin/env bash
# PRIVATE Apache DSO smoke. No service installation or changes to /etc/apache2.
set -euo pipefail
if [ "$(id -u)" -eq 0 ]; then
    echo 'ERROR: run the isolated Apache smoke as a non-root user' >&2
    exit 2
fi
ROOT=$(cd "$(dirname "$0")/.." && pwd)
MODULE=${MAAT_APACHE_MODULE:-"$ROOT/modules/mod_maat/.libs/mod_maat.so"}
[ -s "$MODULE" ] || { echo "SKIP: no compiled mod_maat DSO at $MODULE" >&2; exit 77; }
APACHE=${MAAT_APACHE_BIN:-$(command -v apache2 || command -v httpd || true)}
[ -n "$APACHE" ] || { echo 'SKIP: no Apache binary' >&2; exit 77; }
TMP=$(mktemp -d)
PID=''
cleanup(){ if [ -n "$PID" ]; then kill "$PID" 2>/dev/null || :; wait "$PID" 2>/dev/null || :; fi; rm -rf "$TMP"; }
trap cleanup EXIT
mkdir -p "$TMP/htdocs"
printf 'hello' > "$TMP/htdocs/index.html"
PORT=$(python3 - <<'PY'
import socket
s=socket.socket();s.bind(('127.0.0.1',0));print(s.getsockname()[1]);s.close()
PY
)
MODULE=$(realpath "$MODULE")
cat > "$TMP/apache.conf" <<EOF_CONF
ServerRoot /etc/apache2
ServerName 127.0.0.1
Listen 127.0.0.1:$PORT
PidFile $TMP/apache.pid
ErrorLog $TMP/apache.log
LogLevel warn
LoadModule mpm_prefork_module /usr/lib/apache2/modules/mod_mpm_prefork.so
LoadModule authz_core_module /usr/lib/apache2/modules/mod_authz_core.so
LoadModule maat_module $MODULE
MaatIngress On
User $(id -un)
Group $(id -gn)
DocumentRoot $TMP/htdocs
<Directory "$TMP/htdocs">
  Require all granted
</Directory>
EOF_CONF
"$APACHE" -t -f "$TMP/apache.conf"
"$APACHE" -X -f "$TMP/apache.conf" >"$TMP/console.log" 2>&1 & PID=$!
python3 - "$PORT" <<'PY'
import sys,time
from urllib.request import Request,urlopen
from urllib.error import HTTPError
port=sys.argv[1]; url='http://127.0.0.1:'+port+'/index.html'
def get(headers):
    try:
        r=urlopen(Request(url,headers=headers), timeout=2)
        return r.status,r.read()
    except HTTPError as e:
        return e.code,e.read()
for _ in range(60):
    try:
        status,data=get({})
        if status==403: break
    except Exception: time.sleep(.05)
else: raise AssertionError('Apache never started')
assert get({})[0]==403
assert get({'X-Maat-Ticket':'invalid'})[0]==403
assert get({'X-Maat-User':'forged','X_Maat_Ticket':'fake'})[0]==403
print('PASS private Apache ingress denies unbound TCP requests and ignores bearer headers')
PY
