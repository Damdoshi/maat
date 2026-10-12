#!/bin/bash
# Run only inside a disposable Debian 13 container/VM, as root.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SSH="$ROOT/libs/openssh-portable"
BUILD="${MAAT_BUILD_DIR:-$ROOT/build}"
TMP="$(mktemp -d /tmp/maat-http-e2e-XXXXXX)"
chmod 0755 "$TMP"
USER=maatweb
ORIGINAL_HASH=$(getent shadow "$USER" | cut -d: -f2)
ORIGINAL_SHELL=$(getent passwd "$USER" | cut -d: -f7)
[ -n "$ORIGINAL_HASH" ] || { echo 'Missing Maât account' >&2; exit 77; }
PIDS=()
restore() {
  for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || :; done
  for pid in "${PIDS[@]}"; do wait "$pid" 2>/dev/null || :; done
  if [ -f "$TMP/sshd-auth.backup" ]; then cp "$TMP/sshd-auth.backup" /usr/lib/maat/sshd-auth; else rm -f /usr/lib/maat/sshd-auth; fi
  if [ -f "$TMP/sshd-session.backup" ]; then cp "$TMP/sshd-session.backup" /usr/lib/maat/sshd-session; else rm -f /usr/lib/maat/sshd-session; fi
  usermod -p "$ORIGINAL_HASH" -s "$ORIGINAL_SHELL" "$USER" >/dev/null 2>&1 || :
  rm -f /run/maat/monitor.sock /run/maat-http/bind.sock /run/maat-http/check.sock
  rm -rf "$TMP"
}
if [ "$(id -u)" -ne 0 ] || [ -e /run/maat/monitor.sock ] || [ -e /run/maat-http/bind.sock ]; then
  echo 'TEST PRECONDITIONS FAILED: disposable root container, no existing service' >&2;exit 77
fi
trap restore EXIT
mkdir -p /usr/lib/maat /var/empty/maat
for f in sshd-auth sshd-session; do
  [ ! -f "/usr/lib/maat/$f" ] || cp "/usr/lib/maat/$f" "$TMP/$f.backup"
  cp "$SSH/$f" "/usr/lib/maat/$f"
done
usermod -s /bin/false -p "$(openssl passwd -6 "$(openssl rand -hex 24)")" "$USER"
"$SSH/ssh-keygen" -q -t ed25519 -N '' -f "$TMP/key"
"$SSH/ssh-keygen" -q -t ed25519 -N '' -f "$TMP/host"
cp "$TMP/key.pub" "$TMP/authorized"
PORT="$(python3 - <<'PY'
import socket
s=socket.socket();s.bind(('127.0.0.1',0));print(s.getsockname()[1]);s.close()
PY
)"
cat > "$TMP/ssh.conf" <<EOF_CONF
Port $PORT
ListenAddress 127.0.0.1
HostKey $TMP/host
PidFile $TMP/sshd.pid
AuthorizedKeysFile $TMP/authorized
StrictModes no
PubkeyAuthentication yes
AuthenticationMethods publickey
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
AllowUsers $USER
ForceCommand $BUILD/maat-http-bridge
PermitTTY no
DisableForwarding yes
PermitUserEnvironment no
PermitUserRC no

LogLevel DEBUG1
EOF_CONF
"$SSH/sshd" -t -f "$TMP/ssh.conf"
"$BUILD/maat-monitor-receiver" >"$TMP/monitor.log" 2>&1 & PIDS+=("$!")
for i in $(seq 1 100); do [ -S /run/maat/monitor.sock ] && break; sleep 0.05; done
[ -S /run/maat/monitor.sock ]
"$BUILD/maat-http-broker" root /var/lib/maat/monitor.db "$ROOT/etc/maat/uid_range.dab" >"$TMP/broker.log" 2>&1 & PIDS+=("$!")
for i in $(seq 1 100); do [ -S /run/maat-http/bind.sock ] && break; sleep 0.05; done
[ -S /run/maat-http/bind.sock ] || { cat "$TMP/broker.log"; exit 1; }
php -d "auto_prepend_file=$ROOT/php/maat_auth.php" -S 127.0.0.1:18081 -t "$ROOT/php" > "$TMP/php.log" 2>&1 & PIDS+=("$!")
"$SSH/sshd" -D -e -f "$TMP/ssh.conf" > "$TMP/sshd.log" 2>&1 & PIDS+=("$!")
sleep .4
OPTS=(-F /dev/null -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o IdentitiesOnly=yes -o PreferredAuthentications=publickey -o ConnectTimeout=5 -p "$PORT" -i "$TMP/key")
printf 'GET /whoami.php HTTP/1.1\r\nHost: localhost\r\nX-Maat-User: forged\r\nX-Maat-Ticket: forged\r\n\r\n' |
  "$SSH/ssh" -T "${OPTS[@]}" "$USER@127.0.0.1" ignored >"$TMP/result" 2>"$TMP/ssh.err" || {
  cat "$TMP/ssh.err" "$TMP/broker.log" "$TMP/monitor.log"; tail -35 "$TMP/sshd.log"; exit 1;
}
python3 - "$TMP/result" "$TMP/key.pub" <<'PY_CHECK'
import json,base64,sys
r=open(sys.argv[1],'rb').read().decode(errors='replace')
assert '200 OK' in r,r
body=r.split('\r\n\r\n',1)[-1]
try: obj=json.loads(body)
except: print(repr(r));raise
assert obj['authenticated'] is True, obj
assert obj['identity_verified'] is False, obj
assert obj['ssh_user']=='maatweb',obj
assert obj['public_key'].split()[1]==open(sys.argv[2]).read().split()[1],obj
print('PASS real SSH -> broker -> HTTP -> PHP key identity')
PY_CHECK
python3 - <<'PY_ANON'
import urllib.request,json
for h in ({}, {'X-Maat-Ticket':'f'*64,'X-Maat-User':'forged'}):
    data=urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:18081/whoami.php',headers=h),timeout=3).read()
    assert json.loads(data) is None,data
print('PASS ordinary HTTP and forged ticket -> PHP null')
PY_ANON
"$SSH/ssh-keygen" -q -t ed25519 -N '' -f "$TMP/wrong"
BAD_OPTS=(${OPTS[@]})
BAD_OPTS[${#BAD_OPTS[@]}-1]="$TMP/wrong"
if printf 'GET /whoami.php HTTP/1.1\r\nHost: localhost\r\n\r\n' | "$SSH/ssh" -T "${BAD_OPTS[@]}" "$USER@127.0.0.1" ignored >/dev/null 2>&1; then
 echo 'FAIL wrong SSH key succeeded' >&2;exit 1
fi
echo 'PASS wrong SSH key refused'
# No ordinary user may access the root-only session-registration socket.
if runuser -u "$USER" -- python3 - <<'PY_UNTRUSTED'
import socket
s=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)
try:
    s.connect('/run/maat-http/bind.sock')
except PermissionError:
    raise SystemExit(1)
PY_UNTRUSTED
then echo 'FAIL untrusted UID reached root registration socket' >&2; exit 1
fi
echo 'PASS untrusted UID cannot register SSH session'

# Profile complete authenticated HTTPS-less SSH -> PHP requests (local loopback)
python3 - "$SSH/ssh" "$PORT" "$TMP/key" "$USER" <<'PY_PROFILE'
import subprocess,sys,time,statistics
cli,port,key,user=sys.argv[1:]
args=[cli,'-F','/dev/null','-o','BatchMode=yes','-o','StrictHostKeyChecking=no',
 '-o','UserKnownHostsFile=/dev/null','-o','LogLevel=ERROR','-o','IdentitiesOnly=yes',
 '-p',port,'-i',key,'-T',user+'@127.0.0.1','ignored']
measure=[]
for _ in range(5):
    start=time.perf_counter()
    p=subprocess.run(args,input=b'GET /whoami.php HTTP/1.1\r\nHost: localhost\r\n\r\n',stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=12)
    assert p.returncode==0 and b'authenticated' in p.stdout,(p.returncode,p.stderr,p.stdout)
    measure.append((time.perf_counter()-start)*1000)
print('PROFILE five SSH-to-PHP complete requests: median %.1f ms, mean %.1f ms, max %.1f ms (loopback)' % (statistics.median(measure),statistics.mean(measure),max(measure)))
PY_PROFILE
# Failure of the broker must not result in an HTTP response carrying identity.
kill "${PIDS[1]}" 2>/dev/null || :
if printf 'GET /whoami.php HTTP/1.1\r\nHost: localhost\r\n\r\n' |
    "$SSH/ssh" -T "${OPTS[@]}" "$USER@127.0.0.1" ignored >"$TMP/brokerdown" 2>/dev/null; then
  echo 'FAIL broker failure permitted HTTP identity request' >&2; exit 1
fi
if grep -q '"authenticated"' "$TMP/brokerdown"; then
  echo 'FAIL authenticated result appeared despite dead broker' >&2; exit 1
fi
echo 'PASS broker failure fails closed for HTTP'
echo 'E2E HTTP PASS' 
