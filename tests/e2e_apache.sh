#!/bin/bash
# Run only inside a disposable Debian 13 container/VM, as root.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SSH="$ROOT/libs/openssh-portable"
BUILD="${MAAT_BUILD_DIR:-$ROOT/build}"
TMP="$(mktemp -d /tmp/maat-http-e2e-XXXXXX)"
chmod 0755 "$TMP"
USER=maatweb
# Disposable VM only: temporarily unlock the existing Maât system account.
ORIGINAL_HASH=$(getent shadow "$USER" | cut -d: -f2)
ORIGINAL_SHELL=$(getent passwd "$USER" | cut -d: -f7)
[ -n "$ORIGINAL_HASH" ] || { echo 'Missing Maât test account' >&2; exit 77; }
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
"$BUILD/maat-http-broker" www-data /var/lib/maat/monitor.db "$ROOT/etc/maat/uid_range.dab" >"$TMP/broker.log" 2>&1 & PIDS+=("$!")
for i in $(seq 1 100); do [ -S /run/maat-http/bind.sock ] && break; sleep 0.05; done
[ -S /run/maat-http/bind.sock ] || { cat "$TMP/broker.log"; exit 1; }
PHP_PREPEND="php_admin_value auto_prepend_file \"$ROOT/php/maat_auth.php\""
if [ -n "${MAAT_NATIVE_EXTENSION:-}" ]; then
  [ -f "$MAAT_NATIVE_EXTENSION" ] || { echo 'Native PHP extension not found' >&2; exit 77; }
  mkdir -p "$TMP/php-scan"
  printf 'extension=%s\n' "$MAAT_NATIVE_EXTENSION" > "$TMP/php-scan/maat.ini"
  PHP_PREPEND=''
fi
cat > "$TMP/apache.conf" <<EOF_APACHE
ServerRoot /etc/apache2
ServerName localhost
PidFile $TMP/apache.pid
Listen 127.0.0.1:18081
LoadModule mpm_prefork_module /usr/lib/apache2/modules/mod_mpm_prefork.so
LoadModule authz_core_module /usr/lib/apache2/modules/mod_authz_core.so
LoadModule php_module /usr/lib/apache2/modules/libphp8.4.so
User www-data
Group www-data
ErrorLog $TMP/apache.log
LogLevel warn
DocumentRoot $ROOT/php
<Directory "$ROOT/php">
    Require all granted
    Options -Indexes -FollowSymLinks
$PHP_PREPEND
    <FilesMatch "\\.php$">
        SetHandler application/x-httpd-php
    </FilesMatch>
</Directory>
EOF_APACHE
apache2 -t -f "$TMP/apache.conf"
PHP_INI_SCAN_DIR="${PHP_INI_SCAN_DIR:-}:$TMP/php-scan" apache2 -X -f "$TMP/apache.conf" > "$TMP/apache.stdout" 2>&1 & PIDS+=("$!")
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
print('PASS real SSH -> broker -> HTTP -> PHP with /bin/false login shell (direct bridge exec)')
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

# Critical 0.13 regression: two concurrent SSH connections authenticated as
# the SAME SSH Unix account must run their bridges under DIFFERENT kernel UIDs.
# Keep stdin incomplete to pin both connections inside HTTPRequest::read().
python3 - "$SSH/ssh" "$PORT" "$TMP/key" "$USER" "$BUILD/maat-http-bridge" <<'PY_EPHEMERAL'
import os,sys,subprocess,time,pwd
cli,port,key,user,bridge=sys.argv[1:]
args=[cli,'-F','/dev/null','-o','BatchMode=yes','-o','StrictHostKeyChecking=no',
 '-o','UserKnownHostsFile=/dev/null','-o','LogLevel=ERROR','-o','IdentitiesOnly=yes',
 '-p',port,'-i',key,'-T',user+'@127.0.0.1','ignored']
children=[subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
 stderr=subprocess.PIPE) for _ in range(2)]
def matches():
    found=[]
    for name in os.listdir('/proc'):
        if not name.isdigit():continue
        try:
            cmd=open(f'/proc/{name}/cmdline','rb').read().split(b'\0')[0].decode()
            if cmd!=bridge:continue
            status=open(f'/proc/{name}/status').read()
            uid=int(next(line for line in status.splitlines() if line.startswith('Uid:')).split()[1])
            found.append((int(name),uid))
        except (OSError,StopIteration):pass
    return found
try:
    for proc in children:
        proc.stdin.write(b'GET /whoami.php HTTP/1.1\r\nHost: localhost\r\n')
        proc.stdin.flush()
    limit=time.monotonic()+6
    found=[]
    while time.monotonic()<limit:
        found=matches()
        if len(found)>=2:break
        time.sleep(.05)
    assert len(found)==2, f'Expected two real SSH bridge processes, got {found}'
    first,second=found
    assert first[1]!=second[1], f'sessions share kernel UID: {found}'
    assert all(1000000000<=uid<=2099999999 for pid,uid in found), found
    assert all(uid!=pwd.getpwnam(user).pw_uid for pid,uid in found), found
    # /proc fd/3 stays inaccessible from the ordinary shared account AND
    # from another ephemeral session UID, even across execve transitions.
    for victim in found:
        for attacker_uid in (pwd.getpwnam(user).pw_uid,
                             next(uid for pid,uid in found if pid!=victim[0])):
            script='import os,sys; os.readlink(sys.argv[1])'
            # Preexec setuid with gid removal (script only runs as root in VM).
            def lower(uid=attacker_uid):
                os.setgroups([]);os.setgid(65534);os.setuid(uid)
            probe=subprocess.run([sys.executable,'-c',script,
               f'/proc/{victim[0]}/fd/3'],preexec_fn=lower,
               stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=3)
            assert probe.returncode!=0, (victim,attacker_uid)
    print('PASS two simultaneous SSH sessions: unique kernel UIDs and cross-session /proc isolation',found)
finally:
    for proc in children:
        if proc.stdin and not proc.stdin.closed:proc.stdin.close()
        proc.terminate()
    for proc in children:
        try:proc.communicate(timeout=3)
        except (subprocess.TimeoutExpired,ValueError):
            proc.kill();proc.wait(timeout=3)
PY_EPHEMERAL

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

