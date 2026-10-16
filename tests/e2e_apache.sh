#!/bin/bash
# Run only inside a disposable container/VM, as root. NEVER run on a production host.
set -euo pipefail
# Require an image-build marker in addition to the explicit opt-in. Merely
# setting MAAT_CONFIRM_DISPOSABLE_VM on a workstation is not sufficient.
if [ ! -f /etc/maat-disposable-test-image ] &&
   [ ! -f /etc/maat-disposable-qemu-e2e ]; then
  echo 'REFUSED: disposable Docker or QEMU image marker absent.' >&2
  exit 77
fi
if [ "${MAAT_CONFIRM_DISPOSABLE_VM:-}" != 'yes' ]; then
  echo 'Refusing dangerous privileged E2E test: it changes accounts and /usr/lib/maat.' >&2
  echo 'Use MAAT_CONFIRM_DISPOSABLE_VM=yes ONLY on a disposable container/VM.' >&2
  exit 77
fi
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
  local result=$?
  for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || :; done
  for pid in "${PIDS[@]}"; do wait "$pid" 2>/dev/null || :; done
  # Docker has no bind mount to the host. Preserve actionable failure logs
  # in its stdout/stderr before the throwaway container is discarded.
  if [ "$result" -ne 0 ]; then
    echo "Maât disposable E2E failed (exit=$result); recent service logs:" >&2
    for name in monitor.log broker.log sshd.log apache.log apache.stdout ssh.err; do
      if [ -f "$TMP/$name" ]; then
        echo "--- $name ---" >&2
        tail -n 40 "$TMP/$name" >&2 || :
      fi
    done
    # Keep fatal errors visible even when >40 concurrent sshd events follow.
    if [ -f "$TMP/sshd.log" ]; then
      echo '--- sshd security/transport diagnostics ---' >&2
      grep -aEi 'fatal|error|reject|refus|drop connection|exceeded|resource|busy|binding' \
        "$TMP/sshd.log" | tail -n 60 >&2 || :
    fi
  fi
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
# A second independent Ed25519 identity uses the SAME SSH Unix account.
# The test must distinguish the keys, not confuse the login with identity.
"$SSH/ssh-keygen" -q -t ed25519 -N '' -f "$TMP/key_second"
cat "$TMP/key_second.pub" >> "$TMP/authorized"
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
# The repository is writable by the unprivileged image build user. The
# broker MUST NEVER accept a UID-range file owned by that user: it requires a
# root-owned, non-group/world-writable regular file (O_NOFOLLOW + fstat).
# Install a disposable root-owned copy, without changing production config.
UID_CONFIG="$TMP/uid_range.dab"
install -o root -g root -m 0600 "$ROOT/etc/maat/uid_range.dab" "$UID_CONFIG"
"$BUILD/maat-check-config" "$UID_CONFIG" >"$TMP/uid-range-check.log" 2>&1 || {
  cat "$TMP/uid-range-check.log" >&2
  echo 'FAIL invalid/insecure disposable UID configuration' >&2
  exit 1
}
"$BUILD/maat-http-broker" www-data /var/lib/maat/monitor.db "$UID_CONFIG" >"$TMP/broker.log" 2>&1 & PIDS+=("$!")
for i in $(seq 1 100); do [ -S /run/maat-http/bind.sock ] && break; sleep 0.05; done
[ -S /run/maat-http/bind.sock ] || { cat "$TMP/broker.log"; exit 1; }
PHP_PREPEND=''
if [ "${MAAT_E2E_APACHE_DIRECT:-0}" != 1 ] || [ -z "${MAAT_NATIVE_EXTENSION:-}" ]; then
  echo 'Only descriptor-bound native E2E is supported (use e2e_native_apache_direct.sh)' >&2
  exit 77
fi
if [ -n "${MAAT_NATIVE_EXTENSION:-}" ]; then
  [ -f "$MAAT_NATIVE_EXTENSION" ] || { echo 'Native PHP extension not found' >&2; exit 77; }
  mkdir -p "$TMP/php-scan"
  printf 'extension=%s\n' "$MAAT_NATIVE_EXTENSION" > "$TMP/php-scan/maat.ini"
  PHP_PREPEND=''
fi
# Match the Apache PHP module to the PHP extension build ABI.
PHP_CONFIG_BIN="${PHP_CONFIG_BIN:-php-config}"
PHP_VERSION="$($PHP_CONFIG_BIN --version | cut -d. -f1,2)"
PHP_APACHE_MODULE="/usr/lib/apache2/modules/libphp${PHP_VERSION}.so"
[ -f "$PHP_APACHE_MODULE" ] || {
  echo "Missing mod_php for PHP ${PHP_VERSION}: ${PHP_APACHE_MODULE}" >&2
  exit 77
}
APACHE_MAAT_DIRECT=''
if [ "${MAAT_E2E_APACHE_DIRECT:-0}" = 1 ]; then
  MODULE="$ROOT/modules/mod_maat/.libs/mod_maat.so"
  [ -s "$MODULE" ] || { echo 'Missing compiled mod_maat.so' >&2; exit 77; }
  [ -n "${MAAT_NATIVE_EXTENSION:-}" ] || { echo 'Native module is mandatory in direct mode' >&2; exit 77; }
  APACHE_MAAT_DIRECT="LoadModule maat_module $MODULE
MaatIngress On
"
fi
export MAAT_E2E_APACHE_DIRECT
cat > "$TMP/apache.conf" <<EOF_APACHE
ServerRoot /etc/apache2
ServerName localhost
PidFile $TMP/apache.pid
Listen 127.0.0.1:18081
LoadModule mpm_prefork_module /usr/lib/apache2/modules/mod_mpm_prefork.so
LoadModule authz_core_module /usr/lib/apache2/modules/mod_authz_core.so
LoadModule php_module $PHP_APACHE_MODULE
$APACHE_MAAT_DIRECT
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
# In native mode this exercises actual PHP auto-global population from
# real SSH assertions. Apache runs in -X mode so many requests reuse mod_php.
# Distinct SSH keys share one Unix login, but must NEVER share an identity.
python3 - "$SSH/ssh" "$PORT" "$TMP/key" "$TMP/key_second" "$USER" <<'PY_ROTATE'
import json
import subprocess
import sys
from urllib.request import Request, urlopen
from urllib.error import HTTPError
import os
cli, port, first, second, user = sys.argv[1:]

def ssh_request(key, forged):
    options = [cli, '-F', '/dev/null', '-o', 'BatchMode=yes',
               '-o', 'StrictHostKeyChecking=no',
               '-o', 'UserKnownHostsFile=/dev/null', '-o', 'LogLevel=ERROR',
               '-o', 'IdentitiesOnly=yes', '-o', 'PreferredAuthentications=publickey',
               '-o', 'ConnectTimeout=5', '-p', port, '-i', key,
               '-T', user + '@127.0.0.1', 'ignored']
    headers = b'X-Maat-User: impostor\r\nX-Maat-Ticket: ' + b'f' * 64 + b'\r\n' if forged else b''
    request = b'GET /whoami.php HTTP/1.1\r\nHost: localhost\r\n' + headers + b'\r\n'
    result = subprocess.run(options, input=request, capture_output=True, timeout=12)
    assert result.returncode == 0, (result.returncode, result.stderr, result.stdout)
    assert b'200 OK' in result.stdout, result.stdout
    return json.loads(result.stdout.split(b'\r\n\r\n', 1)[1])

def anonymous(forged):
    headers = {'X-Maat-User': 'impostor', 'X-Maat-Ticket': 'f' * 64} if forged else {}
    try:
        with urlopen(Request('http://127.0.0.1:18081/whoami.php', headers=headers), timeout=3) as response:
            assert response.status == 200
            assert json.loads(response.read()) is None, 'anonymous request leaked SSH identity'
    except HTTPError as e:
        assert os.environ.get('MAAT_E2E_APACHE_DIRECT') == '1' and e.code == 403, e

assert open(first + '.pub').read().split()[1] != open(second + '.pub').read().split()[1]
for index in range(12):
    key = (first, second)[index % 2]
    answer = ssh_request(key, forged=(index % 3 == 0))
    expected = open(key + '.pub').read().split()[1]
    assert answer['authenticated'] is True, answer
    assert answer['identity_verified'] is False, answer
    assert answer['transport'] == 'maat+ssh', answer
    assert answer['public_key'].split()[1] == expected, (index, answer, expected)
    assert answer['ssh_user'] == user, answer
    assert answer['attributes'] == [], answer
    anonymous(forged=(index % 2 == 0))
print('PASS 12 alternating SSH identities (same Unix login), no wrong-key / anonymous contamination')
PY_ROTATE
# Concurrent positive verification: multiple real SSH logins with distinct
# keys must not cross-contaminate the Apache per-request identity context.
python3 - "$SSH/ssh" "$PORT" "$TMP/key" "$TMP/key_second" "$USER" <<'PY_CONCURRENT'
import concurrent.futures
import json
import subprocess
import sys

cli, port, key_a, key_b, user = sys.argv[1:]
keys = (key_a, key_b)
expected = [open(k + '.pub').read().split()[1] for k in keys]
assert expected[0] != expected[1]

def query(index):
    key = keys[index % 2]
    args = [cli, '-F', '/dev/null', '-o', 'BatchMode=yes',
            '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null',
            '-o', 'LogLevel=ERROR', '-o', 'IdentitiesOnly=yes',
            '-o', 'PreferredAuthentications=publickey', '-o', 'ConnectTimeout=5',
            '-p', port, '-i', key, '-T', user + '@127.0.0.1', 'ignored']
    data = b'GET /whoami.php HTTP/1.1\r\nHost: localhost\r\n\r\n'
    result = subprocess.run(args, input=data, capture_output=True, timeout=20)
    assert result.returncode == 0, (index, result.stderr, result.stdout)
    assert b'200 OK' in result.stdout, (index, result.stdout)
    auth = json.loads(result.stdout.split(b'\r\n\r\n', 1)[1])
    assert auth['authenticated'] is True and auth['identity_verified'] is False, auth
    assert auth['public_key'].split()[1] == expected[index % 2], (index, auth)
    return index

with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
    assert sorted(executor.map(query, range(8))) == list(range(8))
print('PASS eight concurrent authenticated requests: Alice/Bob key isolation')
PY_CONCURRENT
python3 - <<'PY_ANON' 
import urllib.request,urllib.error,json,os
for h in ({}, {'X-Maat-Ticket':'f'*64,'X-Maat-User':'forged'}):
    try:
        data=urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:18081/whoami.php',headers=h),timeout=3).read()
        assert json.loads(data) is None,data
    except urllib.error.HTTPError as error:
        assert os.environ.get('MAAT_E2E_APACHE_DIRECT')=='1' and error.code==403,error
print('PASS anonymous is NULL and forged candidate never authenticates')
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

# Additional adversarial runs on the SAME real privileged services.
# Intentionally precedes broker-shutdown test: fresh valid SSH sessions must
# remain functional following malformed requests and interrupted clients.
python3 "$ROOT/tests/adversarial_http.py" \
    "$SSH/ssh" "$PORT" "$TMP/key" "$TMP/key_second" "$USER"

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
# Kill the broker AFTER OpenSSH has authenticated an identity, while its
# forced-command bridge is paused on an incomplete HTTP header. Completing
# the request must fail closed (no registered TCP proof survives broker loss).
python3 - "$SSH/ssh" "$PORT" "$TMP/key" "$USER" "$BUILD/maat-http-bridge" "${PIDS[1]}" <<'PY_INFLIGHT'
import os,signal,subprocess,sys,time
cli,port,key,user,bridge,broker=sys.argv[1:]
args=[cli,'-F','/dev/null','-o','BatchMode=yes','-o','StrictHostKeyChecking=no',
 '-o','UserKnownHostsFile=/dev/null','-o','LogLevel=ERROR','-o','IdentitiesOnly=yes',
 '-p',port,'-i',key,'-T',user+'@127.0.0.1','ignored']
child=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
try:
    child.stdin.write(b'GET /whoami.php HTTP/1.1\r\nHost: localhost\r\n')
    child.stdin.flush()
    # Wait until the *server-side* bridge is running, i.e. SSH auth is done.
    def bridge_running():
        for item in os.listdir('/proc'):
            if not item.isdigit(): continue
            try:
                if open('/proc/'+item+'/cmdline','rb').read().split(b'\0')[0].decode()==bridge:
                    return True
            except OSError: pass
        return False
    end=time.monotonic()+8
    while time.monotonic()<end and not bridge_running():
        time.sleep(.04)
    assert bridge_running(), 'SSH forced-command bridge did not start in time'
    os.kill(int(broker),signal.SIGTERM)
    time.sleep(.15)
    output,errors=child.communicate(input=b'\r\n',timeout=12)
    assert child.returncode!=0, (child.returncode,output,errors)
    assert b'"authenticated"' not in output.lower(), output
    print('PASS broker interrupted after SSH authentication denies in-flight HTTP request')
finally:
    if child.poll() is None:
        child.kill();child.communicate()
PY_INFLIGHT

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

