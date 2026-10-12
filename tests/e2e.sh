#!/bin/bash
# Requires root. Operates only on loopback and isolated Maât files and users.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SSH="$ROOT/libs/openssh-portable"
TMP="$(mktemp -d /tmp/maat-e2e-XXXXXXXX)"
chmod 0755 "$TMP"
USER_NAME="maat_e2e"
PORT=0
RECEIVER_PID=''
SSH_PID=''
cleanup() {
  if [ -n "$SSH_PID" ]; then kill "$SSH_PID" 2>/dev/null || :; wait "$SSH_PID" 2>/dev/null || :; fi
  if [ -n "$RECEIVER_PID" ]; then kill "$RECEIVER_PID" 2>/dev/null || :; wait "$RECEIVER_PID" 2>/dev/null || :; fi
  rm -f /run/maat/monitor.sock
  userdel "$USER_NAME" 2>/dev/null || :
  rm -rf "$TMP"
}
trap cleanup EXIT
if [ "$(id -u)" -ne 0 ]; then echo 'SKIP: requires root'; exit 77; fi
if id "$USER_NAME" &>/dev/null; then echo "Refuse existing user $USER_NAME"; exit 2; fi
if [ -e /run/maat/monitor.sock ]; then echo 'Refuse existing Maât socket'; exit 2; fi
useradd --system --no-create-home --home-dir /nonexistent --shell /bin/sh "$USER_NAME"
# SSH disallows public-key auth to locked Unix accounts. Set an unknown random
# password hash; password-based SSH remains disabled by configuration.
usermod -p "$(openssl passwd -6 "$(openssl rand -hex 32)")" "$USER_NAME"
"$SSH/ssh-keygen" -q -t ed25519 -N '' -f "$TMP/testkey"
"$SSH/ssh-keygen" -q -t ed25519 -N '' -f "$TMP/hostkey"
cp "$TMP/testkey.pub" "$TMP/authorized_keys"
chmod 0644 "$TMP/authorized_keys"
# An ephemeral loopback port from the kernel; race is bounded to test only.
PORT="$(python3 - <<'PY'
import socket
s=socket.socket(); s.bind(('127.0.0.1',0)); print(s.getsockname()[1]); s.close()
PY
)"
cat > "$TMP/sshd_config" <<EOF_CONFIG
Port $PORT
ListenAddress 127.0.0.1
HostKey $TMP/hostkey
PidFile $TMP/sshd.pid
AuthorizedKeysFile $TMP/authorized_keys
StrictModes no
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
PermitEmptyPasswords no
AllowUsers $USER_NAME
LogLevel DEBUG1
Subsystem sftp /usr/lib/maat/sftp-server
EOF_CONFIG
"$SSH/sshd" -t -f "$TMP/sshd_config"
"$ROOT/build/maat-monitor-receiver" > "$TMP/receiver.log" 2>&1 & RECEIVER_PID=$!
for i in $(seq 1 50); do [ -S /run/maat/monitor.sock ] && break; sleep .1; done
[ -S /run/maat/monitor.sock ] || { echo 'Receiver not started'; cat "$TMP/receiver.log"; exit 1; }
"$SSH/sshd" -D -e -f "$TMP/sshd_config" > "$TMP/sshd.log" 2>&1 & SSH_PID=$!
sleep .3
OPTS=(-F /dev/null -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes -o ConnectTimeout=4 -o PreferredAuthentications=publickey -p "$PORT" -i "$TMP/testkey")
if ! "$SSH/ssh" "${OPTS[@]}" "$USER_NAME@127.0.0.1" true >"$TMP/ssh-ok.out" 2>"$TMP/ssh-ok.err"; then
  echo 'FAIL: valid SSH auth'; tail -35 "$TMP/sshd.log"; cat "$TMP/ssh-ok.err"; exit 1
fi
echo 'PASS real Ed25519 OpenSSH authentication + Maât acknowledgement'
COUNT=$(python3 - <<'PY'
import sqlite3
c=sqlite3.connect('/var/lib/maat/monitor.db')
print(c.execute('select count(*) from verified_ssh_sessions').fetchone()[0])
PY
)
[ "$COUNT" -ge 1 ] || { echo 'FAIL: no persisted assertion'; exit 1; }
# Assert DB contains the actual accepted SSH key, not merely some key-shaped data.
python3 - "$TMP/testkey.pub" <<'PY_CHECK'
import base64,sqlite3,sys
pub=open(sys.argv[1]).read().split()[1]
accepted=base64.b64decode(pub)
conn=sqlite3.connect('/var/lib/maat/monitor.db')
rows=conn.execute('SELECT user,key_blob FROM verified_ssh_sessions').fetchall()
assert any(u=='maat_e2e' and bytes(k)==accepted for u,k in rows), 'wrong identity recorded'
print('PASS exact authenticated SSH key bytes persisted')
PY_CHECK
"$SSH/ssh-keygen" -q -t ed25519 -N '' -f "$TMP/wrongkey"
ALT_OPTS=("${OPTS[@]}")
ALT_OPTS[${#ALT_OPTS[@]}-1]="$TMP/wrongkey"
if "$SSH/ssh" "${ALT_OPTS[@]}" "$USER_NAME@127.0.0.1" true > /dev/null 2>&1; then
 echo 'FAIL: wrong key accepted'; exit 1
fi
echo 'PASS wrong key rejected'
# RSA is an acceptable OpenSSH key type in some deployments, but Maât V2
# deliberately declines all publickey types other than raw Ed25519.
"$SSH/ssh-keygen" -q -t rsa -b 2048 -N '' -f "$TMP/rsakey"
cat "$TMP/rsakey.pub" >> "$TMP/authorized_keys"
ALT_OPTS[${#ALT_OPTS[@]}-1]="$TMP/rsakey"
if "$SSH/ssh" "${ALT_OPTS[@]}" "$USER_NAME@127.0.0.1" true > /dev/null 2>&1; then
 echo 'FAIL: RSA should be rejected by Maât'; exit 1
fi
echo 'PASS unsupported RSA auth rejected by Maât monitor'
kill "$RECEIVER_PID"; wait "$RECEIVER_PID" 2>/dev/null || :; RECEIVER_PID=''
[ ! -e /run/maat/monitor.sock ] || { echo 'FAIL: stale socket after SIGTERM'; exit 1; }
echo 'PASS receiver removes socket on graceful shutdown'
"$ROOT/build/maat-monitor-receiver" > "$TMP/receiver-restart.log" 2>&1 & RECEIVER_PID=$!
for i in $(seq 1 50); do [ -S /run/maat/monitor.sock ] && break; sleep .1; done
[ -S /run/maat/monitor.sock ] || { echo 'FAIL receiver restart'; exit 1; }
if ! "$SSH/ssh" "${OPTS[@]}" "$USER_NAME@127.0.0.1" true >/dev/null 2>&1; then
    echo 'FAIL: auth after receiver restart'; exit 1
fi
echo 'PASS reauthentication after receiver restart with persistent replay store'
# Full real-SSH handshake microprofile (loopback only, not production throughput).
python3 - "$SSH/ssh" "$PORT" "$TMP/testkey" "$USER_NAME" <<'PY_LATENCY'
import statistics,subprocess,sys,time
client,port,key,user=sys.argv[1:]
args=[client,'-F','/dev/null','-o','BatchMode=yes',
      '-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile=/dev/null',
      '-o','LogLevel=ERROR','-o','IdentitiesOnly=yes',
      '-o','PreferredAuthentications=publickey','-p',port,'-i',key,
      user+'@127.0.0.1','true']
latencies=[]
for _ in range(8):
    t=time.perf_counter()
    p=subprocess.run(args,capture_output=True,timeout=10)
    if p.returncode: raise SystemExit('FAIL: benchmark SSH auth '+str(p.stderr))
    latencies.append((time.perf_counter()-t)*1000)
print('PROFILE eight full SSH handshakes: median %.1f ms, mean %.1f ms, max %.1f ms (loopback)' %
      (statistics.median(latencies), statistics.mean(latencies), max(latencies)))
PY_LATENCY
kill "$RECEIVER_PID"; wait "$RECEIVER_PID" 2>/dev/null || :; RECEIVER_PID=''
if "$SSH/ssh" "${OPTS[@]}" "$USER_NAME@127.0.0.1" true >/dev/null 2>&1; then
 echo 'FAIL: connection survived missing receiver'; exit 1
fi
echo 'PASS fail closed when broker unavailable'
echo 'E2E PASS'
