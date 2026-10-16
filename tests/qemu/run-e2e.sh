#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Disposable QEMU **system VM** E2E. Requires a separately acquired, vetted
# Ubuntu 22.04 cloud image; never alters the base image or host services.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE="${1:-}"
if [[ $# != 1 || ! -f "$IMAGE" ]]; then
  echo 'usage: tests/qemu/run-e2e.sh /path/to/ubuntu-22.04-server-cloudimg-amd64.img' >&2
  exit 2
fi
for binary in qemu-system-x86_64 qemu-img cloud-localds ssh scp ssh-keygen tar python3 timeout; do
  command -v "$binary" >/dev/null || { echo "Missing host program: $binary" >&2; exit 2; }
done
IMAGE="$(realpath "$IMAGE")"
# A cloud image typically has a very small virtual root disk. Building
# OpenSSH, Apache and PHP requires several gigabytes inside the guest.
MEMORY_MB="${MAAT_QEMU_MEMORY_MB:-4096}"
DISK_GB="${MAAT_QEMU_DISK_GB:-12}"
GUEST_TIMEOUT="${MAAT_QEMU_GUEST_TIMEOUT:-5400}"
for spec in "MEMORY_MB:$MEMORY_MB:3072:65536" "DISK_GB:$DISK_GB:8:128" "GUEST_TIMEOUT:$GUEST_TIMEOUT:300:21600"; do
  IFS=: read -r name value minimum maximum <<<"$spec"
  if [[ ! "$value" =~ ^[1-9][0-9]*$ ]] || ((value < minimum || value > maximum)); then
    echo "Invalid $name=$value (expected integer between $minimum and $maximum)" >&2
    exit 2
  fi
done
if [[ -n "${MAAT_QEMU_IMAGE_SHA256:-}" ]]; then
  if [[ ! "${MAAT_QEMU_IMAGE_SHA256}" =~ ^[[:xdigit:]]{64}$ ]]; then
    echo 'MAAT_QEMU_IMAGE_SHA256 must be 64 hexadecimal digits' >&2
    exit 2
  fi
  python3 - "$IMAGE" "$MAAT_QEMU_IMAGE_SHA256" <<'PY_SHA'
import hashlib,sys
p,expect=sys.argv[1:]
h=hashlib.sha256()
with open(p,'rb') as f:
    for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
if h.hexdigest().lower()!=expect.lower():
    sys.exit('Base image SHA-256 mismatch: refusing to boot')
print('PASS verified SHA-256 of QEMU base image')
PY_SHA
fi
PORT="${MAAT_QEMU_SSH_PORT:-22422}"
if [[ ! "$PORT" =~ ^[0-9]+$ ]] || ((PORT < 1024 || PORT > 65535)); then
  echo 'MAAT_QEMU_SSH_PORT must be a nonprivileged TCP port' >&2; exit 2
fi
if ! python3 - "$PORT" <<'PY'
import socket,sys
s=socket.socket();s.bind(('127.0.0.1',int(sys.argv[1])));s.close()
PY
then
  echo "Local TCP port $PORT is already in use; refusing to interfere." >&2; exit 2
fi
TMP="$(mktemp -d /tmp/maat-qemu-e2e-XXXXXXXX)"
chmod 0700 "$TMP"
VM_PID=''
cleanup() {
  result=$?
  if [[ -n "$VM_PID" ]]; then
    kill "$VM_PID" 2>/dev/null || :
    wait "$VM_PID" 2>/dev/null || :
  fi
  if ((result != 0)); then
    if [[ -s "$TMP/console.log" ]]; then
      echo '--- QEMU guest console (last 80 lines) ---' >&2
      tail -n 80 "$TMP/console.log" >&2 || :
    fi
    if [[ -s "$TMP/qemu.log" ]]; then
      echo '--- QEMU process errors (last 40 lines) ---' >&2
      tail -n 40 "$TMP/qemu.log" >&2 || :
    fi
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT
ssh-keygen -q -t ed25519 -N '' -f "$TMP/guest_key"
PUBKEY="$(cat "$TMP/guest_key.pub")"
cat > "$TMP/user-data" <<EOF_CLOUD
#cloud-config
hostname: maat-e2e
ssh_pwauth: false
disable_root: true
users:
  - name: maatci
    gecos: Maât Disposable E2E
    groups: [sudo]
    shell: /bin/bash
    lock_passwd: true
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    ssh_authorized_keys:
      - '$PUBKEY'
write_files:
  - path: /etc/maat-disposable-qemu-e2e
    content: 'Maât QEMU disposable build, never use on host\n'
    permissions: '0400'
    owner: root:root
# Ensure cloud-init grows the root filesystem after the sparse overlay grows.
growpart:
  mode: auto
  devices: ['/']
resize_rootfs: true
EOF_CLOUD
cat > "$TMP/meta-data" <<EOF_META
instance-id: maat-e2e-$(date +%s)-$$
local-hostname: maat-e2e
EOF_META
cloud-localds "$TMP/seed.img" "$TMP/user-data" "$TMP/meta-data"
FORMAT="$(qemu-img info --output=json "$IMAGE" | python3 -c 'import json,sys;print(json.load(sys.stdin)["format"])')"
if [[ "$FORMAT" != qcow2 ]]; then
  echo "Refusing non-qcow2 base image format: $FORMAT" >&2;exit 2
fi
qemu-img create -f qcow2 -F qcow2 -b "$IMAGE" "$TMP/overlay.qcow2" >/dev/null
# Expand only the throwaway copy-on-write overlay, NEVER the base image.
# cloud-init will enlarge the guest partition and filesystem on first boot.
BASE_SIZE_BYTES="$(qemu-img info --output=json "$IMAGE" | python3 -c 'import json,sys;print(json.load(sys.stdin)["virtual-size"])')"
TARGET_SIZE_BYTES=$((DISK_GB * 1024 * 1024 * 1024))
if ((BASE_SIZE_BYTES < TARGET_SIZE_BYTES)); then
  qemu-img resize -f qcow2 "$TMP/overlay.qcow2" "${DISK_GB}G" >/dev/null
fi
ACCEL="${MAAT_QEMU_ACCEL:-auto}"
if [[ "$ACCEL" == auto ]]; then
  if [[ -r /dev/kvm && -w /dev/kvm ]]; then ACCEL=kvm; else ACCEL=tcg; fi
fi
if [[ "$ACCEL" != kvm && "$ACCEL" != tcg ]]; then
  echo 'MAAT_QEMU_ACCEL must be auto, kvm or tcg' >&2;exit 2
fi
printf 'Starting disposable Ubuntu VM: accelerator=%s RAM=%sMiB disk=%sGiB SSH=127.0.0.1:%s.\n' \
  "$ACCEL" "$MEMORY_MB" "$DISK_GB" "$PORT"
if [[ "$ACCEL" == tcg ]]; then
  echo 'WARNING: no accessible KVM, TCG emulation may be extremely slow.' >&2
fi
qemu-system-x86_64 \
  -machine q35,accel="$ACCEL" -m "$MEMORY_MB" -smp 2 \
  -drive "file=$TMP/overlay.qcow2,format=qcow2,if=virtio" \
  -drive "file=$TMP/seed.img,format=raw,if=virtio,readonly=on" \
  -nic "user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:$PORT-:22" \
  -display none -serial "file:$TMP/console.log" -monitor none \
  -no-reboot >"$TMP/qemu.log" 2>&1 &
VM_PID=$!
SSH=(ssh -i "$TMP/guest_key" -p "$PORT" -o BatchMode=yes
      -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$TMP/known_hosts"
      -o ConnectTimeout=3 -o ServerAliveInterval=30 -o ServerAliveCountMax=4
      -o LogLevel=ERROR maatci@127.0.0.1)
SCP=(scp -q -i "$TMP/guest_key" -P "$PORT" -o BatchMode=yes
      -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$TMP/known_hosts"
      -o ConnectTimeout=3)
READY=0
for attempt in $(seq 1 120); do
  if ! kill -0 "$VM_PID" 2>/dev/null; then
    echo 'QEMU exited before guest SSH became ready' >&2; exit 1
  fi
  if "${SSH[@]}" 'test -f /etc/maat-disposable-qemu-e2e' 2>/dev/null; then READY=1;break;fi
  sleep 3
done
if ((READY != 1)); then echo 'Guest SSH/cloud-init unavailable after 6 minutes' >&2;exit 1;fi
"${SSH[@]}" 'cloud-init status --wait >/dev/null; test -f /etc/maat-disposable-qemu-e2e'
# Detect failed root partition growth before downloading and compiling tools.
"${SSH[@]}" 'bash -se' <<'GUEST_DISK'
set -Eeuo pipefail
free_mb=$(df -Pm / | awk 'NR==2 {print $4}')
[[ "$free_mb" =~ ^[0-9]+$ ]] && ((free_mb >= 4096)) || {
  echo "FAIL QEMU guest has only ${free_mb:-unknown} MiB free on /; cloud-init growpart/resizefs likely failed" >&2
  df -h / >&2
  exit 1
}
echo "PASS QEMU guest root filesystem has ${free_mb} MiB free"
echo "Guest kernel: $(uname -r)"
GUEST_DISK
# No host mounts. All bytes travel through a temporary localhost-only SSH
# port into a copy-on-write guest disk discarded after the test.
# Transport *sources* only. Docker's .dockerignore does not apply to tar:
# previous runs accidentally uploaded hundreds of MiB of build artefacts.
# Only exclude the root CMake build directory: excluding every 'build'
# directory also removes Rust vendor/thiserror/build/probe.rs (checksummed).
tar -czf "$TMP/maat-source.tar.gz" \
  --exclude='.git' --anchored --exclude='./build' --no-anchored --exclude='dist' \
  --exclude='libs/apache-httpd' --exclude='autom4te.cache' \
  --exclude='.libs' --exclude='target' --exclude='__pycache__' \
  --exclude='*.o' --exclude='*.lo' --exclude='*.la' --exclude='*.slo' \
  --exclude='*.a' --exclude='*.dep' \
  --exclude='*.img' --exclude='*.qcow2' --exclude='*.iso' --exclude='*.vmdk' \
  --exclude='traces*' --exclude='*.log' \
  --exclude='php-ext/modules' --exclude='php-ext/Makefile' \
  --exclude='php-ext/config.status' --exclude='php-ext/config.h' \
  --exclude='php-ext/libtool' \
  --exclude='libs/openssh-portable/Makefile' \
  --exclude='libs/openssh-portable/config.h' \
  --exclude='libs/openssh-portable/config.status' \
  --exclude='libs/openssh-portable/openbsd-compat/Makefile' \
  --exclude='libs/openssh-portable/ssh' \
  --exclude='libs/openssh-portable/sshd' \
  --exclude='libs/openssh-portable/sshd-auth' \
  --exclude='libs/openssh-portable/sshd-session' \
  --exclude='libs/openssh-portable/ssh-keygen' \
  -C "$ROOT" .
# Check both the local vendor and the packed archive. With pipefail enabled,
# grep -q can close its input early and make tar exit with SIGPIPE (141),
# falsely reporting a missing file. Drain tar's entire listing instead.
VENDOR_PROBE='libs/maat-bbs/vendor/thiserror/build/probe.rs'
if [[ ! -f "$ROOT/$VENDOR_PROBE" ]]; then
  echo "FAIL: QEMU source tree is missing checksummed Rust $VENDOR_PROBE" >&2
  exit 1
fi
if ! tar -tzf "$TMP/maat-source.tar.gz" | grep -Fx "./$VENDOR_PROBE" >/dev/null; then
  echo "FAIL: QEMU source archive omitted checksummed Rust $VENDOR_PROBE" >&2
  exit 1
fi
SOURCE_BYTES="$(stat -c %s "$TMP/maat-source.tar.gz")"
echo "QEMU source archive: $(( (SOURCE_BYTES + 1048575) / 1048576 )) MiB"
# A source tree this large almost certainly contains generated artefacts.
if (( SOURCE_BYTES > 200 * 1024 * 1024 )); then
  echo 'FAIL: QEMU source archive exceeds 200 MiB; inspect generated files before upload' >&2
  exit 1
fi
# ConnectTimeout covers establishing a connection, not a stalled transfer.
# Bound SCP explicitly; a hung guest must not stall the whole test forever.
if ! timeout --foreground --signal=TERM --kill-after=10s 180s \
     "${SCP[@]}" "$TMP/maat-source.tar.gz" maatci@127.0.0.1:maat-source.tar.gz; then
  echo 'FAIL: QEMU source transfer failed or timed out (180s)' >&2
  exit 1
fi
# A stuck guest test must not leave a headless VM running indefinitely.
# This timeout controls guest install, compilation and privileged E2E.
timeout --foreground --signal=TERM --kill-after=30s "$GUEST_TIMEOUT" \
  "${SSH[@]}" 'bash -se' <<'GUEST'
set -Eeuo pipefail
test -f /etc/maat-disposable-qemu-e2e || exit 77
sudo -n test -f /etc/maat-disposable-qemu-e2e || exit 77
# The privileged SSH monitor drops to a fresh, unrelated UID for each
# session. Ubuntu cloud-init normally creates /home/maatci with restrictive
# traversal permissions, so a ForceCommand built under $HOME is not executable
# by those ephemeral UIDs. Apache (www-data) also needs to read the PHP files
# and native modules. Stage the throwaway source under /opt instead; do NOT
# relax the permissions of maatci's home directory.
WORKTREE=/opt/maat
sudo install -d -o "$(id -un)" -g "$(id -gn)" -m 0755 "$WORKTREE"
tar -xzf "$HOME/maat-source.tar.gz" -C "$WORKTREE"
sudo env DEBIAN_FRONTEND=noninteractive apt-get update
sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  build-essential cmake make pkg-config autoconf automake libtool \
  libssl-dev zlib1g-dev libsqlite3-dev libcrypt-dev libzstd-dev \
  libapr1-dev libaprutil1-dev libpcre2-dev \
  apache2 apache2-dev libapache2-mod-php8.1 \
  php8.1-cli php8.1-dev php8.1-phpdbg \
  python3 curl perl openssl passwd util-linux ca-certificates
getent passwd maatweb >/dev/null || sudo useradd --system --no-create-home --shell /bin/false maatweb
getent passwd maatsshd >/dev/null || sudo useradd --system --no-create-home --shell /usr/sbin/nologin maatsshd
sudo mkdir -p /var/empty/maat /usr/lib/maat
# Ubuntu 22.04's Rust packages cannot compile the locked BBS dependencies.
# The Rust toolchain exists only in this disposable guest user's home.
curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs \
  | sh -s -- -y --profile minimal --default-toolchain 1.95.0
export PATH="$HOME/.cargo/bin:$PATH"
cd "$WORKTREE"
# Do not reuse configure/Makefiles copied from the host or a previous build.
rm -f libs/openssh-portable/Makefile libs/openssh-portable/config.h \
  libs/openssh-portable/openbsd-compat/Makefile
env MAAT_BUILD_JOBS=2 ./build.sh --skip-vendored-apache
# Check access from unrelated, unprivileged UIDs before starting the
# SSH/broker/Apache test, which would otherwise report an opaque EACCES.
# The real bridge still executes with a distinct per-session kernel UID.
if ! sudo -u nobody test -x "$WORKTREE/build/maat-http-bridge" ||
   ! sudo -u www-data test -r "$WORKTREE/php/whoami.php" ||
   ! sudo -u www-data test -r "$WORKTREE/php-ext/modules/maat.so" ||
   ! sudo -u www-data test -r "$WORKTREE/modules/mod_maat/.libs/mod_maat.so"; then
  echo 'FAIL QEMU guest build artifacts cannot be accessed by isolated service UIDs' >&2
  namei -l "$WORKTREE/build/maat-http-bridge" >&2 || :
  namei -l "$WORKTREE/php/whoami.php" >&2 || :
  exit 1
fi
echo 'PASS QEMU build artifacts accessible to isolated SSH and Apache UIDs'
# This script alters account permissions and private /usr/lib/maat INSIDE
# THE GUEST. It refuses absent MAAT_CONFIRM_DISPOSABLE_VM=yes and root.
sudo env MAAT_CONFIRM_DISPOSABLE_VM=yes ./tests/e2e_native_apache_direct.sh
GUEST
printf '%s\n' 'PASS QEMU isolated-kernel Maât native E2E (guest destroyed on exit)'
