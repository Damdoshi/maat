#!/usr/bin/env bash
# Validate QEMU launcher safeguards without booting or installing a VM.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP="$(mktemp -d /tmp/maat-qemu-preflight-XXXXXX)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin"
for cmd in qemu-system-x86_64 ssh scp; do
  printf '#!/bin/sh\nexit 99\n' > "$TMP/bin/$cmd"
  chmod +x "$TMP/bin/$cmd"
done
cat > "$TMP/bin/ssh-keygen" <<'MOCK_SSH'
#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = -f ]; then
    shift
    : > "$1"
    printf 'ssh-ed25519 MOCKING-NO-CRYPTO\n' > "$1.pub"
    exit 0
  fi
  shift
done
exit 99
MOCK_SSH
printf '#!/bin/sh\nexit 0\n' > "$TMP/bin/cloud-localds"
chmod +x "$TMP/bin/ssh-keygen" "$TMP/bin/cloud-localds"
cat > "$TMP/bin/qemu-img" <<'MOCK'
#!/bin/sh
if [ "$1" = info ]; then
  echo '{"format":"raw","virtual-size":2147483648}'
  exit 0
fi
exit 99
MOCK
chmod +x "$TMP/bin/qemu-img"
printf 'NOT A VIRTUAL DISK\n' > "$TMP/disk.img"
export PATH="$TMP/bin:$PATH"
check_failure() {
  local expected="$1"
  shift
  local output
  if output=$("$@" 2>&1); then
    printf 'FAIL expected rejection: %s\n' "$expected" >&2
    exit 1
  fi
  if [[ "$output" != *"$expected"* ]]; then
    printf 'FAIL incorrect rejection for %s:\n%s\n' "$expected" "$output" >&2
    exit 1
  fi
}
check_failure 'Invalid MEMORY_MB=' env MAAT_QEMU_MEMORY_MB=wrong \
  "$ROOT/tests/qemu/run-e2e.sh" "$TMP/disk.img"
check_failure 'Invalid DISK_GB=' env MAAT_QEMU_DISK_GB=2 \
  "$ROOT/tests/qemu/run-e2e.sh" "$TMP/disk.img"
check_failure 'Invalid GUEST_TIMEOUT=' env MAAT_QEMU_GUEST_TIMEOUT=1 \
  "$ROOT/tests/qemu/run-e2e.sh" "$TMP/disk.img"
check_failure 'must be 64 hexadecimal digits' env MAAT_QEMU_IMAGE_SHA256=nope \
  "$ROOT/tests/qemu/run-e2e.sh" "$TMP/disk.img"
check_failure 'Base image SHA-256 mismatch' env MAAT_QEMU_IMAGE_SHA256="$(printf '0%.0s' {1..64})" \
  "$ROOT/tests/qemu/run-e2e.sh" "$TMP/disk.img"
check_failure 'Refusing non-qcow2 base image format' \
  "$ROOT/tests/qemu/run-e2e.sh" "$TMP/disk.img"
echo 'PASS QEMU launcher rejects unsafe sizing, invalid hash, and non-QCOW2 image'
