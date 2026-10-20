#!/usr/bin/env bash
# Fail unless *all* relevant test suites (including privileged E2E) are run.
set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd "$ROOT"
MODE=${1:-full}
[[ $# -le 1 ]] || { echo 'Usage: ./check.sh [unit|full]' >&2; exit 2; }
[[ "$MODE" == unit || "$MODE" == full ]] || { echo 'Usage: ./check.sh [unit|full]' >&2; exit 2; }
[[ -s build/maat-bbs-real-proof-tests ]] || { echo 'Run ./build first' >&2; exit 2; }
ctest --test-dir build --output-on-failure
python3 tests/maat_site_test.py
bash tests/php_abi_probe_test.sh
bash tests/native_apache_smoke.sh
# Privileged tests cannot be safely run as root on the workstation.
if [[ "$MODE" == unit ]]; then
  echo 'PASS local tests; NOT 100% coverage: root-only and QEMU tests not run.'
  exit 0
fi
command -v docker >/dev/null || { echo 'Full check requires Docker' >&2; exit 2; }
# QEMU test fixture: acquire it only for full E2E, not during prebuild/build.
# Keep a single canonical path so both QEMU suites receive the same image.
IMAGE_NAME=ubuntu-22.04-server-cloudimg-amd64.img
IMAGE="$ROOT/$IMAGE_NAME"
BASE=https://cloud-images.ubuntu.com/releases/server/jammy/release
for cmd in wget sha256sum awk mktemp; do
  command -v "$cmd" >/dev/null || { echo "Missing $cmd (QEMU image acquisition)" >&2; exit 2; }
done
[[ ! -L "$IMAGE" ]] || { echo "Refusing symlink for QEMU image: $IMAGE" >&2; exit 2; }
TMP=$(mktemp -d "$ROOT/.maat-qemu-image.XXXXXXXX")
trap 'rm -rf -- "$TMP"' EXIT
printf 'Checking official Ubuntu 22.04 image checksum...\n'
wget -q --https-only -O "$TMP/SHA256SUMS" "$BASE/SHA256SUMS"
EXPECTED=$(awk -v f="$IMAGE_NAME" '($2 == f || $2 == "*" f) && $1 ~ /^[0-9a-fA-F]+$/ && length($1) == 64 { print tolower($1) }' "$TMP/SHA256SUMS")
[[ "$EXPECTED" =~ ^[0-9a-f]{64}$ ]] || { echo "Invalid checksum manifest for $IMAGE_NAME" >&2; exit 1; }
if [[ -e "$IMAGE" ]]; then
  [[ -f "$IMAGE" && -s "$IMAGE" ]] || { echo "Invalid QEMU image: $IMAGE" >&2; exit 1; }
  ACTUAL=$(sha256sum -- "$IMAGE" | awk '{print $1}')
  [[ "$ACTUAL" == "$EXPECTED" ]] || { echo "Checksum mismatch for $IMAGE; move/remove it before retrying." >&2; exit 1; }
  echo "PASS existing QEMU image: $IMAGE"
else
  echo "Downloading verified Ubuntu cloud image: $IMAGE_NAME"
  wget --https-only -O "$TMP/$IMAGE_NAME" "$BASE/$IMAGE_NAME"
  ACTUAL=$(sha256sum -- "$TMP/$IMAGE_NAME" | awk '{print $1}')
  [[ "$ACTUAL" == "$EXPECTED" ]] || { echo 'Downloaded QEMU image checksum mismatch' >&2; exit 1; }
  mv -- "$TMP/$IMAGE_NAME" "$IMAGE"
  echo "PASS downloaded QEMU image: $IMAGE"
fi
# Explicit disposable-root E2E; no host-root CTest. Docker run requires access.
./tests/docker/run-e2e.sh
./tests/qemu/run-e2e.sh "$IMAGE"
./tests/qemu/run-trust-p2p.sh "$IMAGE"
printf '\nPASS all configured local suites plus disposable Docker and both QEMU suites.\n'
