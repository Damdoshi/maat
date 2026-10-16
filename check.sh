#!/usr/bin/env bash
# Fail unless *all* relevant test suites (including privileged E2E) are run.
set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd "$ROOT"
MODE=${1:-full}
[[ $# -le 2 ]] || { echo 'Usage: ./check [unit|full] [ubuntu-cloud-image.img]' >&2; exit 2; }
[[ "$MODE" == unit || "$MODE" == full ]] || { echo 'Usage: ./check [unit|full] [ubuntu-cloud-image.img]' >&2; exit 2; }
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
[[ $# -eq 2 && -s "$2" ]] || {
  echo 'Full check requires an Ubuntu cloud image: ./check full /path/image.img' >&2; exit 2;
}
# Explicit disposable-root E2E; no host-root CTest. Docker run requires access.
./tests/docker/run-e2e.sh
./tests/qemu/run-e2e.sh "$2"
./tests/qemu/run-trust-p2p.sh "$2"
printf '\nPASS all configured local suites plus disposable Docker and both QEMU suites.\n'
