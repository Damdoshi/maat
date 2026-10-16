#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Execute ONLY as the image's entrypoint; never run on the host.
set -Eeuo pipefail
ROOT=/opt/maat
if [[ "$(id -u)" != 0 || ! -f /etc/maat-disposable-test-image \
      || ! -x "$ROOT/tests/e2e_native_apache_direct.sh" ]]; then
    echo 'REFUSED: disposable Docker image with root-only test marker required.' >&2
    exit 77
fi
if [[ -e /run/maat/monitor.sock || -e /run/maat-http/bind.sock \
      || -e /run/maat-http/check.sock ]]; then
    echo 'REFUSED: an existing Maât service is using a test socket.' >&2
    exit 77
fi
# Bound check: this is a disposable container, not a live host instance.
[[ -r /proc/self/status ]] || { echo 'Missing procfs.' >&2; exit 2; }
printf '%s\n' '=== Native Maât Docker E2E: real SSH -> broker -> Apache -> php-maat ==='
"$ROOT/tests/e2e_native_apache_direct.sh"
printf '%s\n' '=== PASS: Maât Docker positive/negative E2E completed ==='
