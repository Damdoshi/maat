#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Host launcher: no source mounts, no published ports, no privileged container.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DOCKER_BIN="${MAAT_DOCKER_BIN:-docker}"
IMAGE="${MAAT_DOCKER_IMAGE:-maat-e2e:0.20-alpha5-bridge}"
MODE="${1:-all}"
if [[ $# -gt 1 || ( "$MODE" != all && "$MODE" != --build-only && "$MODE" != --run-only ) ]]; then
    echo 'usage: tests/docker/run-e2e.sh [--build-only|--run-only]' >&2
    exit 2
fi
command -v "$DOCKER_BIN" >/dev/null 2>&1 || {
    echo "Docker CLI unavailable: $DOCKER_BIN. Install docker.io or Docker Engine." >&2
    exit 2
}
"$DOCKER_BIN" info >/dev/null || {
    echo 'Docker daemon unavailable or insufficient Docker permissions.' >&2
    exit 2
}
if [[ "$MODE" != --run-only ]]; then
    "$DOCKER_BIN" build --file "$ROOT/tests/docker/Dockerfile" --tag "$IMAGE" "$ROOT"
fi
if [[ "$MODE" == --build-only ]]; then
    echo "PASS: built disposable image $IMAGE (privileged E2E not yet executed)."
    exit 0
fi
# No --privileged, host networking, bind mounts, published ports, or host PID namespace.
# Minimal effective capabilities for SSH privilege separation and test account changes.
"$DOCKER_BIN" run --rm \
    --network none \
    --cap-drop ALL \
    --cap-add CHOWN \
    --cap-add DAC_OVERRIDE \
    --cap-add FOWNER \
    --cap-add KILL \
    --cap-add SETGID \
    --cap-add SETUID \
    --cap-add SYS_CHROOT \
    --pids-limit 256 \
    --memory 1024m \
    --tmpfs /run:rw,nosuid,nodev,size=32m \
    --tmpfs /tmp:rw,nosuid,nodev,size=128m \
    "$IMAGE"
