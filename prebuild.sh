#!/usr/bin/env bash
# Prepare a fresh Maât checkout for ./build.sh; no root, services or system installs.
set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
BBS="$ROOT/libs/maat-bbs"
VENDOR="$BBS/vendor"
CONFIG="$BBS/.cargo/config.toml"
LOCK="$BBS/Cargo.lock"
MODE=${1:-auto}
[[ $# -le 1 && ( "$MODE" == auto || "$MODE" == --verify || "$MODE" == --repair ) ]] || {
  echo "Usage: ./prebuild.sh [--verify|--repair]" >&2; exit 2;
}
[[ $EUID -ne 0 ]] || { echo 'ERROR: run as ordinary user, not sudo/root.' >&2; exit 2; }
for f in "$LOCK" "$BBS/Cargo.toml" "$ROOT/CMakeLists.txt"; do
  [[ -f $f ]] || { echo "ERROR: missing source: $f" >&2; exit 2; }
done
for cmd in python3 cargo rustc cmake make cc c++ apxs2 php phpize php-config autoconf; do
  command -v "$cmd" >/dev/null || { echo "ERROR: missing prerequisite: $cmd" >&2; exit 2; }
done
printf 'PHP CLI: %s | development: %s\n' "$(php -r 'echo PHP_MAJOR_VERSION,".",PHP_MINOR_VERSION;')" "$(php-config --version)"
[[ $(php -r 'echo PHP_MAJOR_VERSION,".",PHP_MINOR_VERSION;') == "$(php-config --version | cut -d. -f1,2)" ]] || {
  echo 'ERROR: PHP CLI / php-config version mismatch' >&2; exit 2;
}

verify_vendor() {
  python3 - "$VENDOR" <<'PY'
import hashlib, json, pathlib, sys
root = pathlib.Path(sys.argv[1])
if not root.is_dir():
    print('ERROR: vendor directory absent', file=sys.stderr); sys.exit(1)
errors = []
crates = list(root.glob('*/.cargo-checksum.json'))
if not crates:
    print('ERROR: vendor contains no Cargo checksums', file=sys.stderr); sys.exit(1)
for checksum in crates:
    try:
        entries = json.loads(checksum.read_text())['files']
        if not entries:
            errors.append(f'{checksum.parent.name}: empty file manifest')
        for relative, expected in entries.items():
            p = checksum.parent / relative
            if not p.is_file() or p.is_symlink():
                errors.append(f'{checksum.parent.name}/{relative}: absent or symlink')
            elif hashlib.sha256(p.read_bytes()).hexdigest() != expected:
                errors.append(f'{checksum.parent.name}/{relative}: checksum mismatch')
    except (OSError, ValueError, KeyError) as exc:
        errors.append(f'{checksum}: {exc}')
if errors:
    for line in errors[:25]: print('ERROR:', line, file=sys.stderr)
    print(f'ERROR: {len(errors)} vendored source problems', file=sys.stderr)
    sys.exit(1)
print(f'PASS vendor: {len(crates)} crates, all listed file SHA-256 checksums match')
PY
}

if [[ $MODE != --repair ]] && verify_vendor && (cd "$BBS" && cargo metadata --locked --offline --format-version 1 --no-deps >/dev/null); then
  echo 'PASS Maât prebuild: existing vendor is intact; no network required.'
  exit 0
fi
if [[ $MODE == --verify ]]; then
  echo 'ERROR: vendored dependencies require repair.' >&2
  exit 1
fi

echo 'Vendor needs regeneration from Cargo.lock; network may be required.'
STAGE=$(mktemp -d "$BBS/.prebuild.XXXXXXXX")
# Local Cargo config redirects crates.io back into the damaged vendor.
# Hide it only during `cargo vendor`, and restore it on any exit.
HIDDEN="$BBS/.cargo/config.toml.prebuild.$$"
MOVED_CONFIG=0
cleanup() {
  if [[ $MOVED_CONFIG == 1 ]]; then mv -- "$HIDDEN" "$CONFIG"; fi
  rm -rf -- "$STAGE"
}
trap cleanup EXIT
[[ ! -e $HIDDEN ]] || { echo 'ERROR: temporary config name collision' >&2; exit 2; }
if [[ -f $CONFIG ]]; then
  mv -- "$CONFIG" "$HIDDEN"
  MOVED_CONFIG=1
fi
# Do not change Cargo.lock; fetch the exact locked versions.
(cd "$BBS" && cargo vendor --locked "$STAGE/vendor" >/dev/null)
if [[ $MOVED_CONFIG == 1 ]]; then
  mv -- "$HIDDEN" "$CONFIG"
  MOVED_CONFIG=0
fi
# Check staged contents before changing the existing tree.
OLD_VENDOR="$VENDOR"
VENDOR="$STAGE/vendor"
verify_vendor
VENDOR="$OLD_VENDOR"
# Replace only after success; preserve original if any later validation fails.
BACKUP="$STAGE/previous-vendor"
if [[ -e $VENDOR ]]; then mv -- "$VENDOR" "$BACKUP"; fi
mv -- "$STAGE/vendor" "$VENDOR"
if ! (cd "$BBS" && cargo metadata --locked --offline --format-version 1 --no-deps >/dev/null) || ! verify_vendor; then
  echo 'ERROR: new vendor validation failed, restoring previous vendor.' >&2
  rm -rf -- "$VENDOR"
  if [[ -d $BACKUP ]]; then mv -- "$BACKUP" "$VENDOR"; fi
  exit 1
fi
wget https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img \
     -O ubuntu-22.04-server-cloudimg-amd64.img
echo 'PASS Maât prebuild: source dependencies ready for ./build.sh'
