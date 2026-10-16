#!/usr/bin/env bash
# Restore tracked source snapshot by deleting only allowlisted build outputs.
# Never run git clean -fdx, never touch OS-installed files or user site data.
set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd "$ROOT"
# Docker build cache is global: pruning it must be a separate explicit choice.
YES=false
DOCKER_CACHE=false
for arg in "$@"; do
  case "$arg" in
    --yes) YES=true ;;
    --docker-cache) DOCKER_CACHE=true ;;
    *) echo 'Usage: ./clean [--yes] [--docker-cache]' >&2; exit 2 ;;
  esac
done
if "$DOCKER_CACHE" && ! "$YES"; then
  echo 'Use --yes --docker-cache to confirm shared Docker build-cache cleanup.' >&2
  exit 2
fi
DOCKER_BIN="${MAAT_DOCKER_BIN:-docker}"
DOCKER_IMAGE="${MAAT_DOCKER_IMAGE:-maat-e2e:0.20-alpha5-bridge}"
# Maât images are identified by repository/tag or a dedicated image label.
# Never prune unrelated Docker images or containers here.
paths=(build build-bbs build-asan build-debug dist
  modules/mod_maat/.libs modules/mod_maat/.deps
  php-ext/.libs php-ext/.deps php-ext/modules php-ext/autom4te.cache
  php-ext/build
  libs/maat-bbs/target libs/openssh-portable/.libs)
if ! "$YES"; then
  printf 'Will delete allowlisted build directories only:\n'
  printf '  %s\n' "${paths[@]}"
  echo 'Also removes known generated files in the OpenSSH, Apache module, and PHP extension trees.'
  echo 'Docker: removes all tagged maat-e2e images and stopped Maât-labelled build containers.'
  echo 'Also removes untagged Maât images carrying label org.maat.e2e=true.'
  echo 'Legacy untagged images without this label cannot be safely identified.'
  echo 'Optional --docker-cache also prunes Docker-wide *unused build cache* (affects other projects).'
  echo 'Re-run ./clean --yes to confirm.'
  exit 0
fi
for p in "${paths[@]}"; do
  [[ ! -L "$p" ]] || { echo "Refusing symlink: $p" >&2; exit 1; }
  rm -rf -- "$p"
done
# Autotools-generated files explicitly known to be absent in the alpha15 source snapshot.
for p in \
  modules/mod_maat/mod_maat.lo modules/mod_maat/maat_broker_client.lo modules/mod_maat/ingress_policy.lo \
  php-ext/Makefile php-ext/config.h \
  php-ext/config.log php-ext/config.status php-ext/libtool php-ext/maat.la \
  php-ext/.phpunit.result.cache \
  libs/openssh-portable/Makefile libs/openssh-portable/config.log \
  libs/openssh-portable/config.status libs/openssh-portable/config.h \
  libs/openssh-portable/ssh libs/openssh-portable/sshd \
  libs/openssh-portable/sshd-auth libs/openssh-portable/sshd-session \
  libs/openssh-portable/ssh-keygen; do
  [[ ! -L "$p" ]] || { echo "Refusing symlink: $p" >&2; exit 1; }
  rm -f -- "$p"
done
# Remove only object files under known buildable trees; never delete source files.
find modules/mod_maat php-ext libs/openssh-portable -type f \
  \( -name '*.o' -o -name '*.lo' -o -name '*.la' -o -name '*.slo' \) -delete
printf 'PASS removed generated outputs. Source files and vendored Rust crates retained.\n'

# Only project-labelled stopped containers are removed. An unlabelled legacy
# build container cannot be distinguished reliably from an unrelated project.
if command -v "$DOCKER_BIN" >/dev/null 2>&1 && "$DOCKER_BIN" info >/dev/null 2>&1; then
  mapfile -t maat_containers < <("$DOCKER_BIN" ps -aq \
    --filter 'label=org.maat.e2e=true' --filter 'status=exited')
  if (( ${#maat_containers[@]} )); then
    "$DOCKER_BIN" rm "${maat_containers[@]}"
  fi

  # Remove all historical tagged versions, not only the current alpha tag.
  # Restrict to the exact repository maat-e2e; never call a global image prune.
  mapfile -t maat_tags < <("$DOCKER_BIN" image ls --format '{{.Repository}}:{{.Tag}}' \
    --filter 'reference=maat-e2e:*' | grep '^maat-e2e:' || true)
  for tag in "${maat_tags[@]}"; do
    [[ "$tag" != *':<none>' ]] || continue
    "$DOCKER_BIN" image rm -- "$tag"
    echo "PASS removed Maât Docker image: $tag"
  done

  # New builds are labelled; remove their dangling images without affecting
  # anonymous images from other projects. In-use images remain protected.
  mapfile -t maat_untagged < <("$DOCKER_BIN" image ls -q \
    --filter 'dangling=true' --filter 'label=org.maat.e2e=true' | sort -u)
  if (( ${#maat_untagged[@]} )); then
    "$DOCKER_BIN" image rm "${maat_untagged[@]}"
    echo 'PASS removed labelled Maât intermediate images.'
  fi
  if "$DOCKER_CACHE"; then
    echo 'WARNING: pruning ALL unused Docker build cache, including other projects.'
    "$DOCKER_BIN" builder prune --force
  fi
else
  if "$DOCKER_CACHE"; then
    echo 'FAIL: Docker unavailable; requested cache cleanup could not run.' >&2
    exit 1
  fi
  echo 'SKIP Docker cleanup (Docker unavailable or access denied).'
fi
