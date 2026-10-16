#!/usr/bin/env bash
# Stage artifacts; deliberately never overwrite a running SSH/Apache instance.
set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd "$ROOT"
[[ $# -eq 1 && "$1" == /* && "$1" != / ]] || {
  echo "Usage: ./install /absolute/staging-directory" >&2
  echo 'Stages files only. Does NOT install or enable system services.' >&2
  exit 2
}
DEST=$1
[[ ! -e "$DEST" ]] || { echo "Destination already exists: $DEST" >&2; exit 2; }
for f in build/maat-monitor-receiver build/maat-http-broker build/maat-http-bridge \
         build/maat-check-config build/maat-trust-sync \
         modules/mod_maat/.libs/mod_maat.so php-ext/modules/maat.so \
         libs/openssh-portable/sshd libs/openssh-portable/sshd-auth \
         libs/openssh-portable/sshd-session libs/openssh-portable/ssh; do
  [[ -s "$f" ]] || { echo "Missing $f: run ./build" >&2; exit 1; }
done
mkdir -p -- "$DEST/bin" "$DEST/sbin" "$DEST/apache" "$DEST/php" "$DEST/share/maat" \
  "$DEST/share/maat/tests"
for name in maat-monitor-receiver maat-http-broker maat-http-bridge maat-check-config maat-trust-sync; do
  install -m 0755 "build/$name" "$DEST/sbin/$name"
done
for name in ssh sshd sshd-auth sshd-session; do
  install -m 0755 "libs/openssh-portable/$name" "$DEST/sbin/maat-$name"
done
install -m 0644 modules/mod_maat/.libs/mod_maat.so "$DEST/apache/mod_maat.so"
install -m 0644 php-ext/modules/maat.so "$DEST/php/maat.so"
install -m 0755 tools/maat-site "$DEST/bin/maat-site"
cp -a -- etc "$DEST/share/maat/" 
cat > "$DEST/README.txt" <<'TXT'
Maât staged research build. NO service is enabled.
Review SSH separation, modules, private Apache config, ownership and broker
permissions before any live deployment. Never replace system sshd/apache2.
TXT
printf 'PASS staged in %s; no host service/config modified.\n' "$DEST"
