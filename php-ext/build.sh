#!/bin/sh
# Build and test PHP 8.4 native module (requires php8.4-dev; fails if absent).
set -eu
cd "$(dirname "$0")"
command -v phpize8.4 >/dev/null || { echo 'ERROR php8.4-dev / phpize8.4 not installed' >&2; exit 2; }
command -v php-config8.4 >/dev/null || { echo 'ERROR php8.4-dev / php-config8.4 not installed' >&2; exit 2; }
phpize8.4
./configure --with-php-config="$(command -v php-config8.4)" --enable-maat
make -j2
php -n -d extension="$(pwd)/modules/maat.so" -r '
    function nested() { return $_AUTH; }
    if (!array_key_exists("_AUTH", $GLOBALS) || nested() !== NULL) exit(1);
    echo "PASS PHP native $_AUTH = NULL from nested function\n";
'
# Strict PHPT: must execute every test; refuse to mark a skipped suite successful.
RUN_TESTS="$(php-config8.4 --include-dir)/../build/run-tests.php"
if [ ! -f "$RUN_TESTS" ]; then
    RUN_TESTS="$(find /usr/lib/php -name run-tests.php -print -quit 2>/dev/null)"
fi
if [ ! -f "$RUN_TESTS" ]; then
    echo 'ERROR: php8.4-dev PHPT runner not installed' >&2; exit 2
fi
php -n "$RUN_TESTS" -q -d extension="$(pwd)/modules/maat.so" tests
