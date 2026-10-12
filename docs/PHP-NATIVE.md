# Native PHP 8.4 `$_AUTH` module

1. On a Debian 13 builder with access to signed Debian repositories:
   `apt install php8.4-dev php8.4-cli php8.4-common build-essential autoconf`
2. Run `php-ext/build.sh` (fails unless extension compiles and PHPT passes).
3. Run `packaging/build-php-deb.sh`, producing the **separate** binary
   `php8.4-maat_0.14.0-1_amd64.deb` only after successful tests.
4. Install and manually enable (`phpenmod -v 8.4 -s apache2 maat`).
5. Disable `auto_prepend_file=maat_auth.php` when using this native module.
6. Verify both authenticated Maât SSH HTTP and anonymous HTTP requests.

`$_AUTH` is registered via the Zend auto-global callback. The broker returns
raw SSH key bytes; PHP performs a strict key format check and initializes a
per-request array, with `identity_verified = false` until a citizen registry
has verified the identity. The ticket is single-use and never trusted by
itself. The module does not use sessions or an application-wide global cache.

**Important:** The source test harness can validate anonymous/fake tickets
under PHP CLI. A real positive SSH → Apache → native `$_AUTH` test still must
run on a system with php8.4-dev and the module installed; do not substitute
the existing PHP bootstrap test for that validation.

For the optional native Apache E2E, prepare the disposable test VM as in
`tests/e2e_apache.sh`, then run:
`MAAT_NATIVE_EXTENSION=/path/to/maat.so tests/e2e_apache.sh`.
This suppresses the legacy PHP bootstrap and loads the module via a private
PHP INI scan directory. The test fails if the module is missing.
