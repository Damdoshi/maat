/* Maât native PHP extension; SSH identity comes ONLY from mod_maat's
 * verified Apache request_config. No application-level bearer tokens.
 * The superglobal is request-local. No identity = NULL, fail closed.
 * Civil identity remains unverified until registry integration. */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "php.h"
#include "SAPI.h"
#include "Zend/zend_API.h"
#include "ext/standard/info.h"
#include "ext/standard/base64.h"
#include <string.h>
#define MAAT_PHP_VERSION "0.18.0"

/* An anonymous-only build would appear to pass every CLI PHPT, yet fail
 * every authenticated Apache request. Never ship such a binary. */
#ifndef MAAT_APACHE_REQUEST_ABI
#error "php-maat requires MAAT_APACHE_REQUEST_ABI; check config.m4/config.h"
#endif

#ifdef MAAT_APACHE_REQUEST_ABI
#if PHP_VERSION_ID < 80100 || PHP_VERSION_ID >= 80200
#error "Maât Apache handler integration is currently validated only for PHP 8.1"
#endif
#include <dlfcn.h>
#include "../modules/mod_maat/maat_broker_client.h"
/* Layout of php_struct in PHP 8.1's sapi/apache2handler/php_apache.h.
 * This dependency is deliberately isolated here and MUST be revalidated
 * against upstream PHP for any other minor release. */
struct maat_apache_php81_context { int state; const void *request; };
typedef void *(*maat_apr_retrieve_function)(const char *);
typedef const struct maat_verified_identity *(*maat_apache_get_function)(const void *);

static void maat_resolve_apache(zval *auth)
{
    maat_apr_retrieve_function lookup = NULL;
    maat_apache_get_function get_identity = NULL;
    const struct maat_verified_identity *trusted;
    const struct maat_apache_php81_context *ctx;
    void *symbol;
    zend_string *encoded, *public_key;
    zval attributes;
    if (strcmp(sapi_module.name, "apache2handler") != 0) return;
    ctx = (const struct maat_apache_php81_context *)SG(server_context);
    if (ctx == NULL || ctx->request == NULL) return;
    symbol = dlsym(RTLD_DEFAULT, "apr_dynamic_fn_retrieve");
    if (symbol == NULL) return;
    memcpy(&lookup, &symbol, sizeof(lookup));
    symbol = lookup("maat_request_identity");
    if (symbol == NULL) return;
    memcpy(&get_identity, &symbol, sizeof(get_identity));
    trusted = get_identity(ctx->request);
    if (trusted == NULL || trusted->ssh_user[0] == '\0' ||
        memchr(trusted->ssh_user, '\0', MAAT_MAX_SSH_USER + 1) == NULL ||
        memcmp(trusted->public_key, "\0\0\0\13ssh-ed25519\0\0\0\40", 19) != 0)
        return;
    encoded = php_base64_encode(trusted->public_key, MAAT_KEY_BYTES);
    if (encoded == NULL) return;
    public_key = strpprintf(0, "ssh-ed25519 %s", ZSTR_VAL(encoded));
    zend_string_release(encoded);
    array_init(auth);
    add_assoc_bool(auth, "authenticated", 1);
    add_assoc_string(auth, "transport", "maat+ssh");
    add_assoc_string(auth, "ssh_user", (char *)trusted->ssh_user);
    add_assoc_str(auth, "public_key", public_key);
    add_assoc_bool(auth, "identity_verified", 0);
    array_init(&attributes);
    add_assoc_zval(auth, "attributes", &attributes);
}
#endif

static void maat_resolve(zval *auth)
{
#ifdef MAAT_APACHE_REQUEST_ABI
    if (sapi_module.name != NULL) maat_resolve_apache(auth);
#else
    (void)auth;
#endif
}

static bool maat_autoglobal(zend_string *name)
{
    zval auth;
    (void)name;
    ZVAL_NULL(&auth);
    maat_resolve(&auth);
    zend_hash_str_update(&EG(symbol_table),ZEND_STRL("_AUTH"),&auth);
    return 0;
}
PHP_MINIT_FUNCTION(maat)
{
    zend_register_auto_global(zend_string_init_interned("_AUTH",5,1),0,maat_autoglobal);
    return SUCCESS;
}
PHP_MINFO_FUNCTION(maat)
{
    php_info_print_table_start();
    php_info_print_table_row(2,"Maât PHP","SSH assertions only; civil identity unverified");
    php_info_print_table_row(2,"Version",MAAT_PHP_VERSION);
#ifdef MAAT_APACHE_REQUEST_ABI
    php_info_print_table_row(2,"Apache request ABI","native enabled (PHP 8.1 only)");
#else
    php_info_print_table_row(2,"Apache request ABI","disabled (anonymous only)");
#endif
    php_info_print_table_end();
}
zend_module_entry maat_module_entry={
    STANDARD_MODULE_HEADER,"maat",NULL,PHP_MINIT(maat),NULL,NULL,NULL,
    PHP_MINFO(maat),MAAT_PHP_VERSION,STANDARD_MODULE_PROPERTIES
};
#ifdef COMPILE_DL_MAAT
#ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
#endif
ZEND_GET_MODULE(maat)
#endif
