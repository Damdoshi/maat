/* Maât native PHP 8.4 auto-global, prototype, no civil attestation.
 * The authentication broker is the only authority for SSH assertions.
 * Never trust the HTTP ticket or user-supplied identity header directly. */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "php.h"
#include "Zend/zend_API.h"
#include "ext/standard/info.h"
#include "ext/standard/base64.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>

#define MAAT_PHP_VERSION "0.14.0"
#define MAAT_CHECK_SOCKET "/run/maat-http/check.sock"

static void maat_put(uint8_t *buf, size_t *off, const char *data, size_t n)
{
    buf[(*off)++]=(uint8_t)(n>>24);
    buf[(*off)++]=(uint8_t)(n>>16);
    buf[(*off)++]=(uint8_t)(n>>8);
    buf[(*off)++]=(uint8_t)n;
    memcpy(buf+*off,data,n);
    *off+=n;
}

static int maat_field(const uint8_t *buf,size_t len,size_t *off,
                      const uint8_t **start,size_t *size,size_t max)
{
    size_t n;
    if (*off>len || len-*off<4) return 0;
    n=((size_t)buf[*off]<<24)|((size_t)buf[*off+1]<<16)|
      ((size_t)buf[*off+2]<<8)|(size_t)buf[*off+3];
    *off+=4;
    if (n>max || n>len-*off) return 0;
    *start=buf+*off;*size=n;*off+=n;
    return 1;
}
static int maat_is_ticket(const zend_string *str)
{
    size_t i;
    if (ZSTR_LEN(str)!=64) return 0;
    for(i=0;i<64;++i) {
        char c=ZSTR_VAL(str)[i];
        if (!((c>='0'&&c<='9')||(c>='a'&&c<='f'))) return 0;
    }
    return 1;
}

/* Write a request-local zval; never cache its contents in module globals. */
static void maat_resolve(zval *auth)
{
    const uint8_t *magic,*user,*key;
    size_t magic_len,user_len,key_len,off=0;
    uint8_t request[100],response[512];
    struct sockaddr_un address;
    struct timeval timeout={2,0};
    zval *server,*raw_ticket;
    zend_string *ticket;
    ssize_t n;
    int fd=-1;

    /* _SERVER is itself an auto-global. It must be populated before lookup. */
    zend_is_auto_global_str(ZEND_STRL("_SERVER"));
    server=zend_hash_str_find(&EG(symbol_table),ZEND_STRL("_SERVER"));
    if (server==NULL || Z_TYPE_P(server)!=IS_ARRAY) return;
    raw_ticket=zend_hash_str_find(Z_ARRVAL_P(server),ZEND_STRL("HTTP_X_MAAT_TICKET"));
    if (raw_ticket==NULL || Z_TYPE_P(raw_ticket)!=IS_STRING) return;
    ticket=Z_STR_P(raw_ticket);
    if (!maat_is_ticket(ticket)) return;

    off=0;
    maat_put(request,&off,"MAATCHECK1",10);
    maat_put(request,&off,ZSTR_VAL(ticket),64);
    fd=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0);
    if(fd<0) return;
    (void)setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
    memset(&address,0,sizeof(address));
    address.sun_family=AF_UNIX;
    memcpy(address.sun_path,MAAT_CHECK_SOCKET,sizeof(MAAT_CHECK_SOCKET));
    if (connect(fd,(struct sockaddr *)&address,sizeof(address))<0 ||
        send(fd,request,off,MSG_NOSIGNAL)!=(ssize_t)off) goto done;
    n=recv(fd,response,sizeof(response),MSG_TRUNC);
    if (n<0 || n>(ssize_t)sizeof(response)) goto done;
    off=0;
    if (!maat_field(response,(size_t)n,&off,&magic,&magic_len,20) ||
        magic_len!=10 || memcmp(magic,"MAATIDENT1",10)!=0 ||
        !maat_field(response,(size_t)n,&off,&user,&user_len,128) || user_len==0 ||
        !maat_field(response,(size_t)n,&off,&key,&key_len,51) || key_len!=51 ||
        off!=(size_t)n) goto done;
    /* Re-validate the raw SSH Ed25519 key blob returned by the broker. */
    if (memcmp(key,"\0\0\0\13ssh-ed25519\0\0\0\40",19)!=0) goto done;
    {
        zval attributes;
        zend_string *encoded=php_base64_encode(key,51);
        zend_string *public_key;
        if (encoded==NULL) goto done;
        public_key=strpprintf(0,"ssh-ed25519 %s",ZSTR_VAL(encoded));
        zend_string_release(encoded);
        array_init(auth);
        add_assoc_bool(auth,"authenticated",1);
        add_assoc_string(auth,"transport","maat+ssh");
        add_assoc_stringl(auth,"ssh_user",(const char *)user,user_len);
        add_assoc_str(auth,"public_key",public_key);
        add_assoc_bool(auth,"identity_verified",0);
        array_init(&attributes);
        add_assoc_zval(auth,"attributes",&attributes);
    }
 done:
    if (fd>=0) close(fd);
    /* Do not leave the ticket visible to later PHP application code. */
    zend_hash_str_del(Z_ARRVAL_P(server),ZEND_STRL("HTTP_X_MAAT_TICKET"));
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
