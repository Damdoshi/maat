#ifndef TEST_HTTPD_H
#define TEST_HTTPD_H
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
typedef struct apr_pool_t { int dummy; } apr_pool_t;
typedef struct { const char *key; const char *val; } apr_table_entry_t;
typedef struct { int nelts,capacity; void *elts; size_t element_size; } apr_array_header_t;
typedef struct { apr_array_header_t array; } apr_table_t;
typedef struct apr_socket_t {int fd;} apr_socket_t;
/* The real Apache conn_rec does not expose client_socket. */
typedef struct { char *client_ip; void *conn_config; } conn_rec;
typedef struct { void *module_config; } server_rec;
typedef struct { apr_pool_t *pool; apr_table_t *headers_in; conn_rec *connection; server_rec *server; void *request_config; } request_rec;
struct command_rec;
typedef struct module {
 int magic; void *c1,*c2;
 void *(*s1)(apr_pool_t *,server_rec *);
 void *s2; const struct command_rec *cmd;
 void (*hooks)(apr_pool_t *);
} module;
#define AP_MODULE_DECLARE_DATA
#define STANDARD20_MODULE_STUFF 0
#define OK 0
#define DECLINED (-1)
#define HTTP_BAD_REQUEST 400
#define HTTP_FORBIDDEN 403
#define APLOG_MARK __FILE__,__LINE__
#define APLOG_WARNING 4
void *apr_pcalloc(apr_pool_t *,size_t);
char *apr_pstrdup(apr_pool_t *,const char *);
void *ap_get_module_config(void *,const module *);
void ap_set_module_config(void *,const module *,void *);
#endif
