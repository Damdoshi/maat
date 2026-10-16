#ifndef TEST_HTTP_CONFIG_H
#define TEST_HTTP_CONFIG_H
#include "httpd.h"
typedef struct {server_rec *server; apr_pool_t *pool;} cmd_parms;
typedef struct command_rec {
    const char *name;
    union { const char *(*flag)(cmd_parms *,void *,int);
            const char *(*take1)(cmd_parms *,void *,const char *); } handler;
    void *data;int context;const char *help;
} command_rec;
#define RSRC_CONF 0
#define AP_INIT_FLAG(name,func,data,where,help) {name,{.flag=(func)},data,where,help}
#define AP_INIT_TAKE1(name,func,data,where,help) {name,{.take1=(func)},data,where,help}
#define APR_HOOK_FIRST 0
void ap_hook_post_read_request(int (*fn)(request_rec *),const void *,const void *,int);
#endif
