/* SPDX-License-Identifier: MIT
 * Validate SSH identity against the broker using the kernel TCP connection
 * descriptor, not HTTP headers or bearer strings.
 */
#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_core.h"
#include "http_log.h"
#include "apr_tables.h"
#include "apr_strings.h"
#include "apr_portable.h"
#include "maat_request_identity.h"
#include "ingress_policy.h"
#include <string.h>

module AP_MODULE_DECLARE_DATA maat_module;
#define MAAT_DEFAULT_CHECK_SOCKET "/run/maat-http/check.sock"

typedef struct {
    int ingress_enabled;
    const char *check_socket;
} maat_server_conf;

static void *maat_create_server_conf(apr_pool_t *pool, server_rec *server)
{
    maat_server_conf *conf = apr_pcalloc(pool, sizeof(*conf));
    (void)server;
    conf->ingress_enabled = 0;
    conf->check_socket = MAAT_DEFAULT_CHECK_SOCKET;
    return conf;
}
static const char *maat_set_ingress(cmd_parms *cmd, void *dummy, int enabled)
{
    maat_server_conf *conf;
    (void)dummy;
    conf = ap_get_module_config(cmd->server->module_config, &maat_module);
    conf->ingress_enabled = enabled;
    return NULL;
}
static const char *maat_set_socket(cmd_parms *cmd, void *dummy, const char *path)
{
    maat_server_conf *conf;
    (void)dummy;
    if (path == NULL || path[0] != '/' || strlen(path) > 95)
        return "MaatBrokerSocket requires a short absolute Unix socket path";
    conf = ap_get_module_config(cmd->server->module_config, &maat_module);
    conf->check_socket = apr_pstrdup(cmd->pool,path);
    return NULL;
}
static const command_rec maat_commands[] = {
    AP_INIT_FLAG("MaatIngress", maat_set_ingress, NULL, RSRC_CONF,
                 "On only on a dedicated private Apache listener"),
    AP_INIT_TAKE1("MaatBrokerSocket", maat_set_socket, NULL, RSRC_CONF,
                  "Trusted root-owned descriptor-verification socket"),
    {NULL}
};

/* Optional function for downstream *native* Apache modules.
 * Never accept a caller-supplied identity as an argument. */
static const struct maat_verified_identity *maat_request_identity(const request_rec *r)
{
    if (r == NULL || r->request_config == NULL) return NULL;
    return ap_get_module_config(r->request_config, &maat_module);
}

static int maat_post_read_request(request_rec *r)
{
    const apr_array_header_t *header_array;
    const apr_table_entry_t *entry;
    apr_array_header_t *reserved;
    const maat_server_conf *conf;
    apr_os_sock_t accepted_fd;
    apr_socket_t *accepted_socket;
    struct maat_verified_identity verified;
    struct maat_verified_identity *stored;
    int i;
    conf=ap_get_module_config(r->server->module_config,&maat_module);
    reserved=apr_array_make(r->pool,4,sizeof(const char*));
    header_array=apr_table_elts(r->headers_in);
    entry=(const apr_table_entry_t*)header_array->elts;
    for(i=0;i<header_array->nelts;++i) {
        if(maat_is_reserved_header(entry[i].key))
            APR_ARRAY_PUSH(reserved,const char*)=apr_pstrdup(r->pool,entry[i].key);
    }
    for(i=0;i<reserved->nelts;++i)
        apr_table_unset(r->headers_in,APR_ARRAY_IDX(reserved,i,const char*));
    if(conf==NULL || !conf->ingress_enabled) return DECLINED;
    /* Dedicated private ingress: every request must have a binding. In
     * particular, a local untrusted HTTP client cannot create an anonymous
     * request that is confused with an SSH-authenticated connection. */
    accepted_socket = r->connection ? ap_get_conn_socket(r->connection) : NULL;
    if(r->connection == NULL ||
       !maat_peer_is_loopback(r->connection->client_ip) ||
       accepted_socket == NULL ||
       apr_os_sock_get(&accepted_fd,accepted_socket)!=APR_SUCCESS ||
       !maat_broker_verify(conf->check_socket,0,(int)accepted_fd,&verified)) {
        ap_log_rerror(APLOG_MARK,APLOG_WARNING,0,r,
                      "Maât ingress: no matching SSH connection proof");
        return HTTP_FORBIDDEN;
    }
    stored=apr_pcalloc(r->pool,sizeof(*stored));
    memcpy(stored,&verified,sizeof(*stored));
    ap_set_module_config(r->request_config,&maat_module,stored);
    return DECLINED;
}
static void maat_register_hooks(apr_pool_t *pool)
{
    (void)pool;
    APR_REGISTER_OPTIONAL_FN(maat_request_identity);
    ap_hook_post_read_request(maat_post_read_request, NULL, NULL, APR_HOOK_FIRST);
}
module AP_MODULE_DECLARE_DATA maat_module = {
    STANDARD20_MODULE_STUFF,
    NULL, NULL,
    maat_create_server_conf, NULL,
    maat_commands,
    maat_register_hooks
};
