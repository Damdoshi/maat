/* Self-contained Apache-interface simulation: tests the real mod_maat.c hook.
 * THIS IS NOT a substitute for compiling against apache2-dev. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <strings.h>
#include "../modules/mod_maat/mod_maat.c"

#define REQUIRE(test) do { if (!(test)) {fprintf(stderr,"FAIL %s at %d\n",#test,__LINE__);return 1;} } while (0)
/* Fake APR pool lifetime. Apache frees these when request_rec->pool dies. */
typedef struct allocated { void *memory; struct allocated *next; } allocated;
static allocated *allocations;
static void *pool_allocate(size_t n)
{
    allocated *item=malloc(sizeof(*item));
    if (!item) abort();
    item->memory=calloc(1,n);
    if (!item->memory) abort();
    item->next=allocations;allocations=item;
    return item->memory;
}
static void *pool_reallocate(void *previous,size_t n)
{
    allocated *item;
    for(item=allocations;item;item=item->next) if(item->memory==previous) break;
    if (!item) abort();
    item->memory=realloc(item->memory,n);
    if (!item->memory) abort();
    return item->memory;
}
void *apr_pcalloc(apr_pool_t *p,size_t n){(void)p;return pool_allocate(n);}
char *apr_pstrdup(apr_pool_t *p,const char *s)
{
    char *d=apr_pcalloc(p,strlen(s)+1);memcpy(d,s,strlen(s)+1);return d;
}
void *ap_get_module_config(void *ptr,const module *m){(void)m;return *(void**)ptr;}
void ap_set_module_config(void *ptr,const module *m,void *value){(void)m;*(void**)ptr=value;}
int maat_broker_verify(const char *path,uid_t uid,int fd,struct maat_verified_identity *identity)
{
    (void)path;
    if(uid!=0 || fd!=42) return 0;
    memset(identity,0,sizeof(*identity));
    strcpy(identity->ssh_user,"alice");
    identity->public_key[3]=11;
    return 1;
}
apr_socket_t *ap_get_conn_socket(conn_rec *connection) {
    return connection ? (apr_socket_t *)connection->conn_config : NULL;
}
int apr_os_sock_get(apr_os_sock_t *target,apr_socket_t *socket) {
    if(socket==NULL) return 1;
    *target=socket->fd;return APR_SUCCESS;
}
void ap_hook_post_read_request(int (*fn)(request_rec *),const void *a,const void *b,int n)
{(void)fn;(void)a;(void)b;(void)n;}
apr_array_header_t *apr_array_make(apr_pool_t *p,int n,size_t size)
{
    apr_array_header_t *a=apr_pcalloc(p,sizeof(*a));
    a->element_size=size;
    a->capacity=n?n:1;
    a->elts=apr_pcalloc(p,(size_t)a->capacity*size);
    return a;
}
void *test_array_push(apr_array_header_t *a)
{
    if(a->nelts>=a->capacity) {
        a->capacity*=2;
        a->elts=pool_reallocate(a->elts,(size_t)a->capacity*a->element_size);
    }
    return (char *)a->elts+((size_t)a->nelts++*a->element_size);
}
const apr_array_header_t *apr_table_elts(const apr_table_t *t){return &t->array;}
const char *apr_table_get(const apr_table_t *t,const char *key)
{
    const apr_table_entry_t *entry=t->array.elts;
    int i;
    for(i=0;i<t->array.nelts;++i) if(!strcasecmp(entry[i].key,key)) return entry[i].val;
    return NULL;
}
void apr_table_unset(apr_table_t *t,const char *key)
{
    apr_table_entry_t *entry=t->array.elts;
    int i=0;
    while(i<t->array.nelts) {
        if(!strcasecmp(entry[i].key,key)) {
            memmove(entry+i,entry+i+1,(size_t)(t->array.nelts-i-1)*sizeof(*entry));
            --t->array.nelts;
        } else ++i;
    }
}
void apr_table_setn(apr_table_t *t,const char *key,const char *val)
{
    apr_table_unset(t,key);
    apr_table_entry_t *entry=test_array_push(&t->array);
    entry->key=key;entry->val=val;
}
static int request(maat_server_conf *cfg,const char *peer,int count,const char *token,
                   int expected,const char *expected_ticket,int has_socket)
{
    apr_pool_t pool={0};
    apr_socket_t accepted={42};
    conn_rec connection={(char *)peer,has_socket ? &accepted : NULL};
    maat_server_conf *config_ref=cfg;
    server_rec server={&config_ref};
    apr_table_t table={0};
    void *request_context=NULL;
    request_rec r={&pool,&table,&connection,&server,&request_context};
    char *key="X-Maat-Ticket";
    int i;
    table.array.element_size=sizeof(apr_table_entry_t);
    table.array.capacity=8;
    table.array.elts=calloc(8,sizeof(apr_table_entry_t));
    apr_table_setn(&table,"X-Maat-User","impostor");
    apr_table_setn(&table,"X-Maat-Principal","fake");
    apr_table_setn(&table,"X_Maat_Ticket","falsified-alias");
    for(i=0;i<count;++i) {
        apr_table_entry_t *entry=test_array_push(&table.array);
        entry->key=key;entry->val=token;
    }
    REQUIRE(maat_post_read_request(&r)==expected);
    REQUIRE(apr_table_get(&table,"X-Maat-User")==NULL);
    REQUIRE(apr_table_get(&table,"X-Maat-Principal")==NULL);
    REQUIRE(apr_table_get(&table,"X_Maat_Ticket")==NULL);
    if(expected==DECLINED && cfg->ingress_enabled && maat_peer_is_loopback(peer) && has_socket) {
        REQUIRE(maat_request_identity(&r)!=NULL);
        REQUIRE(strcmp(maat_request_identity(&r)->ssh_user,"alice")==0);
    } else REQUIRE(maat_request_identity(&r)==NULL);
    if(expected_ticket) {
        REQUIRE(apr_table_get(&table,"X-Maat-Ticket")!=NULL);
        REQUIRE(strcmp(apr_table_get(&table,"X-Maat-Ticket"),expected_ticket)==0);
    }else REQUIRE(apr_table_get(&table,"X-Maat-Ticket")==NULL);
    free(table.array.elts);
    return 0;
}
int main(void)
{
    maat_server_conf disabled={0};
    maat_server_conf enabled={1,NULL};
    char ticket[65];memset(ticket,'f',64);ticket[64]='\0';
    REQUIRE(request(&disabled,"127.0.0.1",1,ticket,DECLINED,NULL,1)==0);
    REQUIRE(request(&enabled,"127.0.0.1",0,NULL,DECLINED,NULL,1)==0);
    REQUIRE(request(&enabled,"127.0.0.1",1,ticket,DECLINED,NULL,1)==0);
    REQUIRE(request(&enabled,"::1",1,ticket,DECLINED,NULL,1)==0);
    REQUIRE(request(&enabled,"192.0.2.3",0,NULL,HTTP_FORBIDDEN,NULL,1)==0);
    REQUIRE(request(&enabled,"127.0.0.1",0,NULL,HTTP_FORBIDDEN,NULL,0)==0);
    puts("PASS Apache direct broker verification: stripping, forgery, malformed, remote, anonymous");
    while(allocations) {
        allocated *item=allocations;
        allocations=item->next;
        free(item->memory);free(item);
    }
    return 0;
}
