#ifndef TEST_APR_TABLES_H
#define TEST_APR_TABLES_H
#include "httpd.h"
apr_array_header_t *apr_array_make(apr_pool_t *,int,size_t);
void *test_array_push(apr_array_header_t *);
#define APR_ARRAY_PUSH(a,type) (*(type*)test_array_push((a)))
#define APR_ARRAY_IDX(a,i,type) (((type *)(a)->elts)[i])
const apr_array_header_t *apr_table_elts(const apr_table_t *);
void apr_table_unset(apr_table_t *,const char *);
void apr_table_setn(apr_table_t *,const char *,const char *);
const char *apr_table_get(const apr_table_t *,const char *);
#endif
