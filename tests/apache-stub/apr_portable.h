#ifndef MAAT_STUB_APR_PORTABLE_H
#define MAAT_STUB_APR_PORTABLE_H
#include "httpd.h"
typedef int apr_os_sock_t;
#define APR_SUCCESS 0
int apr_os_sock_get(apr_os_sock_t *,apr_socket_t *);
#endif
