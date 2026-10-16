#ifndef TEST_HTTP_CORE_H
#define TEST_HTTP_CORE_H
#include "httpd.h"
apr_socket_t *ap_get_conn_socket(conn_rec *connection);
#endif
