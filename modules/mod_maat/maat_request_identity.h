/* SPDX-License-Identifier: MIT
 * Apache-only trusted request context. NEVER exposed as HTTP headers.
 * Apache modules may retrieve this optional function and receive a pointer
 * owned by the lifetime of request_rec->pool.
 */
#ifndef MAAT_REQUEST_IDENTITY_H
#define MAAT_REQUEST_IDENTITY_H
#include "httpd.h"
#include "apr_optional.h"
#include "maat_broker_client.h"
APR_DECLARE_OPTIONAL_FN(const struct maat_verified_identity *,
                        maat_request_identity, (const request_rec *r));
#endif
