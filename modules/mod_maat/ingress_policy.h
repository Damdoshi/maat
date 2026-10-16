/* SPDX-License-Identifier: MIT
 * Dependency-free defensive ingress rules for mod_maat.  No authority to
 * authenticate a client is granted by this library: only the broker can do so.
 */
#ifndef MAAT_INGRESS_POLICY_H
#define MAAT_INGRESS_POLICY_H
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
int maat_is_reserved_header(const char *name);
int maat_peer_is_loopback(const char *address);
#ifdef __cplusplus
}
#endif
#endif
