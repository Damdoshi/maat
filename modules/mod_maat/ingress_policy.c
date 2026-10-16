/* SPDX-License-Identifier: MIT */
#define _POSIX_C_SOURCE 200809L
#include "ingress_policy.h"
#include <string.h>
#include <ctype.h>
#include <strings.h>
#include <arpa/inet.h>

int maat_is_reserved_header(const char *name)
{
    /* PHP maps '-' and '_' alike when populating HTTP_* variables.
     * Refuse all alias spellings, not just the canonical X-Maat- form. */
    if (name == NULL || strlen(name) < 7)
        return 0;
    return toupper((unsigned char)name[0]) == 'X' &&
        (name[1] == '-' || name[1] == '_') &&
        strncasecmp(name + 2, "Maat", 4) == 0 &&
        (name[6] == '-' || name[6] == '_');
}

int maat_peer_is_loopback(const char *address)
{
    struct in_addr v4;
    struct in6_addr v6;
    static const unsigned char mapped_prefix[12] =
        {0,0,0,0,0,0,0,0,0,0,255,255};
    static const unsigned char loopback6[16] =
        {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    if (address == NULL)
        return 0;
    if (inet_pton(AF_INET, address, &v4) == 1)
        return (ntohl(v4.s_addr) & 0xff000000UL) == 0x7f000000UL;
    if (inet_pton(AF_INET6, address, &v6) != 1)
        return 0;
    if (memcmp(&v6, loopback6, sizeof(loopback6)) == 0)
        return 1;
    return memcmp(&v6, mapped_prefix, sizeof(mapped_prefix)) == 0 &&
        v6.s6_addr[12] == 127;
}

