/* Native Maât Apache interface. Only file descriptors are credentials.
 * There is no client-visible bearer token and no authentication HTTP header. */
#ifndef MAAT_BROKER_CLIENT_H
#define MAAT_BROKER_CLIENT_H
#include <sys/types.h>
#define MAAT_MAX_SSH_USER 64
#define MAAT_KEY_BYTES 51
struct maat_verified_identity {
    char ssh_user[MAAT_MAX_SSH_USER+1];
    unsigned char public_key[MAAT_KEY_BYTES];
};
int maat_broker_verify_fd(int broker_fd, uid_t expected_broker_uid,
                          int accepted_tcp_fd, struct maat_verified_identity *identity);
int maat_broker_verify(const char *socket_path, uid_t expected_broker_uid,
                       int accepted_tcp_fd, struct maat_verified_identity *identity);
#endif
