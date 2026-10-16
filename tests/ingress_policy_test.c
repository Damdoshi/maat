#include "ingress_policy.h"
#include <stdio.h>
#include <string.h>

static unsigned int assertions = 0;
#define CHECK(expr) do { ++assertions; if (!(expr)) { \
    fprintf(stderr, "FAIL %s at %s:%d\n", #expr, __FILE__, __LINE__); return 1; \
} } while (0)
int main(void)
{
    CHECK(maat_is_reserved_header("X-Maat-Ticket"));
    CHECK(maat_is_reserved_header("x-mAaT-USER"));
    CHECK(maat_is_reserved_header("X_Maat_Ticket"));
    CHECK(maat_is_reserved_header("X-Maat_Ticket"));
    CHECK(maat_is_reserved_header("X_Maat-Ticket"));
    CHECK(!maat_is_reserved_header("X-Other-Ticket"));
    CHECK(!maat_is_reserved_header("X-Maat"));
    CHECK(maat_peer_is_loopback("127.0.0.1"));
    CHECK(maat_peer_is_loopback("127.2.3.4"));
    CHECK(maat_peer_is_loopback("::1"));
    CHECK(maat_peer_is_loopback("::ffff:127.0.0.1"));
    CHECK(!maat_peer_is_loopback("192.168.0.1"));
    CHECK(!maat_peer_is_loopback("::2"));
    CHECK(!maat_peer_is_loopback("::ffff:10.0.0.1"));
    CHECK(!maat_peer_is_loopback("127.0.0.1.example.org"));
    puts("PASS ingress policy: protected headers, reserved aliases and loopback peer checks");
    printf("%u assertions\n", assertions);
    return 0;
}
