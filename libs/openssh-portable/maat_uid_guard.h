/* Maât: generic safety envelope for broker-allocated, never-reused UIDs.
 *
 * The root-owned broker alone chooses and validates the configured UID range,
 * checks NSS collisions, and records allocations transactionally. SSH children
 * must not enforce an unrelated historical hard-coded subrange: the broker's
 * configurable host-reserved range can legitimately begin at 1000000000.
 *
 * This guard is deliberately broader than an individual host configuration;
 * it is a final 32-bit signed UID sanity check, NOT a substitute for the
 * broker's UID-range policy or an OS-wide UID reservation.
 */
#ifndef MAAT_UID_GUARD_H
#define MAAT_UID_GUARD_H

#include <stdint.h>

#define MAAT_UID_MINIMUM 1000000U
#define MAAT_UID_MAXIMUM 2147483646U

static inline int
maat_uid_plausible(uint32_t uid)
{
    return uid >= MAAT_UID_MINIMUM && uid <= MAAT_UID_MAXIMUM;
}

#endif /* MAAT_UID_GUARD_H */
