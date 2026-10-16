// Checks that OpenSSH accepts every valid broker-configurable UID envelope.
#include "../libs/openssh-portable/maat_uid_guard.h"
#include "../src/http/http_domain.hpp"
#include <cstdint>
#include <stdexcept>

int main() {
    using maat::UIDRange;
    const UIDRange standard;
    if (!maat_uid_plausible(static_cast<uint32_t>(standard.first())) ||
        !maat_uid_plausible(static_cast<uint32_t>(standard.last()))) return 1;
    const UIDRange lower(MAAT_UID_MINIMUM, MAAT_UID_MINIMUM + 1);
    const UIDRange upper(MAAT_UID_MAXIMUM - 1, MAAT_UID_MAXIMUM);
    if (!maat_uid_plausible(static_cast<uint32_t>(lower.first())) ||
        !maat_uid_plausible(static_cast<uint32_t>(upper.last()))) return 2;
    if (maat_uid_plausible(0) || maat_uid_plausible(65534) ||
        maat_uid_plausible(MAAT_UID_MINIMUM - 1) ||
        maat_uid_plausible(MAAT_UID_MAXIMUM + 1) ||
        maat_uid_plausible(UINT32_MAX)) return 3;
    try { UIDRange bad(MAAT_UID_MINIMUM - 1, MAAT_UID_MINIMUM); (void)bad; return 4; }
    catch (const std::invalid_argument&) {}
    try { UIDRange bad(MAAT_UID_MAXIMUM, MAAT_UID_MAXIMUM + 1); (void)bad; return 5; }
    catch (const std::invalid_argument&) {}
    return 0;
}
