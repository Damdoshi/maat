#pragma once
#include "replay_store.hpp"
#include <sys/types.h>
namespace maat {
class MonitorReceiver {
    ReplayStore& store_;
    uid_t trusted_uid_;
public:
    MonitorReceiver(ReplayStore& store, uid_t trusted_uid):
        store_(store),trusted_uid_(trusted_uid) {}
    bool receive(int fd);
};
}
