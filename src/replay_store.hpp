#pragma once
#include "monitor_protocol.hpp"
#include <string>
#include <sqlite3.h>

namespace maat {
class ReplayStore {
    sqlite3* db_ = nullptr;
public:
    explicit ReplayStore(const std::string& path);
    ~ReplayStore();
    ReplayStore(const ReplayStore&) = delete;
    ReplayStore& operator=(const ReplayStore&) = delete;
    bool record(const AuthenticatedSession& session);
};
}
