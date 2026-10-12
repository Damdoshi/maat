#include "replay_store.hpp"
#include <stdexcept>
#include <ctime>

namespace maat {
namespace {
void run(sqlite3* db, const char* sql) {
    if (sqlite3_exec(db,sql,nullptr,nullptr,nullptr)!=SQLITE_OK)
        throw std::runtime_error("sqlite initialization failed");
}
}
ReplayStore::ReplayStore(const std::string& path) {
    if (sqlite3_open_v2(path.c_str(),&db_, SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE|
                         SQLITE_OPEN_FULLMUTEX,nullptr)!=SQLITE_OK)
        throw std::runtime_error("could not open replay store");
    run(db_,"PRAGMA journal_mode=WAL;");
    run(db_,"PRAGMA synchronous=FULL;");
    run(db_,"CREATE TABLE IF NOT EXISTS verified_ssh_sessions ("
        "session BLOB PRIMARY KEY NOT NULL, user TEXT NOT NULL,"
        "key_blob BLOB NOT NULL, accepted_at INTEGER NOT NULL);");
}
ReplayStore::~ReplayStore() { if(db_) sqlite3_close(db_); }
bool ReplayStore::record(const AuthenticatedSession& session) {
    // SQLite's primary key constraint atomically forbids reuse across processes
    // and restarts. Do not acknowledge on any failure (including disk full).
    sqlite3_stmt* stmt=nullptr;
    const char* sql="INSERT INTO verified_ssh_sessions"
        "(session,user,key_blob,accepted_at) VALUES (?1,?2,?3,?4)";
    if(sqlite3_prepare_v2(db_,sql,-1,&stmt,nullptr)!=SQLITE_OK) return false;
    const auto& sid=session.sessionId();
    const auto& blob=session.key().blob();
    int rc=sqlite3_bind_blob(stmt,1,sid.data(),int(sid.size()),SQLITE_TRANSIENT);
    if(rc==SQLITE_OK) rc=sqlite3_bind_text(stmt,2,session.user().c_str(),-1,SQLITE_TRANSIENT);
    if(rc==SQLITE_OK) rc=sqlite3_bind_blob(stmt,3,blob.data(),int(blob.size()),SQLITE_TRANSIENT);
    if(rc==SQLITE_OK) rc=sqlite3_bind_int64(stmt,4,std::time(nullptr));
    if(rc==SQLITE_OK) rc=sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc==SQLITE_DONE;
}
}
