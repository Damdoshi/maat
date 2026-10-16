#include "citizen_registry.hpp"

#include <openssl/rand.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <stdexcept>

namespace maat {
namespace identity {
namespace {

// A SQLite store must live in an owner-private directory. This deliberately
// refuses shared project directories and symlinks instead of chmod'ing them.
void requirePrivateDirectory(const std::string& path) {
    const auto slash = path.find_last_of('/');
    const std::string directory = slash == std::string::npos ? "." :
                                  slash == 0 ? "/" : path.substr(0, slash);
    struct stat st{};
    if (lstat(directory.c_str(), &st) != 0 || !S_ISDIR(st.st_mode) ||
        st.st_uid != geteuid() || (st.st_mode & 0077) != 0)
        throw std::runtime_error("Maât registry: database directory must be owner-private");
}
void requirePrivateDatabaseFile(const std::string& path) {
    if (path.empty() || path == ":memory:")
        throw std::invalid_argument("Maât registry: expected a private on-disk database");
    requirePrivateDirectory(path);
    int fd = open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd == -1 && errno == ENOENT)
        fd = open(path.c_str(), O_RDONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0)
        throw std::runtime_error("Maât registry: cannot safely open database file");
    struct stat st{};
    const bool valid = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
        st.st_nlink == 1 && st.st_uid == geteuid() && (st.st_mode & 0077) == 0;
    close(fd);
    if (!valid)
        throw std::runtime_error("Maât registry: insecure database file permissions/type");
}
void execute(sqlite3* db, const char* sql) {
    if (sqlite3_exec(db, sql, nullptr, nullptr, nullptr) != SQLITE_OK)
        throw std::runtime_error("Maât registry: SQL operation failed");
}
sqlite3* openDatabase(const std::string& path) {
    requirePrivateDatabaseFile(path);
    sqlite3* db = nullptr;
    if (sqlite3_open_v2(path.c_str(), &db,
         SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX, nullptr) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        throw std::runtime_error("Maât registry: SQLite open failed");
    }
    try {
        if (sqlite3_busy_timeout(db, 1200) != SQLITE_OK)
            throw std::runtime_error("Maât registry: cannot configure busy timeout");
        execute(db, "PRAGMA foreign_keys=ON;");
        execute(db, "PRAGMA journal_mode=WAL;");
        execute(db, "PRAGMA synchronous=FULL;");
    } catch (...) { sqlite3_close(db); throw; }
    return db;
}
class Statement final {
    sqlite3_stmt* stmt_ = nullptr;
public:
    Statement(sqlite3* db, const char* sql) {
        if (sqlite3_prepare_v2(db, sql, -1, &stmt_, nullptr) != SQLITE_OK)
            throw std::runtime_error("Maât registry: statement preparation failed");
    }
    ~Statement() { if (stmt_) sqlite3_finalize(stmt_); }
    Statement(const Statement&) = delete;
    Statement& operator=(const Statement&) = delete;
    sqlite3_stmt* get() const { return stmt_; }
    void text(int index, const std::string& value) {
        if (sqlite3_bind_text(stmt_, index, value.c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK)
            throw std::runtime_error("Maât registry: cannot bind text");
    }
    void fingerprint(int index, const Fingerprint& value) {
        if (sqlite3_bind_blob(stmt_, index, value.data(), int(value.size()), SQLITE_TRANSIENT)
            != SQLITE_OK)
            throw std::runtime_error("Maât registry: cannot bind fingerprint");
    }
    void integer(int index, int value) {
        if (sqlite3_bind_int(stmt_, index, value) != SQLITE_OK)
            throw std::runtime_error("Maât registry: cannot bind number");
    }
    int step() { return sqlite3_step(stmt_); }
    void done() {
        if (step() != SQLITE_DONE)
            throw std::runtime_error("Maât registry: write failed or violated a constraint");
    }
};
bool allZero(const Fingerprint& value) {
    for (std::uint8_t byte : value) if (byte != 0) return false;
    return true;
}
void requireNonzero(const Fingerprint& value) {
    if (allZero(value)) throw std::invalid_argument("Maât registry: zero fingerprint forbidden");
}
void validateCitizenId(const std::string& value) {
    if (value.size() != 64) throw std::invalid_argument("Maât registry: invalid citizen ID");
    for (char c : value)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            throw std::invalid_argument("Maât registry: invalid citizen ID");
}
void validateServiceId(const std::string& value) {
    if (value.empty() || value.size() > 128)
        throw std::invalid_argument("Maât registry: invalid service scope");
    for (char c : value)
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
              c == '.' || c == '-' || c == '_'))
            throw std::invalid_argument("Maât registry: invalid service scope");
}
std::string newCitizenId() {
    Fingerprint bytes{};
    if (RAND_bytes(bytes.data(), int(bytes.size())) != 1)
        throw std::runtime_error("Maât registry: secure randomness unavailable");
    static constexpr char digits[] = "0123456789abcdef";
    std::string id;
    id.reserve(bytes.size() * 2);
    for (auto b : bytes) { id.push_back(digits[b >> 4]); id.push_back(digits[b & 15]); }
    return id;
}
void initializeCitizenTables(sqlite3* db) {
    execute(db, "CREATE TABLE IF NOT EXISTS citizens ("
        "citizen_id TEXT PRIMARY KEY NOT NULL CHECK(length(citizen_id)=64),"
        "subject_commitment BLOB NOT NULL UNIQUE CHECK(length(subject_commitment)=32),"
        "status INTEGER NOT NULL DEFAULT 1 CHECK(status IN (1,2)),"
        "anonymous_permission INTEGER NOT NULL DEFAULT 0 CHECK(anonymous_permission IN (0,1,2)))");
    execute(db, "CREATE TABLE IF NOT EXISTS citizen_keys ("
        "public_key BLOB PRIMARY KEY NOT NULL CHECK(length(public_key)=32),"
        "citizen_id TEXT NOT NULL REFERENCES citizens(citizen_id),"
        "revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1)))");
}
void initializeBanTables(sqlite3* db) {
    execute(db, "CREATE TABLE IF NOT EXISTS service_bans ("
        "service_id TEXT NOT NULL,"
        "nullifier BLOB NOT NULL CHECK(length(nullifier)=32),"
        "PRIMARY KEY(service_id,nullifier))");
}
} // namespace

CitizenRegistry::CitizenRegistry(const std::string& path) : db_(openDatabase(path)) {
    try { initializeCitizenTables(db_); }
    catch (...) { sqlite3_close(db_); db_=nullptr; throw; }
}
CitizenRegistry::~CitizenRegistry() { if (db_) sqlite3_close(db_); }

std::string CitizenRegistry::enroll(const Fingerprint& subjectCommitment,
                                    const Fingerprint& initialEd25519Key) {
    requireNonzero(subjectCommitment);
    requireNonzero(initialEd25519Key);
    const std::string id = newCitizenId();
    execute(db_, "SAVEPOINT maat_registry_mutation");
    try {
        {
            Statement s(db_, "INSERT INTO citizens(citizen_id,subject_commitment) VALUES(?1,?2)");
            s.text(1,id); s.fingerprint(2,subjectCommitment); s.done();
        }
        {
            Statement s(db_, "INSERT INTO citizen_keys(public_key,citizen_id) VALUES(?1,?2)");
            s.fingerprint(1,initialEd25519Key); s.text(2,id); s.done();
        }
        execute(db_, "RELEASE SAVEPOINT maat_registry_mutation");
    } catch (...) { sqlite3_exec(db_, "ROLLBACK TO SAVEPOINT maat_registry_mutation", nullptr, nullptr, nullptr);
                  sqlite3_exec(db_, "RELEASE SAVEPOINT maat_registry_mutation", nullptr, nullptr, nullptr); throw; }
    return id;
}
bool CitizenRegistry::addKey(const std::string& id, const Fingerprint& key) {
    validateCitizenId(id); requireNonzero(key);
    Statement s(db_, "INSERT INTO citizen_keys(public_key,citizen_id) "
                     "SELECT ?1,citizen_id FROM citizens WHERE citizen_id=?2 AND status=1");
    s.fingerprint(1,key); s.text(2,id); s.done();
    return sqlite3_changes(db_) == 1;
}
bool CitizenRegistry::revokeKey(const std::string& id, const Fingerprint& key) {
    validateCitizenId(id); requireNonzero(key);
    Statement s(db_, "UPDATE citizen_keys SET revoked=1 WHERE citizen_id=?1 "
                     "AND public_key=?2 AND revoked=0");
    s.text(1,id); s.fingerprint(2,key); s.done();
    return sqlite3_changes(db_) == 1;
}
bool CitizenRegistry::revokeCitizen(const std::string& id) {
    validateCitizenId(id);
    execute(db_, "SAVEPOINT maat_registry_mutation");
    try {
        Statement s(db_, "UPDATE citizens SET status=2,anonymous_permission=0 "
                         "WHERE citizen_id=?1 AND status=1");
        s.text(1,id); s.done();
        const bool changed = sqlite3_changes(db_) == 1;
        if (changed) {
            Statement keys(db_, "UPDATE citizen_keys SET revoked=1 WHERE citizen_id=?1");
            keys.text(1,id); keys.done();
        }
        execute(db_, "RELEASE SAVEPOINT maat_registry_mutation");
        return changed;
    } catch (...) { sqlite3_exec(db_, "ROLLBACK TO SAVEPOINT maat_registry_mutation", nullptr, nullptr, nullptr);
                  sqlite3_exec(db_, "RELEASE SAVEPOINT maat_registry_mutation", nullptr, nullptr, nullptr); throw; }
}
bool CitizenRegistry::setAnonymousPermission(const std::string& id,
                                             AnonymousPermission permission) {
    validateCitizenId(id);
    if (permission != AnonymousPermission::denied &&
        permission != AnonymousPermission::allowed &&
        permission != AnonymousPermission::suspended)
        throw std::invalid_argument("Maât registry: invalid anonymous permission");
    Statement s(db_, "UPDATE citizens SET anonymous_permission=?1 "
                     "WHERE citizen_id=?2 AND status=1 AND anonymous_permission<>?1");
    s.integer(1,int(permission)); s.text(2,id); s.done();
    return sqlite3_changes(db_) == 1;
}
std::optional<CitizenRecord> CitizenRegistry::lookup(const std::string& id) const {
    validateCitizenId(id);
    Statement s(db_, "SELECT status,anonymous_permission FROM citizens WHERE citizen_id=?1");
    s.text(1,id);
    const int rc = s.step();
    if (rc == SQLITE_DONE) return std::nullopt;
    if (rc != SQLITE_ROW) throw std::runtime_error("Maât registry: lookup failed");
    return CitizenRecord{id, CitizenStatus(sqlite3_column_int(s.get(),0)),
                         AnonymousPermission(sqlite3_column_int(s.get(),1))};
}
std::optional<std::string> CitizenRegistry::activeKeyOwner(const Fingerprint& key) const {
    requireNonzero(key);
    Statement s(db_, "SELECT k.citizen_id FROM citizen_keys k "
        "JOIN citizens c ON c.citizen_id=k.citizen_id "
        "WHERE k.public_key=?1 AND k.revoked=0 AND c.status=1");
    s.fingerprint(1,key);
    const int rc=s.step();
    if (rc == SQLITE_DONE) return std::nullopt;
    if (rc != SQLITE_ROW) throw std::runtime_error("Maât registry: key lookup failed");
    return std::string(reinterpret_cast<const char*>(sqlite3_column_text(s.get(),0)));
}

ServiceBanLedger::ServiceBanLedger(const std::string& path) : db_(openDatabase(path)) {
    try { initializeBanTables(db_); }
    catch (...) { sqlite3_close(db_); db_=nullptr; throw; }
}
ServiceBanLedger::~ServiceBanLedger() { if (db_) sqlite3_close(db_); }
bool ServiceBanLedger::ban(const std::string& serviceId, const Fingerprint& nullifier) {
    validateServiceId(serviceId); requireNonzero(nullifier);
    Statement s(db_, "INSERT OR IGNORE INTO service_bans(service_id,nullifier) VALUES(?1,?2)");
    s.text(1,serviceId); s.fingerprint(2,nullifier); s.done();
    return sqlite3_changes(db_) == 1;
}
bool ServiceBanLedger::unban(const std::string& serviceId, const Fingerprint& nullifier) {
    validateServiceId(serviceId); requireNonzero(nullifier);
    Statement s(db_, "DELETE FROM service_bans WHERE service_id=?1 AND nullifier=?2");
    s.text(1,serviceId); s.fingerprint(2,nullifier); s.done();
    return sqlite3_changes(db_) == 1;
}
bool ServiceBanLedger::isBanned(const std::string& serviceId, const Fingerprint& nullifier) const {
    validateServiceId(serviceId); requireNonzero(nullifier);
    Statement s(db_, "SELECT 1 FROM service_bans WHERE service_id=?1 AND nullifier=?2");
    s.text(1,serviceId); s.fingerprint(2,nullifier);
    const int rc=s.step();
    if (rc == SQLITE_ROW) return true;
    if (rc == SQLITE_DONE) return false;
    throw std::runtime_error("Maât registry: ban lookup failed");
}

} // namespace identity
} // namespace maat
