#include "identity/authority_commands.hpp"

#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <sqlite3.h>

#include <climits>
#include <limits>
#include <stdexcept>

namespace maat { namespace identity {
namespace {

void sql(sqlite3* db, const char* statement) {
    if (sqlite3_exec(db, statement, nullptr, nullptr, nullptr) != SQLITE_OK)
        throw std::runtime_error("Maât authority: SQLite operation failed");
}
class Statement final {
    sqlite3_stmt* statement_ = nullptr;
public:
    Statement(sqlite3* db, const char* query) {
        if (sqlite3_prepare_v2(db, query, -1, &statement_, nullptr) != SQLITE_OK)
            throw std::runtime_error("Maât authority: cannot prepare statement");
    }
    ~Statement() { if (statement_) sqlite3_finalize(statement_); }
    Statement(const Statement&) = delete;
    Statement& operator=(const Statement&) = delete;
    void blob(int index, const void* bytes, int length) {
        if (sqlite3_bind_blob(statement_, index, bytes, length, SQLITE_TRANSIENT) != SQLITE_OK)
            throw std::runtime_error("Maât authority: cannot bind blob");
    }
    void integer64(int index, sqlite3_int64 value) {
        if (sqlite3_bind_int64(statement_, index, value) != SQLITE_OK)
            throw std::runtime_error("Maât authority: cannot bind counter");
    }
    int step() { return sqlite3_step(statement_); }
    sqlite3_stmt* get() { return statement_; }
    void done() {
        if (step() != SQLITE_DONE)
            throw std::runtime_error("Maât authority: write refused");
    }
};
void schema(sqlite3* db) {
    sql(db, "CREATE TABLE IF NOT EXISTS registry_authority ("
        "singleton INTEGER PRIMARY KEY CHECK(singleton=1),"
        "public_key BLOB NOT NULL CHECK(length(public_key)=32),"
        "registry_id BLOB NOT NULL CHECK(length(registry_id)=32),"
        "last_sequence INTEGER NOT NULL DEFAULT 0 CHECK(last_sequence>=0))");
    sql(db, "CREATE TABLE IF NOT EXISTS registry_authority_events ("
        "sequence INTEGER PRIMARY KEY NOT NULL CHECK(sequence>0),"
        "command_hash BLOB NOT NULL CHECK(length(command_hash)=32),"
        "signature BLOB NOT NULL CHECK(length(signature)=64),"
        "operation INTEGER NOT NULL CHECK(operation BETWEEN 1 AND 5),"
        "changed INTEGER NOT NULL CHECK(changed IN (0,1)))");
}
bool nonzero(const Fingerprint& value) {
    for (auto b : value) if (b) return true;
    return false;
}
void append(std::vector<std::uint8_t>& data, const Fingerprint& value) {
    data.insert(data.end(), value.begin(), value.end());
}
Fingerprint decodeCitizenId(const std::string& id) {
    if (id.size() != 64)
        throw std::invalid_argument("Maât authority: invalid citizen ID");
    Fingerprint result{};
    for (std::size_t i=0; i<64; ++i) {
        const char ch = id[i];
        std::uint8_t digit = 0;
        if (ch >= '0' && ch <= '9') digit = std::uint8_t(ch-'0');
        else if (ch >= 'a' && ch <= 'f') digit = std::uint8_t(ch-'a'+10);
        else throw std::invalid_argument("Maât authority: noncanonical citizen ID");
        result[i/2] = std::uint8_t(result[i/2] | (i%2 ? digit : digit<<4));
    }
    return result;
}
void verifyEd25519(const Fingerprint& key, const std::vector<std::uint8_t>& message,
                   const Ed25519Signature& signature) {
    EVP_PKEY* publicKey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr,
                                                       key.data(), key.size());
    if (!publicKey) throw std::runtime_error("Maât authority: invalid authority key");
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (!context) { EVP_PKEY_free(publicKey); throw std::runtime_error("Maât authority: no verification context"); }
    const int initialized = EVP_DigestVerifyInit(context, nullptr, nullptr, nullptr, publicKey);
    const int valid = initialized == 1 ?
        EVP_DigestVerify(context, signature.data(), signature.size(),
                         message.data(), message.size()) : 0;
    EVP_MD_CTX_free(context);
    EVP_PKEY_free(publicKey);
    if (valid != 1) throw std::runtime_error("Maât authority: signature verification failed");
}
void assertPinnedKey(sqlite3* db, const Fingerprint& expected, const Fingerprint& expectedRegistryId,
                     sqlite3_int64* sequence) {
    Statement s(db, "SELECT public_key,registry_id,last_sequence FROM registry_authority WHERE singleton=1");
    if (s.step() != SQLITE_ROW)
        throw std::runtime_error("Maât authority: not provisioned");
    const auto* key = static_cast<const std::uint8_t*>(sqlite3_column_blob(s.get(),0));
    if (sqlite3_column_bytes(s.get(),0)!=32 || !key ||
        CRYPTO_memcmp(key,expected.data(),expected.size())!=0)
        throw std::runtime_error("Maât authority: pinned key mismatch");
    const auto* id = static_cast<const std::uint8_t*>(sqlite3_column_blob(s.get(),1));
    if (sqlite3_column_bytes(s.get(),1)!=32 || !id ||
        CRYPTO_memcmp(id,expectedRegistryId.data(),expectedRegistryId.size())!=0)
        throw std::runtime_error("Maât authority: registry namespace mismatch");
    if (sequence) *sequence=sqlite3_column_int64(s.get(),2);
}
} // namespace

std::vector<std::uint8_t> authoritySigningBytes(const AuthorityInstruction& command) {
    if (command.sequence == 0 ||
        command.sequence > std::uint64_t(std::numeric_limits<sqlite3_int64>::max()))
        throw std::invalid_argument("Maât authority: invalid sequence");
    if (!nonzero(command.registryId))
        throw std::invalid_argument("Maât authority: empty registry namespace");
    const auto operation = command.operation;
    if (operation < RegistryOperation::enroll || operation > RegistryOperation::set_anonymous_permission)
        throw std::invalid_argument("Maât authority: invalid operation");
    const bool enrolling = operation == RegistryOperation::enroll;
    const bool keyed = enrolling || operation == RegistryOperation::add_key ||
                       operation == RegistryOperation::revoke_key;
    if (enrolling != command.citizenId.empty() ||
        (enrolling != nonzero(command.subjectCommitment)) ||
        (keyed != nonzero(command.publicKey)) ||
        (!enrolling && nonzero(command.subjectCommitment)))
        throw std::invalid_argument("Maât authority: malformed operation fields");
    const bool settingPermission = operation == RegistryOperation::set_anonymous_permission;
    if ((!settingPermission && command.permission != AnonymousPermission::denied) ||
        (settingPermission && command.permission != AnonymousPermission::denied &&
         command.permission != AnonymousPermission::allowed &&
         command.permission != AnonymousPermission::suspended))
        throw std::invalid_argument("Maât authority: malformed permission");
    Fingerprint citizenBytes{};
    if (!enrolling) citizenBytes = decodeCitizenId(command.citizenId);
    // The trailing NUL is intentional and part of the signing domain.
    static constexpr char domain[] = "MAAT/REGISTRY/AUTHORITY-COMMAND/V1";
    std::vector<std::uint8_t> result(domain, domain + sizeof(domain));
    append(result,command.registryId);
    result.push_back(std::uint8_t(operation));
    result.push_back(std::uint8_t(command.permission));
    for (int i=7; i>=0; --i)
        result.push_back(std::uint8_t(command.sequence>>(i*8)));
    append(result,citizenBytes);
    append(result,command.subjectCommitment);
    append(result,command.publicKey);
    return result;
}

void RegistryAuthority::bootstrap(CitizenRegistry& registry, const Fingerprint& key,
                                  const Fingerprint& namespaceId) {
    if (!nonzero(key) || !nonzero(namespaceId))
        throw std::invalid_argument("Maât authority: empty public key or registry namespace");
    // Only a privileged *offline* provisioner owning the protected SQLite DB
    // may call bootstrap. Existing anchors are immutable; no silent rotation.
    sql(registry.db_,"BEGIN IMMEDIATE");
    try {
        schema(registry.db_);
        Statement insert(registry.db_,"INSERT OR IGNORE INTO registry_authority"
                 "(singleton,public_key,registry_id,last_sequence) VALUES(1,?1,?2,0)");
        insert.blob(1,key.data(),int(key.size()));
        insert.blob(2,namespaceId.data(),int(namespaceId.size())); insert.done();
        assertPinnedKey(registry.db_,key,namespaceId,nullptr);
        sql(registry.db_,"COMMIT");
    } catch (...) { sqlite3_exec(registry.db_,"ROLLBACK",nullptr,nullptr,nullptr); throw; }
}
RegistryAuthority::RegistryAuthority(CitizenRegistry& registry,
                                     const Fingerprint& pinnedPublicKey,
                                     const Fingerprint& registryId)
  : registry_(registry), publicKey_(pinnedPublicKey), registryId_(registryId) {
    assertPinnedKey(registry_.db_,publicKey_,registryId_,nullptr);
}
AuthorityResult RegistryAuthority::apply(const AuthorityInstruction& command,
                                          const Ed25519Signature& signature) {
    const auto signingBytes = authoritySigningBytes(command);
    if (CRYPTO_memcmp(command.registryId.data(),registryId_.data(),registryId_.size())!=0)
        throw std::runtime_error("Maât authority: wrong registry namespace");
    verifyEd25519(publicKey_,signingBytes,signature);
    // This transaction covers BOTH replay counter and domain mutation. No
    // credential can consume a sequence without its mutation committing.
    sql(registry_.db_,"BEGIN IMMEDIATE");
    try {
        sqlite3_int64 prior = 0;
        assertPinnedKey(registry_.db_,publicKey_,registryId_,&prior);
        if (prior == std::numeric_limits<sqlite3_int64>::max() ||
            command.sequence != std::uint64_t(prior)+1)
            throw std::runtime_error("Maât authority: replay/out-of-order command");
        AuthorityResult result{};
        switch (command.operation) {
        case RegistryOperation::enroll:
            result.citizenId=registry_.enroll(command.subjectCommitment,command.publicKey);
            result.changed=true;
            break;
        case RegistryOperation::add_key:
            result.changed=registry_.addKey(command.citizenId,command.publicKey);
            break;
        case RegistryOperation::revoke_key:
            result.changed=registry_.revokeKey(command.citizenId,command.publicKey);
            break;
        case RegistryOperation::revoke_citizen:
            result.changed=registry_.revokeCitizen(command.citizenId);
            break;
        case RegistryOperation::set_anonymous_permission:
            result.changed=registry_.setAnonymousPermission(command.citizenId,command.permission);
            break;
        }
        {
            Statement update(registry_.db_,"UPDATE registry_authority SET last_sequence=?1 WHERE singleton=1");
            update.integer64(1,sqlite3_int64(command.sequence)); update.done();
            if (sqlite3_changes(registry_.db_) != 1)
                throw std::runtime_error("Maât authority: missing authority anchor");
        }
        std::array<std::uint8_t,SHA256_DIGEST_LENGTH> digest{};
        if (!SHA256(signingBytes.data(),signingBytes.size(),digest.data()))
            throw std::runtime_error("Maât authority: hashing failed");
        {
            Statement audit(registry_.db_,"INSERT INTO registry_authority_events"
                "(sequence,command_hash,signature,operation,changed) VALUES(?1,?2,?3,?4,?5)");
            audit.integer64(1,sqlite3_int64(command.sequence));
            audit.blob(2,digest.data(),int(digest.size()));
            audit.blob(3,signature.data(),int(signature.size()));
            audit.integer64(4,int(command.operation));
            audit.integer64(5,result.changed ? 1 : 0);
            audit.done();
        }
        sql(registry_.db_,"COMMIT");
        return result;
    } catch (...) { sqlite3_exec(registry_.db_,"ROLLBACK",nullptr,nullptr,nullptr); throw; }
}

}} // namespace maat::identity
