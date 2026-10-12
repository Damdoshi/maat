#include "http_domain.hpp"
#include <sys/random.h>
#include <unistd.h>
#include <cerrno>
#include <stdexcept>
#include <cstring>
#include <ctime>
#include <algorithm>
#include <cctype>
#include <limits>
#include <pwd.h>
namespace maat {
namespace {
uint8_t nibble(char c) {
    if(c>='0' && c<='9') return uint8_t(c-'0');
    if(c>='a' && c<='f') return uint8_t(c-'a'+10);
    throw std::invalid_argument("invalid lowercase hex");
}
std::vector<uint8_t> parseHex(const std::string& hex,size_t min,size_t max) {
    if(hex.size()%2 || hex.size()/2<min || hex.size()/2>max) throw std::invalid_argument("hex length");
    std::vector<uint8_t> r;
    for(size_t i=0;i<hex.size();i+=2) r.push_back(uint8_t(nibble(hex[i])*16+nibble(hex[i+1])));
    return r;
}
std::string hexEncode(const uint8_t* data,size_t n) {
    static constexpr char h[]="0123456789abcdef";
    std::string s;
    s.reserve(n*2);
    for(size_t i=0;i<n;++i) { s+=h[data[i]>>4]; s+=h[data[i]&15]; }
    return s;
}
void put(std::vector<uint8_t>& result,const std::string& s) {
    if(s.size()>65535) throw std::invalid_argument("string too big");
    const uint32_t n=uint32_t(s.size());
    for(int shift=24;shift>=0;shift-=8) result.push_back(uint8_t(n>>shift));
    result.insert(result.end(),s.begin(),s.end());
}
void sqlExec(sqlite3* db,const char* s) {
    if(sqlite3_exec(db,s,nullptr,nullptr,nullptr)!=SQLITE_OK) throw std::runtime_error("sqlite failed");
}
}
SessionIdentifier::SessionIdentifier(const std::string& hex):id_(parseHex(hex,16,128)) {}
RequestTicket::RequestTicket() {
    size_t off=0;
    while(off<value_.size()) {
        ssize_t n=getrandom(value_.data()+off,value_.size()-off,0);
        if(n<0 && errno==EINTR) continue;
        if(n<=0) throw std::runtime_error("getrandom failed");
        off+=size_t(n);
    }
}
RequestTicket::RequestTicket(const std::string& h) {
    auto data=parseHex(h,32,32);
    std::copy(data.begin(),data.end(),value_.begin());
}
std::string RequestTicket::hex() const { return hexEncode(value_.data(),value_.size()); }
std::vector<uint8_t> requestMessage(const std::string& magic,const std::string& hex) {
    std::vector<uint8_t> msg; put(msg,magic); put(msg,hex); return msg;
}
std::string readString(const std::vector<uint8_t>& packet,size_t& offset,size_t max) {
    if(offset>packet.size() || packet.size()-offset<4) throw std::invalid_argument("short message");
    const size_t n=(size_t(packet[offset])<<24)|(size_t(packet[offset+1])<<16)|
      (size_t(packet[offset+2])<<8)|packet[offset+3];
    offset+=4;
    if(n>max || n>packet.size()-offset) throw std::invalid_argument("message field too long");
    std::string s(packet.begin()+offset,packet.begin()+offset+n);
    offset+=n; return s;
}
UIDRange::UIDRange(uint64_t first,uint64_t last):first_(first),last_(last) {
    if(first<1000000ULL || first>last || last>2147483646ULL)
        throw std::invalid_argument("unsafe or invalid ephemeral UID range");
}
EphemeralUID::EphemeralUID(uint64_t value,const UIDRange& range):value_(0) {
    if(!range.contains(value)) throw std::invalid_argument("ephemeral UID outside host-reserved range");
    value_=static_cast<uid_t>(value);
}
IdentityRepository::IdentityRepository(const std::string& path,const UIDRange& range):range_(range) {
    if(sqlite3_open_v2(path.c_str(),&db_,SQLITE_OPEN_READWRITE|SQLITE_OPEN_FULLMUTEX,nullptr)!=SQLITE_OK)
        throw std::runtime_error("cannot open SSH database");
    sqlite3_busy_timeout(db_,2000);
    sqlExec(db_,"PRAGMA journal_mode=WAL;");
    sqlExec(db_,"PRAGMA synchronous=FULL;");
    sqlExec(db_,"CREATE TABLE IF NOT EXISTS maat_request_tokens ("
       "ticket BLOB PRIMARY KEY, session BLOB NOT NULL, issued_at INTEGER NOT NULL,"
       "consumed_at INTEGER, FOREIGN KEY(session) REFERENCES verified_ssh_sessions(session));");
    sqlExec(db_,"CREATE TABLE IF NOT EXISTS maat_session_bindings ("
       "session BLOB PRIMARY KEY NOT NULL, bound_at INTEGER NOT NULL);");
    // This ledger is never truncated or reused: even abandoned sessions burn
    // their UID. This prevents a later SSH session from inheriting procfs/IPC
    // access to an earlier session whose processes survive.
    sqlExec(db_,"CREATE TABLE IF NOT EXISTS maat_ephemeral_uids ("
       "uid INTEGER PRIMARY KEY, session BLOB NOT NULL UNIQUE);");
    // Reject configuration changes that exclude any previously allocated UID.
    sqlite3_stmt* rangeCheck=nullptr;
    if(sqlite3_prepare_v2(db_,"SELECT MIN(uid),MAX(uid) FROM maat_ephemeral_uids",-1,&rangeCheck,nullptr)!=SQLITE_OK)
        throw std::runtime_error("cannot inspect existing UID ledger");
    if(sqlite3_step(rangeCheck)!=SQLITE_ROW) {
        sqlite3_finalize(rangeCheck);
        throw std::runtime_error("cannot inspect existing UID ledger");
    }
    if(sqlite3_column_type(rangeCheck,0)!=SQLITE_NULL &&
       (!range_.contains(static_cast<uint64_t>(sqlite3_column_int64(rangeCheck,0))) ||
        !range_.contains(static_cast<uint64_t>(sqlite3_column_int64(rangeCheck,1))))) {
        sqlite3_finalize(rangeCheck);
        throw std::runtime_error("configured UID range excludes existing allocations");
    }
    sqlite3_finalize(rangeCheck);
    // Crucial: a KEX session ID can be redeemed only once, transactionally.
    sqlExec(db_,"CREATE UNIQUE INDEX IF NOT EXISTS maat_one_ticket_per_session "
       "ON maat_request_tokens(session);");
}
IdentityRepository::~IdentityRepository(){if(db_) sqlite3_close(db_);}
bool IdentityRepository::bind(const SessionIdentifier& id, uid_t& bridgeUID) {
    // All allocation and session binding is one IMMEDIATE SQLite transaction.
    // Never grant a UID on a failed or unacknowledged registration. The root
    // monitor will fail closed if our acknowledgment cannot be received.
    if(sqlite3_exec(db_,"BEGIN IMMEDIATE",nullptr,nullptr,nullptr)!=SQLITE_OK) return false;
    bool success=false;
    sqlite3_stmt* stmt=nullptr;
    do {
        const char* nextSQL="SELECT COALESCE(MAX(uid)+1,?1) FROM maat_ephemeral_uids";
        if(sqlite3_prepare_v2(db_,nextSQL,-1,&stmt,nullptr)!=SQLITE_OK) break;
        if(sqlite3_bind_int64(stmt,1,static_cast<sqlite3_int64>(range_.first()))!=SQLITE_OK ||
           sqlite3_step(stmt)!=SQLITE_ROW) break;
        const auto raw=static_cast<uint64_t>(sqlite3_column_int64(stmt,0));
        sqlite3_finalize(stmt);stmt=nullptr;
        uid_t allocated=0;
        try { allocated=EphemeralUID(raw,range_).value(); }
        catch(const std::exception&) { break; }
        // Never allocate an existing NSS principal. This is a supplementary
        // guard, not a replacement for a host-wide UID reservation policy.
        passwd password{}, *found=nullptr;
        char buffer[16384];
        if(getpwuid_r(allocated,&password,buffer,sizeof(buffer),&found)!=0 || found!=nullptr) break;
        const char* bindSQL="INSERT INTO maat_session_bindings(session,bound_at) "
          "SELECT session,?2 FROM verified_ssh_sessions WHERE session=?1 "
          "AND accepted_at>=?3 AND accepted_at<=?2";
        if(sqlite3_prepare_v2(db_,bindSQL,-1,&stmt,nullptr)!=SQLITE_OK) break;
        const auto now=std::time(nullptr);
        int rc=sqlite3_bind_blob(stmt,1,id.bytes().data(),int(id.bytes().size()),SQLITE_TRANSIENT);
        if(rc==SQLITE_OK) rc=sqlite3_bind_int64(stmt,2,now);
        if(rc==SQLITE_OK) rc=sqlite3_bind_int64(stmt,3,now-60);
        if(rc==SQLITE_OK) rc=sqlite3_step(stmt);
        const bool inserted=rc==SQLITE_DONE && sqlite3_changes(db_)==1;
        sqlite3_finalize(stmt);stmt=nullptr;
        if(!inserted) break;
        if(sqlite3_prepare_v2(db_,"INSERT INTO maat_ephemeral_uids(uid,session) VALUES(?1,?2)",
            -1,&stmt,nullptr)!=SQLITE_OK) break;
        rc=sqlite3_bind_int64(stmt,1,allocated);
        if(rc==SQLITE_OK) rc=sqlite3_bind_blob(stmt,2,id.bytes().data(),int(id.bytes().size()),SQLITE_TRANSIENT);
        if(rc==SQLITE_OK) rc=sqlite3_step(stmt);
        const bool insertedUID=rc==SQLITE_DONE && sqlite3_changes(db_)==1;
        sqlite3_finalize(stmt);stmt=nullptr;
        if(!insertedUID) break;
        if(sqlite3_exec(db_,"COMMIT",nullptr,nullptr,nullptr)!=SQLITE_OK) break;
        bridgeUID=allocated;
        success=true;
    }while(false);
    if(stmt) sqlite3_finalize(stmt);
    if(!success) sqlite3_exec(db_,"ROLLBACK",nullptr,nullptr,nullptr);
    return success;
}
bool IdentityRepository::issue(const SessionIdentifier& id,const RequestTicket& ticket) {
    sqlite3_stmt* stmt=nullptr;
    const char* sql="INSERT INTO maat_request_tokens(ticket,session,issued_at) "
      "SELECT ?1, session,?3 FROM verified_ssh_sessions WHERE session=?2 "
      "AND accepted_at>=?4 AND accepted_at<=?3 "
      "AND EXISTS(SELECT 1 FROM maat_session_bindings WHERE session=?2)";
    if(sqlite3_prepare_v2(db_,sql,-1,&stmt,nullptr)!=SQLITE_OK) return false;
    int rc=sqlite3_bind_blob(stmt,1,ticket.bytes().data(),32,SQLITE_TRANSIENT);
    if(rc==SQLITE_OK) rc=sqlite3_bind_blob(stmt,2,id.bytes().data(),int(id.bytes().size()),SQLITE_TRANSIENT);
    if(rc==SQLITE_OK) rc=sqlite3_bind_int64(stmt,3,std::time(nullptr));
    if(rc==SQLITE_OK) rc=sqlite3_bind_int64(stmt,4,std::time(nullptr)-60);
    if(rc==SQLITE_OK) rc=sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc==SQLITE_DONE && sqlite3_changes(db_)==1;
}
bool IdentityRepository::consume(const RequestTicket& ticket,std::string& user,std::vector<uint8_t>& key) {
    // UPDATE ... RETURNING atomically consumes the token and returns the SSH
    // assertion. The token is never a claim about civil identity.
    const char* sql="UPDATE maat_request_tokens SET consumed_at=?2 "
      "WHERE ticket=?1 AND consumed_at IS NULL AND issued_at>=?3 AND issued_at<=?2 "
      "RETURNING (SELECT user FROM verified_ssh_sessions WHERE session=maat_request_tokens.session),"
      "(SELECT key_blob FROM verified_ssh_sessions WHERE session=maat_request_tokens.session)";
    sqlite3_stmt* stmt=nullptr;
    if(sqlite3_prepare_v2(db_,sql,-1,&stmt,nullptr)!=SQLITE_OK) return false;
    const sqlite3_int64 now=std::time(nullptr);
    int rc=sqlite3_bind_blob(stmt,1,ticket.bytes().data(),32,SQLITE_TRANSIENT);
    if(rc==SQLITE_OK) rc=sqlite3_bind_int64(stmt,2,now);
    if(rc==SQLITE_OK) rc=sqlite3_bind_int64(stmt,3,now-30);
    if(rc==SQLITE_OK) rc=sqlite3_step(stmt);
    bool ok=false;
    if(rc==SQLITE_ROW && sqlite3_column_type(stmt,0)==SQLITE_TEXT &&
       sqlite3_column_type(stmt,1)==SQLITE_BLOB) {
        const char* u=reinterpret_cast<const char*>(sqlite3_column_text(stmt,0));
        auto* bytes=static_cast<const uint8_t*>(sqlite3_column_blob(stmt,1));
        const int len=sqlite3_column_bytes(stmt,1);
        if(u && bytes && len==51) { user=u; key.assign(bytes,bytes+len); ok=true; }
    }
    if(ok && sqlite3_step(stmt)!=SQLITE_DONE) ok=false;
    if(sqlite3_finalize(stmt)!=SQLITE_OK) ok=false;
    return ok;
}
HTTPRequest HTTPRequest::read(int fd,size_t maxBody) {
    HTTPRequest result;
    char buf[4096];
    for(;;) {
        if(result.header_.size()>16384) throw std::invalid_argument("headers too big");
        auto p=result.header_.find("\r\n\r\n");
        if(p!=std::string::npos) {
            result.body_=result.header_.substr(p+4);
            result.header_.resize(p+4);
            break;
        }
        ssize_t n=::read(fd,buf,sizeof(buf));
        if(n<0 && errno==EINTR) continue;
        if(n<=0) throw std::invalid_argument("incomplete headers");
        result.header_.append(buf,size_t(n));
    }
    if(result.header_.size()>16384) throw std::invalid_argument("headers too big");
    auto first=result.header_.find("\r\n");
    if(first==std::string::npos) throw std::invalid_argument("bad request line");
    std::string start=result.header_.substr(0,first);
    if(start.rfind("GET /",0)!=0 && start.rfind("POST /",0)!=0 && start.rfind("HEAD /",0)!=0)
        throw std::invalid_argument("unsupported method or non-origin form");
    if(start.size()<9 || start.substr(start.size()-9)!=" HTTP/1.1")
        throw std::invalid_argument("HTTP 1.1 only");
    for(char c:start) if(uint8_t(c)<32 || uint8_t(c)>126) throw std::invalid_argument("bad request line");
    size_t len=0; bool hasLen=false,hasHost=false;
    size_t cursor=first+2;
    while(cursor<result.header_.size()-2) {
        auto end=result.header_.find("\r\n",cursor);
        if(end==std::string::npos) throw std::invalid_argument("malformed header");
        if(end==cursor) break;
        auto line=result.header_.substr(cursor,end-cursor);
        if(line.empty() || line[0]==' ' || line[0]=='\t') throw std::invalid_argument("header folding");
        auto colon=line.find(':');
        if(colon==std::string::npos) throw std::invalid_argument("missing colon");
        auto name=line.substr(0,colon);
        if(name.empty()) throw std::invalid_argument("empty header name");
        for(char c:name) if(!std::isalnum(static_cast<unsigned char>(c)) && c!='-')
            throw std::invalid_argument("invalid header name");
        std::transform(name.begin(),name.end(),name.begin(),[](unsigned char c){return char(std::tolower(c));});
        for(char c:line) if(c=='\0' || (uint8_t(c)<32 && c!='\t'))
            throw std::invalid_argument("control character");
        if(name=="transfer-encoding" || name=="connection" || name=="upgrade" || name=="proxy-connection")
            throw std::invalid_argument("ambiguous/framing header");
        if(name=="content-length") {
            if(hasLen) throw std::invalid_argument("duplicate content length");
            hasLen=true;
            const auto val=line.substr(colon+1);
            size_t i=val.find_first_not_of(' ');
            if(i==std::string::npos) throw std::invalid_argument("empty length");
            for(size_t j=i;j<val.size();++j) {
                if(val[j]<'0'||val[j]>'9') throw std::invalid_argument("invalid content length");
                if(len>(maxBody-size_t(val[j]-'0'))/10) throw std::invalid_argument("body too large");
                len=len*10+size_t(val[j]-'0');
            }
        }
        if(name=="host") {if(hasHost) throw std::invalid_argument("duplicate host"); hasHost=true;}
        cursor=end+2;
    }
    if(!hasHost || (start.rfind("POST",0)==0 && !hasLen)) throw std::invalid_argument("missing host or length");
    if(result.body_.size()>len) throw std::invalid_argument("pipelining or extra body");
    while(result.body_.size()<len) {
        ssize_t n=::read(fd,buf,std::min(sizeof(buf),len-result.body_.size()));
        if(n<0 && errno==EINTR) continue;
        if(n<=0) throw std::invalid_argument("incomplete request body");
        result.body_.append(buf,size_t(n));
    }
    return result;
}
std::string HTTPRequest::forwarded(const std::string& ticket) const {
    // Strip ALL client-supplied identity headers; token only from issuer.
    size_t first=header_.find("\r\n");
    std::string out=header_.substr(0,first+2);
    size_t cursor=first+2;
    while(cursor<header_.size()-2) {
        size_t end=header_.find("\r\n",cursor);
        if(end==cursor || end==std::string::npos) break;
        std::string line=header_.substr(cursor,end-cursor);
        std::string name=line.substr(0,line.find(':'));
        std::transform(name.begin(),name.end(),name.begin(),[](unsigned char c){return char(std::tolower(c));});
        if(name.rfind("x-maat-",0)!=0 && name!="expect") out+=line+"\r\n";
        cursor=end+2;
    }
    out+="X-Maat-Ticket: "+ticket+"\r\nConnection: close\r\n\r\n";
    return out+body_;
}
}
