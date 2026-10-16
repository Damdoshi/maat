#include "identity/trust_peers.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace maat { namespace identity {
namespace {
void require(bool ok,const char* message) {
    if(!ok)throw std::runtime_error(message);
}
bool safeDestination(const std::string& v) {
    if(v.empty() || v.size()>255 || v[0]=='-')return false;
    bool hasAt=false;
    for(unsigned char c:v) {
        if(c=='@')hasAt=true;
        if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||
             (c>='0'&&c<='9')||c=='@'||c=='.'||c=='-'||
             c=='_'||c=='['||c==']'||c==':'))return false;
    }
    return hasAt && v[0]!='@' && v.find('@')==v.rfind('@') && v.back()!='@';
}
bool safePath(const std::string& path) {
    if(path.size()<2 || path.size()>4096 || path[0]!='/')return false;
    for(unsigned char c:path)if(c<0x21 || c>0x7e)return false;
    return true;
}
unsigned number(const std::string& s,unsigned low,unsigned high) {
    require(!s.empty() && s.size()<=8,"invalid peer numeric setting");
    for(char c:s)require(c>='0'&&c<='9',"invalid peer numeric setting");
    errno=0;
    char* end=nullptr;
    const auto n=std::strtoul(s.c_str(),&end,10);
    require(errno==0 && *end=='\0' && n>=low && n<=high,
            "peer numeric setting out of range");
    return static_cast<unsigned>(n);
}
}

std::vector<TrustPeer> parseTrustPeers(std::istream& in) {
    std::vector<TrustPeer> result;
    std::string line;
    unsigned lineNumber=0;
    while(std::getline(in,line)) {
        ++lineNumber;
        require(lineNumber<=256 && line.size()<=16384,"peer configuration too long");
        std::istringstream fields(line);
        std::string item;
        std::vector<std::string> tokens;
        while(fields>>item)tokens.push_back(item);
        if(tokens.empty() || tokens[0][0]=='#')continue;
        require(tokens.size()==4 || tokens.size()==5,"invalid peer configuration fields");
        require(result.size()<8,"too many trust sync peers");
        TrustPeer peer;
        peer.destination=tokens[0];
        peer.port=tokens[1];
        peer.privateKey=tokens[2];
        peer.knownHosts=tokens[3];
        require(safeDestination(peer.destination),"invalid trust peer destination");
        number(peer.port,1,65535);
        require(safePath(peer.privateKey) && safePath(peer.knownHosts),
                "trust peer key and known_hosts must be absolute safe paths");
        if(tokens.size()==5)peer.maxPages=number(tokens[4],1,4096);
        for(const auto& old:result)
            require(old.destination!=peer.destination || old.port!=peer.port,
                    "duplicate trust sync peer");
        result.push_back(peer);
    }
    require(!in.bad(),"trust peer configuration read failure");
    require(!result.empty(),"trust peer configuration has no peers");
    return result;
}

std::vector<TrustPeer> loadTrustPeers(const std::string& absolutePath) {
    require(safePath(absolutePath),"peer config path must be absolute");
    int fd=open(absolutePath.c_str(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    require(fd>=0,"cannot open trusted peer configuration");
    try {
        struct stat st{};
        require(fstat(fd,&st)==0 && S_ISREG(st.st_mode) && st.st_nlink==1 &&
                (st.st_uid==0 || st.st_uid==geteuid()) &&
                (st.st_mode&0022)==0 && st.st_size>=0 && st.st_size<=65536,
                "peer config must be a regular owner-controlled, non-writable-by-group file");
        std::string contents;
        char block[4096];
        while(true) {
            const auto n=read(fd,block,sizeof(block));
            if(n<0 && errno==EINTR)continue;
            require(n>=0,"peer configuration I/O failure");
            if(n==0)break;
            require(contents.size()+static_cast<std::size_t>(n)<=65536,
                    "oversized peer configuration");
            contents.append(block,static_cast<std::size_t>(n));
        }
        close(fd);fd=-1;
        std::istringstream parsed(contents);
        return parseTrustPeers(parsed);
    } catch(...) {
        if(fd>=0)close(fd);
        throw;
    }
}

}} // namespace maat::identity
