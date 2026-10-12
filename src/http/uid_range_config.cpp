#include "http_domain.hpp"
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cerrno>
#include <cctype>
#include <cstring>
#include <stdexcept>
#include <string>
#include <sstream>
#include <limits>

namespace maat {
namespace {
std::string trim(const std::string& v) {
    const auto a=v.find_first_not_of(" \t\r");
    if(a==std::string::npos) return "";
    const auto b=v.find_last_not_of(" \t\r");
    return v.substr(a,b-a+1);
}
uint64_t decimal(const std::string& s) {
    if(s.empty() || s.size()>10) throw std::invalid_argument("bad UID integer");
    uint64_t n=0;
    for(char c:s) {
        if(c<'0'||c>'9') throw std::invalid_argument("bad UID integer");
        n=n*10+static_cast<uint64_t>(c-'0');
    }
    return n;
}
}
UIDRange UIDRangeConfiguration::read(const std::string& path) {
    int fd=open(path.c_str(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
    if(fd<0) throw std::runtime_error("cannot open UID configuration");
    struct stat st{};
    if(fstat(fd,&st)!=0 || !S_ISREG(st.st_mode) || st.st_uid!=0 ||
       (st.st_mode & 022)!=0 || st.st_size>4096 || st.st_size<0) {
        close(fd);throw std::runtime_error("unsafe UID configuration permissions/type");
    }
    std::string src;
    char buf[1024];ssize_t n;
    while((n=::read(fd,buf,sizeof(buf)))>0) {
        src.append(buf,static_cast<size_t>(n));
        if(src.size()>4096) {close(fd);throw std::runtime_error("oversized UID configuration");}
    }
    int saved=errno;close(fd);
    if(n<0) throw std::runtime_error(std::string("UID configuration read: ")+strerror(saved));
    return parse(src);
}
UIDRange UIDRangeConfiguration::parse(const std::string& src) {
    // Strict, side-effect-free Dabsic subset: one [UIDRange ... ] block.
    std::istringstream input(src);
    std::string line;
    bool opened=false,closed=false,haveFirst=false,haveLast=false;
    uint64_t first=0,last=0;
    while(std::getline(input,line)) {
        line=trim(line);
        if(line.empty() || line[0]=='#') continue;
        if(!opened) {
            if(line!="[UIDRange") throw std::invalid_argument("expected [UIDRange block");
            opened=true;continue;
        }
        if(closed) throw std::invalid_argument("extra content after UIDRange block");
        if(line=="]") {closed=true;continue;}
        const auto eq=line.find('=');
        if(eq==std::string::npos || line.find('=',eq+1)!=std::string::npos)
            throw std::invalid_argument("invalid UIDRange entry");
        const auto key=trim(line.substr(0,eq));
        const auto value=decimal(trim(line.substr(eq+1)));
        if(key=="First" && !haveFirst) {first=value;haveFirst=true;}
        else if(key=="Last" && !haveLast) {last=value;haveLast=true;}
        else throw std::invalid_argument("duplicate/unknown UIDRange entry");
    }
    if(!opened || !closed || !haveFirst || !haveLast)
        throw std::invalid_argument("incomplete UIDRange block");
    return UIDRange(first,last);
}
}
