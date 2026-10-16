#include "identity/trust_peers.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
using namespace maat::identity;
namespace {
void check(bool ok,const char* why) {
    if(!ok){std::fprintf(stderr,"FAIL peer config: %s\n",why);std::exit(1);}
}
template<class F> void rejects(F f,const char* why) {
    try{f();}catch(const std::exception&){return;}
    check(false,why);
}
void parseFailure(const std::string& text,const char* why) {
    rejects([&]{std::istringstream in(text);(void)parseTrustPeers(in);},why);
}
}
int main() {
    const std::string a="sync@a.example 2223 /tmp/maat-key /tmp/maat-hostkeys 12\n";
    const std::string b="sync@b.example 22 /tmp/b-key /tmp/b-hostkeys\n";
    {
        std::istringstream in("# Per-node, not an authority\n\n"+a+b);
        auto peers=parseTrustPeers(in);
        check(peers.size()==2 && peers[0].maxPages==12 &&
              peers[1].maxPages==256 && peers[0].port=="2223",
              "two explicitly pinned peers and bounded pages");
    }
    parseFailure("", "no peers");
    parseFailure("hostonly 2223 /key /hosts\n", "must specify SSH user");
    parseFailure("@node.example 2223 /key /hosts\n", "empty SSH username");
    parseFailure("-oProxyCommand=evil 22 /key /hosts\n", "ssh option injection");
    parseFailure("sync@node;touch 22 /key /hosts\n", "shell punctuation");
    parseFailure("sync@node 0 /key /hosts\n", "invalid port");
    parseFailure("sync@node 65536 /key /hosts\n", "overflow port");
    parseFailure("sync@node 22 relative/key /hosts\n", "relative key path");
    parseFailure("sync@node 22 /key relative/hosts\n", "relative host pin path");
    parseFailure("sync@node 22 /key /hosts 4097\n", "page flood");
    parseFailure("sync@node 22 /key /hosts extra more\n", "extra token");
    parseFailure(a+a,"duplicate peer");
    std::string lots;
    for(unsigned i=0;i<9;++i)
        lots+="sync@node"+std::to_string(i)+" 2223 /key /hosts\n";
    parseFailure(lots,"too many peers");
    char dir[]="/tmp/maat-peers-XXXXXX";
    check(mkdtemp(dir)!=nullptr,"temp directory");
    const std::string file=std::string(dir)+"/peers.conf";
    const std::string link=std::string(dir)+"/peers.link";
    {
        std::ofstream out(file);
        check(static_cast<bool>(out),"create peer config");
        out<<a;
    }
    check(chmod(file.c_str(),0600)==0,"chmod owner-only");
    check(loadTrustPeers(file).size()==1,"load regular trusted config");
    check(chmod(file.c_str(),0666)==0,"chmod unsafe");
    rejects([&]{(void)loadTrustPeers(file);},"group-writable config refused");
    check(chmod(file.c_str(),0600)==0,"chmod safe");
    check(symlink(file.c_str(),link.c_str())==0,"symlink setup");
    rejects([&]{(void)loadTrustPeers(link);},"symlink config refused");
    rejects([&]{(void)loadTrustPeers("relative/peers.conf");},"relative config refused");
    unlink(link.c_str());unlink(file.c_str());rmdir(dir);
    std::puts("PASS explicit peers, no SSH injection, bounded config, trusted file ownership");
}
