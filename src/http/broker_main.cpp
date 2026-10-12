#include "identity_broker.hpp"
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <unistd.h>
#include <pwd.h>
#include <csignal>
#include <cerrno>
#include <cstring>
#include <cstdio>
#include <stdexcept>
#include <vector>
#include <memory>
namespace {
volatile sig_atomic_t stop=0;
void interrupt(int){stop=1;}
uid_t uid(const char* username) {
    passwd* pw=getpwnam(username);
    if(!pw) throw std::runtime_error("missing service account");
    return pw->pw_uid;
}
int createSocket(const char* path,uid_t owner) {
    if(unlink(path)!=0 && errno!=ENOENT) throw std::runtime_error("cannot clear old socket");
    int fd=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0);
    if(fd<0) throw std::runtime_error("socket failed");
    sockaddr_un a{};a.sun_family=AF_UNIX;
    if(std::strlen(path)>=sizeof(a.sun_path)) throw std::runtime_error("socket path too long");
    std::strcpy(a.sun_path,path);
    if(bind(fd,reinterpret_cast<sockaddr*>(&a),sizeof(a))!=0 || chown(path,owner,0)!=0 ||
       chmod(path,0600)!=0 || listen(fd,32)!=0) {close(fd);throw std::runtime_error("bind failed");}
    return fd;
}
}
int main(int argc,char** argv) {
    if((argc!=3 && argc!=4) || geteuid()!=0) {
        std::fprintf(stderr,"usage: maat-http-broker PHP_USER DATABASE [UID_RANGE_DAB] (root)\n");return 2;
    }
    std::signal(SIGTERM,interrupt);std::signal(SIGINT,interrupt);std::signal(SIGPIPE,SIG_IGN);
    umask(0077);
    try {
        uid_t php=uid(argv[1]);
        if(mkdir("/run/maat-http",0711)!=0 && errno!=EEXIST) throw std::runtime_error("runtime mkdir");
        if(chmod("/run/maat-http",0711)!=0) throw std::runtime_error("runtime permissions");
        struct stat st{};
        if(lstat("/run/maat-http",&st)!=0 || !S_ISDIR(st.st_mode) || st.st_uid!=0 ||
          (st.st_mode&0777)!=0711) throw std::runtime_error("unsafe runtime directory");
        maat::UIDRange range=maat::UIDRangeConfiguration::read(
            argc==4 ? argv[3] : "/etc/maat/uid_range.dab");
        maat::IdentityRepository repo(argv[2],range);
        maat::RootSessionBinder binder(repo);
        maat::TicketVerifier verifier(repo,php);
        int incoming=createSocket("/run/maat-http/bind.sock",0);
        int checking=createSocket("/run/maat-http/check.sock",php);
        struct BoundSession {
            int fd;
            maat::SessionIdentifier id;
        };
        std::vector<BoundSession> sessions;
        while(!stop) {
            std::vector<pollfd> fds={{incoming,POLLIN,0},{checking,POLLIN,0}};
            for(const auto& session:sessions) fds.push_back({session.fd,POLLIN,0});
            int ready=poll(fds.data(),fds.size(),500);
            if(ready<0 && errno==EINTR) continue;
            if(ready<0) break;
            if(fds[0].revents&POLLIN) {
                int client=accept4(incoming,nullptr,nullptr,SOCK_CLOEXEC);
                if(client>=0) {
                    timeval timeout{};timeout.tv_sec=2;
                    setsockopt(client,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
                    maat::SessionIdentifier sid(std::string(64,'0'));
                    uid_t assigned=0;
                    int bound=binder.receive(client,sid,assigned);
                    close(client);
                    if(bound>=0) {
                        if(sessions.size()>=256) close(bound);
                        else sessions.push_back({bound,sid});
                    }
                }
            }
            if(fds[1].revents&POLLIN) {
                int client=accept4(checking,nullptr,nullptr,SOCK_CLOEXEC);
                if(client>=0) {
                    timeval timeout{};timeout.tv_sec=2;
                    setsockopt(client,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
                    (void)verifier.serve(client);close(client);
                }
            }
            for(size_t i=sessions.size();i>0;--i) {
                auto& item=sessions[i-1];
                // Registration this iteration happens after poll: process on next pass.
                if(i+1>=fds.size()) continue;
                if(fds[i+1].revents&(POLLIN|POLLERR|POLLHUP|POLLNVAL)) {
                    maat::SessionTicketChannel channel(repo,item.id);
                    (void)channel.serve(item.fd);
                    close(item.fd);
                    sessions.erase(sessions.begin()+(i-1));
                }
            }
        }
        for(const auto& session:sessions) close(session.fd);
        close(incoming);close(checking);
        unlink("/run/maat-http/bind.sock");unlink("/run/maat-http/check.sock");
        return 0;
    }catch(const std::exception& e){std::fprintf(stderr,"maat-http-broker: %s\n",e.what());return 1;}
}
