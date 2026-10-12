#include "receiver.hpp"
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <cerrno>
#include <cstring>
#include <cstdio>
#include <stdexcept>
#include <string>

namespace {
volatile sig_atomic_t exiting = 0;
int listening_fd = -1;
void shutdownSignal(int) {
    exiting = 1;
    if (listening_fd >= 0) close(listening_fd);
}
void privateDirectory(const char* path) {
    if(mkdir(path,0700)!=0 && errno!=EEXIST)
        throw std::runtime_error("cannot create private directory");
    struct stat st{};
    if(lstat(path,&st)!=0 || !S_ISDIR(st.st_mode) || st.st_uid!=0 ||
       (st.st_mode&0777)!=0700) throw std::runtime_error("unsafe directory");
}
}
int main(int argc, char** argv) {
    if(argc!=1 || geteuid()!=0) {
        std::fprintf(stderr,"usage: maat-monitor-receiver (root required)\n");
        return 2;
    }
    umask(0077);
    signal(SIGPIPE,SIG_IGN);
    struct sigaction action{};
    action.sa_handler=shutdownSignal;
    sigemptyset(&action.sa_mask);
    sigaction(SIGTERM,&action,nullptr);
    sigaction(SIGINT,&action,nullptr);
    try {
        privateDirectory("/run/maat");
        privateDirectory("/var/lib/maat");
        const char* path="/run/maat/monitor.sock";
        struct stat st{};
        if(lstat(path,&st)==0) {
            if (!S_ISSOCK(st.st_mode) || st.st_uid!=0 || (st.st_mode&0777)!=0600)
                throw std::runtime_error("unsafe existing socket");
            // Crash recovery: remove only a root-owned stale socket with no listener.
            int probe=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0);
            if(probe<0) throw std::runtime_error("socket probe failed");
            sockaddr_un peer{}; peer.sun_family=AF_UNIX;
            std::strncpy(peer.sun_path,path,sizeof(peer.sun_path)-1);
            int connected=connect(probe,reinterpret_cast<sockaddr*>(&peer),sizeof(peer));
            int problem=errno;
            close(probe);
            if (connected==0 || problem!=ECONNREFUSED || unlink(path)!=0)
                throw std::runtime_error("another receiver or unsafe socket");
        } else if(errno!=ENOENT) {
            throw std::runtime_error("cannot inspect socket");
        }
        maat::ReplayStore store("/var/lib/maat/monitor.db");
        maat::MonitorReceiver receiver(store,0);
        int fd=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0);
        if(fd<0) throw std::runtime_error("socket failed");
        sockaddr_un addr{}; addr.sun_family=AF_UNIX;
        std::strncpy(addr.sun_path,path,sizeof(addr.sun_path)-1);
        if(bind(fd,reinterpret_cast<sockaddr*>(&addr),sizeof(addr))!=0 ||
           chmod(path,0600)!=0 || listen(fd,64)!=0) {
            close(fd); throw std::runtime_error("bind/listen failed");
        }
        listening_fd=fd;
        while(!exiting) {
            int client=accept4(fd,nullptr,nullptr,SOCK_CLOEXEC);
            if(client<0) { if(errno==EINTR && !exiting) continue; break; }
            bool accepted=receiver.receive(client);
            std::fprintf(stderr,"Maât SSH assertion %s\n",accepted?"recorded":"rejected");
            close(client);
        }
        listening_fd=-1;
        if(!exiting) close(fd);
        unlink(path);
        if(exiting) return 0;
    } catch(const std::exception& e) {
        std::fprintf(stderr,"maat-monitor-receiver: %s\n",e.what());
        return 1;
    }
    return 1;
}
