#include "http_domain.hpp"
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <algorithm>
#include <sys/prctl.h>
namespace {
void sendAll(int fd,const std::string& data) {
    size_t off=0;
    while(off<data.size()) {
        ssize_t n=write(fd,data.data()+off,data.size()-off);
        if(n<0 && errno==EINTR) continue;
        if(n<=0) throw std::runtime_error("write failed");
        off+=size_t(n);
    }
}
int connectBackend(){
    int fd=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0);
    if(fd<0) throw std::runtime_error("socket backend");
    sockaddr_in a{};a.sin_family=AF_INET;a.sin_port=htons(18081);
    if(inet_pton(AF_INET,"127.0.0.1",&a.sin_addr)!=1 || connect(fd,reinterpret_cast<sockaddr*>(&a),sizeof(a))<0){close(fd);throw std::runtime_error("HTTP backend unavailable");}
    timeval timeout{};timeout.tv_sec=5;
    setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
    return fd;
}
}
int main(int argc,char** argv) {
    (void)argv;
    if(argc!=1) return 2;
    try {
        // Defence in depth: inhibit same-UID ptrace and procfs fd inspection
        // once the bridge is running. Does not close the exec-time race.
        if(prctl(PR_SET_DUMPABLE,0)!=0 || prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)!=0)
            throw std::runtime_error("cannot isolate bridge process");
        const char* env=getenv("MAAT_BIND_FD");
        if(!env || std::strcmp(env,"3")!=0) throw std::runtime_error("missing inherited session capability");
        int broker=3;
        int domain=0,type=0;socklen_t size=sizeof(int);
        if(getsockopt(broker,SOL_SOCKET,SO_DOMAIN,&domain,&size)!=0 || domain!=AF_UNIX ||
           getsockopt(broker,SOL_SOCKET,SO_TYPE,&type,&size)!=0 || type!=SOCK_SEQPACKET)
            throw std::runtime_error("invalid session capability");
        auto request=maat::HTTPRequest::read(STDIN_FILENO);
        // Single SSH string, not a client-supplied session name.
        auto p=maat::requestMessage("MAATGET2","");
        p.resize(4+std::strlen("MAATGET2"));
        if(send(broker,p.data(),p.size(),MSG_NOSIGNAL)!=ssize_t(p.size()))
            throw std::runtime_error("session capability rejected");
        uint8_t buf[256];ssize_t n=recv(broker,buf,sizeof(buf),MSG_TRUNC);close(broker);
        if(n<=0 || n>ssize_t(sizeof(buf))) throw std::runtime_error("issuer rejected session");
        std::vector<uint8_t> reply(buf,buf+n);size_t off=0;
        if(maat::readString(reply,off,32)!="MAATHTTP1") throw std::runtime_error("issuer version");
        auto token=maat::readString(reply,off,64);
        if(off!=reply.size()) throw std::runtime_error("issuer trailing data");
        (void)maat::RequestTicket(token);
        int upstream=connectBackend();
        try {
            sendAll(upstream,request.forwarded(token));
            shutdown(upstream,SHUT_WR);
            char b[8192];size_t total=0;
            for(;;) {
                ssize_t count=read(upstream,b,sizeof(b));
                if(count<0 && errno==EINTR) continue;
                if(count<=0) break;
                total+=size_t(count);
                if(total>8*1024*1024) throw std::runtime_error("response too large");
                size_t pos=0;
                while(pos<size_t(count)) {
                    ssize_t written=write(STDOUT_FILENO,b+pos,size_t(count)-pos);
                    if(written<0 && errno==EINTR) continue;
                    if(written<=0) throw std::runtime_error("client disconnected");
                    pos+=size_t(written);
                }
            }
        }catch(...){close(upstream);throw;}
        close(upstream);
        return 0;
    } catch(const std::exception& e){
        std::fprintf(stderr,"maat-http-bridge: %s\n",e.what());
        return 1;
    }
}
