#include "http_domain.hpp"
#include "http_stream.hpp"
#include "connection_proof.hpp"
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
#include <csignal>
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
        std::signal(SIGPIPE,SIG_IGN);
        timeval brokerTimeout{};brokerTimeout.tv_sec=5;
        if(setsockopt(broker,SOL_SOCKET,SO_RCVTIMEO,&brokerTimeout,sizeof(brokerTimeout))!=0)
            throw std::runtime_error("cannot set capability timeout");
        maat::HTTPRequestStream stream(STDIN_FILENO);
        maat::HTTPRequest request;
        // Every HTTP message receives a FRESH TCP socket and SCM_RIGHTS
        // proof. No request inherits an earlier Apache identity context.
        for(size_t count=0;count<100 && stream.next(request);++count) {
            int upstream=connectBackend();
            try {
                if(!maat::sendOneFD(broker,upstream,"MAATLINK1"))
                    throw std::runtime_error("cannot register HTTP connection");
                uint8_t buf[128];
                ssize_t n=recv(broker,buf,sizeof(buf),MSG_TRUNC);
                if(n<=0 || n>ssize_t(sizeof(buf)))
                    throw std::runtime_error("broker denied connection");
                std::vector<uint8_t> ack(buf,buf+n);size_t off=0;
                if(maat::readString(ack,off,20)!="MAATREADY1" ||
                   maat::readString(ack,off,0)!="" || off!=ack.size())
                    throw std::runtime_error("broker invalid acknowledgement");
                sendAll(upstream,request.forwarded());
                shutdown(upstream,SHUT_WR);
                char b[8192];std::string response;
                for(;;) {
                    ssize_t got=read(upstream,b,sizeof(b));
                    if(got<0 && errno==EINTR) continue;
                    if(got<0) throw std::runtime_error("HTTP backend read failure");
                    if(got==0) break;
                    if(size_t(got)>8*1024*1024-response.size())
                        throw std::runtime_error("response too large");
                    response.append(b,size_t(got));
                }
                const bool head=request.forwarded().compare(0,5,"HEAD ")==0;
                const std::string framed=maat::HTTPResponse::persistent(response,head);
                sendAll(STDOUT_FILENO,framed);
            }catch(...){close(upstream);throw;}
            close(upstream);
        }
        // A client attempting 101 requests will eventually lose its session
        // capability. Do not offer a way to renew without fresh SSH auth.
        close(broker);
        return 0;
    } catch(const std::exception& e){
        std::fprintf(stderr,"maat-http-bridge: %s\n",e.what());
        return 1;
    }
}
