#include "receiver.hpp"
#include <sys/socket.h>
#include <sys/time.h>
#include <vector>
#include <stdexcept>
#include <cerrno>
#include <cstring>
namespace maat {
bool MonitorReceiver::receive(int fd) {
    ucred creds{};
    socklen_t size=sizeof(creds);
    if (getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&creds,&size)!=0 ||
        size!=sizeof(creds) || creds.uid!=trusted_uid_) return false;
    timeval timeout{}; timeout.tv_sec=2;
    if (setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout))!=0) return false;
    unsigned char bytes[2049];
    const ssize_t n=recv(fd,bytes,sizeof(bytes),MSG_TRUNC);
    if(n<=0 || n>2048) return false;
    try {
        auto identity=MonitorMessage::decode(std::vector<uint8_t>(bytes,bytes+n));
        if(!store_.record(identity)) return false;
        // Only a persisted, vetted SSH assertion receives positive ACK.
        return send(fd,"MAATOK2",7,MSG_NOSIGNAL)==7;
    } catch(const std::exception&) { return false; }
}
}
