#include "http/http_stream.hpp"
#include <unistd.h>
#include <sys/socket.h>
#include <thread>
#include <cstdio>
#include <cstdlib>
#include <stdexcept>
#include <string>

namespace {
int checks=0;
void check(bool ok,const char* why) {
    ++checks;
    if(!ok) {std::fprintf(stderr,"FAIL %s\n",why);std::exit(1);}
}
template<typename F> void bad(F f,const char* why) {
    bool rejected=false;
    try {f();}catch(const std::exception&) {rejected=true;}
    check(rejected,why);
}
void feed(int fd,const std::string& bytes) {
    size_t offset=0;
    while(offset<bytes.size()) {
        const ssize_t count=write(fd,bytes.data()+offset,bytes.size()-offset);
        check(count>0,"feed bytes");
        offset+=size_t(count);
    }
}
}
int main() {
    const std::string a="GET /whoami.php HTTP/1.1\r\nHost: localhost\r\nX-Maat-User: forged\r\n\r\n";
    const std::string b="POST /whoami.php HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\ntest";
    int channel[2];check(pipe(channel)==0,"stream pipe");
    feed(channel[1],a+b+a);close(channel[1]);
    maat::HTTPRequestStream stream(channel[0]);
    maat::HTTPRequest request;
    check(stream.next(request),"first pipelined frame");
    check(request.forwarded().find("X-Maat-User:")==std::string::npos,"identity stripped");
    check(stream.next(request),"second frame");
    check(request.forwarded().find("test")!=std::string::npos,"POST body exact");
    check(stream.next(request),"third frame");
    check(!stream.next(request),"clean EOF between requests");
    close(channel[0]);
    check(pipe(channel)==0,"fragmented pipe");
    std::thread producer([&]() {
        feed(channel[1],a.substr(0,15));
        usleep(10000);
        feed(channel[1],a.substr(15));
        close(channel[1]);
    });
    maat::HTTPRequestStream fragmented(channel[0]);
    check(fragmented.next(request),"fragmented header");
    check(!fragmented.next(request),"fragmented EOF");
    producer.join();close(channel[0]);
    check(pipe(channel)==0,"truncated pipe");
    feed(channel[1],"POST /x HTTP/1.1\r\nHost: local\r\nContent-Length: 4\r\n\r\nab");
    close(channel[1]);
    maat::HTTPRequestStream truncated(channel[0]);
    bad([&](){(void)truncated.next(request);},"truncated POST denied");
    close(channel[0]);
    const std::string plain="HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nhello";
    auto normalized=maat::HTTPResponse::persistent(plain);
    check(normalized.find("Content-Length: 5\r\n")!=std::string::npos,"computed Content-Length");
    check(normalized.find("Connection: keep-alive\r\n")!=std::string::npos,"persistent response");
    check(normalized.substr(normalized.find("\r\n\r\n")+4)=="hello","exact response body");
    const std::string chunked="HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
    auto unchunked=maat::HTTPResponse::persistent(chunked);
    check(unchunked.find("Transfer-Encoding:")==std::string::npos,"chunk framing removed");
    check(unchunked.substr(unchunked.find("\r\n\r\n")+4)=="hello","chunk decoded");
    const std::string head="HTTP/1.1 200 OK\r\nContent-Length: 222\r\n\r\n";
    auto headResponse=maat::HTTPResponse::persistent(head,true);
    check(headResponse.find("Content-Length:")==std::string::npos,"HEAD length omitted");
    bad([&](){maat::HTTPResponse::persistent("HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nhello");},"length mismatch denied");
    bad([&](){maat::HTTPResponse::persistent("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\nhello");},"CL/TE collision denied");
    bad([&](){maat::HTTPResponse::persistent("HTTP/1.1 100 Continue\r\n\r\n");},"interim response denied");
    bad([&](){maat::HTTPResponse::persistent("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-Foo: bar\r\n\r\n");},"chunk trailers denied");
    bad([&](){maat::HTTPResponse::persistent("HTTP/1.1 200 OK\r\nX-Foo: a\r\n X-Foo: b\r\n\r\n");},"folded response denied");
    std::fprintf(stderr,"PASS %d persistent HTTP frame checks\n",checks);
}
