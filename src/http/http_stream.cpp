#include "http_stream.hpp"
#include <sys/poll.h>
#include <unistd.h>
#include <cerrno>
#include <stdexcept>
#include <cctype>
#include <algorithm>
#include <limits>
#include <chrono>
#include <vector>

namespace maat {
namespace {
constexpr size_t maxHeader=16384;
constexpr size_t maxBody=1048576;
constexpr size_t maxResponse=8*1024*1024;
std::string lower(std::string in) {
    std::transform(in.begin(),in.end(),in.begin(),[](unsigned char c){return char(std::tolower(c));});
    return in;
}
size_t decimal(const std::string& input,size_t limit) {
    if(input.empty()) throw std::invalid_argument("empty Content-Length");
    size_t value=0;
    for(char c:input) {
        if(c<'0' || c>'9' || value>(limit-size_t(c-'0'))/10)
            throw std::invalid_argument("invalid Content-Length");
        value=value*10+size_t(c-'0');
    }
    return value;
}
std::string trim(std::string input) {
    const size_t a=input.find_first_not_of(" \t");
    if(a==std::string::npos) return "";
    const size_t b=input.find_last_not_of(" \t");
    return input.substr(a,b-a+1);
}
std::string dechunk(const std::string& encoded) {
    size_t p=0;std::string result;
    for(;;) {
        const size_t line=encoded.find("\r\n",p);
        if(line==std::string::npos || line-p>16 || line==p)
            throw std::invalid_argument("invalid chunk size");
        size_t count=0;
        for(size_t k=p;k<line;k++) {
            char c=encoded[k];
            unsigned int digit;
            if(c>='0' && c<='9') digit=unsigned(c-'0');
            else if(c>='a' && c<='f') digit=unsigned(c-'a'+10);
            else if(c>='A' && c<='F') digit=unsigned(c-'A'+10);
            else throw std::invalid_argument("invalid chunk extension");
            if(count>(maxResponse-digit)/16) throw std::invalid_argument("chunk too large");
            count=count*16+digit;
        }
        p=line+2;
        if(count==0) {
            if(p+2!=encoded.size() || encoded.compare(p,2,"\r\n")!=0)
                throw std::invalid_argument("trailers/extra data not supported");
            return result;
        }
        if(count>maxResponse-result.size() || count>encoded.size()-p ||
           encoded.size()-p-count<2 || encoded.compare(p+count,2,"\r\n")!=0)
            throw std::invalid_argument("truncated/bad chunk");
        result.append(encoded,p,count);
        p+=count+2;
    }
}
}
bool HTTPRequestStream::receive(int waitMs) {
    pollfd watch{fd_,POLLIN,0};
    int rc;
    do {rc=poll(&watch,1,waitMs);}while(rc<0 && errno==EINTR);
    if(rc<=0 || (watch.revents&(POLLERR|POLLNVAL)))
        throw std::runtime_error("SSH request stream timed out or failed");
    char chunk[4096];
    ssize_t n;
    do {n=::read(fd_,chunk,sizeof(chunk));}while(n<0 && errno==EINTR);
    if(n<0) throw std::runtime_error("SSH stream read failed");
    if(n==0) {eof_=true;return false;}
    buffer_.append(chunk,size_t(n));
    return true;
}
bool HTTPRequestStream::next(HTTPRequest& request) {
    using Clock=std::chrono::steady_clock;
    // At most 15 seconds from the first byte of this request to its end.
    // This prevents a malicious peer from keeping a bridge alive forever by
    // dripping one byte every 4 seconds. A clean inter-request idle may wait
    // up to 60 seconds, matching the broker capability idle budget.
    auto started=Clock::now();
    bool inProgress=!buffer_.empty();
    auto waitFor=[&](int requested) {
        if(!inProgress) {
            const bool received=receive(requested);
            if(received) {inProgress=true;started=Clock::now();}
            return received;
        }
        const auto elapsed=std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now()-started);
        const long remain=15000L-elapsed.count();
        if(remain<=0) throw std::runtime_error("request framing deadline exceeded");
        return receive(std::min(requested,static_cast<int>(remain)));
    };
    for(;;) {
        auto pos=buffer_.find("\r\n\r\n");
        if(pos!=std::string::npos) {
            if(pos+4>maxHeader) throw std::invalid_argument("headers too big");
            const std::string head=buffer_.substr(0,pos+4);
            const size_t length=HTTPRequest::expectedBodyLength(head,maxBody);
            const size_t total=pos+4+length;
            while(buffer_.size()<total) {
                if(eof_ || !waitFor(5000))
                    throw std::invalid_argument("truncated request body");
            }
            const std::string body=buffer_.substr(pos+4,length);
            request=HTTPRequest::fromFrame(head,body,maxBody);
            buffer_.erase(0,total);
            return true;
        }
        if(buffer_.size()>maxHeader) throw std::invalid_argument("headers too big");
        if(eof_) {
            if(!buffer_.empty()) throw std::invalid_argument("truncated request headers");
            return false;
        }
        if(!waitFor(buffer_.empty()?60000:5000) && buffer_.empty()) return false;
    }
}
std::string HTTPResponse::persistent(const std::string& wire,bool headRequest) {
    auto boundary=wire.find("\r\n\r\n");
    if(boundary==std::string::npos || boundary+4>maxHeader)
        throw std::invalid_argument("invalid Apache headers");
    auto first=wire.find("\r\n");
    if(first==std::string::npos || first<12 || wire.compare(0,9,"HTTP/1.1 ")!=0)
        throw std::invalid_argument("invalid Apache status");
    const std::string status=wire.substr(0,first);
    if(status.size()>256 || status[9]<'1' || status[9]>'5' ||
       !std::isdigit(static_cast<unsigned char>(status[10])) ||
       !std::isdigit(static_cast<unsigned char>(status[11])))
        throw std::invalid_argument("invalid HTTP status code");
    for(char c:status) if(c<' ' || c>126) throw std::invalid_argument("invalid status text");
    const unsigned int code=100U*unsigned(status[9]-'0')+10U*unsigned(status[10]-'0')+
                            unsigned(status[11]-'0');
    if(code<200 || code==101 || (status.size()>12 && status[12]!=' '))
        throw std::invalid_argument("interim/upgrade response refused");
    bool chunked=false,hasLength=false;
    size_t declared=0;
    std::string headers;
    size_t cursor=first+2;
    while(cursor<boundary) {
        const size_t end=wire.find("\r\n",cursor);
        if(end==std::string::npos || end>boundary || end==cursor)
            throw std::invalid_argument("invalid Apache header line");
        const std::string line=wire.substr(cursor,end-cursor);
        const size_t colon=line.find(':');
        if(colon==std::string::npos || colon==0 || line[0]==' ' || line[0]=='\t')
            throw std::invalid_argument("invalid Apache header");
        const std::string name=lower(line.substr(0,colon));
        for(char c:name) if(!std::isalnum(static_cast<unsigned char>(c)) && c!='-')
            throw std::invalid_argument("invalid Apache header name");
        for(char c:line) if(c=='\0' || (static_cast<unsigned char>(c)<32 && c!='\t'))
            throw std::invalid_argument("invalid Apache header value");
        if(name=="connection" && lower(trim(line.substr(colon+1)))!="close")
            throw std::invalid_argument("unexpected Apache connection negotiation");
        if(name=="transfer-encoding") {
            if(chunked || lower(trim(line.substr(colon+1)))!="chunked")
                throw std::invalid_argument("unsupported transfer encoding");
            chunked=true;
        } else if(name=="content-length") {
            if(hasLength) throw std::invalid_argument("duplicate Apache Content-Length");
            declared=decimal(trim(line.substr(colon+1)),maxResponse);
            hasLength=true;
        } else if(name!="connection" && name!="keep-alive" && name!="upgrade" &&
                  name!="proxy-connection" && name!="trailer" && name!="te" &&
                  name!="proxy-authenticate" && name!="proxy-authorization") {
            headers+=line+"\r\n";
        }
        cursor=end+2;
    }
    if(chunked && hasLength) throw std::invalid_argument("conflicting Apache framing");
    std::string body=wire.substr(boundary+4);
    if(body.size()>maxResponse) throw std::invalid_argument("Apache body too large");
    const bool bodyForbidden=headRequest || code==204 || code==304;
    if(bodyForbidden) {
        if(!body.empty()) throw std::invalid_argument("unexpected Apache response body");
    } else if(chunked) body=dechunk(body);
    else if(hasLength && declared!=body.size())
        throw std::invalid_argument("Apache Content-Length mismatch");
    // HEAD must not send a Content-Length inconsistent with a corresponding GET.
    // Suppress it entirely; HEAD is self-delimiting in HTTP/1.1.
    if(!bodyForbidden) headers+="Content-Length: "+std::to_string(body.size())+"\r\n";
    return status+"\r\n"+headers+"Connection: keep-alive\r\n\r\n"+body;
}
}
