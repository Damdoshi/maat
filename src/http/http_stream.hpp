#pragma once
#include "http_domain.hpp"
#include <string>

namespace maat {
// A bounded HTTP/1.1 request stream over the *same authenticated SSH channel*.
// Every returned frame must be independently bound to a NEW Apache TCP socket.
class HTTPRequestStream {
    int fd_;
    std::string buffer_;
    bool eof_ = false;
    bool receive(int waitMs);
public:
    explicit HTTPRequestStream(int fd):fd_(fd) {}
    // Returns false only on a clean EOF between complete requests.
    bool next(HTTPRequest& request);
};

// Apache is contacted with Connection: close. Reframe its finite response
// as a length-delimited persistent HTTP/1.1 response for the SSH client.
// Parsing fails closed on ambiguous response framing, unexpected 1xx/101,
// invalid trailers and inconsistent Content-Length.
class HTTPResponse {
public:
    static std::string persistent(const std::string& fromApache, bool headRequest=false);
};
}
