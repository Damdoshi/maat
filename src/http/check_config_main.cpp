#include "http_domain.hpp"
#include <cstdio>
#include <exception>
int main(int argc,char** argv) {
    if(argc!=2){std::fprintf(stderr,"usage: maat-check-config FILE.dab\n");return 2;}
    try {
        const auto r=maat::UIDRangeConfiguration::read(argv[1]);
        std::printf("UID range valid: %llu..%llu (%llu allocations)\n",
            static_cast<unsigned long long>(r.first()),
            static_cast<unsigned long long>(r.last()),
            static_cast<unsigned long long>(r.last()-r.first()+1));
        return 0;
    } catch(const std::exception& e) {
        std::fprintf(stderr,"UID range invalid: %s\n",e.what());return 1;
    }
}
