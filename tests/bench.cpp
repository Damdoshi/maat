#include "replay_store.hpp"
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
#include <unistd.h>
int main() {
    char p[]="/tmp/maat-bench-XXXXXX";
    int f=mkstemp(p); if(f<0) return 1; close(f);
    maat::ReplayStore store(p);
    std::vector<uint8_t> pub(51,0); pub[3]=11; pub[18]=32;
    const char* name="ssh-ed25519";
    for(int i=0;i<11;++i) pub[4+i]=static_cast<uint8_t>(name[i]);
    for(int i=0;i<32;++i) pub[19+i]=static_cast<uint8_t>(i);
    constexpr int count=500;
    auto begin=std::chrono::steady_clock::now();
    for(int i=0;i<count;++i) {
        std::vector<uint8_t> session(32,0);
        for(int j=0;j<4;++j) session[j]=static_cast<uint8_t>(i>>(j*8));
        if(!store.record(maat::AuthenticatedSession("bench",session,maat::PublicKey(pub)))) return 2;
    }
    const auto elapsed=std::chrono::duration<double>(std::chrono::steady_clock::now()-begin).count();
    std::printf("%d SQLite FULL-durable writes in %.4f seconds (%.0f writes/s, %.2f ms/write)\n",count,elapsed,count/elapsed,elapsed*1000/count);
    unlink(p);
    return 0;
}
