#include "http/session_registration_budget.hpp"
#include <chrono>
#include <cstdio>
#include <cstdlib>
static void check(bool value,const char* reason){
    if(!value){std::fprintf(stderr,"FAIL %s\n",reason);std::exit(1);}
}
int main() {
    using namespace std::chrono;
    const auto base=steady_clock::now();
    maat::SessionRegistrationBudget budget(base);
    check(budget.canGrant(base),"fresh bound session available");
    check(!budget.canGrant(base+seconds(60)),"idle expiry is exclusive");
    check(budget.recordGrant(base+seconds(59)),"first request at edge of idle interval");
    check(budget.canGrant(base+seconds(118)),"successful registration extends idle timeout");
    check(!budget.canGrant(base+minutes(5)),"absolute session expiry independent of activity");
    check(!budget.recordGrant(base+minutes(5)),"expired capability cannot re-register");
    check(budget.grants()==1,"expired registration cannot change count");
    maat::SessionRegistrationBudget quota(base);
    for(std::size_t i=0;i<maat::SessionRegistrationBudget::maxGrants;++i)
        check(quota.recordGrant(base),"all bounded registrations accepted");
    check(!quota.canGrant(base),"quota exhausted");
    check(!quota.recordGrant(base),"quota cannot be exceeded");
    check(quota.grants()==100,"registration count correct");
    check(!quota.canGrant(base-seconds(1)),"monotonic clock going backwards fails closed");
    std::puts("PASS 100 grants, 60s idle, 5min absolute expiry and fail-closed limits");
}
