#pragma once
#include <chrono>
#include <cstddef>

namespace maat {
// A bound SSH capability remains useful only for a bounded number of fresh
// TCP descriptor registrations. This never authorizes any HTTP request by
// itself: every registration still requires SCM_RIGHTS and broker pairing.
class SessionRegistrationBudget {
    using Clock=std::chrono::steady_clock;
    Clock::time_point opened_;
    Clock::time_point lastGrant_;
    std::size_t grants_=0;
public:
    static constexpr std::size_t maxGrants=100;
    explicit SessionRegistrationBudget(Clock::time_point now=Clock::now())
        :opened_(now),lastGrant_(now) {}
    bool canGrant(Clock::time_point now=Clock::now()) const {
        return now>=lastGrant_ && now>=opened_ &&
               now-opened_<std::chrono::minutes(5) &&
               now-lastGrant_<std::chrono::seconds(60) &&
               grants_<maxGrants;
    }
    bool recordGrant(Clock::time_point now=Clock::now()) {
        if(!canGrant(now)) return false;
        ++grants_;
        lastGrant_=now;
        return true;
    }
    std::size_t grants() const {return grants_;}
};
}
