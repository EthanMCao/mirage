#include <chrono>

#include "mirage/ratelimit.hpp"
#include "test_helpers.hpp"

namespace {

using namespace std::chrono_literals;
using clock_t = mirage::ratelimit::TokenBucketLimiter::clock;

void test_bucket_starts_at_burst_capacity() {
    mirage::ratelimit::Config c;
    c.burst = 5;
    c.refill_per_sec = 0.0;  // never refill, so we know exactly when we run out
    mirage::ratelimit::TokenBucketLimiter lim(c);

    auto t = clock_t::time_point{};
    for (int i = 0; i < 5; ++i) {
        EXPECT_TRUE(lim.try_consume_at("203.0.113.7", t));
    }
    EXPECT_TRUE(!lim.try_consume_at("203.0.113.7", t));  // empty
}

void test_bucket_refills_over_time() {
    mirage::ratelimit::Config c;
    c.burst = 3;
    c.refill_per_sec = 1.0;  // one token per second
    mirage::ratelimit::TokenBucketLimiter lim(c);

    auto t = clock_t::time_point{};
    EXPECT_TRUE(lim.try_consume_at("10.0.0.1", t));
    EXPECT_TRUE(lim.try_consume_at("10.0.0.1", t));
    EXPECT_TRUE(lim.try_consume_at("10.0.0.1", t));
    EXPECT_TRUE(!lim.try_consume_at("10.0.0.1", t));  // empty

    // 2 seconds later, ~2 tokens regenerated.
    auto later = t + 2s;
    EXPECT_TRUE(lim.try_consume_at("10.0.0.1", later));
    EXPECT_TRUE(lim.try_consume_at("10.0.0.1", later));
    EXPECT_TRUE(!lim.try_consume_at("10.0.0.1", later));
}

void test_bucket_isolates_per_ip() {
    mirage::ratelimit::Config c;
    c.burst = 1;
    c.refill_per_sec = 0.0;
    mirage::ratelimit::TokenBucketLimiter lim(c);

    auto t = clock_t::time_point{};
    EXPECT_TRUE(lim.try_consume_at("198.51.100.1", t));
    EXPECT_TRUE(!lim.try_consume_at("198.51.100.1", t));

    // Different IP starts with full bucket.
    EXPECT_TRUE(lim.try_consume_at("198.51.100.2", t));
}

void test_refill_caps_at_burst() {
    mirage::ratelimit::Config c;
    c.burst = 5;
    c.refill_per_sec = 1000.0;  // refill very fast
    mirage::ratelimit::TokenBucketLimiter lim(c);

    auto t = clock_t::time_point{};
    EXPECT_TRUE(lim.try_consume_at("172.16.0.1", t));  // 4 left

    // 100s later, math says 100 * 1000 tokens, but cap is 5 - 1 + 1 = 5,
    // and we consume one immediately so 4 should remain after.
    auto later = t + 100s;
    for (int i = 0; i < 5; ++i) {
        EXPECT_TRUE(lim.try_consume_at("172.16.0.1", later));
    }
    EXPECT_TRUE(!lim.try_consume_at("172.16.0.1", later));
}

void test_drop_counter_increments() {
    mirage::ratelimit::Config c;
    c.burst = 1;
    c.refill_per_sec = 0.0;
    mirage::ratelimit::TokenBucketLimiter lim(c);

    auto t = clock_t::time_point{};
    lim.try_consume_at("10.0.0.42", t);  // ok
    lim.try_consume_at("10.0.0.42", t);  // dropped
    lim.try_consume_at("10.0.0.42", t);  // dropped
    EXPECT_EQ(lim.total_drops(), 2u);
}

}  // namespace

int main() {
    test_bucket_starts_at_burst_capacity();
    test_bucket_refills_over_time();
    test_bucket_isolates_per_ip();
    test_refill_caps_at_burst();
    test_drop_counter_increments();
    return mirage::test::finalize("ratelimit");
}
