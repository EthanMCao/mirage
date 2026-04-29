#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

namespace mirage::ratelimit {

struct Config {
    int burst = 20;
    double refill_per_sec = 5.0;
    std::chrono::seconds idle_gc{600};
    std::chrono::seconds sweep_period{60};
};

// Per-IP token bucket. The accept loop calls try_consume(ip) for every
// inbound connection; when the bucket is empty the connection is dropped
// before any wire-protocol work happens. A background sweep thread evicts
// IPs that have not been seen recently so the map can't grow unbounded.
class TokenBucketLimiter {
public:
    using clock = std::chrono::steady_clock;

    explicit TokenBucketLimiter(Config cfg = {});
    ~TokenBucketLimiter();

    TokenBucketLimiter(const TokenBucketLimiter&) = delete;
    TokenBucketLimiter& operator=(const TokenBucketLimiter&) = delete;

    void start();
    void stop();

    bool try_consume(const std::string& ip);
    bool try_consume_at(const std::string& ip, clock::time_point now);

    size_t tracked_ips() const;
    size_t total_drops() const;

private:
    struct Bucket {
        double tokens;
        clock::time_point last_refill;
        clock::time_point last_seen;
    };

    void sweep_loop();
    void sweep_locked(clock::time_point now);

    Config cfg_;
    mutable std::mutex mu_;
    std::condition_variable cv_;
    std::unordered_map<std::string, Bucket> buckets_;
    bool stop_requested_ = false;
    std::thread sweeper_;
    std::atomic<size_t> drops_{0};
};

}  // namespace mirage::ratelimit
