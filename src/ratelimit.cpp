#include "mirage/ratelimit.hpp"

#include <algorithm>

namespace mirage::ratelimit {

TokenBucketLimiter::TokenBucketLimiter(Config cfg) : cfg_(cfg) {}

TokenBucketLimiter::~TokenBucketLimiter() {
    stop();
}

void TokenBucketLimiter::start() {
    sweeper_ = std::thread([this] { sweep_loop(); });
}

void TokenBucketLimiter::stop() {
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (stop_requested_) return;
        stop_requested_ = true;
    }
    cv_.notify_all();
    if (sweeper_.joinable()) sweeper_.join();
}

bool TokenBucketLimiter::try_consume(const std::string& ip) {
    return try_consume_at(ip, clock::now());
}

bool TokenBucketLimiter::try_consume_at(const std::string& ip, clock::time_point now) {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = buckets_.find(ip);
    if (it == buckets_.end()) {
        Bucket b;
        b.tokens = static_cast<double>(cfg_.burst) - 1.0;  // consume one for this call
        b.last_refill = now;
        b.last_seen = now;
        buckets_.emplace(ip, b);
        return true;
    }
    auto& b = it->second;
    auto elapsed = std::chrono::duration<double>(now - b.last_refill).count();
    b.tokens = std::min<double>(cfg_.burst, b.tokens + elapsed * cfg_.refill_per_sec);
    b.last_refill = now;
    b.last_seen = now;
    if (b.tokens >= 1.0) {
        b.tokens -= 1.0;
        return true;
    }
    drops_.fetch_add(1, std::memory_order_relaxed);
    return false;
}

size_t TokenBucketLimiter::tracked_ips() const {
    std::lock_guard<std::mutex> lock(mu_);
    return buckets_.size();
}

size_t TokenBucketLimiter::total_drops() const {
    return drops_.load(std::memory_order_relaxed);
}

void TokenBucketLimiter::sweep_loop() {
    std::unique_lock<std::mutex> lock(mu_);
    while (!stop_requested_) {
        cv_.wait_for(lock, cfg_.sweep_period,
                     [this] { return stop_requested_; });
        if (stop_requested_) break;
        sweep_locked(clock::now());
    }
}

void TokenBucketLimiter::sweep_locked(clock::time_point now) {
    auto cutoff = now - cfg_.idle_gc;
    for (auto it = buckets_.begin(); it != buckets_.end();) {
        if (it->second.last_seen < cutoff) {
            it = buckets_.erase(it);
        } else {
            ++it;
        }
    }
}

}  // namespace mirage::ratelimit
