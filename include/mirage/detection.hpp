#pragma once

#include <atomic>
#include <chrono>
#include <deque>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <utility>

namespace mirage::detect {

struct Thresholds {
    int connection_rate = 10;
    std::chrono::seconds connection_window{60};
    int auth_spray_users = 5;
    std::chrono::seconds auth_spray_window{300};
};

struct Alert {
    std::string rule;
    std::string src_ip;
    std::string detail;
    int count = 0;
    int window_seconds = 0;
};

// True if `sql` references catalog tables typically targeted during
// credential harvesting or privilege enumeration.
bool query_is_suspicious(const std::string& sql);

// Sliding-window per-IP detector. All on_* methods are write paths;
// snapshot() is a read path. Internally guarded by a shared_mutex so
// snapshot() can run concurrently with itself but blocks on writers.
class Detector {
public:
    struct Snapshot {
        size_t tracked_ips = 0;
        size_t total_connections = 0;
        size_t total_alerts = 0;
    };

    explicit Detector(Thresholds t = {});

    std::optional<Alert> on_connection(const std::string& src_ip);
    std::optional<Alert> on_auth_attempt(const std::string& src_ip,
                                         const std::string& username);
    std::optional<Alert> on_query(const std::string& src_ip,
                                  const std::string& sql);

    Snapshot snapshot() const;

private:
    using clock = std::chrono::steady_clock;

    struct IpState {
        std::deque<clock::time_point> connections;
        std::deque<std::pair<clock::time_point, std::string>> auth_users;
    };

    void prune_connections(IpState& s, clock::time_point now) const;
    void prune_auth(IpState& s, clock::time_point now) const;

    Thresholds t_;
    mutable std::shared_mutex mu_;
    std::unordered_map<std::string, IpState> by_ip_;
    std::atomic<size_t> total_connections_{0};
    std::atomic<size_t> total_alerts_{0};
};

}  // namespace mirage::detect
