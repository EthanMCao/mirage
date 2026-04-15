#include "mirage/detection.hpp"

#include <algorithm>
#include <cctype>
#include <unordered_set>

namespace mirage::detect {

namespace {

std::string to_lower(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    return out;
}

bool contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

}  // namespace

bool query_is_suspicious(const std::string& sql) {
    // Catalog and system-view names that legitimate clients rarely touch on
    // first contact. Any one of these is enough to flag the query for review.
    static const std::unordered_set<std::string> kSensitive{
        "pg_shadow",
        "pg_authid",
        "pg_user",
        "pg_roles",
        "pg_stat_user_tables",
        "pg_stat_user_indexes",
        "information_schema.user_",
        "information_schema.role_",
        "current_setting('is_superuser')",
    };
    auto lower = to_lower(sql);
    for (const auto& needle : kSensitive) {
        if (contains(lower, needle)) return true;
    }
    return false;
}

Detector::Detector(Thresholds t) : t_(t) {}

void Detector::prune_connections(IpState& s, clock::time_point now) const {
    auto cutoff = now - t_.connection_window;
    while (!s.connections.empty() && s.connections.front() < cutoff) {
        s.connections.pop_front();
    }
}

void Detector::prune_auth(IpState& s, clock::time_point now) const {
    auto cutoff = now - t_.auth_spray_window;
    while (!s.auth_users.empty() && s.auth_users.front().first < cutoff) {
        s.auth_users.pop_front();
    }
}

std::optional<Alert> Detector::on_connection(const std::string& src_ip) {
    auto now = clock::now();
    std::unique_lock<std::shared_mutex> lock(mu_);
    auto& s = by_ip_[src_ip];
    s.connections.push_back(now);
    prune_connections(s, now);
    total_connections_.fetch_add(1, std::memory_order_relaxed);

    if (static_cast<int>(s.connections.size()) > t_.connection_rate) {
        total_alerts_.fetch_add(1, std::memory_order_relaxed);
        Alert a;
        a.rule = "conn_rate_spike";
        a.src_ip = src_ip;
        a.count = static_cast<int>(s.connections.size());
        a.window_seconds = static_cast<int>(t_.connection_window.count());
        a.detail = "connection rate exceeded threshold";
        return a;
    }
    return std::nullopt;
}

std::optional<Alert> Detector::on_auth_attempt(const std::string& src_ip,
                                                const std::string& username) {
    auto now = clock::now();
    std::unique_lock<std::shared_mutex> lock(mu_);
    auto& s = by_ip_[src_ip];
    s.auth_users.emplace_back(now, username);
    prune_auth(s, now);

    std::unordered_set<std::string> distinct;
    distinct.reserve(s.auth_users.size());
    for (const auto& [_, u] : s.auth_users) distinct.insert(u);

    if (static_cast<int>(distinct.size()) > t_.auth_spray_users) {
        total_alerts_.fetch_add(1, std::memory_order_relaxed);
        Alert a;
        a.rule = "auth_spray";
        a.src_ip = src_ip;
        a.count = static_cast<int>(distinct.size());
        a.window_seconds = static_cast<int>(t_.auth_spray_window.count());
        a.detail = "distinct usernames attempted from one source exceeded threshold";
        return a;
    }
    return std::nullopt;
}

std::optional<Alert> Detector::on_query(const std::string& src_ip, const std::string& sql) {
    if (!query_is_suspicious(sql)) return std::nullopt;
    total_alerts_.fetch_add(1, std::memory_order_relaxed);
    Alert a;
    a.rule = "suspicious_query";
    a.src_ip = src_ip;
    a.count = 1;
    a.window_seconds = 0;
    a.detail = "query referenced sensitive catalog object";
    return a;
}

Detector::Snapshot Detector::snapshot() const {
    std::shared_lock<std::shared_mutex> lock(mu_);
    Snapshot s;
    s.tracked_ips = by_ip_.size();
    s.total_connections = total_connections_.load(std::memory_order_relaxed);
    s.total_alerts = total_alerts_.load(std::memory_order_relaxed);
    return s;
}

}  // namespace mirage::detect
