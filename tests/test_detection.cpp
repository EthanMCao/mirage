#include "mirage/detection.hpp"
#include "test_helpers.hpp"

namespace {

void test_conn_rate_spike_fires_after_threshold() {
    mirage::detect::Thresholds t;
    t.connection_rate = 5;  // alert when count > 5 within window
    mirage::detect::Detector d(t);

    for (int i = 0; i < 5; ++i) {
        EXPECT_TRUE(!d.on_connection("203.0.113.7").has_value());
    }
    auto a = d.on_connection("203.0.113.7");
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->rule, std::string("conn_rate_spike"));
    EXPECT_EQ(a->src_ip, std::string("203.0.113.7"));
}

void test_conn_rate_per_ip_isolated() {
    mirage::detect::Detector d({3, std::chrono::seconds(60), 5, std::chrono::seconds(300)});
    for (int i = 0; i < 3; ++i) d.on_connection("10.0.0.1");
    // Different IP starts fresh — should not fire on first event.
    EXPECT_TRUE(!d.on_connection("10.0.0.2").has_value());
    auto a = d.on_connection("10.0.0.1");
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->src_ip, std::string("10.0.0.1"));
}

void test_auth_spray_counts_distinct_users() {
    mirage::detect::Thresholds t;
    t.auth_spray_users = 3;
    mirage::detect::Detector d(t);
    EXPECT_TRUE(!d.on_auth_attempt("198.51.100.5", "alice").has_value());
    EXPECT_TRUE(!d.on_auth_attempt("198.51.100.5", "bob").has_value());
    // Repeats of the same user should NOT count toward distinct.
    EXPECT_TRUE(!d.on_auth_attempt("198.51.100.5", "bob").has_value());
    EXPECT_TRUE(!d.on_auth_attempt("198.51.100.5", "carol").has_value());
    auto a = d.on_auth_attempt("198.51.100.5", "dave");
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->rule, std::string("auth_spray"));
}

void test_query_is_suspicious() {
    using mirage::detect::query_is_suspicious;
    EXPECT_TRUE(query_is_suspicious("SELECT * FROM pg_shadow"));
    EXPECT_TRUE(query_is_suspicious("select usename, passwd from PG_AUTHID"));
    EXPECT_TRUE(query_is_suspicious(
        "select * from information_schema.user_privileges"));
    EXPECT_TRUE(!query_is_suspicious("SELECT 1"));
    EXPECT_TRUE(!query_is_suspicious("select count(*) from orders"));
}

void test_detector_snapshot_counts() {
    mirage::detect::Detector d;
    d.on_connection("10.0.0.1");
    d.on_connection("10.0.0.2");
    auto snap = d.snapshot();
    EXPECT_EQ(snap.tracked_ips, 2u);
    EXPECT_EQ(snap.total_connections, 2u);
}

}  // namespace

int main() {
    test_conn_rate_spike_fires_after_threshold();
    test_conn_rate_per_ip_isolated();
    test_auth_spray_counts_distinct_users();
    test_query_is_suspicious();
    test_detector_snapshot_counts();
    return mirage::test::finalize("detection");
}
