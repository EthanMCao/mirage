#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "mirage/audit.hpp"
#include "mirage/detection.hpp"
#include "mirage/logging.hpp"
#include "mirage/session.hpp"
#include "mirage/wire_protocol.hpp"
#include "test_helpers.hpp"

namespace {

std::string temp_path(const char* tag) {
    char path[64];
    std::snprintf(path, sizeof(path), "/tmp/mirage_session_%s_%d.jsonl",
                  tag, ::getpid());
    return path;
}

void put_be32(std::vector<uint8_t>& out, int32_t v) {
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xff));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xff));
    out.push_back(static_cast<uint8_t>((v >> 8)  & 0xff));
    out.push_back(static_cast<uint8_t>( v        & 0xff));
}

std::vector<uint8_t> build_startup(const std::string& user,
                                   const std::string& database) {
    std::vector<uint8_t> body;
    put_be32(body, mirage::wire::kProtocolVersionV3);
    auto put_cstr = [&](const std::string& s) {
        body.insert(body.end(), s.begin(), s.end());
        body.push_back('\0');
    };
    put_cstr("user");     put_cstr(user);
    put_cstr("database"); put_cstr(database);
    body.push_back('\0');

    std::vector<uint8_t> frame;
    put_be32(frame, static_cast<int32_t>(4 + body.size()));
    frame.insert(frame.end(), body.begin(), body.end());
    return frame;
}

std::vector<uint8_t> build_password(const std::string& pw) {
    std::vector<uint8_t> frame;
    frame.push_back('p');
    put_be32(frame, static_cast<int32_t>(4 + pw.size() + 1));
    frame.insert(frame.end(), pw.begin(), pw.end());
    frame.push_back('\0');
    return frame;
}

std::vector<uint8_t> build_query(const std::string& sql) {
    std::vector<uint8_t> frame;
    frame.push_back('Q');
    put_be32(frame, static_cast<int32_t>(4 + sql.size() + 1));
    frame.insert(frame.end(), sql.begin(), sql.end());
    frame.push_back('\0');
    return frame;
}

std::vector<uint8_t> build_terminate() {
    std::vector<uint8_t> frame;
    frame.push_back('X');
    put_be32(frame, 4);
    return frame;
}

// Build an extended-query Parse for the unnamed statement.
std::vector<uint8_t> build_parse(const std::string& sql) {
    std::vector<uint8_t> body;
    body.push_back(0);  // empty statement_name
    body.insert(body.end(), sql.begin(), sql.end());
    body.push_back(0);
    body.push_back(0); body.push_back(0);  // num_param_oids = 0
    std::vector<uint8_t> frame;
    frame.push_back('P');
    put_be32(frame, static_cast<int32_t>(4 + body.size()));
    frame.insert(frame.end(), body.begin(), body.end());
    return frame;
}

// Build an extended-query Bind for the unnamed portal/statement, no params.
std::vector<uint8_t> build_bind() {
    std::vector<uint8_t> body;
    body.push_back(0);  // portal_name = ""
    body.push_back(0);  // statement_name = ""
    body.push_back(0); body.push_back(0);  // num_format_codes = 0
    body.push_back(0); body.push_back(0);  // num_params = 0
    body.push_back(0); body.push_back(0);  // num_result_format_codes = 0
    std::vector<uint8_t> frame;
    frame.push_back('B');
    put_be32(frame, static_cast<int32_t>(4 + body.size()));
    frame.insert(frame.end(), body.begin(), body.end());
    return frame;
}

std::vector<uint8_t> build_describe_portal() {
    std::vector<uint8_t> body;
    body.push_back('P');
    body.push_back(0);  // portal_name = ""
    std::vector<uint8_t> frame;
    frame.push_back('D');
    put_be32(frame, static_cast<int32_t>(4 + body.size()));
    frame.insert(frame.end(), body.begin(), body.end());
    return frame;
}

std::vector<uint8_t> build_execute() {
    std::vector<uint8_t> body;
    body.push_back(0);  // portal_name = ""
    put_be32(body, 0);  // max_rows = 0 (no limit)
    std::vector<uint8_t> frame;
    frame.push_back('E');
    put_be32(frame, static_cast<int32_t>(4 + body.size()));
    frame.insert(frame.end(), body.begin(), body.end());
    return frame;
}

std::vector<uint8_t> build_sync() {
    std::vector<uint8_t> frame;
    frame.push_back('S');
    put_be32(frame, 4);
    return frame;
}

// Read everything until peer closes; bounded so a buggy server can't hang us.
std::vector<uint8_t> drain(int fd, size_t cap = 1 << 14) {
    std::vector<uint8_t> out;
    uint8_t buf[1024];
    while (out.size() < cap) {
        ssize_t r = ::recv(fd, buf, sizeof(buf), 0);
        if (r <= 0) break;
        out.insert(out.end(), buf, buf + r);
    }
    return out;
}

bool send_all(int fd, const std::vector<uint8_t>& bytes) {
    const uint8_t* p = bytes.data();
    size_t n = bytes.size();
    while (n > 0) {
        ssize_t w = ::send(fd, p, n, 0);
        if (w <= 0) return false;
        p += w;
        n -= w;
    }
    return true;
}

bool contains_tag(const std::vector<uint8_t>& bytes, uint8_t tag) {
    // The backend stream is a sequence of <tag><int32 length><body>.
    size_t i = 0;
    while (i + 5 <= bytes.size()) {
        uint8_t t = bytes[i];
        int32_t len = (int32_t(bytes[i + 1]) << 24) |
                      (int32_t(bytes[i + 2]) << 16) |
                      (int32_t(bytes[i + 3]) << 8)  |
                       int32_t(bytes[i + 4]);
        if (len < 4 || i + 1 + static_cast<size_t>(len) > bytes.size()) {
            return false;
        }
        if (t == tag) return true;
        i += 1 + static_cast<size_t>(len);
    }
    return false;
}

std::string read_file(const std::string& path) {
    std::ifstream in(path);
    std::ostringstream os;
    os << in.rdbuf();
    return os.str();
}

bool log_contains(const std::string& path, const std::string& needle) {
    std::string s = read_file(path);
    return s.find(needle) != std::string::npos;
}

struct Harness {
    std::string log_path;
    std::shared_ptr<mirage::log::JsonlSink> sink;
    std::shared_ptr<mirage::detect::Detector> detector;
    std::shared_ptr<mirage::audit::AuditPipeline> pipeline;
    int sv[2]{-1, -1};

    explicit Harness(const char* tag) : log_path(temp_path(tag)) {
        ::unlink(log_path.c_str());
        sink = std::make_shared<mirage::log::JsonlSink>();
        ASSERT_TRUE(sink->open(log_path));
        detector = std::make_shared<mirage::detect::Detector>();
        pipeline = std::make_shared<mirage::audit::AuditPipeline>(sink, detector);
        pipeline->start();
        ASSERT_TRUE(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    }

    int client_fd() { return sv[0]; }
    int server_fd() { return sv[1]; }

    ~Harness() {
        if (sv[0] >= 0) ::close(sv[0]);
        // sv[1] is closed by Session::run().
        if (pipeline) pipeline->stop();
        ::unlink(log_path.c_str());
    }
};

// Wait until the pipeline has drained, with a timeout. Polls pending()
// rather than relying on the worker thread waking us up — keeps tests
// synchronous without adding pipeline plumbing.
void wait_for_drain(mirage::audit::AuditPipeline& p, int max_ms = 2000) {
    using namespace std::chrono;
    auto deadline = steady_clock::now() + milliseconds(max_ms);
    while (steady_clock::now() < deadline) {
        if (p.pending() == 0) {
            // One more sleep so the in-flight handle() call finishes flushing.
            std::this_thread::sleep_for(milliseconds(10));
            return;
        }
        std::this_thread::sleep_for(milliseconds(5));
    }
}

void test_collect_mode_emits_startup_and_password_then_closes() {
    Harness h("collect");
    mirage::session::Config cfg;
    cfg.auth_mode = mirage::session::AuthMode::Collect;

    int server_fd = h.server_fd();
    h.sv[1] = -1;  // ownership transferred to Session::run
    std::thread t([server_fd, &cfg, &h] {
        mirage::session::run(server_fd, "203.0.113.42", 51000, cfg, *h.pipeline);
    });

    ASSERT_TRUE(send_all(h.client_fd(), build_startup("alice", "postgres")));
    ASSERT_TRUE(send_all(h.client_fd(), build_password("hunter2")));

    auto bytes = drain(h.client_fd());
    t.join();

    // Server must have asked for cleartext password ('R') and then sent
    // an error ('E') for the failed auth.
    EXPECT_TRUE(contains_tag(bytes, 'R'));
    EXPECT_TRUE(contains_tag(bytes, 'E'));

    wait_for_drain(*h.pipeline);
    EXPECT_TRUE(log_contains(h.log_path, "\"event\":\"startup\""));
    EXPECT_TRUE(log_contains(h.log_path, "\"event\":\"password\""));
    EXPECT_TRUE(log_contains(h.log_path, "\"user\":\"alice\""));
    EXPECT_TRUE(log_contains(h.log_path, "\"password\":\"hunter2\""));
    EXPECT_TRUE(log_contains(h.log_path, "\"src_ip\":\"203.0.113.42\""));
    EXPECT_TRUE(log_contains(h.log_path, "\"event\":\"conn_close\""));
}

void test_accept_mode_serves_a_query() {
    Harness h("accept");
    mirage::session::Config cfg;
    cfg.auth_mode = mirage::session::AuthMode::Accept;

    int server_fd = h.server_fd();
    h.sv[1] = -1;
    std::thread t([server_fd, &cfg, &h] {
        mirage::session::run(server_fd, "198.51.100.9", 41000, cfg, *h.pipeline);
    });

    ASSERT_TRUE(send_all(h.client_fd(), build_startup("admin", "postgres")));
    ASSERT_TRUE(send_all(h.client_fd(), build_password("letmein")));
    ASSERT_TRUE(send_all(h.client_fd(), build_query("select 1")));
    ASSERT_TRUE(send_all(h.client_fd(), build_terminate()));

    auto bytes = drain(h.client_fd());
    t.join();

    // Auth ok ('R'), parameter status ('S'), backend key data ('K'),
    // ready for query ('Z'), row description ('T'), data row ('D'),
    // command complete ('C').
    EXPECT_TRUE(contains_tag(bytes, 'R'));
    EXPECT_TRUE(contains_tag(bytes, 'S'));
    EXPECT_TRUE(contains_tag(bytes, 'K'));
    EXPECT_TRUE(contains_tag(bytes, 'Z'));
    EXPECT_TRUE(contains_tag(bytes, 'T'));
    EXPECT_TRUE(contains_tag(bytes, 'D'));
    EXPECT_TRUE(contains_tag(bytes, 'C'));

    wait_for_drain(*h.pipeline);
    EXPECT_TRUE(log_contains(h.log_path, "\"event\":\"query\""));
    EXPECT_TRUE(log_contains(h.log_path, "\"sql\":\"select 1\""));
    EXPECT_TRUE(log_contains(h.log_path, "\"event\":\"terminate\""));
}

void test_ssl_request_is_declined_then_startup_proceeds() {
    Harness h("ssl");
    mirage::session::Config cfg;
    cfg.auth_mode = mirage::session::AuthMode::Collect;

    int server_fd = h.server_fd();
    h.sv[1] = -1;
    std::thread t([server_fd, &cfg, &h] {
        mirage::session::run(server_fd, "192.0.2.5", 31000, cfg, *h.pipeline);
    });

    // SSLRequest first.
    std::vector<uint8_t> ssl;
    put_be32(ssl, 8);
    put_be32(ssl, mirage::wire::kProtocolVersionSSLRequest);
    ASSERT_TRUE(send_all(h.client_fd(), ssl));

    // Wait for the single 'N' decline byte before sending the real Startup,
    // so we exercise the full SSL-decline path.
    uint8_t reply = 0;
    ssize_t r = ::recv(h.client_fd(), &reply, 1, 0);
    EXPECT_EQ(r, ssize_t{1});
    EXPECT_EQ(reply, uint8_t{'N'});

    ASSERT_TRUE(send_all(h.client_fd(), build_startup("ssl_user", "postgres")));
    ASSERT_TRUE(send_all(h.client_fd(), build_password("pw")));

    drain(h.client_fd());
    t.join();

    wait_for_drain(*h.pipeline);
    EXPECT_TRUE(log_contains(h.log_path, "\"user\":\"ssl_user\""));
}

void test_extended_query_round_trip() {
    Harness h("ext");
    mirage::session::Config cfg;
    cfg.auth_mode = mirage::session::AuthMode::Accept;

    int server_fd = h.server_fd();
    h.sv[1] = -1;
    std::thread t([server_fd, &cfg, &h] {
        mirage::session::run(server_fd, "192.0.2.7", 21000, cfg, *h.pipeline);
    });

    ASSERT_TRUE(send_all(h.client_fd(), build_startup("admin", "postgres")));
    ASSERT_TRUE(send_all(h.client_fd(), build_password("pw")));
    ASSERT_TRUE(send_all(h.client_fd(), build_parse("select 42")));
    ASSERT_TRUE(send_all(h.client_fd(), build_bind()));
    ASSERT_TRUE(send_all(h.client_fd(), build_describe_portal()));
    ASSERT_TRUE(send_all(h.client_fd(), build_execute()));
    ASSERT_TRUE(send_all(h.client_fd(), build_sync()));
    ASSERT_TRUE(send_all(h.client_fd(), build_terminate()));

    auto bytes = drain(h.client_fd());
    t.join();

    EXPECT_TRUE(contains_tag(bytes, '1'));   // ParseComplete
    EXPECT_TRUE(contains_tag(bytes, '2'));   // BindComplete
    EXPECT_TRUE(contains_tag(bytes, 'T'));   // RowDescription (Describe)
    EXPECT_TRUE(contains_tag(bytes, 'D'));   // DataRow (Execute)
    EXPECT_TRUE(contains_tag(bytes, 'C'));   // CommandComplete
    EXPECT_TRUE(contains_tag(bytes, 'Z'));   // ReadyForQuery (Sync)

    wait_for_drain(*h.pipeline);
    EXPECT_TRUE(log_contains(h.log_path, "\"sql\":\"select 42\""));
}

void test_eof_during_startup_records_only_open_close() {
    Harness h("eof");
    mirage::session::Config cfg;

    int server_fd = h.server_fd();
    h.sv[1] = -1;
    std::thread t([server_fd, &cfg, &h] {
        mirage::session::run(server_fd, "192.0.2.99", 30000, cfg, *h.pipeline);
    });

    // Slam the door before sending anything.
    ::close(h.client_fd());
    h.sv[0] = -1;
    t.join();

    wait_for_drain(*h.pipeline);
    std::string s = read_file(h.log_path);
    EXPECT_TRUE(s.find("\"event\":\"conn_open\"") != std::string::npos);
    EXPECT_TRUE(s.find("\"event\":\"conn_close\"") != std::string::npos);
    EXPECT_TRUE(s.find("\"event\":\"startup\"") == std::string::npos);
}

}  // namespace

int main() {
    mirage::test::ignore_sigpipe_once();
    test_collect_mode_emits_startup_and_password_then_closes();
    test_accept_mode_serves_a_query();
    test_ssl_request_is_declined_then_startup_proceeds();
    test_extended_query_round_trip();
    test_eof_during_startup_records_only_open_close();
    return mirage::test::finalize("session");
}
