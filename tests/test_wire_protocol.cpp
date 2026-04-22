#include <sys/socket.h>
#include <unistd.h>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "mirage/wire_protocol.hpp"
#include "test_helpers.hpp"

namespace {

void write_be32(std::vector<uint8_t>& out, int32_t v) {
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xff));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xff));
    out.push_back(static_cast<uint8_t>((v >> 8)  & 0xff));
    out.push_back(static_cast<uint8_t>( v        & 0xff));
}

// Open a connected pair of stream sockets so a parser can read bytes we wrote.
struct Pair {
    int reader = -1;
    int writer = -1;
    Pair() {
        int sv[2];
        ::socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
        reader = sv[0];
        writer = sv[1];
    }
    ~Pair() {
        if (reader >= 0) ::close(reader);
        if (writer >= 0) ::close(writer);
    }
};

void test_read_startup_basic() {
    Pair p;
    std::vector<uint8_t> body;
    write_be32(body, mirage::wire::kProtocolVersionV3);
    auto put_cstr = [&](const std::string& s) {
        body.insert(body.end(), s.begin(), s.end());
        body.push_back('\0');
    };
    put_cstr("user");      put_cstr("alice");
    put_cstr("database");  put_cstr("mydb");
    body.push_back('\0');  // terminator

    std::vector<uint8_t> frame;
    write_be32(frame, static_cast<int32_t>(4 + body.size()));
    frame.insert(frame.end(), body.begin(), body.end());

    ::send(p.writer, frame.data(), frame.size(), 0);
    ::close(p.writer);
    p.writer = -1;

    auto m = mirage::wire::read_startup(p.reader);
    ASSERT_TRUE(m.has_value());
    EXPECT_EQ(m->protocol_version, mirage::wire::kProtocolVersionV3);
    EXPECT_EQ(m->parameters["user"], std::string("alice"));
    EXPECT_EQ(m->parameters["database"], std::string("mydb"));
}

void test_read_startup_handles_ssl_request() {
    Pair p;
    // First a SSLRequest, then a real StartupMessage.
    std::vector<uint8_t> ssl;
    write_be32(ssl, 8);
    write_be32(ssl, mirage::wire::kProtocolVersionSSLRequest);
    ::send(p.writer, ssl.data(), ssl.size(), 0);

    std::vector<uint8_t> body;
    write_be32(body, mirage::wire::kProtocolVersionV3);
    auto put_cstr = [&](const std::string& s) {
        body.insert(body.end(), s.begin(), s.end());
        body.push_back('\0');
    };
    put_cstr("user"); put_cstr("bob");
    body.push_back('\0');
    std::vector<uint8_t> frame;
    write_be32(frame, static_cast<int32_t>(4 + body.size()));
    frame.insert(frame.end(), body.begin(), body.end());
    ::send(p.writer, frame.data(), frame.size(), 0);
    // Keep writer open: read_startup writes 'N' back when declining SSL,
    // and an early close would EPIPE that write.

    auto m = mirage::wire::read_startup(p.reader);
    ASSERT_TRUE(m.has_value());
    EXPECT_EQ(m->parameters["user"], std::string("bob"));
}

void test_read_query_message() {
    Pair p;
    const std::string sql = "select 1";
    std::vector<uint8_t> frame;
    frame.push_back('Q');
    write_be32(frame, static_cast<int32_t>(4 + sql.size() + 1));
    frame.insert(frame.end(), sql.begin(), sql.end());
    frame.push_back('\0');
    ::send(p.writer, frame.data(), frame.size(), 0);
    ::close(p.writer);
    p.writer = -1;

    auto m = mirage::wire::read_frontend(p.reader);
    ASSERT_TRUE(m.has_value());
    EXPECT_TRUE(m->type == mirage::wire::FrontendType::Query);
    EXPECT_EQ(m->payload, sql);
}

void test_read_terminate() {
    Pair p;
    std::vector<uint8_t> frame;
    frame.push_back('X');
    write_be32(frame, 4);
    ::send(p.writer, frame.data(), frame.size(), 0);
    ::close(p.writer);
    p.writer = -1;

    auto m = mirage::wire::read_frontend(p.reader);
    ASSERT_TRUE(m.has_value());
    EXPECT_TRUE(m->type == mirage::wire::FrontendType::Terminate);
}

void test_backend_frame_layouts() {
    auto auth = mirage::wire::auth_cleartext_password();
    EXPECT_EQ(auth.size(), 9u);
    EXPECT_EQ(auth[0], 'R');

    auto rfq = mirage::wire::ready_for_query('I');
    EXPECT_EQ(rfq.size(), 6u);
    EXPECT_EQ(rfq[0], 'Z');
    EXPECT_EQ(rfq.back(), 'I');

    auto cc = mirage::wire::command_complete("SELECT 1");
    EXPECT_EQ(cc[0], 'C');

    auto err = mirage::wire::error_response("ERROR", "00000", "test");
    EXPECT_EQ(err[0], 'E');
}

}  // namespace

int main() {
    mirage::test::ignore_sigpipe_once();
    test_read_startup_basic();
    test_read_startup_handles_ssl_request();
    test_read_query_message();
    test_read_terminate();
    test_backend_frame_layouts();
    return mirage::test::finalize("wire_protocol");
}
