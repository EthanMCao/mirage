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

void test_extended_query_message_tags() {
    auto send_one = [](uint8_t tag, const std::vector<uint8_t>& body) {
        Pair p;
        std::vector<uint8_t> frame;
        frame.push_back(tag);
        write_be32(frame, static_cast<int32_t>(4 + body.size()));
        frame.insert(frame.end(), body.begin(), body.end());
        ::send(p.writer, frame.data(), frame.size(), 0);
        ::close(p.writer);
        p.writer = -1;
        return mirage::wire::read_frontend(p.reader);
    };

    {
        // Parse: stmt_name="" + query="select 1" + int16 num_params=0
        std::vector<uint8_t> body{0};
        const std::string q = "select 1";
        body.insert(body.end(), q.begin(), q.end());
        body.push_back(0);
        body.push_back(0); body.push_back(0);
        auto m = send_one('P', body);
        ASSERT_TRUE(m.has_value());
        EXPECT_TRUE(m->type == mirage::wire::FrontendType::Parse);
        // payload contains the raw body
        EXPECT_TRUE(m->payload.find("select 1") != std::string::npos);
    }
    {
        auto m = send_one('S', {});
        ASSERT_TRUE(m.has_value());
        EXPECT_TRUE(m->type == mirage::wire::FrontendType::Sync);
    }
    {
        auto m = send_one('H', {});
        ASSERT_TRUE(m.has_value());
        EXPECT_TRUE(m->type == mirage::wire::FrontendType::Flush);
    }
    {
        auto m = send_one('B', std::vector<uint8_t>{0, 0});
        ASSERT_TRUE(m.has_value());
        EXPECT_TRUE(m->type == mirage::wire::FrontendType::Bind);
    }
}

void test_extended_query_backend_frames() {
    auto pc = mirage::wire::parse_complete();
    EXPECT_EQ(pc.size(), 5u);
    EXPECT_EQ(pc[0], '1');

    auto bc = mirage::wire::bind_complete();
    EXPECT_EQ(bc[0], '2');

    auto cc = mirage::wire::close_complete();
    EXPECT_EQ(cc[0], '3');

    auto nd = mirage::wire::no_data();
    EXPECT_EQ(nd[0], 'n');

    auto pd = mirage::wire::parameter_description({23, 25});
    EXPECT_EQ(pd[0], 't');
    // 1 tag + 4 length + 2 count + 2*4 oids
    EXPECT_EQ(pd.size(), 1u + 4u + 2u + 8u);

    auto rd = mirage::wire::row_description_text("col");
    EXPECT_EQ(rd[0], 'T');

    auto dr = mirage::wire::data_row_single_text("hello");
    EXPECT_EQ(dr[0], 'D');
}

}  // namespace

int main() {
    mirage::test::ignore_sigpipe_once();
    test_read_startup_basic();
    test_read_startup_handles_ssl_request();
    test_read_query_message();
    test_read_terminate();
    test_backend_frame_layouts();
    test_extended_query_message_tags();
    test_extended_query_backend_frames();
    return mirage::test::finalize("wire_protocol");
}
