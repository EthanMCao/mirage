#include "mirage/session.hpp"

#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <cstring>
#include <random>
#include <string>
#include <unordered_map>

#include "mirage/wire_protocol.hpp"

namespace mirage::session {

namespace {

void set_recv_timeout(int fd, int seconds) {
    timeval tv{};
    tv.tv_sec = seconds;
    tv.tv_usec = 0;
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

void publish_simple(audit::AuditPipeline& p,
                    audit::EventKind k,
                    const std::string& ip,
                    int port) {
    audit::Event e;
    e.kind = k;
    e.src_ip = ip;
    e.src_port = port;
    p.publish(std::move(e));
}

void send_canned_session_setup(int fd) {
    using namespace mirage::wire;
    write_all(fd, parameter_status("server_version", "16.2"));
    write_all(fd, parameter_status("server_encoding", "UTF8"));
    write_all(fd, parameter_status("client_encoding", "UTF8"));
    write_all(fd, parameter_status("DateStyle", "ISO, MDY"));
    write_all(fd, parameter_status("integer_datetimes", "on"));
    write_all(fd, parameter_status("standard_conforming_strings", "on"));
    write_all(fd, parameter_status("TimeZone", "UTC"));
    static thread_local std::mt19937 rng{std::random_device{}()};
    int32_t pid = static_cast<int32_t>(rng() & 0x7fffffff);
    int32_t secret = static_cast<int32_t>(rng() & 0x7fffffff);
    write_all(fd, backend_key_data(pid, secret));
    write_all(fd, ready_for_query('I'));
}

void serve_query(int fd, const std::string& sql) {
    using namespace mirage::wire;
    if (sql.empty()) {
        write_all(fd, empty_query_response());
    } else {
        // Always return a one-row "ok" answer; enough to keep most clients
        // happy and trigger them to send the next probe.
        write_all(fd, single_text_row("?column?", "1"));
    }
    write_all(fd, ready_for_query('I'));
}

// Read a NUL-terminated string starting at offset i. On success, advances i
// past the NUL and returns true. On EOF before NUL, leaves i unchanged.
bool read_cstring(const std::string& body, size_t& i, std::string& out) {
    size_t start = i;
    while (i < body.size() && body[i] != '\0') ++i;
    if (i >= body.size()) return false;
    out.assign(body, start, i - start);
    ++i;  // skip NUL
    return true;
}

// Parse messages we care about have small, well-defined heads — extract just
// the fields the honeypot uses for audit + dispatch and ignore the rest.
struct ParseHead { std::string statement_name; std::string query; };
struct BindHead  { std::string portal_name;    std::string statement_name; };
struct DescHead  { uint8_t kind = 0;           std::string name; };  // 'S' or 'P'
struct ExecHead  { std::string portal_name; };
struct CloseHead { uint8_t kind = 0;           std::string name; };

bool parse_parse(const std::string& body, ParseHead& out) {
    size_t i = 0;
    if (!read_cstring(body, i, out.statement_name)) return false;
    if (!read_cstring(body, i, out.query)) return false;
    return true;
}

bool parse_bind(const std::string& body, BindHead& out) {
    size_t i = 0;
    if (!read_cstring(body, i, out.portal_name)) return false;
    if (!read_cstring(body, i, out.statement_name)) return false;
    return true;
}

bool parse_describe(const std::string& body, DescHead& out) {
    if (body.empty()) return false;
    out.kind = static_cast<uint8_t>(body[0]);
    size_t i = 1;
    return read_cstring(body, i, out.name);
}

bool parse_execute(const std::string& body, ExecHead& out) {
    size_t i = 0;
    return read_cstring(body, i, out.portal_name);
    // trailing int32 max_rows is ignored — we always return the full result.
}

bool parse_close(const std::string& body, CloseHead& out) {
    if (body.empty()) return false;
    out.kind = static_cast<uint8_t>(body[0]);
    size_t i = 1;
    return read_cstring(body, i, out.name);
}

void publish_query(audit::AuditPipeline& p,
                   const std::string& ip, int port,
                   const std::string& user, const std::string& sql) {
    audit::Event e;
    e.kind = audit::EventKind::Query;
    e.src_ip = ip;
    e.src_port = port;
    e.user = user;
    e.sql = sql;
    p.publish(std::move(e));
}

}  // namespace

void run(int fd,
         const std::string& src_ip,
         int src_port,
         const Config& cfg,
         audit::AuditPipeline& pipeline) {
    set_recv_timeout(fd, 30);

    publish_simple(pipeline, audit::EventKind::ConnectionAccepted, src_ip, src_port);

    auto startup = wire::read_startup(fd);
    if (!startup) {
        publish_simple(pipeline, audit::EventKind::ConnectionClosed, src_ip, src_port);
        ::close(fd);
        return;
    }

    std::string user;
    std::string database;
    if (auto it = startup->parameters.find("user"); it != startup->parameters.end()) {
        user = it->second;
    }
    if (auto it = startup->parameters.find("database"); it != startup->parameters.end()) {
        database = it->second;
    }

    {
        audit::Event e;
        e.kind = audit::EventKind::Startup;
        e.src_ip = src_ip;
        e.src_port = src_port;
        e.user = user;
        e.database = database;
        pipeline.publish(std::move(e));
    }

    if (!wire::write_all(fd, wire::auth_cleartext_password())) {
        publish_simple(pipeline, audit::EventKind::ConnectionClosed, src_ip, src_port);
        ::close(fd);
        return;
    }

    auto pw_msg = wire::read_frontend(fd);
    std::string password;
    if (pw_msg && pw_msg->type == wire::FrontendType::Password) {
        password = pw_msg->payload;
        audit::Event e;
        e.kind = audit::EventKind::Password;
        e.src_ip = src_ip;
        e.src_port = src_port;
        e.user = user;
        e.password = password;
        pipeline.publish(std::move(e));
    }

    if (cfg.auth_mode == AuthMode::Collect) {
        wire::write_all(fd, wire::auth_failed(user));
        publish_simple(pipeline, audit::EventKind::ConnectionClosed, src_ip, src_port);
        ::close(fd);
        return;
    }

    // Accept mode: pretend the password was right, set up the session, then
    // loop on queries.
    if (!wire::write_all(fd, wire::auth_ok())) {
        publish_simple(pipeline, audit::EventKind::ConnectionClosed, src_ip, src_port);
        ::close(fd);
        return;
    }
    send_canned_session_setup(fd);

    // Extended-query state. Both maps are session-local; libpq-style clients
    // typically use the unnamed "" entry. We only track names so Bind can
    // look up the SQL associated with a previously parsed statement.
    std::unordered_map<std::string, std::string> statements;  // name -> SQL
    std::unordered_map<std::string, std::string> portals;     // portal -> stmt

    for (;;) {
        auto msg = wire::read_frontend(fd);
        if (!msg) break;
        switch (msg->type) {
            case wire::FrontendType::Terminate: {
                audit::Event e;
                e.kind = audit::EventKind::Terminate;
                e.src_ip = src_ip;
                e.src_port = src_port;
                e.user = user;
                pipeline.publish(std::move(e));
                goto end_loop;
            }
            case wire::FrontendType::Query: {
                publish_query(pipeline, src_ip, src_port, user, msg->payload);
                serve_query(fd, msg->payload);
                break;
            }
            case wire::FrontendType::Parse: {
                ParseHead ph;
                if (parse_parse(msg->payload, ph)) {
                    statements[ph.statement_name] = ph.query;
                    if (!ph.query.empty()) {
                        publish_query(pipeline, src_ip, src_port, user, ph.query);
                    }
                }
                wire::write_all(fd, wire::parse_complete());
                break;
            }
            case wire::FrontendType::Bind: {
                BindHead bh;
                if (parse_bind(msg->payload, bh)) {
                    portals[bh.portal_name] = bh.statement_name;
                }
                wire::write_all(fd, wire::bind_complete());
                break;
            }
            case wire::FrontendType::Describe: {
                DescHead dh;
                if (!parse_describe(msg->payload, dh)) break;
                if (dh.kind == 'S') {
                    // Statement: ParameterDescription (no params) + RowDescription.
                    wire::write_all(fd, wire::parameter_description({}));
                }
                // Portal or statement: we always look like a single text column.
                wire::write_all(fd, wire::row_description_text("?column?"));
                break;
            }
            case wire::FrontendType::Execute: {
                ExecHead eh;
                std::string sql;
                if (parse_execute(msg->payload, eh)) {
                    auto pit = portals.find(eh.portal_name);
                    if (pit != portals.end()) {
                        auto sit = statements.find(pit->second);
                        if (sit != statements.end()) sql = sit->second;
                    }
                }
                if (sql.empty()) {
                    wire::write_all(fd, wire::empty_query_response());
                } else {
                    wire::write_all(fd, wire::data_row_single_text("1"));
                    wire::write_all(fd, wire::command_complete("SELECT 1"));
                }
                break;
            }
            case wire::FrontendType::Close: {
                CloseHead ch;
                if (parse_close(msg->payload, ch)) {
                    if (ch.kind == 'S') statements.erase(ch.name);
                    else if (ch.kind == 'P') portals.erase(ch.name);
                }
                wire::write_all(fd, wire::close_complete());
                break;
            }
            case wire::FrontendType::Sync: {
                wire::write_all(fd, wire::ready_for_query('I'));
                break;
            }
            case wire::FrontendType::Flush:
                // We never buffer responses, so Flush is a no-op.
                break;
            case wire::FrontendType::Password:
                // Stray password mid-session — ignore.
                break;
            case wire::FrontendType::Unknown:
            default:
                wire::write_all(fd,
                                wire::error_response("ERROR", "0A000",
                                                     "feature not supported"));
                wire::write_all(fd, wire::ready_for_query('I'));
                break;
        }
    }
end_loop:;

    publish_simple(pipeline, audit::EventKind::ConnectionClosed, src_ip, src_port);
    ::close(fd);
}

}  // namespace mirage::session
