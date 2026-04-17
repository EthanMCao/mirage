#include "mirage/session.hpp"

#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <random>
#include <string>

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

    for (;;) {
        auto msg = wire::read_frontend(fd);
        if (!msg) break;
        if (msg->type == wire::FrontendType::Terminate) {
            audit::Event e;
            e.kind = audit::EventKind::Terminate;
            e.src_ip = src_ip;
            e.src_port = src_port;
            e.user = user;
            pipeline.publish(std::move(e));
            break;
        }
        if (msg->type == wire::FrontendType::Query) {
            audit::Event e;
            e.kind = audit::EventKind::Query;
            e.src_ip = src_ip;
            e.src_port = src_port;
            e.user = user;
            e.sql = msg->payload;
            pipeline.publish(std::move(e));
            serve_query(fd, msg->payload);
            continue;
        }
        // Unknown / unsupported frontend message types: be polite, send
        // an error response, then keep the connection open.
        wire::write_all(fd,
                        wire::error_response("ERROR", "0A000",
                                             "feature not supported"));
        wire::write_all(fd, wire::ready_for_query('I'));
    }

    publish_simple(pipeline, audit::EventKind::ConnectionClosed, src_ip, src_port);
    ::close(fd);
}

}  // namespace mirage::session
