#include "mirage/server.hpp"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>

#include <csignal>
#include <cstring>
#include <iostream>
#include <utility>

namespace mirage::server {

namespace {

std::string ip_to_string(const sockaddr_storage& ss) {
    char buf[INET6_ADDRSTRLEN];
    if (ss.ss_family == AF_INET) {
        const auto* sa = reinterpret_cast<const sockaddr_in*>(&ss);
        inet_ntop(AF_INET, &sa->sin_addr, buf, sizeof(buf));
    } else if (ss.ss_family == AF_INET6) {
        const auto* sa = reinterpret_cast<const sockaddr_in6*>(&ss);
        inet_ntop(AF_INET6, &sa->sin6_addr, buf, sizeof(buf));
    } else {
        return "?";
    }
    // Normalize IPv4-mapped IPv6 ("::ffff:1.2.3.4") to plain "1.2.3.4" so
    // dual-stack detection state matches across address families.
    std::string s(buf);
    if (s.rfind("::ffff:", 0) == 0 && s.find('.', 7) != std::string::npos) {
        s = s.substr(7);
    }
    return s;
}

int port_from_storage(const sockaddr_storage& ss) {
    if (ss.ss_family == AF_INET) {
        return ntohs(reinterpret_cast<const sockaddr_in*>(&ss)->sin_port);
    } else if (ss.ss_family == AF_INET6) {
        return ntohs(reinterpret_cast<const sockaddr_in6*>(&ss)->sin6_port);
    }
    return 0;
}

}  // namespace

Server::Server(Config cfg, std::shared_ptr<audit::AuditPipeline> pipeline)
    : cfg_(std::move(cfg)), pipeline_(std::move(pipeline)) {
    if (cfg_.ratelimit_enabled) {
        limiter_ = std::make_unique<ratelimit::TokenBucketLimiter>(cfg_.ratelimit);
    }
}

Server::~Server() {
    stop();
    wait();
}

bool Server::open_listen_socket() {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;       // let getaddrinfo pick v4 or v6 by host
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;

    char port_buf[16];
    std::snprintf(port_buf, sizeof(port_buf), "%d", cfg_.port);

    addrinfo* res = nullptr;
    int rc = ::getaddrinfo(cfg_.host.c_str(), port_buf, &hints, &res);
    if (rc != 0 || res == nullptr) {
        std::cerr << "getaddrinfo " << cfg_.host << ":" << cfg_.port << ": "
                  << ::gai_strerror(rc) << "\n";
        return false;
    }

    listen_fd_ = ::socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (listen_fd_ < 0) {
        std::cerr << "socket: " << std::strerror(errno) << "\n";
        ::freeaddrinfo(res);
        return false;
    }

    int yes = 1;
    ::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
#ifdef SO_REUSEPORT
    ::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes));
#endif
    if (res->ai_family == AF_INET6) {
        // Accept both IPv4 (mapped) and IPv6 clients on a single socket.
        int v6only = 0;
        ::setsockopt(listen_fd_, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
    }

    if (::bind(listen_fd_, res->ai_addr, res->ai_addrlen) < 0) {
        std::cerr << "bind " << cfg_.host << ":" << cfg_.port << ": "
                  << std::strerror(errno) << "\n";
        ::close(listen_fd_);
        listen_fd_ = -1;
        ::freeaddrinfo(res);
        return false;
    }
    ::freeaddrinfo(res);

    if (::listen(listen_fd_, cfg_.backlog) < 0) {
        std::cerr << "listen: " << std::strerror(errno) << "\n";
        ::close(listen_fd_);
        listen_fd_ = -1;
        return false;
    }
    return true;
}

bool Server::start() {
    // SIGPIPE on a closed peer would otherwise kill the process; ignore it
    // so write_all() returns an error we can handle.
    std::signal(SIGPIPE, SIG_IGN);

    if (!open_listen_socket()) return false;

    if (limiter_) limiter_->start();

    workers_.reserve(static_cast<size_t>(cfg_.worker_threads));
    for (int i = 0; i < cfg_.worker_threads; ++i) {
        workers_.emplace_back([this] { worker_loop(); });
    }
    accept_thread_ = std::thread([this] { accept_loop(); });
    return true;
}

void Server::stop() {
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (stop_requested_) return;
        stop_requested_ = true;
    }
    if (listen_fd_ >= 0) {
        // Unblock the accept() in accept_loop().
        ::shutdown(listen_fd_, SHUT_RDWR);
        ::close(listen_fd_);
        listen_fd_ = -1;
    }
    cv_.notify_all();
    if (limiter_) limiter_->stop();
}

void Server::wait() {
    if (accept_thread_.joinable()) accept_thread_.join();
    for (auto& t : workers_) {
        if (t.joinable()) t.join();
    }
    workers_.clear();
}

void Server::accept_loop() {
    for (;;) {
        sockaddr_storage addr{};
        socklen_t len = sizeof(addr);
        int fd = ::accept(listen_fd_, reinterpret_cast<sockaddr*>(&addr), &len);
        if (fd < 0) {
            if (errno == EINTR) continue;
            // listen_fd_ closed by stop(); leave the loop.
            break;
        }
        std::string src_ip = ip_to_string(addr);
        int src_port = port_from_storage(addr);

        if (limiter_ && !limiter_->try_consume(src_ip)) {
            // Drop on the accept thread before any wire-protocol work runs.
            ::close(fd);
            audit::Event drop;
            drop.kind = audit::EventKind::RateLimitDrop;
            drop.src_ip = src_ip;
            drop.src_port = src_port;
            pipeline_->publish(std::move(drop));
            continue;
        }

        Pending p;
        p.fd = fd;
        p.src_ip = std::move(src_ip);
        p.src_port = src_port;
        accepted_.fetch_add(1, std::memory_order_relaxed);
        {
            std::lock_guard<std::mutex> lock(mu_);
            queue_.push(std::move(p));
        }
        cv_.notify_one();
    }
}

void Server::worker_loop() {
    for (;;) {
        Pending p;
        {
            std::unique_lock<std::mutex> lock(mu_);
            cv_.wait(lock, [this] { return stop_requested_ || !queue_.empty(); });
            if (queue_.empty() && stop_requested_) return;
            p = std::move(queue_.front());
            queue_.pop();
        }
        active_.fetch_add(1, std::memory_order_relaxed);
        session::run(p.fd, p.src_ip, p.src_port, cfg_.session, *pipeline_);
        active_.fetch_sub(1, std::memory_order_relaxed);
    }
}

size_t Server::connections_accepted() const {
    return accepted_.load(std::memory_order_relaxed);
}

size_t Server::connections_active() const {
    return active_.load(std::memory_order_relaxed);
}

size_t Server::connections_dropped() const {
    return limiter_ ? limiter_->total_drops() : 0;
}

}  // namespace mirage::server
