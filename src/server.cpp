#include "mirage/server.hpp"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
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

std::string ip_to_string(const sockaddr_in& sa) {
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &sa.sin_addr, buf, sizeof(buf));
    return buf;
}

}  // namespace

Server::Server(Config cfg, std::shared_ptr<audit::AuditPipeline> pipeline)
    : cfg_(std::move(cfg)), pipeline_(std::move(pipeline)) {}

Server::~Server() {
    stop();
    wait();
}

bool Server::open_listen_socket() {
    listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd_ < 0) {
        std::cerr << "socket: " << std::strerror(errno) << "\n";
        return false;
    }

    int yes = 1;
    ::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
#ifdef SO_REUSEPORT
    ::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes));
#endif

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(cfg_.port));
    if (::inet_pton(AF_INET, cfg_.host.c_str(), &addr.sin_addr) != 1) {
        std::cerr << "invalid host: " << cfg_.host << "\n";
        ::close(listen_fd_);
        listen_fd_ = -1;
        return false;
    }

    if (::bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::cerr << "bind " << cfg_.host << ":" << cfg_.port << ": "
                  << std::strerror(errno) << "\n";
        ::close(listen_fd_);
        listen_fd_ = -1;
        return false;
    }
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
        sockaddr_in addr{};
        socklen_t len = sizeof(addr);
        int fd = ::accept(listen_fd_, reinterpret_cast<sockaddr*>(&addr), &len);
        if (fd < 0) {
            if (errno == EINTR) continue;
            // listen_fd_ closed by stop(); leave the loop.
            break;
        }
        Pending p;
        p.fd = fd;
        p.src_ip = ip_to_string(addr);
        p.src_port = static_cast<int>(ntohs(addr.sin_port));
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

}  // namespace mirage::server
