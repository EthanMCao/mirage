#pragma once

#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <vector>

#include "mirage/audit.hpp"
#include "mirage/ratelimit.hpp"
#include "mirage/session.hpp"

namespace mirage::server {

struct Config {
    std::string host = "127.0.0.1";
    int port = 55432;
    int worker_threads = 4;
    int backlog = 64;
    bool ratelimit_enabled = true;
    ratelimit::Config ratelimit;
    session::Config session;
};

class Server {
public:
    Server(Config cfg, std::shared_ptr<audit::AuditPipeline> pipeline);
    ~Server();

    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;

    bool start();
    void stop();
    void wait();

    // Periodically-updated counters; safe to read from any thread.
    size_t connections_accepted() const;
    size_t connections_active() const;
    size_t connections_dropped() const;

private:
    struct Pending {
        int fd;
        std::string src_ip;
        int src_port;
    };

    void accept_loop();
    void worker_loop();
    bool open_listen_socket();

    Config cfg_;
    std::shared_ptr<audit::AuditPipeline> pipeline_;
    std::unique_ptr<ratelimit::TokenBucketLimiter> limiter_;

    int listen_fd_ = -1;
    std::thread accept_thread_;
    std::vector<std::thread> workers_;

    mutable std::mutex mu_;
    std::condition_variable cv_;
    std::queue<Pending> queue_;
    bool stop_requested_ = false;

    std::atomic<size_t> accepted_{0};
    std::atomic<size_t> active_{0};
};

}  // namespace mirage::server
