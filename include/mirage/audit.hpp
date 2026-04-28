#pragma once

#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <thread>

#include "mirage/detection.hpp"
#include "mirage/logging.hpp"

namespace mirage::audit {

enum class EventKind {
    Startup,
    Password,
    Query,
    Terminate,
    ConnectionAccepted,
    ConnectionClosed,
    RateLimitDrop,
};

struct Event {
    EventKind kind;
    std::string src_ip;
    int src_port = 0;
    std::string user;
    std::string database;
    std::string password;
    std::string sql;
};

// MPSC queue + dedicated audit thread. Producers (worker threads handling
// sessions) call publish(); the audit thread drains, runs detection rules,
// and writes one structured JSONL record per event (and one per alert).
class AuditPipeline {
public:
    AuditPipeline(std::shared_ptr<log::JsonlSink> sink,
                  std::shared_ptr<detect::Detector> detector);
    ~AuditPipeline();

    AuditPipeline(const AuditPipeline&) = delete;
    AuditPipeline& operator=(const AuditPipeline&) = delete;

    void start();
    void stop();
    void publish(Event ev);

    size_t pending() const;
    size_t processed() const;

private:
    void run();
    void handle(const Event& ev);
    void emit_event(const Event& ev);
    void emit_alert(const detect::Alert& alert, const Event& ev);

    std::shared_ptr<log::JsonlSink> sink_;
    std::shared_ptr<detect::Detector> detector_;

    mutable std::mutex mu_;
    std::condition_variable cv_;
    std::queue<Event> q_;
    bool stop_requested_ = false;
    std::thread worker_;
    std::atomic<size_t> processed_{0};
};

}  // namespace mirage::audit
