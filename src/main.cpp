#include <signal.h>

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <thread>

#include "mirage/audit.hpp"
#include "mirage/detection.hpp"
#include "mirage/logging.hpp"
#include "mirage/server.hpp"

namespace {

std::atomic<bool> g_should_exit{false};

void on_signal(int) {
    g_should_exit.store(true, std::memory_order_relaxed);
}

void print_usage() {
    std::cout <<
      "mirage - postgres-wire honeypot\n"
      "\n"
      "Usage: mirage [options]\n"
      "  --host HOST            bind address (default 127.0.0.1)\n"
      "  --port PORT            bind port (default 55432)\n"
      "  --workers N            worker threads (default 4)\n"
      "  --audit-log PATH       jsonl output path (default ./audit.jsonl)\n"
      "  --auth-mode MODE       collect|accept (default collect)\n"
      "  --help                 show this message\n";
}

bool starts_with(const std::string& s, const std::string& p) {
    return s.size() >= p.size() && s.compare(0, p.size(), p) == 0;
}

}  // namespace

int main(int argc, char** argv) {
    mirage::server::Config cfg;
    std::string audit_path = "audit.jsonl";

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&](const char* name) -> std::string {
            if (i + 1 >= argc) {
                std::cerr << name << " requires an argument\n";
                std::exit(2);
            }
            return argv[++i];
        };
        if (a == "--help" || a == "-h") { print_usage(); return 0; }
        else if (a == "--host")        cfg.host = next("--host");
        else if (a == "--port")        cfg.port = std::atoi(next("--port").c_str());
        else if (a == "--workers")     cfg.worker_threads = std::atoi(next("--workers").c_str());
        else if (a == "--audit-log")   audit_path = next("--audit-log");
        else if (a == "--auth-mode") {
            std::string mode = next("--auth-mode");
            if (mode == "collect")     cfg.session.auth_mode = mirage::session::AuthMode::Collect;
            else if (mode == "accept") cfg.session.auth_mode = mirage::session::AuthMode::Accept;
            else { std::cerr << "unknown auth mode: " << mode << "\n"; return 2; }
        }
        else if (starts_with(a, "--")) {
            std::cerr << "unknown option: " << a << "\n";
            print_usage();
            return 2;
        }
    }

    auto sink = std::make_shared<mirage::log::JsonlSink>();
    if (!sink->open(audit_path)) {
        std::cerr << "failed to open audit log: " << audit_path << "\n";
        return 1;
    }
    auto detector = std::make_shared<mirage::detect::Detector>();
    auto pipeline = std::make_shared<mirage::audit::AuditPipeline>(sink, detector);
    pipeline->start();

    auto server = std::make_unique<mirage::server::Server>(cfg, pipeline);
    if (!server->start()) {
        pipeline->stop();
        return 1;
    }

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    std::cout << "mirage listening on " << cfg.host << ":" << cfg.port
              << " (workers=" << cfg.worker_threads << ", audit=" << audit_path << ")\n";

    auto last = std::chrono::steady_clock::now();
    while (!g_should_exit.load(std::memory_order_relaxed)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        auto now = std::chrono::steady_clock::now();
        if (now - last >= std::chrono::seconds(30)) {
            auto snap = detector->snapshot();
            std::cout << "[stats] accepted=" << server->connections_accepted()
                      << " active=" << server->connections_active()
                      << " events=" << pipeline->processed()
                      << " ips=" << snap.tracked_ips
                      << " alerts=" << snap.total_alerts << "\n";
            last = now;
        }
    }

    std::cout << "shutting down\n";
    server->stop();
    server->wait();
    pipeline->stop();
    return 0;
}
