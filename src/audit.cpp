#include "mirage/audit.hpp"

#include <utility>

namespace mirage::audit {

namespace {

const char* kind_name(EventKind k) {
    switch (k) {
        case EventKind::Startup:            return "startup";
        case EventKind::Password:           return "password";
        case EventKind::Query:              return "query";
        case EventKind::Terminate:          return "terminate";
        case EventKind::ConnectionAccepted: return "conn_open";
        case EventKind::ConnectionClosed:   return "conn_close";
        case EventKind::RateLimitDrop:      return "ratelimit_drop";
    }
    return "unknown";
}

}  // namespace

AuditPipeline::AuditPipeline(std::shared_ptr<log::JsonlSink> sink,
                             std::shared_ptr<detect::Detector> detector)
    : sink_(std::move(sink)), detector_(std::move(detector)) {}

AuditPipeline::~AuditPipeline() {
    stop();
}

void AuditPipeline::start() {
    worker_ = std::thread([this] { run(); });
}

void AuditPipeline::stop() {
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (stop_requested_) return;
        stop_requested_ = true;
    }
    cv_.notify_all();
    if (worker_.joinable()) worker_.join();
}

void AuditPipeline::publish(Event ev) {
    {
        std::lock_guard<std::mutex> lock(mu_);
        q_.push(std::move(ev));
    }
    cv_.notify_one();
}

size_t AuditPipeline::pending() const {
    std::lock_guard<std::mutex> lock(mu_);
    return q_.size();
}

size_t AuditPipeline::processed() const {
    return processed_.load(std::memory_order_relaxed);
}

void AuditPipeline::run() {
    for (;;) {
        Event ev;
        {
            std::unique_lock<std::mutex> lock(mu_);
            cv_.wait(lock, [this] { return stop_requested_ || !q_.empty(); });
            if (q_.empty() && stop_requested_) return;
            ev = std::move(q_.front());
            q_.pop();
        }
        handle(ev);
        processed_.fetch_add(1, std::memory_order_relaxed);
    }
}

void AuditPipeline::handle(const Event& ev) {
    emit_event(ev);

    std::optional<detect::Alert> alert;
    switch (ev.kind) {
        case EventKind::ConnectionAccepted:
            alert = detector_->on_connection(ev.src_ip);
            break;
        case EventKind::Password:
            alert = detector_->on_auth_attempt(ev.src_ip, ev.user);
            break;
        case EventKind::Query:
            alert = detector_->on_query(ev.src_ip, ev.sql);
            break;
        default:
            break;
    }
    if (alert) emit_alert(*alert, ev);
}

void AuditPipeline::emit_event(const Event& ev) {
    std::unordered_map<std::string, std::string> fields;
    fields.emplace("ts", log::now_iso8601());
    fields.emplace("event", kind_name(ev.kind));
    fields.emplace("src_ip", ev.src_ip);
    fields.emplace("src_port", std::to_string(ev.src_port));
    if (!ev.user.empty())     fields.emplace("user", ev.user);
    if (!ev.database.empty()) fields.emplace("database", ev.database);
    if (!ev.password.empty()) fields.emplace("password", ev.password);
    if (!ev.sql.empty())      fields.emplace("sql", ev.sql);
    sink_->write_line(log::render_json_line(fields));
}

void AuditPipeline::emit_alert(const detect::Alert& alert, const Event& ev) {
    std::unordered_map<std::string, std::string> fields;
    fields.emplace("ts", log::now_iso8601());
    fields.emplace("event", "detection");
    fields.emplace("rule", alert.rule);
    fields.emplace("src_ip", alert.src_ip);
    fields.emplace("count", std::to_string(alert.count));
    if (alert.window_seconds > 0) {
        fields.emplace("window_s", std::to_string(alert.window_seconds));
    }
    fields.emplace("detail", alert.detail);
    if (!ev.user.empty()) fields.emplace("user", ev.user);
    sink_->write_line(log::render_json_line(fields));
}

}  // namespace mirage::audit
