#pragma once

#include <chrono>
#include <fstream>
#include <mutex>
#include <string>
#include <unordered_map>

namespace mirage::log {

// Returns RFC3339 UTC timestamp like "2026-05-08T20:14:03Z".
std::string now_iso8601();

// Escape a string for safe inclusion as a JSON string literal.
std::string json_escape(const std::string& s);

// Render a flat string-keyed map as a single JSON object on one line.
// Preserves no key ordering (uses unordered_map iteration order).
std::string render_json_line(const std::unordered_map<std::string, std::string>& fields);

// Thread-safe append-only JSONL sink. Open() may be called once at startup;
// every write_line() acquires a mutex and appends a single line + '\n'.
class JsonlSink {
public:
    JsonlSink() = default;
    explicit JsonlSink(const std::string& path);
    ~JsonlSink();

    JsonlSink(const JsonlSink&) = delete;
    JsonlSink& operator=(const JsonlSink&) = delete;

    bool open(const std::string& path);
    void write_line(const std::string& line);
    void flush();

private:
    std::mutex mu_;
    std::ofstream out_;
};

}  // namespace mirage::log
