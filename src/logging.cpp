#include "mirage/logging.hpp"

#include <ctime>
#include <iomanip>
#include <sstream>
#include <utility>

namespace mirage::log {

std::string now_iso8601() {
    using namespace std::chrono;
    auto t = system_clock::to_time_t(system_clock::now());
    std::tm tm{};
    gmtime_r(&t, &tm);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 2);
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c < 0x20) {
                    char esc[8];
                    std::snprintf(esc, sizeof(esc), "\\u%04x", c);
                    out += esc;
                } else {
                    out.push_back(static_cast<char>(c));
                }
        }
    }
    return out;
}

std::string render_json_line(const std::unordered_map<std::string, std::string>& fields) {
    std::ostringstream os;
    os << '{';
    bool first = true;
    for (const auto& [k, v] : fields) {
        if (!first) os << ',';
        first = false;
        os << '"' << json_escape(k) << "\":\"" << json_escape(v) << '"';
    }
    os << '}';
    return os.str();
}

JsonlSink::JsonlSink(const std::string& path) {
    open(path);
}

JsonlSink::~JsonlSink() {
    if (out_.is_open()) {
        out_.flush();
        out_.close();
    }
}

bool JsonlSink::open(const std::string& path) {
    std::lock_guard<std::mutex> lock(mu_);
    out_.open(path, std::ios::out | std::ios::app);
    return out_.is_open();
}

void JsonlSink::write_line(const std::string& line) {
    std::lock_guard<std::mutex> lock(mu_);
    if (!out_.is_open()) return;
    out_ << line << '\n';
    out_.flush();
}

void JsonlSink::flush() {
    std::lock_guard<std::mutex> lock(mu_);
    if (out_.is_open()) out_.flush();
}

}  // namespace mirage::log
