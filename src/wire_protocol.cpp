#include "mirage/wire_protocol.hpp"

#include <arpa/inet.h>
#include <errno.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>

namespace mirage::wire {
namespace {

bool read_exact(int fd, void* buf, size_t n) {
    auto* p = static_cast<uint8_t*>(buf);
    while (n > 0) {
        ssize_t r = ::recv(fd, p, n, 0);
        if (r == 0) return false;
        if (r < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        p += static_cast<size_t>(r);
        n -= static_cast<size_t>(r);
    }
    return true;
}

int32_t read_be32(const uint8_t* p) {
    return (int32_t(p[0]) << 24) | (int32_t(p[1]) << 16) |
           (int32_t(p[2]) << 8)  |  int32_t(p[3]);
}

void write_be32(std::vector<uint8_t>& out, int32_t v) {
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xff));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xff));
    out.push_back(static_cast<uint8_t>((v >> 8)  & 0xff));
    out.push_back(static_cast<uint8_t>( v        & 0xff));
}

void write_be16(std::vector<uint8_t>& out, int16_t v) {
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
    out.push_back(static_cast<uint8_t>( v       & 0xff));
}

void write_cstring(std::vector<uint8_t>& out, const std::string& s) {
    out.insert(out.end(), s.begin(), s.end());
    out.push_back('\0');
}

// Build a tagged backend frame: <tag><int32 length-including-self><body>.
std::vector<uint8_t> frame(uint8_t tag, const std::vector<uint8_t>& body) {
    std::vector<uint8_t> out;
    out.reserve(1 + 4 + body.size());
    out.push_back(tag);
    write_be32(out, static_cast<int32_t>(4 + body.size()));
    out.insert(out.end(), body.begin(), body.end());
    return out;
}

// Parse null-terminated key/value pairs in a StartupMessage parameter blob.
// Format ends when a key with zero length is encountered.
void parse_startup_params(const std::vector<uint8_t>& body,
                          std::unordered_map<std::string, std::string>& out) {
    size_t i = 4;  // skip the protocol-version int32 at the head of body
    while (i < body.size()) {
        size_t key_start = i;
        while (i < body.size() && body[i] != '\0') ++i;
        if (i >= body.size()) break;
        std::string key(body.begin() + static_cast<long>(key_start),
                        body.begin() + static_cast<long>(i));
        ++i;  // skip null
        if (key.empty()) break;  // terminator pair
        size_t val_start = i;
        while (i < body.size() && body[i] != '\0') ++i;
        if (i >= body.size()) break;
        std::string val(body.begin() + static_cast<long>(val_start),
                        body.begin() + static_cast<long>(i));
        ++i;
        out.emplace(std::move(key), std::move(val));
    }
}

}  // namespace

std::optional<StartupMessage> read_startup(int fd) {
    for (int attempt = 0; attempt < 2; ++attempt) {
        uint8_t hdr[4];
        if (!read_exact(fd, hdr, 4)) return std::nullopt;
        int32_t len = read_be32(hdr);
        if (len < 8 || len > 1 << 20) return std::nullopt;
        std::vector<uint8_t> body(static_cast<size_t>(len - 4));
        if (!read_exact(fd, body.data(), body.size())) return std::nullopt;
        int32_t version = read_be32(body.data());
        if (version == kProtocolVersionSSLRequest ||
            version == kProtocolVersionGSSEncRequest) {
            // Decline encryption negotiation, then loop to read the real Startup.
            uint8_t reply = 'N';
            if (!write_all(fd, &reply, 1)) return std::nullopt;
            continue;
        }
        if (version == kProtocolVersionCancelRequest) {
            return std::nullopt;  // not a session we care about
        }
        StartupMessage msg;
        msg.protocol_version = version;
        parse_startup_params(body, msg.parameters);
        return msg;
    }
    return std::nullopt;
}

std::optional<FrontendMessage> read_frontend(int fd) {
    uint8_t hdr[5];
    if (!read_exact(fd, hdr, 5)) return std::nullopt;
    uint8_t tag = hdr[0];
    int32_t len = read_be32(hdr + 1);
    if (len < 4 || len > 1 << 24) return std::nullopt;
    std::vector<uint8_t> body(static_cast<size_t>(len - 4));
    if (!body.empty() && !read_exact(fd, body.data(), body.size())) {
        return std::nullopt;
    }

    FrontendMessage msg;
    switch (tag) {
        case 'p':
            msg.type = FrontendType::Password;
            if (!body.empty() && body.back() == '\0') body.pop_back();
            msg.payload.assign(body.begin(), body.end());
            return msg;
        case 'Q':
            msg.type = FrontendType::Query;
            if (!body.empty() && body.back() == '\0') body.pop_back();
            msg.payload.assign(body.begin(), body.end());
            return msg;
        case 'X':
            msg.type = FrontendType::Terminate;
            return msg;
        default:
            msg.type = FrontendType::Unknown;
            msg.payload.assign(body.begin(), body.end());
            return msg;
    }
}

std::vector<uint8_t> auth_cleartext_password() {
    std::vector<uint8_t> body;
    write_be32(body, 3);  // AuthenticationCleartextPassword
    return frame('R', body);
}

std::vector<uint8_t> auth_ok() {
    std::vector<uint8_t> body;
    write_be32(body, 0);
    return frame('R', body);
}

std::vector<uint8_t> auth_failed(const std::string& user) {
    return error_response("FATAL", "28P01",
                          "password authentication failed for user \"" + user + "\"");
}

std::vector<uint8_t> parameter_status(const std::string& key, const std::string& value) {
    std::vector<uint8_t> body;
    write_cstring(body, key);
    write_cstring(body, value);
    return frame('S', body);
}

std::vector<uint8_t> backend_key_data(int32_t pid, int32_t secret) {
    std::vector<uint8_t> body;
    write_be32(body, pid);
    write_be32(body, secret);
    return frame('K', body);
}

std::vector<uint8_t> ready_for_query(char status) {
    std::vector<uint8_t> body{static_cast<uint8_t>(status)};
    return frame('Z', body);
}

std::vector<uint8_t> empty_query_response() {
    return frame('I', {});
}

std::vector<uint8_t> command_complete(const std::string& tag) {
    std::vector<uint8_t> body;
    write_cstring(body, tag);
    return frame('C', body);
}

std::vector<uint8_t> error_response(const std::string& severity,
                                    const std::string& code,
                                    const std::string& message) {
    std::vector<uint8_t> body;
    body.push_back('S');
    write_cstring(body, severity);
    body.push_back('V');
    write_cstring(body, severity);
    body.push_back('C');
    write_cstring(body, code);
    body.push_back('M');
    write_cstring(body, message);
    body.push_back('\0');
    return frame('E', body);
}

std::vector<uint8_t> single_text_row(const std::string& column_name,
                                     const std::string& value) {
    std::vector<uint8_t> result;

    // RowDescription ('T'): one column of type text (oid 25).
    std::vector<uint8_t> desc;
    write_be16(desc, 1);  // field count
    write_cstring(desc, column_name);
    write_be32(desc, 0);   // table oid
    write_be16(desc, 0);   // column attno
    write_be32(desc, 25);  // type oid: text
    write_be16(desc, -1);  // type size (variable)
    write_be32(desc, -1);  // type modifier
    write_be16(desc, 0);   // format code: text
    auto desc_frame = frame('T', desc);
    result.insert(result.end(), desc_frame.begin(), desc_frame.end());

    // DataRow ('D'): one column.
    std::vector<uint8_t> row;
    write_be16(row, 1);
    write_be32(row, static_cast<int32_t>(value.size()));
    row.insert(row.end(), value.begin(), value.end());
    auto row_frame = frame('D', row);
    result.insert(result.end(), row_frame.begin(), row_frame.end());

    auto cc = command_complete("SELECT 1");
    result.insert(result.end(), cc.begin(), cc.end());
    return result;
}

bool write_all(int fd, const std::vector<uint8_t>& bytes) {
    return write_all(fd, bytes.data(), bytes.size());
}

bool write_all(int fd, const uint8_t* data, size_t n) {
    while (n > 0) {
        ssize_t w = ::send(fd, data, n, 0);
        if (w < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        data += static_cast<size_t>(w);
        n -= static_cast<size_t>(w);
    }
    return true;
}

}  // namespace mirage::wire
