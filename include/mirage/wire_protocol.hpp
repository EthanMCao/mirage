#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace mirage::wire {

// Postgres v3 protocol constants. See:
// https://www.postgresql.org/docs/current/protocol-message-formats.html
constexpr int32_t kProtocolVersionV3 = 0x00030000;
constexpr int32_t kProtocolVersionSSLRequest = 80877103;
constexpr int32_t kProtocolVersionCancelRequest = 80877102;
constexpr int32_t kProtocolVersionGSSEncRequest = 80877104;

enum class FrontendType : uint8_t {
    Password,    // 'p'
    Query,       // 'Q' simple query
    Terminate,   // 'X'
    Parse,       // 'P' extended query: prepare statement
    Bind,        // 'B' bind portal to statement
    Describe,    // 'D' describe portal or statement
    Execute,     // 'E' run portal
    Close,       // 'C' close portal or statement
    Sync,        // 'S' end of extended-query batch
    Flush,       // 'H' flush
    Unknown,
};

struct StartupMessage {
    int32_t protocol_version{0};
    std::unordered_map<std::string, std::string> parameters;
};

// payload semantics by type:
//   Password / Query: textual content with the trailing NUL stripped.
//   Parse / Bind / Describe / Execute / Close: raw binary body so the
//     caller can decode the per-message structure.
//   Terminate / Sync / Flush / Unknown: empty.
struct FrontendMessage {
    FrontendType type{FrontendType::Unknown};
    std::string payload;
};

// Reads the very first message a client sends. Transparently handles SSL/GSS
// negotiation by replying 'N' (no encryption) and re-reading until a real
// StartupMessage arrives. Returns nullopt on EOF, malformed input, or
// CancelRequest (which is a one-shot side channel).
std::optional<StartupMessage> read_startup(int fd);

// Reads one tagged frontend message after the startup phase.
std::optional<FrontendMessage> read_frontend(int fd);

// Backend (server -> client) frame builders. Each returns a wire-ready buffer.
std::vector<uint8_t> auth_cleartext_password();
std::vector<uint8_t> auth_ok();
std::vector<uint8_t> auth_failed(const std::string& user);
std::vector<uint8_t> parameter_status(const std::string& key, const std::string& value);
std::vector<uint8_t> backend_key_data(int32_t pid, int32_t secret);
std::vector<uint8_t> ready_for_query(char status = 'I');
std::vector<uint8_t> empty_query_response();
std::vector<uint8_t> command_complete(const std::string& tag);
std::vector<uint8_t> error_response(const std::string& severity,
                                    const std::string& code,
                                    const std::string& message);
std::vector<uint8_t> single_text_row(const std::string& column_name,
                                     const std::string& value);

// Extended-query backend responses.
std::vector<uint8_t> parse_complete();
std::vector<uint8_t> bind_complete();
std::vector<uint8_t> close_complete();
std::vector<uint8_t> no_data();
std::vector<uint8_t> portal_suspended();
std::vector<uint8_t> parameter_description(const std::vector<int32_t>& oids);
std::vector<uint8_t> row_description_text(const std::string& column_name);
std::vector<uint8_t> data_row_single_text(const std::string& value);

// Best-effort write-all on a blocking socket. Returns false on error/closed.
bool write_all(int fd, const std::vector<uint8_t>& bytes);
bool write_all(int fd, const uint8_t* data, size_t n);

}  // namespace mirage::wire
