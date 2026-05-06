// libFuzzer harness for the Postgres-wire parsers.
//
// The parsers consume bytes from a file descriptor, so we feed each fuzzer
// input through a socketpair: write the bytes to one end, close it, and let
// read_startup() / read_frontend() drain the other end until EOF.

#include <sys/socket.h>
#include <unistd.h>

#include <cstddef>
#include <cstdint>

#include "mirage/wire_protocol.hpp"

namespace {

void drive_one_input(const uint8_t* data, size_t size) {
    int sv[2];
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return;

    // Stuff bytes in, then close the writer so the reader sees a clean EOF
    // instead of blocking forever waiting for more data.
    const uint8_t* p = data;
    size_t remaining = size;
    while (remaining > 0) {
        ssize_t w = ::send(sv[1], p, remaining, 0);
        if (w <= 0) break;
        p += w;
        remaining -= static_cast<size_t>(w);
    }
    ::close(sv[1]);

    auto startup = mirage::wire::read_startup(sv[0]);
    (void)startup;
    while (auto m = mirage::wire::read_frontend(sv[0])) {
        // Reach into payload to make sure parsed contents are addressable.
        if (!m->payload.empty()) {
            volatile char sink = m->payload[0];
            (void)sink;
        }
    }

    ::close(sv[0]);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    drive_one_input(data, size);
    return 0;
}
