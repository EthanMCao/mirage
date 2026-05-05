// connection_storm: drive Mirage with N parallel client threads, each
// performing the full Postgres v3 startup -> password -> error-response
// cycle in a tight loop. Reports total successful sessions, dropped
// connections, and end-to-end throughput.
//
// Run mirage *without* the rate limiter:
//   ./build/mirage --no-ratelimit --workers 8 --audit-log /tmp/bench.jsonl
//
// Then drive it:
//   ./build/connection_storm --port 55432 --threads 8 --per-thread 2000

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

namespace {

bool send_all(int fd, const void* buf, size_t n) {
    auto* p = static_cast<const uint8_t*>(buf);
    while (n > 0) {
        ssize_t w = ::send(fd, p, n, 0);
        if (w <= 0) return false;
        p += w; n -= static_cast<size_t>(w);
    }
    return true;
}

bool recv_some(int fd, void* buf, size_t n) {
    ssize_t r = ::recv(fd, buf, n, 0);
    return r > 0;
}

void put_be32(std::vector<uint8_t>& out, int32_t v) {
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xff));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xff));
    out.push_back(static_cast<uint8_t>((v >> 8)  & 0xff));
    out.push_back(static_cast<uint8_t>( v        & 0xff));
}

bool one_session(uint16_t port) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return false;
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        ::close(fd); return false;
    }

    std::vector<uint8_t> body;
    put_be32(body, 0x00030000);
    auto put_cstr = [&](const char* s) {
        body.insert(body.end(), s, s + std::strlen(s));
        body.push_back('\0');
    };
    put_cstr("user"); put_cstr("bench");
    put_cstr("database"); put_cstr("postgres");
    body.push_back('\0');
    std::vector<uint8_t> frame;
    put_be32(frame, static_cast<int32_t>(4 + body.size()));
    frame.insert(frame.end(), body.begin(), body.end());
    if (!send_all(fd, frame.data(), frame.size())) { ::close(fd); return false; }

    uint8_t auth_chal[9];
    if (!recv_some(fd, auth_chal, sizeof(auth_chal))) { ::close(fd); return false; }

    const char* pw = "bench\0";
    std::vector<uint8_t> pmsg;
    pmsg.push_back('p');
    put_be32(pmsg, 4 + 6);
    pmsg.insert(pmsg.end(), pw, pw + 6);
    if (!send_all(fd, pmsg.data(), pmsg.size())) { ::close(fd); return false; }

    uint8_t reply[256];
    recv_some(fd, reply, sizeof(reply));  // expect 'E' ErrorResponse
    ::close(fd);
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    uint16_t port = 55432;
    int threads = 8;
    int per_thread = 1000;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&]() { return std::string(argv[++i]); };
        if      (a == "--port")        port = static_cast<uint16_t>(std::atoi(next().c_str()));
        else if (a == "--threads")     threads = std::atoi(next().c_str());
        else if (a == "--per-thread")  per_thread = std::atoi(next().c_str());
    }

    std::atomic<uint64_t> ok{0};
    std::atomic<uint64_t> fail{0};

    auto t0 = std::chrono::steady_clock::now();
    std::vector<std::thread> ts;
    ts.reserve(static_cast<size_t>(threads));
    for (int t = 0; t < threads; ++t) {
        ts.emplace_back([&, port, per_thread] {
            for (int i = 0; i < per_thread; ++i) {
                if (one_session(port)) ok.fetch_add(1, std::memory_order_relaxed);
                else fail.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }
    for (auto& t : ts) t.join();
    auto t1 = std::chrono::steady_clock::now();

    auto elapsed = std::chrono::duration<double>(t1 - t0).count();
    uint64_t total_ok = ok.load();
    uint64_t total_fail = fail.load();
    double rps = static_cast<double>(total_ok) / elapsed;

    std::printf("threads=%d per_thread=%d total_ok=%llu fail=%llu elapsed=%.3fs sessions/s=%.1f\n",
                threads, per_thread,
                static_cast<unsigned long long>(total_ok),
                static_cast<unsigned long long>(total_fail),
                elapsed, rps);
    return 0;
}
