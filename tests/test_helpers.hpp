#pragma once

#include <signal.h>

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <string>

namespace mirage::test {

inline int& failure_count() {
    static int n = 0;
    return n;
}

inline void ignore_sigpipe_once() {
    static bool installed = false;
    if (!installed) {
        std::signal(SIGPIPE, SIG_IGN);
        installed = true;
    }
}

inline int finalize(const char* suite) {
    if (failure_count() > 0) {
        std::fprintf(stderr, "[FAIL] %s: %d failures\n", suite, failure_count());
        return 1;
    }
    std::fprintf(stderr, "[ OK ] %s\n", suite);
    return 0;
}

}  // namespace mirage::test

#define EXPECT_TRUE(cond) do { \
    if (!(cond)) { \
        std::fprintf(stderr, "EXPECT_TRUE failed: %s @ %s:%d\n", \
                     #cond, __FILE__, __LINE__); \
        ++mirage::test::failure_count(); \
    } \
} while (0)

#define EXPECT_EQ(a, b) do { \
    auto _av = (a); \
    auto _bv = (b); \
    if (!(_av == _bv)) { \
        std::fprintf(stderr, "EXPECT_EQ failed: %s == %s @ %s:%d\n", \
                     #a, #b, __FILE__, __LINE__); \
        ++mirage::test::failure_count(); \
    } \
} while (0)

#define ASSERT_TRUE(cond) do { \
    if (!(cond)) { \
        std::fprintf(stderr, "ASSERT_TRUE failed: %s @ %s:%d\n", \
                     #cond, __FILE__, __LINE__); \
        std::exit(1); \
    } \
} while (0)
