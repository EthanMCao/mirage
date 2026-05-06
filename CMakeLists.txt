cmake_minimum_required(VERSION 3.16)
project(mirage VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

add_compile_options(-Wall -Wextra -Wpedantic -Wshadow -Wnon-virtual-dtor)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
  add_compile_options(-O2)
endif()

# Fuzzing build: instrument every translation unit so libFuzzer + ASan can
# observe coverage across mirage_core. The actual fuzzer target lives under
# fuzz/ and adds -fsanitize=fuzzer for the runtime.
option(MIRAGE_FUZZ "Build libFuzzer harnesses (clang only)" OFF)
if(MIRAGE_FUZZ)
  if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "MIRAGE_FUZZ=ON requires clang")
  endif()
  add_compile_options(-fsanitize=fuzzer-no-link,address -fno-omit-frame-pointer)
  add_link_options(-fsanitize=fuzzer-no-link,address)
endif()

find_package(Threads REQUIRED)

add_library(mirage_core STATIC
  src/wire_protocol.cpp
  src/logging.cpp
  src/detection.cpp
  src/ratelimit.cpp
  src/audit.cpp
  src/session.cpp
  src/server.cpp
)

target_include_directories(mirage_core PUBLIC include)
target_link_libraries(mirage_core PUBLIC Threads::Threads)

add_executable(mirage src/main.cpp)
target_link_libraries(mirage PRIVATE mirage_core)

add_executable(connection_storm bench/connection_storm.cpp)
target_link_libraries(connection_storm PRIVATE Threads::Threads)

enable_testing()
add_subdirectory(tests)

if(MIRAGE_FUZZ)
  add_subdirectory(fuzz)
endif()
