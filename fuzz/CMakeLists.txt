# Built only when -DMIRAGE_FUZZ=ON. Requires a clang toolchain that supports
# -fsanitize=fuzzer (every clang since ~6.0).
add_executable(fuzz_wire_protocol fuzz_wire_protocol.cpp)
target_link_libraries(fuzz_wire_protocol PRIVATE mirage_core)
target_compile_options(fuzz_wire_protocol PRIVATE -fsanitize=fuzzer)
target_link_options(fuzz_wire_protocol PRIVATE -fsanitize=fuzzer)
