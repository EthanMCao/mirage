add_executable(test_wire_protocol test_wire_protocol.cpp)
target_link_libraries(test_wire_protocol PRIVATE mirage_core)
target_include_directories(test_wire_protocol PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
add_test(NAME wire_protocol COMMAND test_wire_protocol)

add_executable(test_detection test_detection.cpp)
target_link_libraries(test_detection PRIVATE mirage_core)
target_include_directories(test_detection PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
add_test(NAME detection COMMAND test_detection)

add_executable(test_ratelimit test_ratelimit.cpp)
target_link_libraries(test_ratelimit PRIVATE mirage_core)
target_include_directories(test_ratelimit PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
add_test(NAME ratelimit COMMAND test_ratelimit)
