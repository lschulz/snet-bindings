cmake_minimum_required(VERSION 3.16)

add_executable(tests
    test_addresses.cpp
)
target_link_libraries(tests PRIVATE snet_cpp)
set_target_properties(tests PROPERTIES
    CXX_STANDARD 20
    OUTPUT_NAME test
)
