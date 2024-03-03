cmake_minimum_required(VERSION 3.16)

add_executable(unit-tests
    test_addresses.cpp
)
target_link_libraries(unit-tests PRIVATE snet_cpp)
set_target_properties(unit-tests PROPERTIES
    CXX_STANDARD 20
)
