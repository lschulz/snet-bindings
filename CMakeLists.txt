cmake_minimum_required(VERSION 3.16)

project(snet-bindings)
include(CTest)

set(GO_BINARY "go" CACHE FILEPATH "Path to go binary")
set(BUILD_STATIC_LIBS OFF CACHE BOOL "Build static/archive libraries")
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build shared libraries")
set(BUILD_EXAMPLES ON CACHE BOOL "Build the examples")

add_compile_options(-Wall -Wextra -Wpedantic -Wno-unused-parameter)

# C library
add_subdirectory(go)

# C++ library
add_library(snet_cpp src/snet.cpp)
target_link_libraries(snet_cpp PRIVATE snet_c)
target_include_directories(snet_cpp PUBLIC "${CMAKE_SOURCE_DIR}/include")
set_target_properties(snet_cpp PROPERTIES
    CXX_STANDARD 20
    PUBLIC_HEADER "${CMAKE_SOURCE_DIR}/include/snet/snet.hpp"
    OUTPUT_NAME "snetcpp"
    DEBUG_POSTFIX "d"
)
install(TARGETS snet_cpp
    ARCHIVE
    LIBRARY
    PUBLIC_HEADER DESTINATION "include/snet/"
)

# Examples
if (BUILD_EXAMPLES)
    add_subdirectory(examples/cpp)
endif()

# Tests
add_subdirectory(tests)
add_test(NAME DocTest COMMAND tests)
