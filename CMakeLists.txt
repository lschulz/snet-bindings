cmake_minimum_required(VERSION 3.16)

project(snet-bindings)
include(CTest)

set(GO_BINARY "go" CACHE FILEPATH "Path to go binary")
option(BUILD_STATIC_LIBS "Build static/archive libraries" OFF)
option(BUILD_SHARED_LIBS "Build shared libraries" OFF)
option(BUILD_EXAMPLES "Build the examples" ON)

add_compile_options(-Wall -Wextra -Wpedantic -Wno-unused-parameter)

# C library
add_subdirectory(go)

# C++ library
add_library(snet_cpp src/snet.cpp)
target_link_libraries(snet_cpp PRIVATE snet_c)
target_include_directories(snet_cpp PUBLIC "${PROJECT_SOURCE_DIR}/include")
set_target_properties(snet_cpp PROPERTIES
    CXX_STANDARD 20
    PUBLIC_HEADER "${PROJECT_SOURCE_DIR}/include/snet/snet.hpp"
    OUTPUT_NAME "snetcpp"
    DEBUG_POSTFIX "d"
    VERSION "1.0.0"
    SOVERSION "1"
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
add_test(NAME DocTest COMMAND unit-tests)
