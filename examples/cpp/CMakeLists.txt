cmake_minimum_required(VERSION 3.16)

find_package(Curses)


# Echo client/server
set(SRC_ECHO
    echo/main.cpp
    common/message_parser.cpp
)
if (NOT WIN32)
    list(APPEND SRC_ECHO echo/ncurses_helper.cpp)
endif()

add_executable(echo ${SRC_ECHO})
target_include_directories(echo PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(echo PRIVATE snet_cpp)
set_target_properties(echo PROPERTIES
    CXX_STANDARD 20
    PREFIX "snet-"
)

if (WIN32)
    target_precompile_headers(echo PRIVATE common/pch.hpp)
else()
    target_include_directories(echo PRIVATE ${CURSES_INCLUDE_DIR})
    target_link_libraries(echo PRIVATE ${CURSES_LIBRARIES})
endif()

install(TARGETS echo)


# Async echo client/server
set(SRC_ECHO_ASYNC
    echo_async/main.cpp
    common/message_parser.cpp
)

add_executable(echo-async ${SRC_ECHO_ASYNC})
target_include_directories(echo-async PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(echo-async PRIVATE snet_cpp)
set_target_properties(echo-async PROPERTIES
    CXX_STANDARD 20
    PREFIX "snet-"
)

if (WIN32)
    target_precompile_headers(echo-async REUSE_FROM echo)
    target_link_libraries(echo-async PRIVATE Ws2_32.lib)
endif()

install(TARGETS echo-async)
