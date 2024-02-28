cmake_minimum_required(VERSION 3.16)

set(SRC
    snet_wrapper.go
    async_linux.go
    async_windows.go
)
set(HEADERS
    "${PROJECT_SOURCE_DIR}/include/snet/snet_cdefs.h"
)

if (WIN32)
    set(LIB lib)
else()
    set(LIB a)
endif()

if (NOT CMAKE_BUILD_TYPE OR CMAKE_BUILD_TYPE STREQUAL "Debug")
    # -N disables optimizations
    # -l disables inlining
    set(GCFLAGS -N -l)
    set(CGO_BUILD_FLAGS -gcflags="${GCFLAGS}")
else()
    set(CGO_BUILD_FLAGS)
endif()

set(CGO_OUT_NAME cgo_out)
set(HEADER ${CGO_OUT_NAME}.h)
set(GENERATED_HEADER "${PROJECT_SOURCE_DIR}/include/snet/snet.h")
set(CGO_HEADER_OUT "${CMAKE_CURRENT_BINARY_DIR}/${HEADER}")
set(CGO_STATIC_LIBRARY ${CGO_OUT_NAME}.${LIB})

# Static library compiled from Go code
add_custom_target(snet_cgo ALL DEPENDS ${CGO_STATIC_LIBRARY} ${GENERATED_HEADER})
add_custom_command(
    OUTPUT ${CGO_STATIC_LIBRARY}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMAND ${CMAKE_COMMAND} -E env CGO_ENABLED=1
         ${GO_BINARY} build ${CGO_BUILD_FLAGS} -buildmode=c-archive
        -o "${CMAKE_CURRENT_BINARY_DIR}/${CGO_STATIC_LIBRARY}" ${CMAKE_CURRENT_SOURCE_DIR}
    DEPENDS ${SRC} ${HEADERS}
)
add_custom_command(
    OUTPUT ${GENERATED_HEADER}
    DEPENDS ${CGO_STATIC_LIBRARY}
    COMMAND ${CMAKE_COMMAND} -E copy "${CGO_HEADER_OUT}" "${GENERATED_HEADER}"
)

# Import result of CGo compilation as library target
add_library(cgo_imported STATIC IMPORTED GLOBAL)
add_dependencies(cgo_imported snet_cgo)
set_target_properties(cgo_imported PROPERTIES
    IMPORTED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/${CGO_STATIC_LIBRARY}
    INTERFACE_INCLUDE_DIRECTORIES ${PROJECT_SOURCE_DIR}/include)

# Static library compiled from C code, linked with CGo output
add_library(snet_c OBJECT
    "${PROJECT_SOURCE_DIR}/src/addr.c"
    "${PROJECT_SOURCE_DIR}/src/path.c"
)
target_link_libraries(snet_c PUBLIC cgo_imported)
target_include_directories(snet_c PRIVATE "${PROJECT_SOURCE_DIR}/include")
if (WIN32)
    target_link_libraries(snet_c INTERFACE Ws2_32.lib)
endif()

install(FILES "${CGO_HEADER_OUT}" DESTINATION include/snet RENAME snet.h)
install(FILES "${PROJECT_SOURCE_DIR}/include/snet/snet_cdefs.h" DESTINATION include/snet)

# Build archive
if (${BUILD_STATIC_LIBS})
    add_library(snet_static STATIC)
    target_link_libraries(snet_static PUBLIC snet_c)
    set_target_properties(snet_static PROPERTIES
        OUTPUT_NAME snet
        DEBUG_POSTFIX "d"
    )
    install(TARGETS snet_static ARCHIVE)
endif(${BUILD_STATIC_LIBS})

# Link as shared library
if (${BUILD_SHARED_LIBS})
    add_library(snet_shared SHARED ${CGO_OBJS} "$<TARGET_OBJECTS:snet_c>")
    add_dependencies(snet_shared snet_cgo snet_c)
    target_include_directories(snet_shared INTERFACE ${PROJECT_SOURCE_DIR}/include)
    set_target_properties(snet_shared PROPERTIES
        OUTPUT_NAME snet
        DEBUG_POSTFIX "d"
    )
    if (WIN32)
        target_link_libraries(snet_shared PRIVATE Ws2_32.lib)
    endif()
    install(TARGETS snet_shared LIBRARY)
endif(${BUILD_SHARED_LIBS})
