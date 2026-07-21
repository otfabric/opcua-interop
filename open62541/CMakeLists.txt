cmake_minimum_required(VERSION 3.16)
project(opcua-interop-open62541 C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# ---------------------------------------------------------------------------
# open62541 amalgamation
# ---------------------------------------------------------------------------
if(NOT UA_AMALGAM_INCLUDE)
    message(FATAL_ERROR "UA_AMALGAM_INCLUDE must point to the directory containing open62541.h")
endif()
if(NOT UA_AMALGAM_SOURCE)
    message(FATAL_ERROR "UA_AMALGAM_SOURCE must point to open62541.c")
endif()

# ---------------------------------------------------------------------------
# cJSON
# ---------------------------------------------------------------------------
find_package(PkgConfig REQUIRED)
pkg_check_modules(CJSON REQUIRED libcjson)

# ---------------------------------------------------------------------------
# Adapter sources
# ---------------------------------------------------------------------------
set(ADAPTER_SRCS
    src/main.c
    src/fixture.c
    src/server.c
    src/client.c
    src/output.c
    "${UA_AMALGAM_SOURCE}"
)

add_executable(opcua-interop-open62541 ${ADAPTER_SRCS})

target_include_directories(opcua-interop-open62541 PRIVATE
    "${UA_AMALGAM_INCLUDE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
    ${CJSON_INCLUDE_DIRS}
)

target_link_libraries(opcua-interop-open62541 PRIVATE
    ${CJSON_LIBRARIES}
    pthread
    m
)

target_compile_options(opcua-interop-open62541 PRIVATE
    ${CJSON_CFLAGS_OTHER}
)

install(TARGETS opcua-interop-open62541 RUNTIME DESTINATION bin)

# ---------------------------------------------------------------------------
# Fixture parser unit tests (optional, built separately)
# ---------------------------------------------------------------------------
option(BUILD_TESTS "Build fixture parser unit tests" OFF)
if(BUILD_TESTS)
    add_executable(fixture_test
        tests/fixture_test.c
        src/fixture.c
    )
    target_include_directories(fixture_test PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
        ${CJSON_INCLUDE_DIRS}
    )
    target_link_libraries(fixture_test PRIVATE
        ${CJSON_LIBRARIES}
        m
    )
    target_compile_options(fixture_test PRIVATE ${CJSON_CFLAGS_OTHER})
    enable_testing()
    add_test(NAME fixture_test COMMAND fixture_test
        "${CMAKE_SOURCE_DIR}/../fixtures/baseline/fixture.json")
endif()
