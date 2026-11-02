cmake_minimum_required(VERSION 3.16)
project(open62541-amalgam C)

# Compiles the open62541 amalgamation (open62541.c) into a static library.
#
# The amalgamation takes minutes to compile; building it in its own project
# lets the Docker build cache that step in a layer that only changes when the
# open62541 pin or its build options change, not on every adapter edit.

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

if(NOT UA_AMALGAM_INCLUDE)
    message(FATAL_ERROR "UA_AMALGAM_INCLUDE must point to the directory containing open62541.h")
endif()
if(NOT UA_AMALGAM_SOURCE)
    message(FATAL_ERROR "UA_AMALGAM_SOURCE must point to open62541.c")
endif()

find_package(OpenSSL REQUIRED)

add_library(open62541 STATIC "${UA_AMALGAM_SOURCE}")
target_include_directories(open62541 PRIVATE "${UA_AMALGAM_INCLUDE}" ${OPENSSL_INCLUDE_DIR})

install(TARGETS open62541 ARCHIVE DESTINATION lib)
