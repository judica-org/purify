# Copyright (c) 2026 Judica, Inc.
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

cmake_minimum_required(VERSION 3.20)

project(purify LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Doxygen QUIET)

if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/secp256k1-zkp/include/secp256k1_bppp.h")
    message(FATAL_ERROR "Missing third_party/secp256k1-zkp. Run: git submodule update --init --recursive")
endif()

if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/nanobench/src/include/nanobench.h")
    message(FATAL_ERROR "Missing third_party/nanobench. Run: git submodule update --init --recursive")
endif()

function(purify_enable_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4)
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -pedantic)
    endif()
endfunction()

function(purify_enable_optimizations target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /O2)
    else()
        target_compile_options(${target} PRIVATE -O3)
    endif()
endfunction()

add_library(purify_bppp_support STATIC
    src/purify_bppp.cpp
    src/purify_bppp_bridge.c
)

target_include_directories(purify_bppp_support
    PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}"
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
)

purify_enable_warnings(purify_bppp_support)
purify_enable_optimizations(purify_bppp_support)

add_executable(purify_cpp
    cli/main.cpp
)

target_link_libraries(purify_cpp
    PRIVATE
        purify_bppp_support
)

purify_enable_warnings(purify_cpp)
purify_enable_optimizations(purify_cpp)

add_executable(bench_purify
    bench/bench_purify.cpp
)

target_link_libraries(bench_purify
    PRIVATE
        purify_bppp_support
)

purify_enable_warnings(bench_purify)
purify_enable_optimizations(bench_purify)

if(DOXYGEN_FOUND)
    file(GLOB_RECURSE PURIFY_DOCS_INPUT
        CONFIGURE_DEPENDS
        "${CMAKE_CURRENT_SOURCE_DIR}/src/*.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/*.hpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/cli/*.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/bench/*.cpp"
    )

    set(PURIFY_DOXYGEN_OUTPUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/docs")
    set(PURIFY_DOXYGEN_CONFIG "${CMAKE_CURRENT_BINARY_DIR}/Doxyfile")
    set(PURIFY_DOXYGEN_INDEX "${PURIFY_DOXYGEN_OUTPUT_DIR}/html/index.html")

    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in"
        "${PURIFY_DOXYGEN_CONFIG}"
        @ONLY
    )

    add_custom_command(
        OUTPUT "${PURIFY_DOXYGEN_INDEX}"
        COMMAND "${DOXYGEN_EXECUTABLE}" "${PURIFY_DOXYGEN_CONFIG}"
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        DEPENDS
            "${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in"
            "${CMAKE_CURRENT_SOURCE_DIR}/README.md"
            "${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt"
            ${PURIFY_DOCS_INPUT}
        COMMENT "Generating API documentation with Doxygen"
        VERBATIM
    )

    add_custom_target(docs
        DEPENDS "${PURIFY_DOXYGEN_INDEX}"
    )
else()
    message(STATUS "Doxygen not found; 'docs' target will not be available")
endif()
