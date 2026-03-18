cmake_minimum_required(VERSION 3.20)

project(purify LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

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
    src/purify.cpp
)

target_link_libraries(purify_cpp
    PRIVATE
        purify_bppp_support
)

purify_enable_warnings(purify_cpp)
purify_enable_optimizations(purify_cpp)

add_executable(bench_purify
    src/bench_purify.cpp
)

target_link_libraries(bench_purify
    PRIVATE
        purify_bppp_support
)

purify_enable_warnings(bench_purify)
purify_enable_optimizations(bench_purify)
