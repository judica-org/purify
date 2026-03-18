# Copyright (c) 2026 Judica, Inc.
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

cmake_minimum_required(VERSION 3.20)

project(purify LANGUAGES C CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    set(PURIFY_IS_TOP_LEVEL ON)
else()
    set(PURIFY_IS_TOP_LEVEL OFF)
endif()

option(PURIFY_BUILD_CLI "Build the purify_cpp CLI target." ${PURIFY_IS_TOP_LEVEL})
option(PURIFY_BUILD_BENCH "Build the bench_purify benchmark target." ${PURIFY_IS_TOP_LEVEL})
option(PURIFY_BUILD_DOCS "Build the Doxygen docs target when Doxygen is available." ${PURIFY_IS_TOP_LEVEL})

if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/secp256k1-zkp/include/secp256k1_bppp.h")
    message(FATAL_ERROR "Missing third_party/secp256k1-zkp. Run: git submodule update --init third_party/secp256k1-zkp")
endif()

if(PURIFY_BUILD_BENCH AND NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/nanobench/src/include/nanobench.h")
    message(FATAL_ERROR "Missing third_party/nanobench. Run: git submodule update --init third_party/nanobench")
endif()

function(purify_enable_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4)
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -pedantic)
    endif()
endfunction()

add_library(purify
    src/purify_bppp.cpp
    src/purify_bppp_bridge.c
)

add_library(purify::purify ALIAS purify)
add_library(purify_bppp_support ALIAS purify)

target_compile_features(purify PUBLIC cxx_std_23)

set_target_properties(purify PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS OFF
    CXX_EXTENSIONS OFF
    POSITION_INDEPENDENT_CODE ON
)

target_include_directories(purify
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}"
)

if(NOT MSVC)
    set_source_files_properties(src/purify_bppp_bridge.c PROPERTIES
        COMPILE_OPTIONS "-Wno-unused-function"
    )
endif()

purify_enable_warnings(purify)

install(TARGETS purify
    EXPORT purifyTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(
    FILES
        "${CMAKE_CURRENT_SOURCE_DIR}/include/purify.hpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/include/purify_bppp.hpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/include/purify_secp_bridge.h"
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(
    DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/include/purify"
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

set(PURIFY_INSTALL_CMAKEDIR "${CMAKE_INSTALL_LIBDIR}/cmake/purify")

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/purifyConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/purifyConfig.cmake"
    INSTALL_DESTINATION "${PURIFY_INSTALL_CMAKEDIR}"
    NO_SET_AND_CHECK_MACRO
    NO_CHECK_REQUIRED_COMPONENTS_MACRO
)

install(
    EXPORT purifyTargets
    FILE purifyTargets.cmake
    NAMESPACE purify::
    DESTINATION "${PURIFY_INSTALL_CMAKEDIR}"
)

install(
    FILES "${CMAKE_CURRENT_BINARY_DIR}/purifyConfig.cmake"
    DESTINATION "${PURIFY_INSTALL_CMAKEDIR}"
)

if(PURIFY_BUILD_CLI)
    add_executable(purify_cpp
        cli/main.cpp
    )

    target_include_directories(purify_cpp
        PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}/src"
    )

    target_link_libraries(purify_cpp
        PRIVATE
            purify::purify
    )

    purify_enable_warnings(purify_cpp)
endif()

if(PURIFY_BUILD_BENCH)
    add_subdirectory(third_party/nanobench EXCLUDE_FROM_ALL)

    add_executable(bench_purify
        bench/bench_purify.cpp
    )

    target_link_libraries(bench_purify
        PRIVATE
            purify::purify
            nanobench::nanobench
    )

    purify_enable_warnings(bench_purify)
endif()

if(PURIFY_BUILD_DOCS)
    find_package(Doxygen QUIET)

    if(DOXYGEN_FOUND)
        file(GLOB_RECURSE PURIFY_DOCS_INPUT
            CONFIGURE_DEPENDS
            "${CMAKE_CURRENT_SOURCE_DIR}/include/*.h"
            "${CMAKE_CURRENT_SOURCE_DIR}/include/*.hpp"
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
endif()
