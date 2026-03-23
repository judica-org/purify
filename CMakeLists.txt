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

get_property(PURIFY_IS_MULTI_CONFIG GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)

option(PURIFY_BUILD_CLI "Build the purify_cpp CLI target." ${PURIFY_IS_TOP_LEVEL})
option(PURIFY_BUILD_BENCH "Build the bench_purify benchmark target." ${PURIFY_IS_TOP_LEVEL})
option(PURIFY_BUILD_DOCS "Build the Doxygen docs target when Doxygen is available." ${PURIFY_IS_TOP_LEVEL})
option(PURIFY_BUILD_TESTS "Build the Purify regression test target." ${PURIFY_IS_TOP_LEVEL})
option(PURIFY_BUILD_FUZZ "Build the deterministic fuzz/stress harness." ${PURIFY_IS_TOP_LEVEL})
option(PURIFY_BUILD_REFERENCE_TESTS "Enable Python reference regression tests from reference/purify." OFF)
option(PURIFY_USE_LEGACY_FIELD_HASHES "Use the legacy HKDF-based field-hash path for hash_to_curve and BIP340 key derivation." OFF)

if(PURIFY_BUILD_REFERENCE_TESTS AND NOT PURIFY_BUILD_TESTS)
    message(FATAL_ERROR "PURIFY_BUILD_REFERENCE_TESTS requires PURIFY_BUILD_TESTS=ON")
endif()

if(PURIFY_BUILD_REFERENCE_TESTS AND NOT PURIFY_BUILD_CLI)
    message(FATAL_ERROR "PURIFY_BUILD_REFERENCE_TESTS requires PURIFY_BUILD_CLI=ON")
endif()

if(PURIFY_IS_TOP_LEVEL AND NOT PURIFY_IS_MULTI_CONFIG)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS Debug Release RelWithDebInfo MinSizeRel)
    if(PURIFY_BUILD_BENCH AND NOT CMAKE_BUILD_TYPE)
        message(STATUS "Setting build type to Release because bench_purify should be built in Release")
        set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build." FORCE)
    endif()
endif()

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

if(NOT MSVC)
    set_source_files_properties(src/bridge/bppp_bridge.c PROPERTIES
        COMPILE_OPTIONS "-Wno-unused-function"
    )
    set_source_files_properties(src/legacy_bulletproof/scratch_frames.c PROPERTIES
        COMPILE_OPTIONS "-Wno-unused-function"
    )
endif()

if(MSVC)
    # `purify_bppp_bridge.c` directly compiles vendored secp256k1-zkp sources,
    # which trigger a large number of benign narrowing/constant-expression
    # diagnostics under MSVC. Keep warnings enabled for our own code and
    # suppress the known third-party warnings only for this translation unit.
    set_property(SOURCE src/bridge/bppp_bridge.c APPEND PROPERTY COMPILE_OPTIONS
        /wd4127
        /wd4146
        /wd4244
        /wd4267
        /wd4310
    )

    # Visual Studio generators do not reliably honor target-wide
    # `$<COMPILE_LANGUAGE:C>` options for mixed C/C++ targets, so attach the
    # C11 atomics flag directly to the source that includes `<stdatomic.h>`.
    set_property(SOURCE src/legacy_bulletproof/scratch_frames.c APPEND PROPERTY COMPILE_OPTIONS
        /experimental:c11atomics
    )
endif()

function(purify_configure_library_target target)
    target_compile_features(${target} PUBLIC cxx_std_23)

    set_target_properties(${target} PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
        CXX_EXTENSIONS OFF
        POSITION_INDEPENDENT_CODE ON
    )

    target_include_directories(${target}
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
            $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
        PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/core"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/api"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/support"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/protocol"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/bridge"
    )

    if(PURIFY_USE_LEGACY_FIELD_HASHES)
        target_compile_definitions(${target} PUBLIC PURIFY_USE_LEGACY_FIELD_HASHES=1)
    else()
        target_compile_definitions(${target} PUBLIC PURIFY_USE_LEGACY_FIELD_HASHES=0)
    endif()

    purify_enable_warnings(${target})
endfunction()

function(purify_enable_release_optimizations target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /O2)
    else()
        target_compile_options(${target} PRIVATE -O3)
    endif()

    target_compile_definitions(${target} PRIVATE NDEBUG)
endfunction()

add_library(purify
    src/core/core.c
    src/core/curve.c
    src/core/field.c
    src/core/uint.c
    src/api/c_api.cpp
    src/api/api.cpp
    src/protocol/bulletproof.cpp
    src/support/curve.cpp
    src/protocol/expr.cpp
    src/legacy_bulletproof/scratch_frames.c
    src/support/numeric.cpp
    src/puresign/legacy.cpp
    src/puresign/codecs/legacy.cpp
    src/puresign/bppp.cpp
    src/puresign/codecs/bppp.cpp
    src/protocol/bppp.cpp
    src/bridge/bppp_bridge.c
)

add_library(purify::purify ALIAS purify)
add_library(purify_bppp_support ALIAS purify)

purify_configure_library_target(purify)

if(WIN32)
    target_link_libraries(purify PUBLIC bcrypt)
endif()

install(TARGETS purify
    EXPORT purifyTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(
    FILES
        "${CMAKE_CURRENT_SOURCE_DIR}/include/purify.hpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/include/purify.h"
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

    target_link_libraries(purify_cpp
        PRIVATE
            purify::purify
    )

    purify_enable_warnings(purify_cpp)
endif()

if(PURIFY_BUILD_BENCH)
    add_subdirectory(third_party/nanobench EXCLUDE_FROM_ALL)

    add_library(purify_bench_support STATIC
        src/core/core.c
        src/core/curve.c
        src/core/field.c
        src/core/uint.c
        src/api/c_api.cpp
        src/api/api.cpp
        src/protocol/bulletproof.cpp
        src/support/curve.cpp
        src/protocol/expr.cpp
        src/legacy_bulletproof/scratch_frames.c
        src/support/numeric.cpp
        src/puresign/legacy.cpp
        src/puresign/codecs/legacy.cpp
        src/puresign/bppp.cpp
        src/puresign/codecs/bppp.cpp
        src/protocol/bppp.cpp
        src/bridge/bppp_bridge.c
    )

    purify_configure_library_target(purify_bench_support)
    purify_enable_release_optimizations(purify_bench_support)
    purify_enable_release_optimizations(nanobench)

    if(PURIFY_IS_MULTI_CONFIG)
        set(PURIFY_BENCH_BUILD_CONFIG_EXPR "$<CONFIG>")
        set(PURIFY_BENCH_IS_RELEASE_EXPR "$<IF:$<CONFIG:Release>,1,0>")
    else()
        if(CMAKE_BUILD_TYPE)
            set(PURIFY_BENCH_BUILD_CONFIG_EXPR "${CMAKE_BUILD_TYPE}")
        else()
            set(PURIFY_BENCH_BUILD_CONFIG_EXPR "unspecified")
        endif()

        if(CMAKE_BUILD_TYPE STREQUAL "Release")
            set(PURIFY_BENCH_IS_RELEASE_EXPR 1)
        else()
            set(PURIFY_BENCH_IS_RELEASE_EXPR 0)
        endif()
    endif()

    add_executable(bench_purify
        bench/bench_purify.cpp
    )

    target_link_libraries(bench_purify
        PRIVATE
            purify_bench_support
            nanobench::nanobench
    )

    target_compile_definitions(bench_purify
        PRIVATE
            PURIFY_BENCH_BUILD_CONFIG="${PURIFY_BENCH_BUILD_CONFIG_EXPR}"
            PURIFY_BENCH_IS_RELEASE=${PURIFY_BENCH_IS_RELEASE_EXPR}
    )

    purify_enable_warnings(bench_purify)
    purify_enable_release_optimizations(bench_purify)
endif()

if(PURIFY_BUILD_TESTS)
    enable_testing()

    add_executable(purify_tests
        tests/purify_tests_main.cpp
        tests/purify_tests.cpp
        tests/puresign_tests.cpp
        tests/legacy_bulletproof_tests.cpp
    )

    target_link_libraries(purify_tests
        PRIVATE
            purify::purify
    )

    purify_enable_warnings(purify_tests)

    add_test(NAME purify.tests COMMAND purify_tests)

    add_executable(purify_property_tests
        tests/purify_property_tests.cpp
    )

    target_link_libraries(purify_property_tests
        PRIVATE
            purify::purify
    )

    purify_enable_warnings(purify_property_tests)

    add_test(NAME purify.property_tests COMMAND purify_property_tests)
    set_tests_properties(purify.property_tests PROPERTIES TIMEOUT 300)

    add_executable(purify_c_tests
        tests/purify_c_tests.c
    )

    target_link_libraries(purify_c_tests
        PRIVATE
            purify::purify
    )

    set_target_properties(purify_c_tests PROPERTIES
        LINKER_LANGUAGE CXX
    )

    purify_enable_warnings(purify_c_tests)

    add_test(NAME purify.c_api COMMAND purify_c_tests)

    if(PURIFY_BUILD_BENCH)
        add_test(NAME purify.bench COMMAND bench_purify --epochs 1 --min-epoch-ms 1)
        set_tests_properties(purify.bench PROPERTIES TIMEOUT 300)
    endif()

    if(PURIFY_BUILD_FUZZ)
        add_test(NAME purify.fuzz_smoke COMMAND purify_fuzz --seed 1 --iterations 1 --proof-every 1)
        set_tests_properties(purify.fuzz_smoke PROPERTIES TIMEOUT 300)
    endif()

    if(PURIFY_BUILD_REFERENCE_TESTS)
        set(PURIFY_REFERENCE_PYTHON_SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/reference/purify/purify.py")
        set(PURIFY_REFERENCE_PATCHES_DIR "${CMAKE_CURRENT_SOURCE_DIR}/patches/reference_purify")
        if(NOT EXISTS "${PURIFY_REFERENCE_PYTHON_SCRIPT}")
            message(FATAL_ERROR
                "Missing reference/purify/purify.py. Run: git submodule update --init --depth 1 reference/purify"
            )
        endif()

        find_package(Python3 COMPONENTS Interpreter REQUIRED)

        if(PURIFY_USE_LEGACY_FIELD_HASHES)
            set(PURIFY_REFERENCE_HASH_MODE "legacy")
        else()
            set(PURIFY_REFERENCE_HASH_MODE "tagged")
        endif()

        add_test(
            NAME purify.reference_circuit
            COMMAND
                "${Python3_EXECUTABLE}"
                "${CMAKE_CURRENT_SOURCE_DIR}/tests/reference_circuit_regression.py"
                --reference-script "${PURIFY_REFERENCE_PYTHON_SCRIPT}"
                --reference-patches-dir "${PURIFY_REFERENCE_PATCHES_DIR}"
                --purify-cpp "$<TARGET_FILE:purify_cpp>"
                --hash-mode "${PURIFY_REFERENCE_HASH_MODE}"
        )
        set_tests_properties(purify.reference_circuit PROPERTIES TIMEOUT 300)
    endif()
endif()

if(PURIFY_BUILD_FUZZ)
    add_executable(purify_fuzz
        fuzz/purify_fuzz.cpp
    )

    target_link_libraries(purify_fuzz
        PRIVATE
            purify::purify
    )

    purify_enable_warnings(purify_fuzz)
    purify_enable_release_optimizations(purify_fuzz)
endif()

if(PURIFY_BUILD_DOCS)
    find_package(Doxygen QUIET)

    if(DOXYGEN_FOUND)
        set(PURIFY_DOXYGEN_AWESOME_CSS "" CACHE STRING "Optional path to doxygen-awesome.css for themed docs")
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
            "${CMAKE_CURRENT_SOURCE_DIR}/fuzz/*.cpp"
        )

        set(PURIFY_DOXYGEN_OUTPUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/docs")
        set(PURIFY_DOXYGEN_CONFIG "${CMAKE_CURRENT_BINARY_DIR}/Doxyfile")
        set(PURIFY_DOXYGEN_INDEX "${PURIFY_DOXYGEN_OUTPUT_DIR}/html/index.html")
        set(PURIFY_DOXYGEN_CUSTOM_CSS "${CMAKE_CURRENT_SOURCE_DIR}/site/doxygen-awesome-custom.css")
        set(PURIFY_DOXYGEN_HTML_COLORSTYLE "LIGHT")
        set(PURIFY_DOXYGEN_HTML_COLORSTYLE_HUE "193")
        set(PURIFY_DOXYGEN_HTML_COLORSTYLE_SAT "110")
        set(PURIFY_DOXYGEN_HTML_COLORSTYLE_GAMMA "108")
        set(PURIFY_DOXYGEN_STYLE_DEPENDS "${PURIFY_DOXYGEN_CUSTOM_CSS}")

        if(PURIFY_DOXYGEN_AWESOME_CSS)
            set(PURIFY_DOXYGEN_HTML_EXTRA_STYLESHEET
                "${PURIFY_DOXYGEN_AWESOME_CSS} ${PURIFY_DOXYGEN_CUSTOM_CSS}"
            )
            list(APPEND PURIFY_DOXYGEN_STYLE_DEPENDS "${PURIFY_DOXYGEN_AWESOME_CSS}")
        else()
            set(PURIFY_DOXYGEN_HTML_EXTRA_STYLESHEET "${PURIFY_DOXYGEN_CUSTOM_CSS}")
        endif()

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
                ${PURIFY_DOXYGEN_STYLE_DEPENDS}
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
