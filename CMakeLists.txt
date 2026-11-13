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

set(PURIFY_HAVE_CLI_SOURCES OFF)
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/cli/main.cpp")
    set(PURIFY_HAVE_CLI_SOURCES ON)
endif()

set(PURIFY_HAVE_BENCH_SOURCES OFF)
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/bench/bench_purify.cpp")
    set(PURIFY_HAVE_BENCH_SOURCES ON)
endif()

set(PURIFY_HAVE_NANOBENCH OFF)
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/nanobench/src/include/nanobench.h")
    set(PURIFY_HAVE_NANOBENCH ON)
endif()

set(PURIFY_HAVE_DOCS_SOURCES OFF)
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in"
   AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/site/doxygen-awesome-custom.css")
    set(PURIFY_HAVE_DOCS_SOURCES ON)
endif()

set(PURIFY_HAVE_TEST_SOURCES OFF)
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/purify_tests.cpp")
    set(PURIFY_HAVE_TEST_SOURCES ON)
endif()

set(PURIFY_HAVE_FUZZ_SOURCES OFF)
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/fuzz/purify_fuzz.cpp")
    set(PURIFY_HAVE_FUZZ_SOURCES ON)
endif()

set(PURIFY_HAVE_CBMC_SOURCES OFF)
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/verification/cbmc/run_cbmc.py")
    set(PURIFY_HAVE_CBMC_SOURCES ON)
endif()

set(PURIFY_BUILD_CLI_DEFAULT OFF)
if(PURIFY_IS_TOP_LEVEL AND PURIFY_HAVE_CLI_SOURCES)
    set(PURIFY_BUILD_CLI_DEFAULT ON)
endif()

set(PURIFY_BUILD_BENCH_DEFAULT OFF)
if(PURIFY_IS_TOP_LEVEL AND PURIFY_HAVE_BENCH_SOURCES AND PURIFY_HAVE_NANOBENCH)
    set(PURIFY_BUILD_BENCH_DEFAULT ON)
endif()

set(PURIFY_BUILD_DOCS_DEFAULT OFF)
if(PURIFY_IS_TOP_LEVEL AND PURIFY_HAVE_DOCS_SOURCES)
    set(PURIFY_BUILD_DOCS_DEFAULT ON)
endif()

set(PURIFY_BUILD_TESTS_DEFAULT OFF)
if(PURIFY_IS_TOP_LEVEL AND PURIFY_HAVE_TEST_SOURCES)
    set(PURIFY_BUILD_TESTS_DEFAULT ON)
endif()

set(PURIFY_BUILD_FUZZ_DEFAULT OFF)
if(PURIFY_IS_TOP_LEVEL AND PURIFY_HAVE_FUZZ_SOURCES)
    set(PURIFY_BUILD_FUZZ_DEFAULT ON)
endif()

option(PURIFY_BUILD_CLI "Build the purify_cpp CLI target." ${PURIFY_BUILD_CLI_DEFAULT})
option(PURIFY_BUILD_BENCH "Build the bench_purify benchmark target." ${PURIFY_BUILD_BENCH_DEFAULT})
option(PURIFY_BUILD_DOCS "Build the Doxygen docs target when Doxygen is available." ${PURIFY_BUILD_DOCS_DEFAULT})
option(PURIFY_BUILD_TESTS "Build the Purify regression test target." ${PURIFY_BUILD_TESTS_DEFAULT})
option(PURIFY_BUILD_FUZZ "Build the deterministic fuzz/stress harness." ${PURIFY_BUILD_FUZZ_DEFAULT})
option(PURIFY_BUILD_REFERENCE_TESTS "Enable Python reference regression tests from reference/purify." OFF)
option(PURIFY_USE_LEGACY_FIELD_HASHES "Use the legacy HKDF-based field-hash path for hash_to_curve and BIP340 key derivation." OFF)
option(PURIFY_ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer on supported compilers." OFF)
set(PURIFY_CXX_STANDARD "23" CACHE STRING
    "C++ standard used to compile Purify targets. Supported values: 20, 23."
)
set_property(CACHE PURIFY_CXX_STANDARD PROPERTY STRINGS 20 23)
set(PURIFY_SANITIZER_LIST "address,undefined" CACHE STRING
    "Comma-separated -fsanitize list used when PURIFY_ENABLE_SANITIZERS=ON."
)
option(PURIFY_BUILD_CBMC "Enable optional CBMC proof harnesses for the pure C wide-integer core." OFF)
option(PURIFY_BUILD_CBMC_EXTENDED "Enable heavier experimental CBMC proofs that are not part of the default CI suite." OFF)
option(PURIFY_BUILD_VALGRIND_TESTS "Enable optional Valgrind-backed memcheck and constant-time tests." OFF)
option(PURIFY_BUILD_CONSTRUCTION_PARENT_VERIFIER
    "Build the transparent construction-parent verifier backend."
    OFF
)
option(PURIFY_BUILD_CONSTRUCTION_PARENT_PROVER
    "Build the purpose-specific construction-parent prover executable."
    OFF
)
set(PURIFY_CONSTRUCTION_PARENT_CARGO_TARGET "" CACHE STRING
    "Optional Rust target triple for construction-parent Rust targets."
)
set(PURIFY_CONSTRUCTION_PARENT_VERIFIER_ARTIFACT "" CACHE FILEPATH
    "Qualified construction-parent verifier artifact for opt-in tests."
)

if(PURIFY_BUILD_CLI AND NOT PURIFY_HAVE_CLI_SOURCES)
    message(FATAL_ERROR "PURIFY_BUILD_CLI=ON requires cli/main.cpp")
endif()

if(PURIFY_BUILD_BENCH AND NOT PURIFY_HAVE_BENCH_SOURCES)
    message(FATAL_ERROR "PURIFY_BUILD_BENCH=ON requires bench/bench_purify.cpp")
endif()

if(PURIFY_BUILD_BENCH AND NOT PURIFY_HAVE_NANOBENCH)
    message(FATAL_ERROR "Missing third_party/nanobench. Run: git submodule update --init third_party/nanobench")
endif()

if(PURIFY_BUILD_DOCS AND NOT PURIFY_HAVE_DOCS_SOURCES)
    message(FATAL_ERROR "PURIFY_BUILD_DOCS=ON requires Doxyfile.in and site/doxygen-awesome-custom.css")
endif()

if(PURIFY_BUILD_TESTS AND NOT PURIFY_HAVE_TEST_SOURCES)
    message(FATAL_ERROR "PURIFY_BUILD_TESTS=ON requires the tests/ source tree")
endif()

if(PURIFY_BUILD_FUZZ AND NOT PURIFY_HAVE_FUZZ_SOURCES)
    message(FATAL_ERROR "PURIFY_BUILD_FUZZ=ON requires fuzz/purify_fuzz.cpp")
endif()

if(PURIFY_BUILD_CBMC AND NOT PURIFY_HAVE_CBMC_SOURCES)
    message(FATAL_ERROR "PURIFY_BUILD_CBMC=ON requires the verification/cbmc/ source tree")
endif()

if(PURIFY_BUILD_REFERENCE_TESTS AND NOT PURIFY_BUILD_TESTS)
    message(FATAL_ERROR "PURIFY_BUILD_REFERENCE_TESTS requires PURIFY_BUILD_TESTS=ON")
endif()

if(PURIFY_BUILD_REFERENCE_TESTS AND NOT PURIFY_BUILD_CLI)
    message(FATAL_ERROR "PURIFY_BUILD_REFERENCE_TESTS requires PURIFY_BUILD_CLI=ON")
endif()

if(PURIFY_BUILD_VALGRIND_TESTS AND NOT PURIFY_BUILD_TESTS)
    message(FATAL_ERROR "PURIFY_BUILD_VALGRIND_TESTS requires PURIFY_BUILD_TESTS=ON")
endif()

if(PURIFY_BUILD_VALGRIND_TESTS AND WIN32)
    message(FATAL_ERROR "PURIFY_BUILD_VALGRIND_TESTS is not supported on Windows")
endif()

if(PURIFY_BUILD_CONSTRUCTION_PARENT_VERIFIER AND
   PURIFY_USE_LEGACY_FIELD_HASHES)
    message(FATAL_ERROR
        "PURIFY_BUILD_CONSTRUCTION_PARENT_VERIFIER requires the modern "
        "tagged field-hash suite."
    )
endif()

if(PURIFY_BUILD_CONSTRUCTION_PARENT_PROVER AND
   PURIFY_USE_LEGACY_FIELD_HASHES)
    message(FATAL_ERROR
        "PURIFY_BUILD_CONSTRUCTION_PARENT_PROVER requires the modern "
        "tagged field-hash suite."
    )
endif()

if(PURIFY_CONSTRUCTION_PARENT_VERIFIER_ARTIFACT)
    if(NOT PURIFY_BUILD_TESTS)
        message(FATAL_ERROR
            "PURIFY_CONSTRUCTION_PARENT_VERIFIER_ARTIFACT requires "
            "PURIFY_BUILD_TESTS=ON."
        )
    endif()
    if(NOT PURIFY_BUILD_CONSTRUCTION_PARENT_VERIFIER)
        message(FATAL_ERROR
            "PURIFY_CONSTRUCTION_PARENT_VERIFIER_ARTIFACT requires "
            "PURIFY_BUILD_CONSTRUCTION_PARENT_VERIFIER=ON."
        )
    endif()
    get_filename_component(
        PURIFY_CONSTRUCTION_PARENT_VERIFIER_ARTIFACT
        "${PURIFY_CONSTRUCTION_PARENT_VERIFIER_ARTIFACT}"
        ABSOLUTE BASE_DIR "${CMAKE_BINARY_DIR}"
    )
    if(NOT EXISTS "${PURIFY_CONSTRUCTION_PARENT_VERIFIER_ARTIFACT}"
       OR IS_DIRECTORY "${PURIFY_CONSTRUCTION_PARENT_VERIFIER_ARTIFACT}")
        message(FATAL_ERROR
            "PURIFY_CONSTRUCTION_PARENT_VERIFIER_ARTIFACT must name an "
            "existing regular file."
        )
    endif()
    file(SIZE "${PURIFY_CONSTRUCTION_PARENT_VERIFIER_ARTIFACT}"
        PURIFY_CONSTRUCTION_PARENT_VERIFIER_ARTIFACT_SIZE)
    if(NOT PURIFY_CONSTRUCTION_PARENT_VERIFIER_ARTIFACT_SIZE EQUAL 693708278)
        message(FATAL_ERROR
            "PURIFY_CONSTRUCTION_PARENT_VERIFIER_ARTIFACT has the wrong "
            "qualified size."
        )
    endif()
    unset(PURIFY_CONSTRUCTION_PARENT_VERIFIER_ARTIFACT_SIZE)
endif()

if(NOT PURIFY_CXX_STANDARD MATCHES "^(20|23)$")
    message(FATAL_ERROR "PURIFY_CXX_STANDARD must be one of: 20, 23")
endif()

if(PURIFY_BUILD_CBMC_EXTENDED AND NOT PURIFY_BUILD_CBMC)
    message(FATAL_ERROR "PURIFY_BUILD_CBMC_EXTENDED requires PURIFY_BUILD_CBMC=ON")
endif()

if(PURIFY_ENABLE_SANITIZERS
   AND PURIFY_SANITIZER_LIST MATCHES "(^|,)integer(,|$)"
   AND NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "PURIFY_SANITIZER_LIST containing 'integer' requires a Clang-family compiler")
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

function(purify_enable_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4)
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -pedantic)
    endif()
endfunction()

function(purify_enable_header_hygiene_warnings)
    foreach(source IN LISTS ARGN)
        if(MSVC)
            set_property(SOURCE "${source}" APPEND PROPERTY COMPILE_OPTIONS /WX)
        else()
            set_property(SOURCE "${source}" APPEND PROPERTY COMPILE_OPTIONS
                -Werror
                -Wredundant-decls
                -Wreturn-type
            )
            if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
                set_property(SOURCE "${source}" APPEND PROPERTY COMPILE_OPTIONS
                    -Wdocumentation
                )
            endif()
            if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
                set_property(SOURCE "${source}" APPEND PROPERTY COMPILE_OPTIONS
                    -Wduplicated-branches
                )
            endif()
        endif()
    endforeach()
endfunction()

function(purify_enable_sanitizers target)
    if(NOT PURIFY_ENABLE_SANITIZERS)
        return()
    endif()

    if(MSVC)
        message(FATAL_ERROR "PURIFY_ENABLE_SANITIZERS requires a compiler with -fsanitize support")
    endif()

    target_compile_options(${target} PRIVATE
        -fno-omit-frame-pointer
        "-fsanitize=${PURIFY_SANITIZER_LIST}"
    )
    target_link_options(${target} PRIVATE
        -fno-omit-frame-pointer
        "-fsanitize=${PURIFY_SANITIZER_LIST}"
    )
endfunction()

if(NOT MSVC)
    set_source_files_properties(src/bridge/bppp_bridge.c PROPERTIES
        COMPILE_OPTIONS "-Wno-unused-function"
    )
    set_source_files_properties(src/legacy_bulletproof/scratch_frames.c PROPERTIES
        COMPILE_OPTIONS "-Wno-unused-function"
    )
    if(PURIFY_ENABLE_SANITIZERS AND PURIFY_SANITIZER_LIST MATCHES "(^|,)integer(,|$)")
        set_property(SOURCE src/bridge/bppp_bridge.c APPEND PROPERTY COMPILE_OPTIONS
            -fno-sanitize=integer
        )
        # The wide-int core intentionally relies on unsigned modular arithmetic.
        set_property(SOURCE src/core/uint.c APPEND PROPERTY COMPILE_OPTIONS
            -fno-sanitize=integer
        )
    endif()
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
    target_compile_features(${target} PUBLIC cxx_std_${PURIFY_CXX_STANDARD})

    set_target_properties(${target} PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        CXX_STANDARD ${PURIFY_CXX_STANDARD}
        CXX_STANDARD_REQUIRED ON
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
    purify_enable_sanitizers(${target})
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
    src/protocol/nonce_batch.cpp
    src/support/curve.cpp
    src/protocol/expr.cpp
    src/legacy_bulletproof/scratch_frames.c
    src/support/numeric.cpp
    src/puresign/legacy.cpp
    src/puresign/codecs/legacy.cpp
    src/puresign/bppp.cpp
    src/puresign/codecs/bppp.cpp
    src/puresign/accountable.cpp
    src/puresign/coalition_formation.cpp
    src/puresign/accountable_roster.cpp
    src/puresign/accountable_responses.cpp
    src/puresign/recovery_root.cpp
    src/puresign/anchor_escrow.cpp
    src/puresign/construction_receipt.cpp
    src/puresign/construction_parent_input.cpp
    src/puresign/construction_parent_prover_input.cpp
    src/protocol/bppp.cpp
    src/protocol/accumulation.cpp
    src/protocol/sha256_transcript.cpp
    src/protocol/sha256_circuit_transcript.cpp
    src/bridge/bppp_bridge.c
)

add_library(purify::purify ALIAS purify)

purify_configure_library_target(purify)

if(PURIFY_BUILD_TESTS)
    target_compile_definitions(purify PRIVATE
        PURIFY_INTERNAL_TEST_SUPPORT=1
    )
endif()

if(PURIFY_BUILD_CONSTRUCTION_PARENT_VERIFIER)
    if(NOT APPLE AND NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
        message(FATAL_ERROR
            "The construction-parent backend is supported only on 64-bit "
            "macOS and Linux."
        )
    endif()
    if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
        message(FATAL_ERROR
            "The construction-parent backend requires a 64-bit target."
        )
    endif()
    if(CMAKE_CROSSCOMPILING AND
       NOT PURIFY_CONSTRUCTION_PARENT_CARGO_TARGET)
        message(FATAL_ERROR
            "Cross-compiling the construction-parent backend requires "
            "PURIFY_CONSTRUCTION_PARENT_CARGO_TARGET."
        )
    endif()
endif()

if(PURIFY_BUILD_CONSTRUCTION_PARENT_PROVER)
    if(NOT CMAKE_SYSTEM_NAME STREQUAL "Darwin" AND
       NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
        message(FATAL_ERROR
            "PURIFY_BUILD_CONSTRUCTION_PARENT_PROVER supports only Darwin "
            "and Linux targets."
        )
    endif()
    if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
        message(FATAL_ERROR
            "The construction-parent prover requires a 64-bit target."
        )
    endif()
    if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        list(LENGTH CMAKE_OSX_ARCHITECTURES
            PURIFY_CONSTRUCTION_PARENT_OSX_ARCH_COUNT)
        if(PURIFY_CONSTRUCTION_PARENT_OSX_ARCH_COUNT GREATER 1)
            message(FATAL_ERROR
                "The construction-parent prover does not support a "
                "multi-architecture CMAKE_OSX_ARCHITECTURES."
            )
        endif()
        unset(PURIFY_CONSTRUCTION_PARENT_OSX_ARCH_COUNT)
        if(CMAKE_OSX_ARCHITECTURES AND
           NOT PURIFY_CONSTRUCTION_PARENT_CARGO_TARGET)
            message(FATAL_ERROR
                "An explicit CMAKE_OSX_ARCHITECTURES requires "
                "PURIFY_CONSTRUCTION_PARENT_CARGO_TARGET for the "
                "construction-parent prover."
            )
        endif()
    endif()
    if(CMAKE_CROSSCOMPILING AND
       NOT PURIFY_CONSTRUCTION_PARENT_CARGO_TARGET)
        message(FATAL_ERROR
            "Cross-compiling the construction-parent prover requires "
            "PURIFY_CONSTRUCTION_PARENT_CARGO_TARGET."
        )
    endif()
endif()

if(PURIFY_BUILD_CONSTRUCTION_PARENT_VERIFIER OR
   PURIFY_BUILD_CONSTRUCTION_PARENT_PROVER)
    find_program(PURIFY_CARGO_EXECUTABLE cargo REQUIRED)
    set(PURIFY_CONSTRUCTION_PARENT_DIR
        "${CMAKE_CURRENT_SOURCE_DIR}/rust/construction-parent"
    )
    file(GLOB_RECURSE PURIFY_CONSTRUCTION_PARENT_RUST_SOURCES
        CONFIGURE_DEPENDS
        "${PURIFY_CONSTRUCTION_PARENT_DIR}/src/*.rs"
    )
endif()

if(PURIFY_BUILD_CONSTRUCTION_PARENT_VERIFIER)
    set(PURIFY_CONSTRUCTION_PARENT_TARGET_DIR
        "${CMAKE_CURRENT_BINARY_DIR}/construction-parent-target"
    )
    set(PURIFY_CONSTRUCTION_PARENT_CARGO_ARGS build --locked --release)
    set(PURIFY_CONSTRUCTION_PARENT_LIBRARY_DIR
        "${PURIFY_CONSTRUCTION_PARENT_TARGET_DIR}/release"
    )
    if(PURIFY_CONSTRUCTION_PARENT_CARGO_TARGET)
        list(APPEND PURIFY_CONSTRUCTION_PARENT_CARGO_ARGS
            --target "${PURIFY_CONSTRUCTION_PARENT_CARGO_TARGET}"
        )
        set(PURIFY_CONSTRUCTION_PARENT_LIBRARY_DIR
            "${PURIFY_CONSTRUCTION_PARENT_TARGET_DIR}/${PURIFY_CONSTRUCTION_PARENT_CARGO_TARGET}/release"
        )
    endif()
    set(PURIFY_CONSTRUCTION_PARENT_LIBRARY
        "${PURIFY_CONSTRUCTION_PARENT_LIBRARY_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}purify_construction_parent${CMAKE_SHARED_LIBRARY_SUFFIX}"
    )
    set(PURIFY_CONSTRUCTION_PARENT_VALIDATION_STAMP
        "${PURIFY_CONSTRUCTION_PARENT_TARGET_DIR}/backend.validated"
    )
    # The shared Purify library resolves its private backend dependency. Static
    # Purify consumers resolve the same dependency in their own link step.
    set_property(TARGET purify APPEND PROPERTY
        BUILD_RPATH "${PURIFY_CONSTRUCTION_PARENT_LIBRARY_DIR}"
    )
    if(APPLE)
        set_property(TARGET purify APPEND PROPERTY
            INSTALL_RPATH "@loader_path"
        )
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        set_property(TARGET purify APPEND PROPERTY
            INSTALL_RPATH "$ORIGIN"
        )
    endif()
    # Keep static-Purify build-tree executables runnable without exposing an
    # absolute backend path through the installed target interface.
    list(APPEND CMAKE_BUILD_RPATH
        "${PURIFY_CONSTRUCTION_PARENT_LIBRARY_DIR}"
    )
    set(PURIFY_CONSTRUCTION_PARENT_CARGO_ENV
        --unset=MAKEFLAGS
        --unset=MFLAGS
        --unset=CARGO_MAKEFLAGS
        "CARGO_INCREMENTAL=0"
        "CARGO_TARGET_DIR=${PURIFY_CONSTRUCTION_PARENT_TARGET_DIR}"
    )
    if(APPLE AND CMAKE_OSX_DEPLOYMENT_TARGET)
        list(APPEND PURIFY_CONSTRUCTION_PARENT_CARGO_ENV
            "MACOSX_DEPLOYMENT_TARGET=${CMAKE_OSX_DEPLOYMENT_TARGET}"
        )
    endif()
    set(PURIFY_CONSTRUCTION_PARENT_VALIDATE_ARGS
        "-DBACKEND_LIBRARY=${PURIFY_CONSTRUCTION_PARENT_LIBRARY}"
        "-DBACKEND_NM=${CMAKE_NM}"
        "-DBACKEND_APPLE=${APPLE}"
    )
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        if(CMAKE_READELF)
            set(PURIFY_READELF_EXECUTABLE "${CMAKE_READELF}")
        else()
            find_program(PURIFY_READELF_EXECUTABLE
                NAMES llvm-readelf readelf
                REQUIRED
            )
        endif()
        list(APPEND PURIFY_CONSTRUCTION_PARENT_VALIDATE_ARGS
            "-DBACKEND_READELF=${PURIFY_READELF_EXECUTABLE}"
            "-DBACKEND_SONAME=${CMAKE_SHARED_LIBRARY_PREFIX}purify_construction_parent${CMAKE_SHARED_LIBRARY_SUFFIX}"
        )
    endif()
    if(APPLE)
        if(CMAKE_INSTALL_NAME_TOOL AND
           EXISTS "${CMAKE_INSTALL_NAME_TOOL}")
            set(PURIFY_INSTALL_NAME_TOOL_EXECUTABLE
                "${CMAKE_INSTALL_NAME_TOOL}"
            )
        else()
            find_program(PURIFY_INSTALL_NAME_TOOL_EXECUTABLE
                NAMES llvm-install-name-tool install_name_tool
                REQUIRED
                NO_CACHE
            )
        endif()
        set(PURIFY_CONSTRUCTION_PARENT_POST_BUILD
            COMMAND "${PURIFY_INSTALL_NAME_TOOL_EXECUTABLE}"
                -id "@rpath/${CMAKE_SHARED_LIBRARY_PREFIX}purify_construction_parent${CMAKE_SHARED_LIBRARY_SUFFIX}"
                "${PURIFY_CONSTRUCTION_PARENT_LIBRARY}"
        )
    endif()
    add_custom_command(
        OUTPUT "${PURIFY_CONSTRUCTION_PARENT_LIBRARY}"
        COMMAND "${CMAKE_COMMAND}" -E env
            ${PURIFY_CONSTRUCTION_PARENT_CARGO_ENV}
            "${PURIFY_CARGO_EXECUTABLE}" ${PURIFY_CONSTRUCTION_PARENT_CARGO_ARGS}
        ${PURIFY_CONSTRUCTION_PARENT_POST_BUILD}
        DEPENDS
            "${PURIFY_CONSTRUCTION_PARENT_DIR}/Cargo.lock"
            "${PURIFY_CONSTRUCTION_PARENT_DIR}/Cargo.toml"
            "${PURIFY_CONSTRUCTION_PARENT_DIR}/build.rs"
            "${PURIFY_CONSTRUCTION_PARENT_DIR}/rust-toolchain.toml"
            ${PURIFY_CONSTRUCTION_PARENT_RUST_SOURCES}
        WORKING_DIRECTORY "${PURIFY_CONSTRUCTION_PARENT_DIR}"
        COMMENT "Building transparent construction-parent verifier backend"
        VERBATIM
    )
    add_custom_command(
        OUTPUT "${PURIFY_CONSTRUCTION_PARENT_VALIDATION_STAMP}"
        COMMAND "${CMAKE_COMMAND}" -E rm -f
            "${PURIFY_CONSTRUCTION_PARENT_VALIDATION_STAMP}"
        COMMAND "${CMAKE_COMMAND}"
            ${PURIFY_CONSTRUCTION_PARENT_VALIDATE_ARGS}
            -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/ValidateConstructionParentBackend.cmake"
        COMMAND "${CMAKE_COMMAND}" -E touch
            "${PURIFY_CONSTRUCTION_PARENT_VALIDATION_STAMP}"
        DEPENDS
            "${PURIFY_CONSTRUCTION_PARENT_LIBRARY}"
            "${CMAKE_CURRENT_SOURCE_DIR}/cmake/ValidateConstructionParentBackend.cmake"
        COMMENT "Validating construction-parent verifier backend"
        VERBATIM
    )
    unset(PURIFY_CONSTRUCTION_PARENT_CARGO_ENV)
    unset(PURIFY_CONSTRUCTION_PARENT_POST_BUILD)
    unset(PURIFY_CONSTRUCTION_PARENT_VALIDATE_ARGS)
    unset(PURIFY_READELF_EXECUTABLE)
    add_custom_target(purify_construction_parent_backend_build
        DEPENDS "${PURIFY_CONSTRUCTION_PARENT_VALIDATION_STAMP}"
    )
    unset(PURIFY_CONSTRUCTION_PARENT_VALIDATION_STAMP)
    add_library(purify_construction_parent_backend SHARED IMPORTED GLOBAL)
    set_target_properties(purify_construction_parent_backend PROPERTIES
        IMPORTED_LOCATION "${PURIFY_CONSTRUCTION_PARENT_LIBRARY}"
    )
    add_dependencies(purify_construction_parent_backend
        purify_construction_parent_backend_build
    )
    target_link_libraries(purify PRIVATE
        purify_construction_parent_backend
    )
    target_sources(purify PRIVATE
        src/puresign/construction_parent_verifier.cpp
    )
    target_compile_definitions(purify PUBLIC
        PURIFY_HAS_CONSTRUCTION_PARENT_VERIFIER=1
    )
    install(FILES "${PURIFY_CONSTRUCTION_PARENT_LIBRARY}"
        DESTINATION ${CMAKE_INSTALL_LIBDIR}
    )
endif()

if(PURIFY_BUILD_CONSTRUCTION_PARENT_PROVER)
    set(PURIFY_CONSTRUCTION_PARENT_PROVER_SOURCE
        "${PURIFY_CONSTRUCTION_PARENT_DIR}/src/bin/purify-construction-parent-prover.rs"
    )
    if(NOT EXISTS "${PURIFY_CONSTRUCTION_PARENT_PROVER_SOURCE}")
        message(FATAL_ERROR
            "PURIFY_BUILD_CONSTRUCTION_PARENT_PROVER requires "
            "${PURIFY_CONSTRUCTION_PARENT_PROVER_SOURCE}."
        )
    endif()
    set(PURIFY_CONSTRUCTION_PARENT_PROVER_TARGET_DIR
        "${CMAKE_CURRENT_BINARY_DIR}/construction-parent-prover-target"
    )
    set(PURIFY_CONSTRUCTION_PARENT_PROVER_CARGO_ARGS
        build
        --locked
        --release
        --no-default-features
        --features prover
        --bin purify-construction-parent-prover
    )
    set(PURIFY_CONSTRUCTION_PARENT_PROVER_DIR
        "${PURIFY_CONSTRUCTION_PARENT_PROVER_TARGET_DIR}/release"
    )
    if(PURIFY_CONSTRUCTION_PARENT_CARGO_TARGET)
        list(APPEND PURIFY_CONSTRUCTION_PARENT_PROVER_CARGO_ARGS
            --target "${PURIFY_CONSTRUCTION_PARENT_CARGO_TARGET}"
        )
        set(PURIFY_CONSTRUCTION_PARENT_PROVER_DIR
            "${PURIFY_CONSTRUCTION_PARENT_PROVER_TARGET_DIR}/${PURIFY_CONSTRUCTION_PARENT_CARGO_TARGET}/release"
        )
    endif()
    set(PURIFY_CONSTRUCTION_PARENT_PROVER
        "${PURIFY_CONSTRUCTION_PARENT_PROVER_DIR}/purify-construction-parent-prover${CMAKE_EXECUTABLE_SUFFIX}"
    )
    set(PURIFY_CONSTRUCTION_PARENT_PROVER_CARGO_ENV
        --unset=MAKEFLAGS
        --unset=MFLAGS
        --unset=CARGO_MAKEFLAGS
        "CARGO_INCREMENTAL=0"
        "CARGO_TARGET_DIR=${PURIFY_CONSTRUCTION_PARENT_PROVER_TARGET_DIR}"
    )
    if(APPLE AND CMAKE_OSX_DEPLOYMENT_TARGET)
        list(APPEND PURIFY_CONSTRUCTION_PARENT_PROVER_CARGO_ENV
            "MACOSX_DEPLOYMENT_TARGET=${CMAKE_OSX_DEPLOYMENT_TARGET}"
        )
    endif()
    add_custom_command(
        OUTPUT "${PURIFY_CONSTRUCTION_PARENT_PROVER}"
        COMMAND "${CMAKE_COMMAND}" -E env
            ${PURIFY_CONSTRUCTION_PARENT_PROVER_CARGO_ENV}
            "${PURIFY_CARGO_EXECUTABLE}"
            ${PURIFY_CONSTRUCTION_PARENT_PROVER_CARGO_ARGS}
        DEPENDS
            "${PURIFY_CONSTRUCTION_PARENT_DIR}/Cargo.lock"
            "${PURIFY_CONSTRUCTION_PARENT_DIR}/Cargo.toml"
            "${PURIFY_CONSTRUCTION_PARENT_DIR}/build.rs"
            "${PURIFY_CONSTRUCTION_PARENT_DIR}/rust-toolchain.toml"
            ${PURIFY_CONSTRUCTION_PARENT_RUST_SOURCES}
        WORKING_DIRECTORY "${PURIFY_CONSTRUCTION_PARENT_DIR}"
        COMMENT "Building purpose-specific construction-parent prover"
        VERBATIM
    )
    add_custom_target(purify_construction_parent_prover ALL
        DEPENDS "${PURIFY_CONSTRUCTION_PARENT_PROVER}"
    )
    install(PROGRAMS "${PURIFY_CONSTRUCTION_PARENT_PROVER}"
        DESTINATION "${CMAKE_INSTALL_BINDIR}"
        COMPONENT construction_parent_prover
    )
    unset(PURIFY_CONSTRUCTION_PARENT_PROVER_CARGO_ENV)
endif()

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
    PATH_VARS CMAKE_INSTALL_LIBDIR
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
    purify_enable_sanitizers(purify_cpp)
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
        src/protocol/nonce_batch.cpp
        src/support/curve.cpp
        src/protocol/expr.cpp
        src/legacy_bulletproof/scratch_frames.c
        src/support/numeric.cpp
        src/puresign/legacy.cpp
        src/puresign/codecs/legacy.cpp
        src/puresign/bppp.cpp
        src/puresign/codecs/bppp.cpp
        src/puresign/accountable.cpp
        src/puresign/coalition_formation.cpp
        src/puresign/accountable_roster.cpp
        src/puresign/accountable_responses.cpp
        src/puresign/recovery_root.cpp
        src/puresign/anchor_escrow.cpp
        src/puresign/construction_receipt.cpp
        src/puresign/construction_parent_input.cpp
        src/puresign/construction_parent_prover_input.cpp
        src/protocol/bppp.cpp
        src/protocol/accumulation.cpp
        src/protocol/sha256_transcript.cpp
        src/protocol/sha256_circuit_transcript.cpp
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
    purify_enable_sanitizers(bench_purify)
    purify_enable_release_optimizations(bench_purify)

    add_executable(bench_norm_accumulation bench/bench_norm_accumulation.cpp)
    target_link_libraries(bench_norm_accumulation PRIVATE purify_bench_support)
    purify_enable_warnings(bench_norm_accumulation)
    purify_enable_sanitizers(bench_norm_accumulation)
    purify_enable_release_optimizations(bench_norm_accumulation)
    add_executable(bench_aggregate_nonce bench/bench_aggregate_nonce.cpp)
    target_link_libraries(bench_aggregate_nonce PRIVATE purify::purify)
    purify_enable_warnings(bench_aggregate_nonce)
    purify_enable_sanitizers(bench_aggregate_nonce)

    add_executable(bench_nonce_batch bench/bench_nonce_batch.cpp)
    target_link_libraries(bench_nonce_batch PRIVATE purify::purify)
    purify_enable_warnings(bench_nonce_batch)
    purify_enable_sanitizers(bench_nonce_batch)
endif()

if(PURIFY_BUILD_TESTS OR PURIFY_BUILD_CBMC)
    enable_testing()
endif()

if(PURIFY_BUILD_VALGRIND_TESTS)
    find_program(PURIFY_VALGRIND_EXECUTABLE valgrind REQUIRED)
    find_path(PURIFY_VALGRIND_INCLUDE_DIR valgrind/memcheck.h REQUIRED)
    set(PURIFY_VALGRIND_COMMON_ARGS
        --tool=memcheck
        --error-exitcode=1
        --undef-value-errors=yes
        --leak-check=full
        --show-leak-kinds=all
        --errors-for-leak-kinds=all
        --track-origins=yes
    )

    function(purify_add_valgrind_test name target)
        add_test(
            NAME ${name}
            COMMAND "${PURIFY_VALGRIND_EXECUTABLE}" ${PURIFY_VALGRIND_COMMON_ARGS} $<TARGET_FILE:${target}> ${ARGN}
        )
        set_tests_properties(${name} PROPERTIES TIMEOUT 900)
    endfunction()
endif()

if(PURIFY_BUILD_TESTS)
    if((APPLE OR CMAKE_SYSTEM_NAME STREQUAL "Linux") AND
       CMAKE_SIZEOF_VOID_P EQUAL 8 AND
       NOT CMAKE_CROSSCOMPILING)
        add_test(NAME purify.tests.construction_parent_prover_package
            COMMAND "${CMAKE_COMMAND}"
                "-DTEST_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
                "-DTEST_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}"
                "-DTEST_GENERATOR=${CMAKE_GENERATOR}"
                "-DTEST_GENERATOR_PLATFORM=${CMAKE_GENERATOR_PLATFORM}"
                "-DTEST_GENERATOR_TOOLSET=${CMAKE_GENERATOR_TOOLSET}"
                "-DTEST_BUILD_TYPE=${CMAKE_BUILD_TYPE}"
                "-DTEST_CONFIG=$<CONFIG>"
                "-DTEST_C_COMPILER=${CMAKE_C_COMPILER}"
                "-DTEST_CXX_COMPILER=${CMAKE_CXX_COMPILER}"
                "-DTEST_SYSTEM_NAME=${CMAKE_SYSTEM_NAME}"
                "-DTEST_SYSTEM_PROCESSOR=${CMAKE_SYSTEM_PROCESSOR}"
                "-DTEST_INSTALL_BINDIR=${CMAKE_INSTALL_BINDIR}"
                "-DTEST_EXECUTABLE_SUFFIX=${CMAKE_EXECUTABLE_SUFFIX}"
                -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/construction_parent_prover_package/run.cmake"
        )
        set_tests_properties(
            purify.tests.construction_parent_prover_package
            PROPERTIES RUN_SERIAL TRUE TIMEOUT 120
        )
    endif()

    add_executable(purify_opening_base_vector_tests
        tests/opening_base_vector_tests.cpp
    )
    target_link_libraries(purify_opening_base_vector_tests
        PRIVATE purify::purify
    )
    purify_enable_warnings(purify_opening_base_vector_tests)
    purify_enable_sanitizers(purify_opening_base_vector_tests)
    add_test(NAME purify.tests.opening_base_vector
        COMMAND purify_opening_base_vector_tests
    )

    set(PURIFY_HEADER_HYGIENE_SOURCES
        tests/public_header_hygiene_c_then_cpp.cpp
        tests/public_header_hygiene_cpp_then_c.cpp
    )

    add_executable(purify_tests
        tests/purify_tests_main.cpp
        tests/purify_tests.cpp
        tests/puresign_tests.cpp
        tests/legacy_bulletproof_tests.cpp
        tests/expected_tests.cpp
        tests/secure_cleanup_tests.cpp
        tests/norm_protocol_tests.cpp
        tests/norm_accumulation_tests.cpp
        tests/accountable_signature_tests.cpp
        tests/coalition_formation_tests.cpp
        tests/accountable_roster_tests.cpp
        tests/accountable_response_tests.cpp
        tests/slashability_e2e_fixture.cpp
        tests/slashability_e2e_tests.cpp
        tests/canonical_recovery_root_tests.cpp
        tests/canonical_recovery_root_helpers.cpp
        tests/recovery_root_share_tests.cpp
        tests/recovery_root_contribution_tests.cpp
        tests/anchor_escrow_tests.cpp
        tests/companion_scalar_escrow_tests.cpp
        tests/companion_scalar_escrow_helpers.cpp
        tests/construction_receipt_codec_tests.cpp
        tests/aggregate_nonce_tests.cpp
        tests/nonce_batch_tests.cpp
        tests/nonce_certificate_tests.cpp
        tests/circuit_soundness_tests.cpp
        tests/sha256_transcript_tests.cpp
        tests/sha256_circuit_transcript_tests.cpp
        ${PURIFY_HEADER_HYGIENE_SOURCES}
    )

    target_link_libraries(purify_tests
        PRIVATE
            purify::purify
    )

    target_include_directories(purify_tests PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src/support"
    )

    purify_enable_warnings(purify_tests)
    purify_enable_sanitizers(purify_tests)
    purify_enable_header_hygiene_warnings(${PURIFY_HEADER_HYGIENE_SOURCES})
    target_compile_definitions(purify_tests PRIVATE
        "PURIFY_TEST_CONSTRUCTION_PARENT_WIT3_PATH=\"${CMAKE_CURRENT_SOURCE_DIR}/tests/vectors/construction_parent_sha256_accepted.wit3\""
        "PURIFY_TEST_CONSTRUCTION_PARENT_NONDECIDING_WIT3_PATH=\"${CMAKE_CURRENT_SOURCE_DIR}/tests/vectors/construction_parent_sha256_nondeciding.wit3\""
    )

    if(PURIFY_BUILD_CONSTRUCTION_PARENT_VERIFIER)
        target_compile_definitions(purify_tests PRIVATE
            "PURIFY_TEST_CONSTRUCTION_PARENT_PROOF_PATH=\"${CMAKE_CURRENT_SOURCE_DIR}/tests/vectors/construction_parent_sha256_accepted.proof\""
            "PURIFY_TEST_CONSTRUCTION_PARENT_NONDECIDING_PROOF_PATH=\"${CMAKE_CURRENT_SOURCE_DIR}/tests/vectors/construction_parent_sha256_nondeciding.proof\""
        )
        if(PURIFY_CONSTRUCTION_PARENT_VERIFIER_ARTIFACT)
            target_compile_definitions(purify_tests PRIVATE
                PURIFY_TEST_REQUIRES_CONSTRUCTION_PARENT_ARTIFACT=1
            )
        endif()
        if(NOT CMAKE_CROSSCOMPILING)
            add_test(NAME purify.tests.installed_package
                COMMAND "${CMAKE_COMMAND}"
                    "-DTEST_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}"
                    "-DTEST_GENERATOR=${CMAKE_GENERATOR}"
                    "-DTEST_GENERATOR_PLATFORM=${CMAKE_GENERATOR_PLATFORM}"
                    "-DTEST_GENERATOR_TOOLSET=${CMAKE_GENERATOR_TOOLSET}"
                    "-DTEST_BUILD_TYPE=${CMAKE_BUILD_TYPE}"
                    "-DTEST_CONFIG=$<CONFIG>"
                    "-DTEST_CXX_COMPILER=${CMAKE_CXX_COMPILER}"
                    "-DTEST_BACKEND_RELATIVE_PATH=${CMAKE_INSTALL_LIBDIR}/${CMAKE_SHARED_LIBRARY_PREFIX}purify_construction_parent${CMAKE_SHARED_LIBRARY_SUFFIX}"
                    -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/installed_package/run.cmake"
            )
            set_tests_properties(purify.tests.installed_package
                PROPERTIES RUN_SERIAL TRUE TIMEOUT 300
            )
            add_test(NAME purify.tests.absolute_install_libdir_config
                COMMAND "${CMAKE_COMMAND}"
                    "-DTEST_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
                    "-DTEST_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}"
                    "-DTEST_GENERATOR=${CMAKE_GENERATOR}"
                    "-DTEST_GENERATOR_PLATFORM=${CMAKE_GENERATOR_PLATFORM}"
                    "-DTEST_GENERATOR_TOOLSET=${CMAKE_GENERATOR_TOOLSET}"
                    "-DTEST_BUILD_TYPE=${CMAKE_BUILD_TYPE}"
                    "-DTEST_CXX_COMPILER=${CMAKE_CXX_COMPILER}"
                    "-DTEST_SHARED_LIBRARY_PREFIX=${CMAKE_SHARED_LIBRARY_PREFIX}"
                    "-DTEST_SHARED_LIBRARY_SUFFIX=${CMAKE_SHARED_LIBRARY_SUFFIX}"
                    -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/installed_package/absolute_libdir.cmake"
            )
            set_tests_properties(
                purify.tests.absolute_install_libdir_config
                PROPERTIES RUN_SERIAL TRUE TIMEOUT 120
            )
        endif()

        get_target_property(PURIFY_TEST_LIBRARY_TYPE purify TYPE)
        if(UNIX AND CMAKE_NM AND
           PURIFY_TEST_LIBRARY_TYPE STREQUAL "SHARED_LIBRARY")
            add_test(NAME purify.tests.private_construction_parent_symbols
                COMMAND "${CMAKE_COMMAND}"
                    "-DTEST_NM=${CMAKE_NM}"
                    "-DTEST_LIBRARY=$<TARGET_FILE:purify>"
                    -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/shared_symbol_visibility.cmake"
            )
        endif()
        unset(PURIFY_TEST_LIBRARY_TYPE)
    endif()

    function(purify_add_cpp_suite_test suite_name)
        add_test(NAME "purify.tests.${suite_name}" COMMAND purify_tests --suite "${suite_name}")
    endfunction()

    purify_add_cpp_suite_test(core)
    purify_add_cpp_suite_test(puresign)
    purify_add_cpp_suite_test(legacy_bulletproof)
    purify_add_cpp_suite_test(expected)
    purify_add_cpp_suite_test(secure_cleanup)
    purify_add_cpp_suite_test(norm_protocol)
    purify_add_cpp_suite_test(norm_accumulation)
    purify_add_cpp_suite_test(circuit_soundness)
    find_package(Python3 COMPONENTS Interpreter QUIET)
    if(Python3_Interpreter_FOUND)
        add_test(NAME purify.tests.opening_base_reference
            COMMAND "${Python3_EXECUTABLE}"
                "${CMAKE_CURRENT_SOURCE_DIR}/tests/reference_opening_base.py")
        set_tests_properties(purify.tests.opening_base_reference
            PROPERTIES TIMEOUT 30)
        add_test(NAME purify.tests.norm_accumulation_reference
            COMMAND "${Python3_EXECUTABLE}"
                "${CMAKE_CURRENT_SOURCE_DIR}/tests/reference_norm_accumulation.py")
        set_tests_properties(purify.tests.norm_accumulation_reference PROPERTIES TIMEOUT 30)
        add_test(NAME purify.tests.sha256_accumulation_reference
            COMMAND "${Python3_EXECUTABLE}"
                "${CMAKE_CURRENT_SOURCE_DIR}/tests/reference_sha256_accumulation.py")
        set_tests_properties(purify.tests.sha256_accumulation_reference
            PROPERTIES TIMEOUT 30)
        add_test(NAME purify.tests.sha256_transcript_reference
            COMMAND "${Python3_EXECUTABLE}"
                "${CMAKE_CURRENT_SOURCE_DIR}/tests/reference_sha256_transcript.py")
        set_tests_properties(purify.tests.sha256_transcript_reference
            PROPERTIES TIMEOUT 30)
        add_test(NAME purify.tests.sha256_circuit_v4_reference
            COMMAND "${Python3_EXECUTABLE}"
                "${CMAKE_CURRENT_SOURCE_DIR}/tests/reference_sha256_circuit_v4.py")
        set_tests_properties(purify.tests.sha256_circuit_v4_reference
            PROPERTIES TIMEOUT 30)
        add_test(NAME purify.tests.coalition_formation_reference
            COMMAND "${Python3_EXECUTABLE}"
                "${CMAKE_CURRENT_SOURCE_DIR}/tests/reference_coalition_formation.py")
        set_tests_properties(purify.tests.coalition_formation_reference
            PROPERTIES TIMEOUT 30)
    endif()
    purify_add_cpp_suite_test(accountable_signature)
    purify_add_cpp_suite_test(coalition_formation)
    purify_add_cpp_suite_test(accountable_roster)
    purify_add_cpp_suite_test(accountable_response)
    purify_add_cpp_suite_test(slashability_native)
    purify_add_cpp_suite_test(canonical_recovery_root)
    purify_add_cpp_suite_test(recovery_root_share)
    purify_add_cpp_suite_test(recovery_root_contribution)
    purify_add_cpp_suite_test(anchor_escrow)
    purify_add_cpp_suite_test(companion_scalar_escrow)
    purify_add_cpp_suite_test(construction_receipt_codec)
    purify_add_cpp_suite_test(sha256_transcript)
    purify_add_cpp_suite_test(sha256_circuit_transcript)

    # These proof suites saturate sanitizer runners. Keep their work
    # out of the property suites' bounded execution time.
    set_tests_properties(
        purify.tests.slashability_native
        PROPERTIES RUN_SERIAL TRUE
    )
    if(PURIFY_BUILD_CONSTRUCTION_PARENT_VERIFIER AND
       PURIFY_CONSTRUCTION_PARENT_VERIFIER_ARTIFACT)
        purify_add_cpp_suite_test(slashability_e2e)
        set_tests_properties(purify.tests.slashability_e2e PROPERTIES
            ENVIRONMENT
                "PURIFY_CONSTRUCTION_PARENT_VERIFIER_ARTIFACT=${PURIFY_CONSTRUCTION_PARENT_VERIFIER_ARTIFACT}"
            RUN_SERIAL TRUE
            TIMEOUT 3600
        )
    endif()
    purify_add_cpp_suite_test(aggregate_nonce)
    purify_add_cpp_suite_test(aggregate_nonce_100)
    purify_add_cpp_suite_test(nonce_batch)
    purify_add_cpp_suite_test(nonce_certificate)

    add_executable(purify_property_tests
        tests/purify_property_tests.cpp
    )

    target_link_libraries(purify_property_tests
        PRIVATE
            purify::purify
    )

    purify_enable_warnings(purify_property_tests)
    purify_enable_sanitizers(purify_property_tests)

    function(purify_add_property_suite_test suite_name)
        add_test(NAME "purify.property.${suite_name}" COMMAND purify_property_tests --suite "${suite_name}")
        if(PURIFY_ENABLE_SANITIZERS)
            set_tests_properties("purify.property.${suite_name}" PROPERTIES TIMEOUT 900)
        else()
            set_tests_properties("purify.property.${suite_name}" PROPERTIES TIMEOUT 300)
        endif()
    endfunction()

    purify_add_property_suite_test(key_and_circuit)
    purify_add_property_suite_test(experimental)
    purify_add_property_suite_test(split_eval)
    purify_add_property_suite_test(assume_valid_proof)
    purify_add_property_suite_test(puresign)
    purify_add_property_suite_test(puresign_plusplus)

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
    purify_enable_sanitizers(purify_c_tests)

    add_test(NAME purify.c_api COMMAND purify_c_tests)

    if(PURIFY_BUILD_VALGRIND_TESTS)
        target_compile_definitions(purify PRIVATE PURIFY_VALGRIND_TESTING=1)
        target_include_directories(purify PRIVATE
            "${PURIFY_VALGRIND_INCLUDE_DIR}"
        )

        add_executable(purify_valgrind_tests
            tests/purify_valgrind_tests.c
        )

        target_link_libraries(purify_valgrind_tests
            PRIVATE
                purify::purify
        )

        target_include_directories(purify_valgrind_tests PRIVATE
            "${PURIFY_VALGRIND_INCLUDE_DIR}"
        )

        target_compile_definitions(purify_valgrind_tests PRIVATE
            PURIFY_VALGRIND_TESTING=1
        )

        set_target_properties(purify_valgrind_tests PROPERTIES
            LINKER_LANGUAGE CXX
        )

        purify_enable_warnings(purify_valgrind_tests)

        purify_add_valgrind_test(purify.valgrind.c_api purify_c_tests)
        purify_add_valgrind_test(purify.valgrind.consttime_divmod purify_valgrind_tests divmod)
        purify_add_valgrind_test(purify.valgrind.consttime_ladder purify_valgrind_tests ladder)
        purify_add_valgrind_test(purify.valgrind.consttime_affine purify_valgrind_tests affine)
        purify_add_valgrind_test(purify.valgrind.consttime_inverse purify_valgrind_tests inverse)
        purify_add_valgrind_test(purify.valgrind.consttime_packed_secret purify_valgrind_tests packed_secret)
        purify_add_valgrind_test(purify.valgrind.consttime_uint purify_valgrind_tests uint)
        purify_add_valgrind_test(purify.valgrind.consttime_bppp purify_valgrind_tests bppp)
    endif()

    if(PURIFY_BUILD_BENCH)
        add_test(NAME purify.bench COMMAND bench_purify --epochs 1 --min-epoch-ms 1)
        # Proof suites can saturate the runner; isolate benchmark smoke work
        # so its time limit does not measure contention with other tests.
        set_tests_properties(purify.bench PROPERTIES TIMEOUT 900 RUN_SERIAL TRUE)
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

if(PURIFY_BUILD_CBMC)
    find_program(PURIFY_CBMC_EXECUTABLE cbmc REQUIRED)
    find_package(Python3 COMPONENTS Interpreter REQUIRED)

    set(PURIFY_CBMC_INCLUDE_ARGS
        "-I${CMAKE_CURRENT_SOURCE_DIR}"
        "-I${CMAKE_CURRENT_SOURCE_DIR}/include"
        "-I${CMAKE_CURRENT_SOURCE_DIR}/src/core"
    )
    set(PURIFY_CBMC_COMMON_ARGS
        --c11
        --bounds-check
        --pointer-check
        --pointer-overflow-check
        --div-by-zero-check
        --signed-overflow-check
        --unwinding-assertions
    )

    add_custom_target(purify_cbmc)

    function(purify_add_cbmc_proof name harness unwind)
        cmake_parse_arguments(PURIFY_CBMC_PROOF "" "" "SOURCES;DEFINES" ${ARGN})

        set(proof_target "purify_cbmc_${name}")
        set(proof_test "purify.cbmc.${name}")
        set(proof_sources "${CMAKE_CURRENT_SOURCE_DIR}/${harness}")
        set(proof_cbmc_args)

        foreach(source IN LISTS PURIFY_CBMC_PROOF_SOURCES)
            list(APPEND proof_sources "${CMAKE_CURRENT_SOURCE_DIR}/${source}")
        endforeach()

        list(APPEND proof_cbmc_args ${proof_sources})
        list(APPEND proof_cbmc_args
            --function main
            --unwind "${unwind}"
            ${PURIFY_CBMC_COMMON_ARGS}
            ${PURIFY_CBMC_INCLUDE_ARGS}
        )

        foreach(define IN LISTS PURIFY_CBMC_PROOF_DEFINES)
            list(APPEND proof_cbmc_args "-D${define}")
        endforeach()

        add_custom_target(${proof_target}
            COMMAND
                "${Python3_EXECUTABLE}"
                "${CMAKE_CURRENT_SOURCE_DIR}/verification/cbmc/run_cbmc.py"
                --name "${proof_test}"
                --cbmc "${PURIFY_CBMC_EXECUTABLE}"
                --
                ${proof_cbmc_args}
            WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
            USES_TERMINAL
            VERBATIM
        )
        add_dependencies(purify_cbmc ${proof_target})

        add_test(
            NAME "${proof_test}"
            COMMAND
                "${Python3_EXECUTABLE}"
                "${CMAKE_CURRENT_SOURCE_DIR}/verification/cbmc/run_cbmc.py"
                --name "${proof_test}"
                --cbmc "${PURIFY_CBMC_EXECUTABLE}"
                --
                ${proof_cbmc_args}
        )
        set_tests_properties("${proof_test}" PROPERTIES TIMEOUT 300)
    endfunction()

    purify_add_cbmc_proof(
        core_validate_secret_key_contract
        verification/cbmc/core_validate_secret_key_contract_harness.c
        90
        SOURCES
            verification/cbmc/secp_bridge_small_field.c
            src/core/core.c
    )
    purify_add_cbmc_proof(
        core_validate_public_key_contract
        verification/cbmc/core_validate_public_key_contract_harness.c
        90
        SOURCES
            verification/cbmc/secp_bridge_small_field.c
            src/core/core.c
    )
    purify_add_cbmc_proof(
        u256_bytes_roundtrip
        verification/cbmc/u256_bytes_roundtrip_harness.c
        64
        SOURCES
            src/core/uint.c
    )
    purify_add_cbmc_proof(
        u256_add_sub_inverse
        verification/cbmc/u256_add_sub_inverse_harness.c
        32
        SOURCES
            src/core/uint.c
    )
    purify_add_cbmc_proof(
        u256_shift_roundtrip
        verification/cbmc/u256_shift_roundtrip_harness.c
        32
        SOURCES
            src/core/uint.c
    )
    purify_add_cbmc_proof(
        u256_widen_narrow
        verification/cbmc/u256_widen_narrow_harness.c
        32
        SOURCES
            src/core/uint.c
    )
    purify_add_cbmc_proof(
        u512_divmod_same
        verification/cbmc/u512_divmod_same_harness.c
        600
        SOURCES
            src/core/uint.c
    )
    purify_add_cbmc_proof(
        u512_divmod_same_equivalence
        verification/cbmc/u512_divmod_same_equivalence_harness.c
        700
        SOURCES
            src/core/uint.c
    )
    purify_add_cbmc_proof(
        field_encoding_boundaries
        verification/cbmc/field_encoding_boundaries_harness.c
        120
        SOURCES
            verification/cbmc/secp_bridge_small_field.c
            src/core/uint.c
            src/core/field.c
        DEFINES
            PURIFY_CBMC_MODEL_SMALL_FIELD=1
    )
    purify_add_cbmc_proof(
        field_local_identities
        verification/cbmc/field_local_identities_harness.c
        220
        SOURCES
            verification/cbmc/secp_bridge_small_field.c
            src/core/uint.c
            src/core/field.c
        DEFINES
            PURIFY_CBMC_MODEL_SMALL_FIELD=1
    )
    purify_add_cbmc_proof(
        field_inverse_equivalence
        verification/cbmc/field_inverse_equivalence_harness.c
        180
        SOURCES
            verification/cbmc/secp_bridge_small_field.c
            src/core/uint.c
            src/core/field.c
        DEFINES
            PURIFY_CBMC_MODEL_SMALL_FIELD=1
    )
    purify_add_cbmc_proof(
        curve_lift_x_contract
        verification/cbmc/curve_lift_x_contract_harness.c
        260
        SOURCES
            verification/cbmc/secp_bridge_small_field.c
            src/core/uint.c
            src/core/field.c
            src/core/curve.c
        DEFINES
            PURIFY_CBMC_MODEL_SMALL_FIELD=1
    )
    purify_add_cbmc_proof(
        curve_group_laws
        verification/cbmc/curve_group_laws_harness.c
        320
        SOURCES
            verification/cbmc/secp_bridge_small_field.c
            src/core/uint.c
            src/core/field.c
            src/core/curve.c
        DEFINES
            PURIFY_CBMC_MODEL_SMALL_FIELD=1
    )
    purify_add_cbmc_proof(
        curve_affine_negate_contract
        verification/cbmc/curve_affine_negate_contract_harness.c
        260
        SOURCES
            verification/cbmc/secp_bridge_small_field.c
            src/core/uint.c
            src/core/field.c
            src/core/curve.c
        DEFINES
            PURIFY_CBMC_MODEL_SMALL_FIELD=1
    )
    purify_add_cbmc_proof(
        curve_add_mixed_equivalence
        verification/cbmc/curve_add_mixed_equivalence_harness.c
        360
        SOURCES
            verification/cbmc/secp_bridge_small_field.c
            src/core/uint.c
            src/core/field.c
            src/core/curve.c
        DEFINES
            PURIFY_CBMC_MODEL_SMALL_FIELD=1
    )
    purify_add_cbmc_proof(
        curve_double_in_place
        verification/cbmc/curve_double_in_place_harness.c
        340
        SOURCES
            verification/cbmc/secp_bridge_small_field.c
            src/core/uint.c
            src/core/field.c
            src/core/curve.c
        DEFINES
            PURIFY_CBMC_MODEL_SMALL_FIELD=1
    )
    purify_add_cbmc_proof(
        curve_secret_mul_consistency
        verification/cbmc/curve_secret_mul_consistency_harness.c
        260
        SOURCES
            verification/cbmc/secp_bridge_small_field.c
            src/core/uint.c
            src/core/field.c
            src/core/curve.c
        DEFINES
            PURIFY_CBMC_MODEL_SMALL_FIELD=1
    )
    purify_add_cbmc_proof(
        curve_secret_mul_zero_reject
        verification/cbmc/curve_secret_mul_zero_reject_harness.c
        220
        SOURCES
            verification/cbmc/secp_bridge_small_field.c
            src/core/uint.c
            src/core/field.c
            src/core/curve.c
        DEFINES
            PURIFY_CBMC_MODEL_SMALL_FIELD=1
    )
    purify_add_cbmc_proof(
        curve_secret_mul_one_identity
        verification/cbmc/curve_secret_mul_one_identity_harness.c
        220
        SOURCES
            verification/cbmc/secp_bridge_small_field.c
            src/core/uint.c
            src/core/field.c
            src/core/curve.c
        DEFINES
            PURIFY_CBMC_MODEL_SMALL_FIELD=1
    )
    purify_add_cbmc_proof(
        curve_secret_mul_checked_unchecked_equivalence
        verification/cbmc/curve_secret_mul_checked_unchecked_equivalence_harness.c
        360
        SOURCES
            verification/cbmc/secp_bridge_small_field.c
            src/core/uint.c
            src/core/field.c
            src/core/curve.c
        DEFINES
            PURIFY_CBMC_MODEL_SMALL_FIELD=1
            PURIFY_CBMC_TESTING=1
    )
    purify_add_cbmc_proof(
        curve_combine_point_average
        verification/cbmc/curve_combine_point_average_harness.c
        360
        SOURCES
            verification/cbmc/secp_bridge_small_field.c
            src/core/uint.c
            src/core/field.c
            src/core/curve.c
        DEFINES
            PURIFY_CBMC_MODEL_SMALL_FIELD=1
    )
    purify_add_cbmc_proof(
        curve_hash_to_curve_contract
        verification/cbmc/curve_hash_to_curve_contract_harness.c
        220
        SOURCES
            verification/cbmc/secp_bridge_small_field.c
            src/core/uint.c
            src/core/field.c
            src/core/curve.c
        DEFINES
            PURIFY_CBMC_MODEL_SMALL_FIELD=1
    )
    purify_add_cbmc_proof(
        curve_key_to_bits_roundtrip
        verification/cbmc/curve_key_to_bits_roundtrip_harness.c
        200
        SOURCES
            verification/cbmc/secp_bridge_small_field.c
            src/core/uint.c
            src/core/field.c
            src/core/curve.c
        DEFINES
            PURIFY_CBMC_MODEL_SMALL_FIELD=1
    )
    purify_add_cbmc_proof(
        curve_pack_public_roundtrip
        verification/cbmc/curve_pack_public_roundtrip_harness.c
        160
        SOURCES
            verification/cbmc/secp_bridge_small_field.c
            src/core/uint.c
            src/core/field.c
            src/core/curve.c
        DEFINES
            PURIFY_CBMC_MODEL_SMALL_FIELD=1
    )
    purify_add_cbmc_proof(
        curve_unpack_public_inverse
        verification/cbmc/curve_unpack_public_inverse_harness.c
        180
        SOURCES
            verification/cbmc/secp_bridge_small_field.c
            src/core/uint.c
            src/core/field.c
            src/core/curve.c
        DEFINES
            PURIFY_CBMC_MODEL_SMALL_FIELD=1
    )
    purify_add_cbmc_proof(
        curve_unpack_secret_roundtrip
        verification/cbmc/curve_unpack_secret_roundtrip_harness.c
        700
        SOURCES
            verification/cbmc/secp_bridge_small_field.c
            src/core/uint.c
            src/core/field.c
            src/core/curve.c
        DEFINES
            PURIFY_CBMC_MODEL_SMALL_FIELD=1
    )
    purify_add_cbmc_proof(
        curve_unpack_secret_inverse
        verification/cbmc/curve_unpack_secret_inverse_harness.c
        700
        SOURCES
            verification/cbmc/secp_bridge_small_field.c
            src/core/uint.c
            src/core/field.c
            src/core/curve.c
        DEFINES
            PURIFY_CBMC_MODEL_SMALL_FIELD=1
    )
    purify_add_cbmc_proof(
        curve_unpack_secret_unchecked_roundtrip
        verification/cbmc/curve_unpack_secret_unchecked_roundtrip_harness.c
        700
        SOURCES
            verification/cbmc/secp_bridge_small_field.c
            src/core/uint.c
            src/core/field.c
            src/core/curve.c
        DEFINES
            PURIFY_CBMC_MODEL_SMALL_FIELD=1
            PURIFY_CBMC_TESTING=1
    )
    if(PURIFY_BUILD_CBMC_EXTENDED)
        purify_add_cbmc_proof(
            curve_valid_packed_secret_public1_derivation_equivalence
            verification/cbmc/curve_valid_packed_secret_public1_derivation_equivalence_harness.c
            700
            SOURCES
                verification/cbmc/secp_bridge_small_field.c
                src/core/uint.c
                src/core/field.c
                src/core/curve.c
            DEFINES
                PURIFY_CBMC_MODEL_SMALL_FIELD=1
                PURIFY_CBMC_TESTING=1
        )
        purify_add_cbmc_proof(
            curve_valid_packed_secret_public2_derivation_equivalence
            verification/cbmc/curve_valid_packed_secret_public2_derivation_equivalence_harness.c
            700
            SOURCES
                verification/cbmc/secp_bridge_small_field.c
                src/core/uint.c
                src/core/field.c
                src/core/curve.c
            DEFINES
                PURIFY_CBMC_MODEL_SMALL_FIELD=1
                PURIFY_CBMC_TESTING=1
        )
    endif()
    purify_add_cbmc_proof(
        curve_key_space_invariants
        verification/cbmc/curve_key_space_invariants_harness.c
        700
        SOURCES
            verification/cbmc/secp_bridge_small_field.c
            src/core/uint.c
            src/core/field.c
            src/core/curve.c
        DEFINES
            PURIFY_CBMC_MODEL_SMALL_FIELD=1
    )
    purify_add_cbmc_proof(
        curve_invalid_key_rejection
        verification/cbmc/curve_invalid_key_rejection_harness.c
        120
        SOURCES
            verification/cbmc/secp_bridge_small_field.c
            src/core/uint.c
            src/core/field.c
            src/core/curve.c
        DEFINES
            PURIFY_CBMC_MODEL_SMALL_FIELD=1
    )
    purify_add_cbmc_proof(
        hash_to_curve_generator1_point
        verification/cbmc/hash_to_curve_generator1_point_harness.c
        140
        SOURCES
            verification/cbmc/secp_bridge_small_field.c
            src/core/uint.c
            src/core/field.c
            src/core/curve.c
        DEFINES
            PURIFY_CBMC_MODEL_SMALL_FIELD=1
    )
    purify_add_cbmc_proof(
        hash_to_curve_generator2_point
        verification/cbmc/hash_to_curve_generator2_point_harness.c
        140
        SOURCES
            verification/cbmc/secp_bridge_small_field.c
            src/core/uint.c
            src/core/field.c
            src/core/curve.c
        DEFINES
            PURIFY_CBMC_MODEL_SMALL_FIELD=1
    )
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
    purify_enable_sanitizers(purify_fuzz)
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
