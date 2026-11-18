foreach(required IN ITEMS
        TEST_SOURCE_DIR
        TEST_BINARY_DIR
        TEST_GENERATOR
        TEST_C_COMPILER
        TEST_CXX_COMPILER
        TEST_SYSTEM_NAME
        TEST_SYSTEM_PROCESSOR
        TEST_INSTALL_BINDIR
        TEST_EXECUTABLE_SUFFIX)
    if(NOT DEFINED ${required} OR "${${required}}" STREQUAL "")
        if("${required}" STREQUAL "TEST_EXECUTABLE_SUFFIX" AND
           DEFINED TEST_EXECUTABLE_SUFFIX)
            continue()
        endif()
        message(FATAL_ERROR "missing prover-package input: ${required}")
    endif()
endforeach()

set(test_root "${TEST_BINARY_DIR}/construction-parent-prover-package")
set(off_binary "${test_root}/off")
set(on_binary "${test_root}/on")
set(verifier_binary "${test_root}/verifier")
set(both_binary "${test_root}/both")
set(cross_binary "${test_root}/cross")
set(unsupported_binary "${test_root}/unsupported")
set(prefix "${test_root}/prefix")
file(REMOVE_RECURSE "${test_root}")

set(fake_cargo "${test_root}/fake-cargo")
set(cargo_args_log "${test_root}/cargo-args")
set(cargo_target_log "${test_root}/cargo-target-dir")
file(MAKE_DIRECTORY "${test_root}")
file(WRITE "${fake_cargo}"
    "#!/bin/sh\n"
    "set -eu\n"
    "printf '%s\\n' \"$@\" > \"${cargo_args_log}\"\n"
    "printf '%s\\n' \"$CARGO_TARGET_DIR\" > \"${cargo_target_log}\"\n"
    "mkdir -p \"$CARGO_TARGET_DIR/release\"\n"
    "printf '#!/bin/sh\\nexit 0\\n' > "
        "\"$CARGO_TARGET_DIR/release/"
        "purify-construction-parent-prover${TEST_EXECUTABLE_SUFFIX}\"\n"
    "chmod +x \"$CARGO_TARGET_DIR/release/"
        "purify-construction-parent-prover${TEST_EXECUTABLE_SUFFIX}\"\n"
)
file(CHMOD "${fake_cargo}"
    PERMISSIONS
        OWNER_READ OWNER_WRITE OWNER_EXECUTE
        GROUP_READ GROUP_EXECUTE
        WORLD_READ WORLD_EXECUTE
)

function(run_configure binary_dir build_prover build_verifier
         result_variable output_variable)
    set(configure_command
        "${CMAKE_COMMAND}"
        -S "${TEST_SOURCE_DIR}"
        -B "${binary_dir}"
        -G "${TEST_GENERATOR}"
        "-DCMAKE_C_COMPILER=${TEST_C_COMPILER}"
        "-DCMAKE_CXX_COMPILER=${TEST_CXX_COMPILER}"
        "-DCMAKE_BUILD_TYPE=${TEST_BUILD_TYPE}"
        -DBUILD_SHARED_LIBS=ON
        -DPURIFY_BUILD_TESTS=OFF
        -DPURIFY_BUILD_CLI=OFF
        -DPURIFY_BUILD_BENCH=OFF
        -DPURIFY_BUILD_DOCS=OFF
        -DPURIFY_BUILD_FUZZ=OFF
        "-DPURIFY_CARGO_EXECUTABLE=${fake_cargo}"
        "-DPURIFY_BUILD_CONSTRUCTION_PARENT_VERIFIER=${build_verifier}"
    )
    if(NOT "${build_prover}" STREQUAL "DEFAULT")
        list(APPEND configure_command
            "-DPURIFY_BUILD_CONSTRUCTION_PARENT_PROVER=${build_prover}"
        )
    endif()
    list(APPEND configure_command ${ARGN})
    if(DEFINED TEST_GENERATOR_PLATFORM AND
       NOT "${TEST_GENERATOR_PLATFORM}" STREQUAL "")
        list(APPEND configure_command -A "${TEST_GENERATOR_PLATFORM}")
    endif()
    if(DEFINED TEST_GENERATOR_TOOLSET AND
       NOT "${TEST_GENERATOR_TOOLSET}" STREQUAL "")
        list(APPEND configure_command -T "${TEST_GENERATOR_TOOLSET}")
    endif()
    execute_process(
        COMMAND ${configure_command}
        RESULT_VARIABLE configure_result
        OUTPUT_VARIABLE configure_stdout
        ERROR_VARIABLE configure_stderr
    )
    set(${result_variable} "${configure_result}" PARENT_SCOPE)
    set(${output_variable}
        "${configure_stdout}${configure_stderr}" PARENT_SCOPE)
endfunction()

function(configure_case binary_dir build_prover build_verifier)
    run_configure("${binary_dir}" "${build_prover}" "${build_verifier}"
        configure_result configure_output ${ARGN})
    if(NOT configure_result EQUAL 0)
        message(FATAL_ERROR
            "construction-parent prover ${build_prover}, verifier "
            "${build_verifier} configure failed:\n${configure_output}"
        )
    endif()
endfunction()

function(require_configure_failure binary_dir build_prover build_verifier
         expected_error)
    run_configure("${binary_dir}" "${build_prover}" "${build_verifier}"
        configure_result configure_output ${ARGN})
    if(configure_result EQUAL 0)
        message(FATAL_ERROR
            "configuration unexpectedly accepted: ${expected_error}"
        )
    endif()
    string(FIND "${configure_output}" "${expected_error}" error_position)
    if(error_position EQUAL -1)
        message(FATAL_ERROR
            "configuration did not report '${expected_error}':\n"
            "${configure_output}"
        )
    endif()
endfunction()

function(require_missing_prover binary_dir description)
    execute_process(
        COMMAND "${CMAKE_COMMAND}" --build "${binary_dir}"
            --target purify_construction_parent_prover
        RESULT_VARIABLE build_result
        OUTPUT_QUIET
        ERROR_QUIET
    )
    if(build_result EQUAL 0)
        message(FATAL_ERROR "${description} exposes the prover target")
    endif()
    if(EXISTS "${binary_dir}/construction-parent-prover-target")
        message(FATAL_ERROR "${description} created a prover target dir")
    endif()
    file(READ "${binary_dir}/cmake_install.cmake" install_script)
    string(FIND "${install_script}"
        "CMAKE_INSTALL_COMPONENT STREQUAL \"construction_parent_prover\""
        component_position)
    if(NOT component_position EQUAL -1)
        message(FATAL_ERROR "${description} installs the prover")
    endif()
endfunction()

configure_case("${off_binary}" DEFAULT OFF)
file(STRINGS "${off_binary}/CMakeCache.txt" prover_cache
    REGEX "^PURIFY_BUILD_CONSTRUCTION_PARENT_PROVER:BOOL=")
if(NOT "${prover_cache}" STREQUAL
   "PURIFY_BUILD_CONSTRUCTION_PARENT_PROVER:BOOL=OFF")
    message(FATAL_ERROR "construction-parent prover is not default OFF")
endif()
require_missing_prover("${off_binary}" "default configuration")

configure_case("${verifier_binary}" OFF ON)
require_missing_prover("${verifier_binary}" "verifier-only configuration")

require_configure_failure(
    "${unsupported_binary}" ON OFF
    "supports only Darwin"
    "-DCMAKE_SYSTEM_NAME=Generic"
    -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY
)
require_configure_failure(
    "${cross_binary}" ON OFF
    "Cross-compiling the construction-parent prover"
    "-DCMAKE_SYSTEM_NAME=${TEST_SYSTEM_NAME}"
    -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY
)

if(TEST_SYSTEM_NAME STREQUAL "Darwin")
    set(single_arch_binary "${test_root}/single-arch")
    set(multi_arch_binary "${test_root}/multi-arch")
    set(multi_arch_cache "${test_root}/multi-arch-cache.cmake")
    if(TEST_SYSTEM_PROCESSOR STREQUAL "arm64")
        set(other_architecture x86_64)
    else()
        set(other_architecture arm64)
    endif()
    file(WRITE "${multi_arch_cache}"
        "set(CMAKE_OSX_ARCHITECTURES "
        "\"${TEST_SYSTEM_PROCESSOR};${other_architecture}\" "
        "CACHE STRING \"\")\n"
    )
    require_configure_failure(
        "${single_arch_binary}" ON OFF
        "An explicit CMAKE_OSX_ARCHITECTURES requires"
        "-DCMAKE_OSX_ARCHITECTURES=${TEST_SYSTEM_PROCESSOR}"
    )
    require_configure_failure(
        "${multi_arch_binary}" ON OFF
        "does not support a multi-architecture"
        -C "${multi_arch_cache}"
        -DPURIFY_CONSTRUCTION_PARENT_CARGO_TARGET=aarch64-apple-darwin
    )
endif()

configure_case("${both_binary}" ON ON)
file(READ "${both_binary}/cmake_install.cmake" both_install)
foreach(target_dir IN ITEMS
        construction-parent-target
        construction-parent-prover-target)
    string(FIND "${both_install}" "/${target_dir}/" target_dir_position)
    if(target_dir_position EQUAL -1)
        message(FATAL_ERROR
            "both-enabled install omits ${target_dir}"
        )
    endif()
endforeach()

configure_case("${on_binary}" ON OFF)
execute_process(
    COMMAND "${CMAKE_COMMAND}" --build "${on_binary}"
        --target purify_construction_parent_prover
    RESULT_VARIABLE prover_build_result
)
if(NOT prover_build_result EQUAL 0)
    message(FATAL_ERROR "fake construction-parent prover build failed")
endif()
file(STRINGS "${cargo_args_log}" cargo_args)
set(expected_cargo_args
    build
    --locked
    --release
    --no-default-features
    --features
    prover
    --bin
    purify-construction-parent-prover
)
if(NOT "${cargo_args}" STREQUAL "${expected_cargo_args}")
    message(FATAL_ERROR
        "prover Cargo arguments are '${cargo_args}', expected "
        "'${expected_cargo_args}'"
    )
endif()
file(READ "${cargo_target_log}" cargo_target_dir)
string(STRIP "${cargo_target_dir}" cargo_target_dir)
set(expected_target_dir
    "${on_binary}/construction-parent-prover-target")
if(NOT "${cargo_target_dir}" STREQUAL "${expected_target_dir}")
    message(FATAL_ERROR
        "prover Cargo target is '${cargo_target_dir}', expected "
        "'${expected_target_dir}'"
    )
endif()
if(EXISTS "${on_binary}/construction-parent-target")
    message(FATAL_ERROR "prover-only configuration created a verifier target dir")
endif()

set(prover_name
    "purify-construction-parent-prover${TEST_EXECUTABLE_SUFFIX}")

set(install_command
    "${CMAKE_COMMAND}" --install "${on_binary}"
    --prefix "${prefix}"
    --component construction_parent_prover
)
if(DEFINED TEST_CONFIG AND NOT "${TEST_CONFIG}" STREQUAL "")
    list(APPEND install_command --config "${TEST_CONFIG}")
endif()
execute_process(
    COMMAND ${install_command}
    RESULT_VARIABLE install_result
)
if(NOT install_result EQUAL 0)
    message(FATAL_ERROR "prover component installation failed")
endif()

file(GLOB_RECURSE installed_files
    LIST_DIRECTORIES FALSE
    RELATIVE "${prefix}"
    "${prefix}/*"
)
set(expected_file "${TEST_INSTALL_BINDIR}/${prover_name}")
if(NOT "${installed_files}" STREQUAL "${expected_file}")
    message(FATAL_ERROR
        "prover component installed '${installed_files}', expected "
        "'${expected_file}'"
    )
endif()
