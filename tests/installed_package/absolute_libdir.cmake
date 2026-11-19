foreach(required IN ITEMS
        TEST_SOURCE_DIR
        TEST_BINARY_DIR
        TEST_GENERATOR
        TEST_CXX_COMPILER
        TEST_SHARED_LIBRARY_SUFFIX)
    if(NOT DEFINED ${required} OR "${${required}}" STREQUAL "")
        message(FATAL_ERROR "missing absolute-libdir input: ${required}")
    endif()
endforeach()

set(test_build "${TEST_BINARY_DIR}/absolute-libdir-config")
set(test_libdir "${TEST_BINARY_DIR}/absolute-package-lib")
file(REMOVE_RECURSE "${test_build}" "${test_libdir}")

set(configure_command
    "${CMAKE_COMMAND}"
    -S "${TEST_SOURCE_DIR}"
    -B "${test_build}"
    -G "${TEST_GENERATOR}"
    "-DCMAKE_CXX_COMPILER=${TEST_CXX_COMPILER}"
    "-DCMAKE_INSTALL_LIBDIR=${test_libdir}"
    -DBUILD_SHARED_LIBS=ON
    -DPURIFY_BUILD_TESTS=OFF
    -DPURIFY_BUILD_CONSTRUCTION_PARENT_VERIFIER=ON
    -DPURIFY_BUILD_CLI=OFF
    -DPURIFY_BUILD_BENCH=OFF
    -DPURIFY_BUILD_DOCS=OFF
    -DPURIFY_BUILD_FUZZ=OFF)
if(DEFINED TEST_GENERATOR_PLATFORM AND
   NOT "${TEST_GENERATOR_PLATFORM}" STREQUAL "")
    list(APPEND configure_command -A "${TEST_GENERATOR_PLATFORM}")
endif()
if(DEFINED TEST_GENERATOR_TOOLSET AND
   NOT "${TEST_GENERATOR_TOOLSET}" STREQUAL "")
    list(APPEND configure_command -T "${TEST_GENERATOR_TOOLSET}")
endif()
if(DEFINED TEST_BUILD_TYPE AND NOT "${TEST_BUILD_TYPE}" STREQUAL "")
    list(APPEND configure_command
        "-DCMAKE_BUILD_TYPE=${TEST_BUILD_TYPE}")
endif()
execute_process(
    COMMAND ${configure_command}
    RESULT_VARIABLE configure_result
)
if(NOT configure_result EQUAL 0)
    message(FATAL_ERROR "absolute-libdir Purify configuration failed")
endif()

set(config_path "${test_build}/purifyConfig.cmake")
file(READ "${config_path}" config_contents)
set(expected_backend
    "${test_libdir}/${TEST_SHARED_LIBRARY_PREFIX}purify_construction_parent${TEST_SHARED_LIBRARY_SUFFIX}")
string(FIND "${config_contents}" "\"${expected_backend}\""
    expected_position)
if(expected_position EQUAL -1)
    message(FATAL_ERROR
        "installed config does not use the absolute backend path: "
        "${expected_backend}"
    )
endif()
