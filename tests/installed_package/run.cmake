foreach(required IN ITEMS
        TEST_BINARY_DIR
        TEST_GENERATOR
        TEST_CXX_COMPILER
        TEST_BACKEND_RELATIVE_PATH)
    if(NOT DEFINED ${required} OR "${${required}}" STREQUAL "")
        message(FATAL_ERROR "missing installed-package input: ${required}")
    endif()
endforeach()

set(prefix "${TEST_BINARY_DIR}/installed-package-prefix")
set(consumer_binary "${TEST_BINARY_DIR}/installed-package-consumer")
file(REMOVE_RECURSE "${prefix}" "${consumer_binary}")

set(install_command
    "${CMAKE_COMMAND}" --install "${TEST_BINARY_DIR}"
    --prefix "${prefix}")
if(DEFINED TEST_CONFIG AND NOT "${TEST_CONFIG}" STREQUAL "")
    list(APPEND install_command --config "${TEST_CONFIG}")
endif()
execute_process(
    COMMAND ${install_command}
    RESULT_VARIABLE install_result
)
if(NOT install_result EQUAL 0)
    message(FATAL_ERROR "Purify package installation failed")
endif()

set(installed_backend "${prefix}/${TEST_BACKEND_RELATIVE_PATH}")
if(NOT EXISTS "${installed_backend}" OR IS_DIRECTORY "${installed_backend}")
    message(FATAL_ERROR
        "installed package is missing the construction-parent backend: "
        "${installed_backend}"
    )
endif()

set(configure_command
    "${CMAKE_COMMAND}"
    -S "${CMAKE_CURRENT_LIST_DIR}"
    -B "${consumer_binary}"
    -G "${TEST_GENERATOR}"
    "-DCMAKE_PREFIX_PATH=${prefix}"
    "-DCMAKE_CXX_COMPILER=${TEST_CXX_COMPILER}")
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
    message(FATAL_ERROR "installed Purify consumer configuration failed")
endif()

set(build_command
    "${CMAKE_COMMAND}" --build "${consumer_binary}" --parallel 1)
if(DEFINED TEST_CONFIG AND NOT "${TEST_CONFIG}" STREQUAL "")
    list(APPEND build_command --config "${TEST_CONFIG}")
endif()
execute_process(
    COMMAND ${build_command}
    RESULT_VARIABLE build_result
)
if(NOT build_result EQUAL 0)
    message(FATAL_ERROR "installed Purify consumer build failed")
endif()

set(test_command
    "${CMAKE_CTEST_COMMAND}" --test-dir "${consumer_binary}"
    --output-on-failure)
if(DEFINED TEST_CONFIG AND NOT "${TEST_CONFIG}" STREQUAL "")
    list(APPEND test_command -C "${TEST_CONFIG}")
endif()
execute_process(
    COMMAND ${test_command}
    RESULT_VARIABLE test_result
)
if(NOT test_result EQUAL 0)
    message(FATAL_ERROR "installed Purify consumer test failed")
endif()
