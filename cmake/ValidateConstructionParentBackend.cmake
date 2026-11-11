if(NOT DEFINED BACKEND_LIBRARY OR BACKEND_LIBRARY STREQUAL "")
    message(FATAL_ERROR "BACKEND_LIBRARY is required")
endif()
if(NOT DEFINED BACKEND_NM OR BACKEND_NM STREQUAL "")
    message(FATAL_ERROR "BACKEND_NM is required")
endif()

if(BACKEND_APPLE)
    set(_nm_args -gU)
else()
    set(_nm_args -D --defined-only)
endif()

execute_process(
    COMMAND "${BACKEND_NM}" ${_nm_args} "${BACKEND_LIBRARY}"
    RESULT_VARIABLE _nm_result
    OUTPUT_VARIABLE _nm_output
    ERROR_VARIABLE _nm_error
)
if(NOT _nm_result EQUAL 0)
    message(FATAL_ERROR
        "Failed to inspect construction-parent backend: ${_nm_error}"
    )
endif()

set(_expected
    purify_construction_parent_verifier_destroy
    purify_construction_parent_verifier_load
    purify_construction_parent_verify
)
set(_actual)
string(REPLACE "\r\n" "\n" _nm_output "${_nm_output}")
string(REPLACE "\n" ";" _nm_lines "${_nm_output}")
foreach(_line IN LISTS _nm_lines)
    string(STRIP "${_line}" _line)
    if(_line STREQUAL "")
        continue()
    endif()
    string(REGEX MATCH "(_?[^ ]+)$" _symbol "${_line}")
    string(REGEX REPLACE "^_" "" _symbol "${_symbol}")
    list(APPEND _actual "${_symbol}")
endforeach()
list(SORT _actual)
list(SORT _expected)

if(NOT _actual STREQUAL _expected)
    message(FATAL_ERROR
        "Construction-parent backend exports '${_actual}', expected '${_expected}'"
    )
endif()

if(DEFINED BACKEND_SONAME)
    if(NOT DEFINED BACKEND_READELF OR BACKEND_READELF STREQUAL "")
        message(FATAL_ERROR "BACKEND_READELF is required for SONAME validation")
    endif()
    execute_process(
        COMMAND "${BACKEND_READELF}" -d "${BACKEND_LIBRARY}"
        RESULT_VARIABLE _readelf_result
        OUTPUT_VARIABLE _readelf_output
        ERROR_VARIABLE _readelf_error
    )
    if(NOT _readelf_result EQUAL 0)
        message(FATAL_ERROR
            "Failed to inspect construction-parent SONAME: ${_readelf_error}"
        )
    endif()
    set(_soname_found FALSE)
    string(REPLACE "\r\n" "\n" _readelf_output "${_readelf_output}")
    string(REPLACE "\n" ";" _readelf_lines "${_readelf_output}")
    foreach(_line IN LISTS _readelf_lines)
        if(_line MATCHES "\\(SONAME\\)")
            string(FIND "${_line}" "[${BACKEND_SONAME}]" _soname_position)
            if(NOT _soname_position EQUAL -1)
                set(_soname_found TRUE)
            endif()
        endif()
    endforeach()
    if(NOT _soname_found)
        message(FATAL_ERROR
            "Construction-parent backend has no '${BACKEND_SONAME}' SONAME"
        )
    endif()
endif()
