foreach(required IN ITEMS TEST_NM TEST_LIBRARY)
    if(NOT DEFINED ${required} OR "${${required}}" STREQUAL "")
        message(FATAL_ERROR "missing symbol-check input: ${required}")
    endif()
endforeach()

execute_process(
    COMMAND "${TEST_NM}" -g "${TEST_LIBRARY}"
    RESULT_VARIABLE nm_result
    OUTPUT_VARIABLE global_symbols
    ERROR_VARIABLE nm_error
)
if(NOT nm_result EQUAL 0)
    message(FATAL_ERROR "failed to inspect shared symbols: ${nm_error}")
endif()

foreach(private_symbol IN ITEMS
        purify_construction_parent_verifier_load
        purify_construction_parent_verify
        purify_construction_parent_verifier_destroy
        purify_receipt_cycle)
    string(FIND "${global_symbols}" "${private_symbol}" symbol_offset)
    if(NOT symbol_offset EQUAL -1)
        message(FATAL_ERROR
            "private receipt symbol is globally visible: ${private_symbol}"
        )
    endif()
endforeach()
