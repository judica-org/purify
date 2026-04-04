// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include <cassert>

#include "purify.h"
#include "purify/error.hpp"

namespace purify::core_api_detail {

#define PURIFY_FOR_EACH_ERROR_CODE(X) \
    X(InvalidHex, PURIFY_ERROR_INVALID_HEX) \
    X(InvalidHexLength, PURIFY_ERROR_INVALID_HEX_LENGTH) \
    X(InvalidFixedSize, PURIFY_ERROR_INVALID_FIXED_SIZE) \
    X(Overflow, PURIFY_ERROR_OVERFLOW) \
    X(Underflow, PURIFY_ERROR_UNDERFLOW) \
    X(NarrowingOverflow, PURIFY_ERROR_NARROWING_OVERFLOW) \
    X(DivisionByZero, PURIFY_ERROR_DIVISION_BY_ZERO) \
    X(BitIndexOutOfRange, PURIFY_ERROR_BIT_INDEX_OUT_OF_RANGE) \
    X(RangeViolation, PURIFY_ERROR_RANGE_VIOLATION) \
    X(EmptyInput, PURIFY_ERROR_EMPTY_INPUT) \
    X(SizeMismatch, PURIFY_ERROR_SIZE_MISMATCH) \
    X(MissingValue, PURIFY_ERROR_MISSING_VALUE) \
    X(InvalidSymbol, PURIFY_ERROR_INVALID_SYMBOL) \
    X(UnsupportedSymbol, PURIFY_ERROR_UNSUPPORTED_SYMBOL) \
    X(UninitializedState, PURIFY_ERROR_UNINITIALIZED_STATE) \
    X(IndexOutOfRange, PURIFY_ERROR_INDEX_OUT_OF_RANGE) \
    X(InvalidDimensions, PURIFY_ERROR_INVALID_DIMENSIONS) \
    X(NonBooleanValue, PURIFY_ERROR_NON_BOOLEAN_VALUE) \
    X(EquationMismatch, PURIFY_ERROR_EQUATION_MISMATCH) \
    X(BindingMismatch, PURIFY_ERROR_BINDING_MISMATCH) \
    X(IoOpenFailed, PURIFY_ERROR_IO_OPEN_FAILED) \
    X(IoWriteFailed, PURIFY_ERROR_IO_WRITE_FAILED) \
    X(EntropyUnavailable, PURIFY_ERROR_ENTROPY_UNAVAILABLE) \
    X(BackendRejectedInput, PURIFY_ERROR_BACKEND_REJECTED_INPUT) \
    X(HashToCurveExhausted, PURIFY_ERROR_HASH_TO_CURVE_EXHAUSTED) \
    X(UnexpectedSize, PURIFY_ERROR_UNEXPECTED_SIZE) \
    X(GeneratorOrderCheckFailed, PURIFY_ERROR_GENERATOR_ORDER_CHECK_FAILED) \
    X(InternalMismatch, PURIFY_ERROR_INTERNAL_MISMATCH) \
    X(TranscriptCheckFailed, PURIFY_ERROR_TRANSCRIPT_CHECK_FAILED)

constexpr ErrorCode from_core_error_code(purify_error_code code) noexcept {
    switch (code) {
#define PURIFY_FROM_CORE_CASE(cpp_code, c_code) \
    case c_code: \
        return ErrorCode::cpp_code;
        PURIFY_FOR_EACH_ERROR_CODE(PURIFY_FROM_CORE_CASE)
#undef PURIFY_FROM_CORE_CASE
    case PURIFY_ERROR_OK:
        break;
    }

    assert(false && "from_core_error_code() requires a non-success core status");
    return ErrorCode::InternalMismatch;
}

constexpr purify_error_code to_core_error_code(ErrorCode code) noexcept {
    switch (code) {
#define PURIFY_TO_CORE_CASE(cpp_code, c_code) \
    case ErrorCode::cpp_code: \
        return c_code;
        PURIFY_FOR_EACH_ERROR_CODE(PURIFY_TO_CORE_CASE)
#undef PURIFY_TO_CORE_CASE
    }

    assert(false && "to_core_error_code() requires a mapped ErrorCode");
    return PURIFY_ERROR_INTERNAL_MISMATCH;
}

#undef PURIFY_FOR_EACH_ERROR_CODE

}  // namespace purify::core_api_detail
