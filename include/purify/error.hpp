// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file error.hpp
 * @brief Library-level error taxonomy used to classify Purify failures.
 */

#pragma once

#include <compare>
#include <cstdint>
#include <string_view>
#include <utility>

#include "purify/expected.hpp"

namespace purify {

/**
 * @brief High-level classification for all recoverable Purify errors.
 *
 * `Natural` errors can happen in valid operation and should be surfaced in checked APIs.
 * `Usage` errors mean the caller supplied malformed input or violated a documented contract.
 * `Internal` errors indicate a broken library invariant and should generally map to debug
 * assertions or unchecked fast-fail paths instead of normal error returns.
 */
enum class ErrorCategory : std::uint8_t {
    Natural,
    Usage,
    Internal,
};

/**
 * @brief Machine-readable error codes shared across the library.
 *
 * The intent is that checked APIs list the exact `ErrorCode` values they may return, while the
 * category helpers below make it obvious whether each error is a normal runtime condition,
 * caller misuse, or a library defect.
 */
enum class ErrorCode : std::uint16_t {
    InvalidHex,
    InvalidHexLength,
    InvalidFixedSize,
    Overflow,
    Underflow,
    NarrowingOverflow,
    DivisionByZero,
    BitIndexOutOfRange,
    RangeViolation,
    EmptyInput,
    SizeMismatch,
    MissingValue,
    InvalidSymbol,
    UnsupportedSymbol,
    UninitializedState,
    IndexOutOfRange,
    InvalidDimensions,
    NonBooleanValue,
    EquationMismatch,
    BindingMismatch,
    IoOpenFailed,
    IoWriteFailed,
    EntropyUnavailable,
    BackendRejectedInput,
    HashToCurveExhausted,
    UnexpectedSize,
    GeneratorOrderCheckFailed,
    InternalMismatch,
    TranscriptCheckFailed,
};

/** @brief Compact error object returned by checked APIs. */
struct Error {
    ErrorCode code{};

    [[nodiscard]] constexpr ErrorCategory category() const noexcept;
    [[nodiscard]] constexpr std::string_view name() const noexcept;
    [[nodiscard]] constexpr std::string_view message() const noexcept;

    [[nodiscard]] constexpr bool is_natural() const noexcept {
        return category() == ErrorCategory::Natural;
    }

    [[nodiscard]] constexpr bool is_usage_error() const noexcept {
        return category() == ErrorCategory::Usage;
    }

    [[nodiscard]] constexpr bool is_internal() const noexcept {
        return category() == ErrorCategory::Internal;
    }

    constexpr auto operator<=>(const Error&) const = default;
};

/** @brief Expected-returning convenience alias for Purify value-producing APIs. */
template <typename T>
using Result = Expected<T, Error>;

/** @brief Expected-returning convenience alias for Purify status-only APIs. */
using Status = Expected<void, Error>;

/** @brief Returns the high-level category for a concrete error code. */
[[nodiscard]] constexpr ErrorCategory error_category(ErrorCode code) noexcept {
    switch (code) {
    case ErrorCode::IoOpenFailed:
    case ErrorCode::IoWriteFailed:
    case ErrorCode::EntropyUnavailable:
    case ErrorCode::HashToCurveExhausted:
        return ErrorCategory::Natural;

    case ErrorCode::InvalidHex:
    case ErrorCode::InvalidHexLength:
    case ErrorCode::InvalidFixedSize:
    case ErrorCode::Overflow:
    case ErrorCode::Underflow:
    case ErrorCode::NarrowingOverflow:
    case ErrorCode::DivisionByZero:
    case ErrorCode::BitIndexOutOfRange:
    case ErrorCode::RangeViolation:
    case ErrorCode::EmptyInput:
    case ErrorCode::SizeMismatch:
    case ErrorCode::MissingValue:
    case ErrorCode::InvalidSymbol:
    case ErrorCode::UnsupportedSymbol:
    case ErrorCode::UninitializedState:
    case ErrorCode::IndexOutOfRange:
    case ErrorCode::InvalidDimensions:
    case ErrorCode::NonBooleanValue:
    case ErrorCode::EquationMismatch:
    case ErrorCode::BindingMismatch:
    case ErrorCode::BackendRejectedInput:
        return ErrorCategory::Usage;

    case ErrorCode::UnexpectedSize:
    case ErrorCode::GeneratorOrderCheckFailed:
    case ErrorCode::InternalMismatch:
    case ErrorCode::TranscriptCheckFailed:
        return ErrorCategory::Internal;
    }
    return ErrorCategory::Internal;
}

/** @brief Returns a stable programmatic name for an error category. */
[[nodiscard]] constexpr std::string_view to_string(ErrorCategory category) noexcept {
    switch (category) {
    case ErrorCategory::Natural:
        return "natural";
    case ErrorCategory::Usage:
        return "usage";
    case ErrorCategory::Internal:
        return "internal";
    }
    return "unknown_category";
}

/** @brief Returns a stable programmatic name for an error code. */
[[nodiscard]] constexpr std::string_view to_string(ErrorCode code) noexcept {
    switch (code) {
    case ErrorCode::InvalidHex:
        return "invalid_hex";
    case ErrorCode::InvalidHexLength:
        return "invalid_hex_length";
    case ErrorCode::InvalidFixedSize:
        return "invalid_fixed_size";
    case ErrorCode::Overflow:
        return "overflow";
    case ErrorCode::Underflow:
        return "underflow";
    case ErrorCode::NarrowingOverflow:
        return "narrowing_overflow";
    case ErrorCode::DivisionByZero:
        return "division_by_zero";
    case ErrorCode::BitIndexOutOfRange:
        return "bit_index_out_of_range";
    case ErrorCode::RangeViolation:
        return "range_violation";
    case ErrorCode::EmptyInput:
        return "empty_input";
    case ErrorCode::SizeMismatch:
        return "size_mismatch";
    case ErrorCode::MissingValue:
        return "missing_value";
    case ErrorCode::InvalidSymbol:
        return "invalid_symbol";
    case ErrorCode::UnsupportedSymbol:
        return "unsupported_symbol";
    case ErrorCode::UninitializedState:
        return "uninitialized_state";
    case ErrorCode::IndexOutOfRange:
        return "index_out_of_range";
    case ErrorCode::InvalidDimensions:
        return "invalid_dimensions";
    case ErrorCode::NonBooleanValue:
        return "non_boolean_value";
    case ErrorCode::EquationMismatch:
        return "equation_mismatch";
    case ErrorCode::BindingMismatch:
        return "binding_mismatch";
    case ErrorCode::IoOpenFailed:
        return "io_open_failed";
    case ErrorCode::IoWriteFailed:
        return "io_write_failed";
    case ErrorCode::EntropyUnavailable:
        return "entropy_unavailable";
    case ErrorCode::BackendRejectedInput:
        return "backend_rejected_input";
    case ErrorCode::HashToCurveExhausted:
        return "hash_to_curve_exhausted";
    case ErrorCode::UnexpectedSize:
        return "unexpected_size";
    case ErrorCode::GeneratorOrderCheckFailed:
        return "generator_order_check_failed";
    case ErrorCode::InternalMismatch:
        return "internal_mismatch";
    case ErrorCode::TranscriptCheckFailed:
        return "transcript_check_failed";
    }
    return "unknown_error";
}

/** @brief Returns the human-facing description for an error code. */
[[nodiscard]] constexpr std::string_view error_message(ErrorCode code) noexcept {
    switch (code) {
    case ErrorCode::InvalidHex:
        return "hex input contains a non-hexadecimal character";
    case ErrorCode::InvalidHexLength:
        return "hex input has an invalid length";
    case ErrorCode::InvalidFixedSize:
        return "input does not have the required fixed size";
    case ErrorCode::Overflow:
        return "operation overflowed the target representation";
    case ErrorCode::Underflow:
        return "operation underflowed the target representation";
    case ErrorCode::NarrowingOverflow:
        return "narrowing conversion would discard non-zero bits";
    case ErrorCode::DivisionByZero:
        return "division by zero is not permitted";
    case ErrorCode::BitIndexOutOfRange:
        return "bit index is outside the valid range";
    case ErrorCode::RangeViolation:
        return "input is outside the documented valid range";
    case ErrorCode::EmptyInput:
        return "input must not be empty";
    case ErrorCode::SizeMismatch:
        return "related inputs do not have matching sizes";
    case ErrorCode::MissingValue:
        return "required value is missing";
    case ErrorCode::InvalidSymbol:
        return "symbol encoding is malformed";
    case ErrorCode::UnsupportedSymbol:
        return "symbol is well-formed but not supported";
    case ErrorCode::UninitializedState:
        return "object must be initialized before this operation";
    case ErrorCode::IndexOutOfRange:
        return "index is outside the valid range";
    case ErrorCode::InvalidDimensions:
        return "inputs imply an invalid shape or dimension";
    case ErrorCode::NonBooleanValue:
        return "value violates a required boolean constraint";
    case ErrorCode::EquationMismatch:
        return "value violates a required equality constraint";
    case ErrorCode::BindingMismatch:
        return "prepared state is bound to a different secret, message, or topic";
    case ErrorCode::IoOpenFailed:
        return "unable to open the requested file or stream";
    case ErrorCode::IoWriteFailed:
        return "unable to write the requested file or stream";
    case ErrorCode::EntropyUnavailable:
        return "unable to obtain secure operating-system randomness";
    case ErrorCode::BackendRejectedInput:
        return "the cryptographic backend rejected the supplied input";
    case ErrorCode::HashToCurveExhausted:
        return "hash-to-curve sampling exhausted all retry attempts";
    case ErrorCode::UnexpectedSize:
        return "backend returned an unexpected serialized size";
    case ErrorCode::GeneratorOrderCheckFailed:
        return "fixed generator failed its subgroup order check";
    case ErrorCode::InternalMismatch:
        return "internal consistency check failed";
    case ErrorCode::TranscriptCheckFailed:
        return "internally generated transcript failed validation";
    }
    return "unknown error";
}

/**
 * @brief Constructs an unexpected Error value from a machine-readable code.
 *
 * `context` is reserved for future diagnostic plumbing and must have static lifetime.
 */
[[nodiscard]] constexpr Unexpected<Error> unexpected_error(ErrorCode code, [[maybe_unused]] const char* context = nullptr) {
    return Unexpected<Error>(Error{code});
}

/**
 * @brief Re-wraps an existing Error value for propagation through another Result.
 *
 * `context` is reserved for future diagnostic plumbing and must have static lifetime.
 */
[[nodiscard]] constexpr Unexpected<Error> unexpected_error(Error error, [[maybe_unused]] const char* context = nullptr) {
    return Unexpected<Error>(error);
}

inline constexpr ErrorCategory Error::category() const noexcept {
    return error_category(code);
}

inline constexpr std::string_view Error::name() const noexcept {
    return to_string(code);
}

inline constexpr std::string_view Error::message() const noexcept {
    return error_message(code);
}

}  // namespace purify

#define PURIFY_DETAIL_CONCAT_IMPL(x, y) x##y
#define PURIFY_DETAIL_CONCAT(x, y) PURIFY_DETAIL_CONCAT_IMPL(x, y)

/**
 * @brief Evaluates an expected-like expression and returns the wrapped error on failure.
 *
 * This is intended for `Status`-style propagation and may also be used with `Result<T>` when the
 * value is intentionally discarded. `context` is forwarded to `unexpected_error()`.
 */
#define PURIFY_RETURN_IF_ERROR(expr, context) \
    PURIFY_DETAIL_RETURN_IF_ERROR_IMPL(PURIFY_DETAIL_CONCAT(_purify_status_, __COUNTER__), expr, context)

/**
 * @brief Evaluates an expected-like expression, binds the value to `lhs`, and propagates errors.
 *
 * Example: `PURIFY_ASSIGN_OR_RETURN(auto secret, SecretKey::from_hex(hex), "caller:from_hex");`
 * `context` is forwarded to `unexpected_error()`.
 */
#define PURIFY_ASSIGN_OR_RETURN(lhs, expr, context) \
    PURIFY_DETAIL_ASSIGN_OR_RETURN_IMPL(PURIFY_DETAIL_CONCAT(_purify_result_, __COUNTER__), lhs, expr, context)

#define PURIFY_DETAIL_RETURN_IF_ERROR_IMPL(status_name, expr, context) \
    auto status_name = (expr); \
    if (!status_name.has_value()) \
        return ::purify::unexpected_error(status_name.error(), context)

#define PURIFY_DETAIL_ASSIGN_OR_RETURN_IMPL(result_name, lhs, expr, context) \
    auto result_name = (expr); \
    if (!result_name.has_value()) \
        return ::purify::unexpected_error(result_name.error(), context); \
    lhs = std::move(*result_name)
