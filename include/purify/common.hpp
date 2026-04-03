// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file common.hpp
 * @brief Shared includes and foundational aliases for the Purify C++ implementation.
 */

#pragma once

#include <algorithm>
#include <array>
#include <cassert>
#include <bit>
#include <cctype>
#include <charconv>
#include <cstdint>
#include <iomanip>
#include <map>
#include <memory>
#include <optional>
#include <ostream>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "purify/error.hpp"
#include "purify/secp_bridge.h"

#ifndef PURIFY_USE_LEGACY_FIELD_HASHES
#define PURIFY_USE_LEGACY_FIELD_HASHES 0
#endif

namespace purify {

struct SecpContextDeleter {
    void operator()(purify_secp_context* context) const noexcept {
        purify_secp_context_destroy(context);
    }
};

using SecpContextPtr = std::unique_ptr<purify_secp_context, SecpContextDeleter>;

inline SecpContextPtr make_secp_context() noexcept {
    return SecpContextPtr(purify_secp_context_create());
}

inline Status require_secp_context(const purify_secp_context* context, const char* error_context) {
    if (context == nullptr) {
        return unexpected_error(ErrorCode::MissingValue, error_context);
    }
    return {};
}

/** @brief Dynamically sized byte string used for messages, serialized witnesses, and proofs. */
using Bytes = std::vector<unsigned char>;

/**
 * @brief Checked span wrapper that guarantees a minimum runtime length.
 *
 * This is useful for API boundaries where a raw `std::span` is too permissive and callers need an
 * explicit checked contract such as "at least 16 bytes of seed material".
 */
template <std::size_t MinSize, typename T>
class SpanAtLeast {
public:
    static constexpr std::size_t min_size = MinSize;
    using element_type = T;

    template <std::size_t Extent>
    requires(Extent != std::dynamic_extent && Extent >= MinSize)
    constexpr explicit SpanAtLeast(std::span<T, Extent> span) noexcept : span_(span) {}

    [[nodiscard]] static Result<SpanAtLeast> try_from(std::span<T> span) {
        if (span.size() < MinSize) {
            return unexpected_error(ErrorCode::RangeViolation, "SpanAtLeast::try_from:too_short");
        }
        return SpanAtLeast(span);
    }

    [[nodiscard]] constexpr std::span<T> span() const noexcept {
        return span_;
    }

    [[nodiscard]] constexpr const T* data() const noexcept {
        return span_.data();
    }

    [[nodiscard]] constexpr std::size_t size() const noexcept {
        return span_.size();
    }

    [[nodiscard]] constexpr auto begin() const noexcept {
        return span_.begin();
    }

    [[nodiscard]] constexpr auto end() const noexcept {
        return span_.end();
    }

    [[nodiscard]] constexpr operator std::span<T>() const noexcept {
        return span_;
    }

private:
    constexpr explicit SpanAtLeast(std::span<T> span) noexcept : span_(span) {}

    std::span<T> span_;
};

}  // namespace purify
