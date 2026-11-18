// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include <cassert>
#include <concepts>
#include <cstddef>
#include <limits>
#include <utility>

#include "purify/common.hpp"

namespace purify::detail {

/**
 * Size arithmetic that records overflow instead of wrapping.
 *
 * Once a step overflows, or an operand does not fit in `std::size_t`, every
 * later result stays overflowed. A whole computation therefore needs exactly
 * one check, at the point where its result is stored:
 *
 *     std::size_t bytes = 0;
 *     if (!(CheckedSize(count) * sizeof(Entry) + header_size).store(bytes)) {
 *         return unexpected_error(ErrorCode::Overflow);
 *     }
 */
class CheckedSize {
public:
    template <std::integral T>
    constexpr CheckedSize(T value) noexcept
        : value_(static_cast<std::size_t>(value)),
          overflowed_(!std::in_range<std::size_t>(value)) {}

    [[nodiscard]] constexpr bool overflowed() const noexcept {
        return overflowed_;
    }

    /** Write the result to `out`, or leave `out` untouched and return false after an overflow. */
    [[nodiscard]] constexpr bool store(std::size_t& out) const noexcept {
        if (overflowed_) {
            return false;
        }
        out = value_;
        return true;
    }

    constexpr CheckedSize& operator+=(CheckedSize rhs) noexcept {
        overflowed_ = overflowed_ || rhs.overflowed_ ||
                      !checked_add_size(value_, rhs.value_, value_);
        return *this;
    }

    constexpr CheckedSize& operator*=(CheckedSize rhs) noexcept {
        overflowed_ = overflowed_ || rhs.overflowed_ ||
                      !checked_mul_size(value_, rhs.value_, value_);
        return *this;
    }

    /** Round up to the next multiple of `alignment`, which must be non-zero. */
    [[nodiscard]] constexpr CheckedSize aligned_up(std::size_t alignment) const noexcept {
        assert(alignment != 0 && "alignment must be non-zero");
        CheckedSize out = *this;
        const std::size_t remainder = value_ % alignment;
        if (remainder != 0) {
            out += alignment - remainder;
        }
        return out;
    }

    [[nodiscard]] friend constexpr CheckedSize operator+(CheckedSize lhs, CheckedSize rhs) noexcept {
        return lhs += rhs;
    }

    [[nodiscard]] friend constexpr CheckedSize operator*(CheckedSize lhs, CheckedSize rhs) noexcept {
        return lhs *= rhs;
    }

private:
    std::size_t value_;
    bool overflowed_;
};

namespace checked_size_selftest {

inline constexpr std::size_t kMax = std::numeric_limits<std::size_t>::max();

constexpr bool stores(CheckedSize size, std::size_t expected) noexcept {
    std::size_t out = 0;
    return size.store(out) && out == expected;
}

constexpr bool leaves_output_untouched(CheckedSize size) noexcept {
    std::size_t out = 7;
    return !size.store(out) && out == 7;
}

static_assert(stores(CheckedSize(3) * 5 + 2, 17));
static_assert(stores(CheckedSize(kMax - 1) + 1, kMax));
static_assert(stores(CheckedSize(kMax) * 1 + 0, kMax));
static_assert(stores(CheckedSize(0) * kMax, 0));
static_assert(leaves_output_untouched(CheckedSize(kMax) + 1));
static_assert(leaves_output_untouched(CheckedSize(kMax / 2 + 1) * 2));
static_assert(leaves_output_untouched(CheckedSize(-1)));
// Overflow is sticky even when a later step would bring the value back in range.
static_assert(leaves_output_untouched((CheckedSize(kMax) + 1) * 0));
static_assert(leaves_output_untouched(CheckedSize(2) + CheckedSize(kMax) * 2));
static_assert(stores(CheckedSize(16).aligned_up(8), 16));
static_assert(stores(CheckedSize(17).aligned_up(8), 24));
static_assert(leaves_output_untouched(CheckedSize(kMax).aligned_up(8)));

}  // namespace checked_size_selftest

}  // namespace purify::detail
