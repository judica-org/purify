// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include <cstddef>
#include <memory>
#include <ranges>
#include <type_traits>

#include "purify/secret.hpp"

namespace purify::detail {

template <typename T>
concept MutableContiguousRange =
    std::ranges::contiguous_range<T> && std::ranges::sized_range<T> &&
    !std::is_const_v<std::remove_reference_t<
        std::ranges::range_reference_t<T>>> &&
    std::is_trivially_destructible_v<
        std::remove_cv_t<std::ranges::range_value_t<T>>>;

/** Wipe every live element in a mutable contiguous range. */
template <MutableContiguousRange T>
void secure_erase(T& value) noexcept {
    using Element = std::remove_cv_t<std::ranges::range_value_t<T>>;
    const auto count = static_cast<std::size_t>(std::ranges::size(value));
    secure_clear_bytes(std::ranges::data(value), count * sizeof(Element));
}

/** Wipe the complete representation of one mutable trivial object. */
template <typename T>
    requires (!std::ranges::range<T> && !std::is_const_v<T> &&
              std::is_trivially_destructible_v<T>)
void secure_erase(T& value) noexcept {
    secure_clear_bytes(std::addressof(value), sizeof(T));
}

template <typename T>
concept SecureErasable = requires(T& value) {
    secure_erase(value);
};

template <typename T>
concept SecretValue = SecureErasable<T> &&
                      std::is_trivially_destructible_v<T> &&
                      !std::ranges::view<T>;

/** Own a value and erase it immediately before destruction. */
template <SecretValue T>
class Secret {
public:
    Secret() = default;
    Secret(const Secret&) = delete;
    Secret& operator=(const Secret&) = delete;
    Secret(Secret&&) = delete;
    Secret& operator=(Secret&&) = delete;

    ~Secret() {
        secure_erase(value);
    }

    T value{};
};

/** Borrow a value and wipe it when the current scope exits. */
template <SecureErasable T>
class WipeOnDestruction {
public:
    explicit WipeOnDestruction(T& value) noexcept
        : value_(std::addressof(value)) {}

    WipeOnDestruction(const WipeOnDestruction&) = delete;
    WipeOnDestruction& operator=(const WipeOnDestruction&) = delete;
    WipeOnDestruction(WipeOnDestruction&&) = delete;
    WipeOnDestruction& operator=(WipeOnDestruction&&) = delete;

    ~WipeOnDestruction() {
        secure_erase(*value_);
    }

private:
    T* value_;
};

}  // namespace purify::detail
