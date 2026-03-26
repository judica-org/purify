// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file expected.hpp
 * @brief Public aliases for the C++23 expected vocabulary used by Purify.
 */

#pragma once

#include <exception>
#include <memory>
#include <type_traits>
#include <utility>

#if defined(__has_include)
#if __has_include(<expected>)
#include <expected>
#endif
#endif

#if !defined(__cpp_lib_expected) || __cpp_lib_expected < 202202L
#include <variant>
#endif

namespace purify {

#if defined(__cpp_lib_expected) && __cpp_lib_expected >= 202202L
/** @brief Purify result carrier that either holds a value or an error. */
template <typename T, typename E>
using Expected = std::expected<T, E>;

/** @brief Purify wrapper for constructing the error side of an Expected value. */
template <typename E>
using Unexpected = std::unexpected<E>;

using std::bad_expected_access;
using std::unexpect_t;

inline constexpr unexpect_t unexpect = std::unexpect;
#else
struct unexpect_t {
    explicit constexpr unexpect_t() noexcept = default;
};

inline constexpr unexpect_t unexpect{};

template <typename E = void>
class bad_expected_access : public std::exception {
public:
    const char* what() const noexcept override {
        return "bad expected access";
    }
};

template <typename E>
class Unexpected {
public:
    constexpr explicit Unexpected(const E& error) : error_(error) {}
    constexpr explicit Unexpected(E&& error) : error_(std::move(error)) {}

    [[nodiscard]] constexpr E& error() & noexcept {
        return error_;
    }

    [[nodiscard]] constexpr const E& error() const& noexcept {
        return error_;
    }

    [[nodiscard]] constexpr E&& error() && noexcept {
        return std::move(error_);
    }

    [[nodiscard]] constexpr const E&& error() const&& noexcept {
        return std::move(error_);
    }

private:
    E error_;
};

/** @brief Purify result carrier that either holds a value or an error. */
template <typename T, typename E>
class Expected {
public:
    using value_type = T;
    using error_type = E;
    using unexpected_type = Unexpected<E>;

    constexpr Expected()
    requires std::is_default_constructible_v<T>
        : storage_(std::in_place_index<0>) {}

    constexpr Expected(const T& value) : storage_(std::in_place_index<0>, value) {}
    constexpr Expected(T&& value) : storage_(std::in_place_index<0>, std::move(value)) {}
    constexpr Expected(const Unexpected<E>& error) : storage_(std::in_place_index<1>, error.error()) {}
    constexpr Expected(Unexpected<E>&& error) : storage_(std::in_place_index<1>, std::move(error).error()) {}

    constexpr Expected(const Expected&) = default;
    constexpr Expected(Expected&&) noexcept = default;
    constexpr Expected& operator=(const Expected&) = default;
    constexpr Expected& operator=(Expected&&) noexcept = default;
    ~Expected() = default;

    [[nodiscard]] constexpr bool has_value() const noexcept {
        return storage_.index() == 0;
    }

    [[nodiscard]] constexpr explicit operator bool() const noexcept {
        return has_value();
    }

    [[nodiscard]] constexpr T& operator*() & {
        return value();
    }

    [[nodiscard]] constexpr const T& operator*() const& {
        return value();
    }

    [[nodiscard]] constexpr T&& operator*() && {
        return std::move(value());
    }

    [[nodiscard]] constexpr const T&& operator*() const&& {
        return std::move(value());
    }

    [[nodiscard]] constexpr T* operator->() {
        return std::addressof(value());
    }

    [[nodiscard]] constexpr const T* operator->() const {
        return std::addressof(value());
    }

    [[nodiscard]] constexpr T& value() & {
        if (!has_value()) {
            throw bad_expected_access<E>();
        }
        return std::get<0>(storage_);
    }

    [[nodiscard]] constexpr const T& value() const& {
        if (!has_value()) {
            throw bad_expected_access<E>();
        }
        return std::get<0>(storage_);
    }

    [[nodiscard]] constexpr T&& value() && {
        if (!has_value()) {
            throw bad_expected_access<E>();
        }
        return std::move(std::get<0>(storage_));
    }

    [[nodiscard]] constexpr const T&& value() const&& {
        if (!has_value()) {
            throw bad_expected_access<E>();
        }
        return std::move(std::get<0>(storage_));
    }

    [[nodiscard]] constexpr E& error() & {
        if (has_value()) {
            throw bad_expected_access<E>();
        }
        return std::get<1>(storage_);
    }

    [[nodiscard]] constexpr const E& error() const& {
        if (has_value()) {
            throw bad_expected_access<E>();
        }
        return std::get<1>(storage_);
    }

    [[nodiscard]] constexpr E&& error() && {
        if (has_value()) {
            throw bad_expected_access<E>();
        }
        return std::move(std::get<1>(storage_));
    }

    [[nodiscard]] constexpr const E&& error() const&& {
        if (has_value()) {
            throw bad_expected_access<E>();
        }
        return std::move(std::get<1>(storage_));
    }

private:
    std::variant<T, E> storage_;
};

template <typename E>
class Expected<void, E> {
public:
    using value_type = void;
    using error_type = E;
    using unexpected_type = Unexpected<E>;

    constexpr Expected() noexcept = default;
    constexpr Expected(const Unexpected<E>& error) : has_value_(false), error_(error.error()) {}
    constexpr Expected(Unexpected<E>&& error) : has_value_(false), error_(std::move(error).error()) {}

    constexpr Expected(const Expected&) = default;
    constexpr Expected(Expected&&) noexcept = default;
    constexpr Expected& operator=(const Expected&) = default;
    constexpr Expected& operator=(Expected&&) noexcept = default;
    ~Expected() = default;

    [[nodiscard]] constexpr bool has_value() const noexcept {
        return has_value_;
    }

    [[nodiscard]] constexpr explicit operator bool() const noexcept {
        return has_value();
    }

    constexpr void value() const {
        if (!has_value_) {
            throw bad_expected_access<E>();
        }
    }

    [[nodiscard]] constexpr E& error() & {
        if (has_value_) {
            throw bad_expected_access<E>();
        }
        return error_;
    }

    [[nodiscard]] constexpr const E& error() const& {
        if (has_value_) {
            throw bad_expected_access<E>();
        }
        return error_;
    }

    [[nodiscard]] constexpr E&& error() && {
        if (has_value_) {
            throw bad_expected_access<E>();
        }
        return std::move(error_);
    }

    [[nodiscard]] constexpr const E&& error() const&& {
        if (has_value_) {
            throw bad_expected_access<E>();
        }
        return std::move(error_);
    }

private:
    bool has_value_ = true;
    E error_{};
};
#endif

}  // namespace purify
