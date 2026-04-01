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
#include <new>
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

    Expected()
    requires std::is_default_constructible_v<T>
    {
        ConstructValue();
    }

    Expected(const T& value)
    {
        ConstructValue(value);
    }
    Expected(T&& value)
    {
        ConstructValue(std::move(value));
    }
    Expected(const Unexpected<E>& error)
    {
        ConstructError(error.error());
    }
    Expected(Unexpected<E>&& error)
    {
        ConstructError(std::move(error).error());
    }

    Expected(const Expected& other)
    {
        if (other.has_value()) {
            ConstructValue(other.ValueRef());
        } else {
            ConstructError(other.ErrorRef());
        }
    }

    Expected(Expected&& other) noexcept(std::is_nothrow_move_constructible_v<T> &&
                                        std::is_nothrow_move_constructible_v<E>)
    {
        if (other.has_value()) {
            ConstructValue(std::move(other.ValueRef()));
        } else {
            ConstructError(std::move(other.ErrorRef()));
        }
    }

    Expected& operator=(const Expected& other)
    {
        if (this == &other) {
            return *this;
        }
        if (has_value() && other.has_value()) {
            ValueRef() = other.ValueRef();
            return *this;
        }
        if (!has_value() && !other.has_value()) {
            ErrorRef() = other.ErrorRef();
            return *this;
        }
        if (other.has_value()) {
            T tmp(other.ValueRef());
            Destroy();
            ConstructValue(std::move(tmp));
            return *this;
        }
        E tmp(other.ErrorRef());
        Destroy();
        ConstructError(std::move(tmp));
        return *this;
    }

    Expected& operator=(Expected&& other) noexcept(std::is_nothrow_move_assignable_v<T> &&
                                                   std::is_nothrow_move_assignable_v<E> &&
                                                   std::is_nothrow_move_constructible_v<T> &&
                                                   std::is_nothrow_move_constructible_v<E>)
    {
        if (this == &other) {
            return *this;
        }
        if (has_value() && other.has_value()) {
            ValueRef() = std::move(other.ValueRef());
            return *this;
        }
        if (!has_value() && !other.has_value()) {
            ErrorRef() = std::move(other.ErrorRef());
            return *this;
        }
        if (other.has_value()) {
            T tmp(std::move(other.ValueRef()));
            Destroy();
            ConstructValue(std::move(tmp));
            return *this;
        }
        E tmp(std::move(other.ErrorRef()));
        Destroy();
        ConstructError(std::move(tmp));
        return *this;
    }

    ~Expected()
    {
        Destroy();
    }

    [[nodiscard]] bool has_value() const noexcept {
        return m_has_value;
    }

    [[nodiscard]] explicit operator bool() const noexcept {
        return has_value();
    }

    [[nodiscard]] T& operator*() & {
        return value();
    }

    [[nodiscard]] const T& operator*() const& {
        return value();
    }

    [[nodiscard]] T&& operator*() && {
        return std::move(value());
    }

    [[nodiscard]] const T&& operator*() const&& {
        return std::move(value());
    }

    [[nodiscard]] T* operator->() {
        return std::addressof(value());
    }

    [[nodiscard]] const T* operator->() const {
        return std::addressof(value());
    }

    [[nodiscard]] T& value() & {
        if (!has_value()) {
            throw bad_expected_access<E>();
        }
        return ValueRef();
    }

    [[nodiscard]] const T& value() const& {
        if (!has_value()) {
            throw bad_expected_access<E>();
        }
        return ValueRef();
    }

    [[nodiscard]] T&& value() && {
        if (!has_value()) {
            throw bad_expected_access<E>();
        }
        return std::move(ValueRef());
    }

    [[nodiscard]] const T&& value() const&& {
        if (!has_value()) {
            throw bad_expected_access<E>();
        }
        return std::move(ValueRef());
    }

    [[nodiscard]] E& error() & {
        if (has_value()) {
            throw bad_expected_access<E>();
        }
        return ErrorRef();
    }

    [[nodiscard]] const E& error() const& {
        if (has_value()) {
            throw bad_expected_access<E>();
        }
        return ErrorRef();
    }

    [[nodiscard]] E&& error() && {
        if (has_value()) {
            throw bad_expected_access<E>();
        }
        return std::move(ErrorRef());
    }

    [[nodiscard]] const E&& error() const&& {
        if (has_value()) {
            throw bad_expected_access<E>();
        }
        return std::move(ErrorRef());
    }

private:
    union Storage {
        char empty;
        T value;
        E error;

        Storage() noexcept : empty() {}
        ~Storage() {}
    };

    template <typename... Args>
    void ConstructValue(Args&&... args)
    {
        std::construct_at(std::addressof(storage_.value), std::forward<Args>(args)...);
        m_has_value = true;
    }

    template <typename... Args>
    void ConstructError(Args&&... args)
    {
        std::construct_at(std::addressof(storage_.error), std::forward<Args>(args)...);
        m_has_value = false;
    }

    void Destroy() noexcept
    {
        if (m_has_value) {
            std::destroy_at(std::addressof(storage_.value));
            return;
        }
        std::destroy_at(std::addressof(storage_.error));
    }

    T& ValueRef() & noexcept
    {
        return storage_.value;
    }

    const T& ValueRef() const& noexcept
    {
        return storage_.value;
    }

    E& ErrorRef() & noexcept
    {
        return storage_.error;
    }

    const E& ErrorRef() const& noexcept
    {
        return storage_.error;
    }

    // Keep the fallback explicitly tagged; i686 was surfacing valueless
    // std::variant states through Purify's checked-return path.
    bool m_has_value{false};
    Storage storage_{};
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
