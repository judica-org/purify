// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file expected.hpp
 * @brief Public aliases for the C++23 expected vocabulary used by Purify.
 */

#pragma once

#include <expected>

namespace purify {

/** @brief Purify result carrier that either holds a value or an error. */
template <typename T, typename E>
using Expected = std::expected<T, E>;

/** @brief Purify wrapper for constructing the error side of an Expected value. */
template <typename E>
using Unexpected = std::unexpected<E>;

using std::bad_expected_access;
using std::unexpect_t;

inline constexpr unexpect_t unexpect = std::unexpect;

}  // namespace purify
