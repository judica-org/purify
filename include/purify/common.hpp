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
#include <cctype>
#include <charconv>
#include <cstdint>
#include <format>
#include <iomanip>
#include <map>
#include <optional>
#include <ostream>
#include <sstream>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "purify/error.hpp"
#include "purify_secp_bridge.h"

namespace purify {

/** @brief Dynamically sized byte string used for messages, serialized witnesses, and proofs. */
using Bytes = std::vector<unsigned char>;

}  // namespace purify
