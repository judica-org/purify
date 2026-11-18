// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file bppp_backend_cache.hpp
 * @brief Cache key shared by the BPPP translation units.
 */

#pragma once

#include <array>
#include <span>

#include "purify/bppp.hpp"

namespace purify::bppp {

using GeneratorBackendCacheKey = std::array<unsigned char, 32>;

GeneratorBackendCacheKey generator_backend_cache_key(
    std::span<const PointBytes> generators);

} // namespace purify::bppp
