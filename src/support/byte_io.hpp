// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace purify::detail {

/** Consume one fixed-width field from a length-checked encoding. */
template <std::size_t Size>
void take_bytes(std::span<const unsigned char>& remaining,
                std::array<unsigned char, Size>& field) {
    assert(remaining.size() >= Size);
    std::copy_n(remaining.begin(), Size, field.begin());
    remaining = remaining.subspan(Size);
}

inline void append_u32_be(std::vector<unsigned char>& out, std::uint32_t value) {
    for (unsigned int i = 0; i < 4; ++i) {
        out.push_back(static_cast<unsigned char>(value >> (24 - 8 * i)));
    }
}

inline void append_u32_le(std::vector<unsigned char>& out, std::uint32_t value) {
    for (unsigned int i = 0; i < 4; ++i) {
        out.push_back(static_cast<unsigned char>(value >> (8 * i)));
    }
}

template <typename Allocator>
void append_u64_le(std::vector<unsigned char, Allocator>& out, std::uint64_t value) {
    for (unsigned int i = 0; i < 8; ++i) {
        out.push_back(static_cast<unsigned char>(value >> (8 * i)));
    }
}

inline std::optional<std::uint32_t> read_u32_le(
    std::span<const unsigned char> bytes, std::size_t offset) {
    if (offset > bytes.size() || bytes.size() - offset < 4) {
        return std::nullopt;
    }
    std::uint32_t value = 0;
    for (unsigned int i = 0; i < 4; ++i) {
        value |= static_cast<std::uint32_t>(bytes[offset + i]) << (8 * i);
    }
    return value;
}

}  // namespace purify::detail
