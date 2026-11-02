// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include <array>
#include <cstdint>
#include <span>

#include "poseidon.hpp"
#include "purify/common.hpp"
#include "purify/numeric.hpp"

namespace purify::bppp::candidate {

using TranscriptDigest = std::array<unsigned char, 32>;

/** Native candidate typed transcript matching the parent relation. */
class AlgebraicTranscript {
public:
    AlgebraicTranscript();

    void append_field(const CoordinateFieldElement& value);
    void append_scalar(const FieldElement& value);
    [[nodiscard]] Status append_point(unsigned char prefix, const CoordinateFieldElement& x);
    [[nodiscard]] Status append_point_pair(unsigned char parity,
                                           const CoordinateFieldElement& first_x,
                                           const CoordinateFieldElement& second_x);
    [[nodiscard]] Status append_bytes(std::span<const unsigned char> bytes);
    void append_u64(std::uint64_t value);

    [[nodiscard]] std::array<CoordinateFieldElement, 2> challenge(std::uint64_t round) const;
    [[nodiscard]] std::array<CoordinateFieldElement, 2>
    opening_base_scalar(const TranscriptDigest& basis_digest, std::uint64_t role) const;

private:
    void absorb(const CoordinateFieldElement& value);

    PoseidonState state_;
    std::size_t rate_index_{0};
};

/** Select the first canonical nonzero secp scalar from two field lanes. */
[[nodiscard]] Result<FieldElement>
select_nonzero_scalar(const std::array<CoordinateFieldElement, 2>& lanes);

} // namespace purify::bppp::candidate
