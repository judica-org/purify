// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include <array>
#include <cstddef>

#include "coordinate_field.hpp"

namespace purify::bppp::candidate {

inline constexpr std::size_t kPoseidonWidth = 3;
inline constexpr std::size_t kPoseidonFullRounds = 8;
inline constexpr std::size_t kPoseidonPartialRounds = 64;
inline constexpr std::size_t kPoseidonRoundConstants =
    kPoseidonWidth * (kPoseidonFullRounds + kPoseidonPartialRounds);

using PoseidonState = std::array<CoordinateFieldElement, kPoseidonWidth>;
using PoseidonMatrix =
    std::array<std::array<CoordinateFieldElement, kPoseidonWidth>, kPoseidonWidth>;

struct PoseidonParameters {
    std::array<CoordinateFieldElement, kPoseidonRoundConstants> round_constants;
    PoseidonMatrix mds;
};

/** Reproduce the pinned candidate parameter generator. */
[[nodiscard]] const PoseidonParameters& poseidon_parameters();

/** Apply the pinned candidate permutation over secp256k1's base field. */
[[nodiscard]] PoseidonState poseidon_permute(PoseidonState state);

} // namespace purify::bppp::candidate
