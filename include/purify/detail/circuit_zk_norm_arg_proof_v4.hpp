// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include <array>
#include <cstddef>

#include "purify/bppp.hpp"

namespace purify::bppp::candidate {

/**
 * V4 proof body shared by the protocol and its enclosing records.
 *
 * Native BP++ proofs use the backend's finite initial-commitment language.
 * Raw A, S, derived A_anch/P, public-mode commitment points, and every
 * intermediate public batch operation therefore must stay finite.
 * Reconstructed Cc and Q_off may use canonical zero33 identity encoding.
 * The constrained leaf permits more algebraic identity fixtures, but this
 * producer/verifier pair intentionally exposes the finite native subset
 * until the underlying norm encoding supports infinity.
 */
struct CircuitZkNormArgProofV4 {
    static constexpr std::size_t kPrefixSize =
        2 * PointBytes{}.size() + 2 * ScalarBytes{}.size() +
        std::array<unsigned char, 32>{}.size();

    PointBytes raw_commitment{};
    PointBytes mask_commitment{};
    ScalarBytes t2{};
    std::array<unsigned char, 32> public_commitment_dlog_nonce{};
    ScalarBytes public_commitment_dlog_response{};
    Bytes norm_proof;
};

} // namespace purify::bppp::candidate
