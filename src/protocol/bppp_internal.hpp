// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include <optional>

#include "purify/bppp.hpp"

namespace purify::bppp::detail {

/** The protocol's fixed even scalar-field square root of minus one. */
inline Result<FieldElement> canonical_sqrt_minus_one()
{
    std::optional<FieldElement> root = FieldElement::one().negate().sqrt();
    if (!root.has_value()) {
        return unexpected_error(ErrorCode::InternalMismatch,
                                "bppp:canonical_sqrt_minus_one");
    }
    if ((root->to_bytes_be().back() & 1U) != 0U) {
        *root = root->negate();
    }
    return *root;
}

/**
 * Fully reconstructed public V3 norm statement.
 *
 * Construction verifies the public-output DLog proof, validates the outer
 * encodings and replays the outer transcript. The reconstructed inner norm
 * proof remains a pending obligation.
 */
struct PreparedExperimentalCircuitZkNormArg {
    NormArgProof norm;
    std::array<unsigned char, 32> raw_generator_digest{};
    std::array<unsigned char, 32> challenge_digest{};
    FieldElement mul_scale = FieldElement::zero();
    FieldElement mul_ratio = FieldElement::zero();
};

Result<std::optional<PreparedExperimentalCircuitZkNormArg>>
prepare_experimental_circuit_zk_norm_arg_with_public_commitments(
    const NativeBulletproofCircuit& circuit,
    const ExperimentalCircuitZkNormArgProof& proof,
    std::span<const PointBytes> public_commitments,
    purify_secp_context* secp_context,
    std::span<const unsigned char> statement_binding,
    ExperimentalCircuitBackend* cache);

} // namespace purify::bppp::detail
