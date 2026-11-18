// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file bppp_norm_arg.hpp
 * @brief Norm-argument entry points shared by the BPPP circuit proofs.
 */

#pragma once

#include <cstddef>
#include <span>
#include <vector>

#include "algebraic_circuit_proof.hpp"
#include "bppp_support.hpp"
#include "purify/bppp.hpp"

namespace purify::bppp {

Result<PointBytes>
commit_norm_arg_with_cache(const NormArgInputs &inputs,
                           purify_secp_context *secp_context,
                           ExperimentalCircuitBackend *cache = nullptr);

Result<NormArgProof> prove_norm_arg_to_commitment_with_cache(
    const NormArgInputs &inputs, const PointBytes &commitment,
    purify_secp_context *secp_context,
    ExperimentalCircuitBackend *cache = nullptr);

Result<NormArgProof> prove_norm_arg_to_commitment_v4(
    const NormArgInputs &inputs, const PointBytes &commitment,
    candidate::CircuitProofTranscriptV4 &transcript,
    purify_secp_context *secp_context);

bool verify_norm_arg_with_cache(const NormArgProof &proof,
                                purify_secp_context *secp_context,
                                ExperimentalCircuitBackend *cache = nullptr);

Result<std::vector<candidate::PackedPointPairV4>>
parse_norm_rounds_v4(const Bytes &proof, std::size_t round_count,
                     ScalarBytes &terminal_n, ScalarBytes &terminal_l);

Result<PointBytes> prepare_norm_arg_v4(
    const NormArgProof &norm,
    std::span<const candidate::CircuitChallengeV4> gammas,
    ScalarBytes &terminal_n, ScalarBytes &terminal_l,
    purify_secp_context *secp_context);

bool verify_norm_arg_v4(
    const NormArgProof &norm,
    std::span<const candidate::CircuitChallengeV4> gammas,
    purify_secp_context *secp_context);

} // namespace purify::bppp
