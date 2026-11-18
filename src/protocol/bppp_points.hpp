// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file bppp_points.hpp
 * @brief Curve-point arithmetic and commitment construction for the BPPP circuit proofs.
 */

#pragma once

#include <span>

#include "bppp_circuit_reduction.hpp"
#include "bppp_support.hpp"
#include "purify/bppp.hpp"

namespace purify::bppp {

namespace detail {

Result<PointBytes>
commit_norm_arg_witness_only(const NormArgInputs &inputs,
                             purify_secp_context *secp_context,
                             ExperimentalCircuitBackend *cache = nullptr);

Result<PointBytes> point_scale(const PointBytes &point,
                               const FieldElement &scalar,
                               purify_secp_context *secp_context);

Result<PointBytes> generator_scale(const PointBytes &generator,
                                   const FieldElement &scalar,
                                   purify_secp_context *secp_context);

Result<PointBytes> generator_to_point(const PointBytes &generator,
                                      purify_secp_context *secp_context);

Result<PointBytes> point_add(const PointBytes &lhs,
                             const PointBytes &rhs,
                             purify_secp_context *secp_context);

Result<PointBytes> point_subtract_allow_infinity(
    const PointBytes &lhs, const PointBytes &rhs,
    purify_secp_context *secp_context);

Result<PointBytes> point_from_scalar_base(const FieldElement &scalar,
                                          purify_secp_context *secp_context);

Result<PointBytes> circuit_anchored_offset_v4(
    const CircuitNormArgPublicData &public_data,
    std::span<const PointBytes> public_commitments,
    purify_secp_context *secp_context);

Result<PointBytes>
anchor_zk_a_commitment(const PointBytes &a_witness_commitment,
                       const CircuitNormArgPublicData &public_data,
                       std::span<const PointBytes> public_commitments,
                       purify_secp_context *secp_context);

Result<PointBytes> coefficient_commitment_v4(
    const CircuitNormArgPublicData &public_data,
    purify_secp_context *secp_context);

Result<PointBytes>
commit_explicit_norm_arg(const NormArgInputs &inputs, const FieldElement &value,
                         purify_secp_context *secp_context,
                         ExperimentalCircuitBackend *cache = nullptr);

Result<PointBytes> combine_zk_commitments(const PointBytes &a_commitment,
                                          const PointBytes &s_commitment,
                                          const FieldElement &challenge,
                                          const FieldElement &t2,
                                          purify_secp_context *secp_context);

} // namespace detail

} // namespace purify::bppp
