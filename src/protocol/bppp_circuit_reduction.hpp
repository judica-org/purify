// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file bppp_circuit_reduction.hpp
 * @brief Public data and witness vectors of a circuit reduced to the BPPP norm argument.
 */

#pragma once

#include <cstddef>
#include <memory>
#include <span>
#include <vector>

#include "bppp_support.hpp"
#include "purify/bppp.hpp"

namespace purify::bppp {

namespace detail {

struct CircuitNormArgPublicData {
  FieldElement rho = FieldElement::zero();
  FieldElement mul_scale = FieldElement::zero();
  FieldElement mul_ratio = FieldElement::zero();
  ScalarBytes rho_bytes{};
  FieldElement target = FieldElement::zero();
  Bytes challenge_digest;
  std::vector<PointBytes> generators;
  std::vector<PointBytes> raw_generators;
  std::vector<PointBytes> raw_generator_points;
  std::vector<FieldElement> c_vec;
  std::vector<ScalarBytes> c_vec_bytes;
  std::vector<FieldElement> public_commitment_coeffs;
  std::vector<FieldElement> plus_shift;
  std::vector<FieldElement> minus_shift;
  std::vector<FieldElement> plus_terms;
  std::vector<FieldElement> minus_terms;
  std::size_t n_vec_len = 0;
  std::size_t used_l = 0;
};

using CircuitNormArgPublicDataPtr =
    std::shared_ptr<const CircuitNormArgPublicData>;

struct CircuitNormArgReduction {
  CircuitNormArgPublicDataPtr public_data;
  SecretVector<FieldElement> n_vec;
  SecretVector<FieldElement> l_vec;
};

struct CircuitNormArgChallenges {
  FieldElement rho;
  FieldElement mul_scale;
  FieldElement mul_ratio;
  FieldElement row_ratio;
};

struct CircuitNormArgDimensions {
  std::size_t gate_count = 0;
  std::size_t n_vec_len = 0;
  std::size_t l_vec_len = 0;
  std::size_t used_l = 0;
};

Result<CircuitNormArgDimensions> circuit_norm_arg_dimensions(
    const NativeBulletproofCircuit &circuit, bool externalize_commitments);

Result<SecretNormArgInputs>
build_raw_circuit_norm_arg_inputs(const NativeBulletproofCircuit &circuit,
                                  const BulletproofAssignmentData &assignment,
                                  std::span<const FieldElement> padding,
                                  bool externalize_commitments,
                                  purify_secp_context *secp_context);

Result<CircuitNormArgPublicDataPtr> build_circuit_norm_arg_public_data(
    const NativeBulletproofCircuit &circuit,
    std::span<const unsigned char> statement_binding,
    const PointBytes &raw_commitment,
    purify_secp_context *secp_context,
    bool externalize_commitments = false,
    const CircuitNormArgChallenges *explicit_challenges = nullptr);

Result<CircuitNormArgPublicDataPtr>
build_circuit_norm_arg_public_data_from_challenges(
    const NativeBulletproofCircuit &circuit,
    purify_secp_context *secp_context, bool externalize_commitments,
    const CircuitNormArgChallenges &explicit_challenges);

Result<CircuitNormArgReduction> reduce_experimental_circuit_to_norm_arg(
    const NativeBulletproofCircuit &circuit,
    const BulletproofAssignmentData &assignment,
    const PointBytes &raw_commitment,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    bool externalize_commitments = false,
    const CircuitNormArgChallenges *explicit_challenges = nullptr);

SecretNormArgInputs
build_norm_arg_inputs(const CircuitNormArgReduction &reduction);

} // namespace detail

} // namespace purify::bppp
