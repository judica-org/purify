// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file bppp_circuit_reduction.cpp
 * @brief Reduction of a native circuit and its assignment to BPPP norm-argument inputs.
 */

#include "purify/bppp.hpp"

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <memory>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

#include "bppp_circuit_reduction.hpp"
#include "bppp_internal.hpp"
#include "bppp_points.hpp"
#include "bppp_support.hpp"
#include "bulletproof_internal.hpp"

namespace purify::bppp {

// Helpers shared between the translation units of this module live in detail.
using namespace detail;

namespace {

constexpr std::string_view kCircuitNormArgRhoTag =
    "Purify/BPPP/CircuitNormArgV3/Rho";
constexpr std::string_view kCircuitNormArgMulTag =
    "Purify/BPPP/CircuitNormArgV3/Mul";
constexpr std::string_view kCircuitNormArgConstraintTag =
    "Purify/BPPP/CircuitNormArgV3/Constraint";

constexpr std::string_view kCircuitNormArgPrecommitTag =
    "Purify/BPPP/CircuitNormArgV3/Precommit";

const TaggedHash kCircuitNormArgRhoTaggedHash(kCircuitNormArgRhoTag);
const TaggedHash kCircuitNormArgMulTaggedHash(kCircuitNormArgMulTag);
const TaggedHash kCircuitNormArgConstraintTaggedHash(kCircuitNormArgConstraintTag);
const TaggedHash kCircuitNormArgPrecommitTaggedHash(kCircuitNormArgPrecommitTag);

Result<Bytes> circuit_norm_arg_precommit_digest(
    std::span<const unsigned char> binding_digest,
    const PointBytes &raw_commitment) {
  Bytes seed(binding_digest.begin(), binding_digest.end());
  seed.insert(seed.end(), raw_commitment.begin(), raw_commitment.end());
  const ScalarBytes digest = kCircuitNormArgPrecommitTaggedHash.digest(seed);
  return Bytes(digest.begin(), digest.end());
}

} // namespace

namespace detail {

Result<CircuitNormArgDimensions> circuit_norm_arg_dimensions(
    const NativeBulletproofCircuit &circuit, bool externalize_commitments) {
  CircuitNormArgDimensions out;
  const std::size_t committed_values =
      externalize_commitments ? 0 : circuit.n_commitments;
  std::size_t minimum_gate_count = 0;
  if (!(CheckedSize(committed_values) + 1).store(minimum_gate_count)) {
    return unexpected_error(ErrorCode::Overflow);
  }
  PURIFY_ASSIGN_OR_RETURN(
      out.gate_count,
      round_up_power_of_two(std::max(circuit.n_gates, minimum_gate_count)));
  if (!(CheckedSize(out.gate_count) + committed_values).store(out.used_l) ||
      !(CheckedSize(out.gate_count) * 2).store(out.n_vec_len)) {
    return unexpected_error(ErrorCode::Overflow);
  }
  out.l_vec_len = out.n_vec_len;
  assert(out.used_l < out.l_vec_len &&
         "virtual gate padding must leave a hiding coordinate");
  return out;
}

Result<SecretNormArgInputs>
build_raw_circuit_norm_arg_inputs(const NativeBulletproofCircuit &circuit,
                                  const BulletproofAssignmentData &assignment,
                                  std::span<const FieldElement> padding,
                                  bool externalize_commitments,
                                  purify_secp_context *secp_context) {
  if (assignment.left.size() != circuit.n_gates ||
      assignment.right.size() != circuit.n_gates ||
      assignment.output.size() != circuit.n_gates ||
      assignment.commitments.size() != circuit.n_commitments) {
    return unexpected_error(ErrorCode::SizeMismatch);
  }
  PURIFY_ASSIGN_OR_RETURN(
      const auto &dimensions,
      circuit_norm_arg_dimensions(circuit, externalize_commitments));
  const std::size_t padding_size = dimensions.l_vec_len - dimensions.used_l;
  if (!padding.empty() && padding.size() != padding_size) {
    return unexpected_error(ErrorCode::SizeMismatch);
  }

  std::size_t generator_count = 0;
  if (!(CheckedSize(dimensions.n_vec_len) + dimensions.l_vec_len)
           .store(generator_count)) {
    return unexpected_error(ErrorCode::Overflow);
  }

  SecretNormArgInputs out;
  PURIFY_ASSIGN_OR_RETURN(out.generators,
                          create_generators(generator_count, secp_context));
  SecretVector<FieldElement> raw_n(dimensions.n_vec_len, FieldElement::zero());
  SecretVector<FieldElement> raw_l(dimensions.l_vec_len, FieldElement::zero());
  for (std::size_t i = 0; i < circuit.n_gates; ++i) {
    raw_n[2 * i] = assignment.left[i] + assignment.right[i];
    raw_n[2 * i + 1] = assignment.left[i] - assignment.right[i];
    raw_l[i] = assignment.output[i];
  }
  if (!externalize_commitments) {
    for (std::size_t i = 0; i < circuit.n_commitments; ++i) {
      raw_l[dimensions.gate_count + i] = assignment.commitments[i];
    }
  }
  if (!padding.empty()) {
    std::copy(padding.begin(), padding.end(),
              raw_l.begin() + dimensions.used_l);
  }
  out.n_vec = scalar_bytes(raw_n);
  out.l_vec = scalar_bytes(raw_l);
  return out;
}

} // namespace detail

namespace {

/** The reduction challenges and, when they were derived here, the digest they come from. */
struct ReductionChallenges {
  CircuitNormArgChallenges values;
  Bytes digest;
};

/**
 * Takes the challenges the caller supplies, or derives them from the circuit
 * binding and the raw witness commitment.
 */
Result<ReductionChallenges> reduction_challenges(
    const NativeBulletproofCircuit &circuit,
    std::span<const unsigned char> statement_binding,
    const PointBytes *raw_commitment,
    const CircuitNormArgChallenges *explicit_challenges) {
  Bytes challenge_digest;
  FieldElement rho = FieldElement::zero();
  FieldElement mul_scale = FieldElement::zero();
  FieldElement mul_ratio = FieldElement::zero();
  FieldElement row_ratio = FieldElement::zero();
  if (explicit_challenges != nullptr) {
    rho = explicit_challenges->rho;
    mul_scale = explicit_challenges->mul_scale;
    mul_ratio = explicit_challenges->mul_ratio;
    row_ratio = explicit_challenges->row_ratio;
  } else {
    if (raw_commitment == nullptr) {
      return unexpected_error(ErrorCode::InternalMismatch);
    }
    PURIFY_ASSIGN_OR_RETURN(
        const auto &binding_digest,
        experimental_circuit_binding_digest(circuit, statement_binding));
    PURIFY_ASSIGN_OR_RETURN(
        challenge_digest,
        circuit_norm_arg_precommit_digest(binding_digest, *raw_commitment));
    PURIFY_ASSIGN_OR_RETURN(
        rho, derive_nonzero_scalar(challenge_digest,
                                   kCircuitNormArgRhoTaggedHash, 0));
    PURIFY_ASSIGN_OR_RETURN(
        mul_scale, derive_nonzero_scalar(challenge_digest,
                                         kCircuitNormArgMulTaggedHash, 0));
    PURIFY_ASSIGN_OR_RETURN(
        mul_ratio, derive_nonzero_scalar(challenge_digest,
                                         kCircuitNormArgMulTaggedHash, 1));
    if (!circuit.c.empty()) {
      PURIFY_ASSIGN_OR_RETURN(
          row_ratio,
          derive_nonzero_scalar(challenge_digest,
                                kCircuitNormArgConstraintTaggedHash, 0));
    }
  }
  return ReductionChallenges{
      CircuitNormArgChallenges{rho, mul_scale, mul_ratio, row_ratio},
      std::move(challenge_digest)};
}

/**
 * Folds the circuit's constraint rows into one weighted equation and
 * completes the square on each gate: the per-gate terms and shifts, the
 * coefficient vector and the target constant.
 */
std::shared_ptr<CircuitNormArgPublicData> fold_circuit_constraints(
    const NativeBulletproofCircuit &circuit,
    const CircuitNormArgDimensions &dimensions,
    const ReductionChallenges &challenges, const FieldElement &sqrt_minus_one,
    bool externalize_commitments) {
  const FieldElement &rho = challenges.values.rho;
  const FieldElement &mul_scale = challenges.values.mul_scale;
  const FieldElement &mul_ratio = challenges.values.mul_ratio;
  const FieldElement &row_ratio = challenges.values.row_ratio;
  const Bytes &challenge_digest = challenges.digest;

  const FieldElement zero = FieldElement::zero();
  const FieldElement two = FieldElement::from_int(2);
  const FieldElement four = FieldElement::from_int(4);
  const FieldElement inv2 = two.inverse();

  std::vector<FieldElement> mul_weights(dimensions.gate_count, zero);
  std::vector<FieldElement> plus_terms(dimensions.gate_count, zero);
  std::vector<FieldElement> minus_terms(dimensions.gate_count, zero);
  FieldElement mul_term = mul_scale;
  for (std::size_t i = 0; i < dimensions.gate_count; ++i) {
    plus_terms[i] = mul_term;
    minus_terms[i] = sqrt_minus_one * mul_term;
    mul_weights[i] = four * mul_term * mul_term;
    mul_term = mul_term * mul_ratio;
  }

  std::vector<FieldElement> row_weights(circuit.c.size(), zero);
  if (!row_weights.empty()) {
    FieldElement row_weight = row_ratio;
    for (FieldElement &weight : row_weights) {
      weight = row_weight;
      row_weight = row_weight * row_ratio;
    }
  }

  std::vector<FieldElement> left_coeffs(dimensions.gate_count, zero);
  std::vector<FieldElement> right_coeffs(dimensions.gate_count, zero);
  std::vector<FieldElement> output_coeffs(dimensions.gate_count, zero);
  std::vector<FieldElement> commitment_coeffs(circuit.n_commitments, zero);
  for (std::size_t i = 0; i < dimensions.gate_count; ++i) {
    output_coeffs[i] = mul_weights[i].negate();
  }

  FieldElement constant = zero;
  for (std::size_t j = 0; j < circuit.c.size(); ++j) {
    constant = constant - (row_weights[j] * circuit.c[j]);
  }

  auto accumulate_coeffs =
      [&](const std::vector<NativeBulletproofCircuitRow> &rows,
          std::vector<FieldElement> &coeffs, bool negate_entries) {
        for (std::size_t i = 0; i < rows.size(); ++i) {
          for (const NativeBulletproofCircuitTerm &entry : rows[i].entries) {
            const FieldElement scalar =
                negate_entries ? entry.scalar.negate() : entry.scalar;
            coeffs[i] = coeffs[i] + (row_weights[entry.idx] * scalar);
          }
        }
      };
  accumulate_coeffs(circuit.wl, left_coeffs, false);
  accumulate_coeffs(circuit.wr, right_coeffs, false);
  accumulate_coeffs(circuit.wo, output_coeffs, false);
  accumulate_coeffs(circuit.wv, commitment_coeffs, true);

  auto out = std::make_shared<CircuitNormArgPublicData>();
  out->rho = rho;
  out->rho_bytes = scalar_bytes(rho);
  out->mul_scale = mul_scale;
  out->mul_ratio = mul_ratio;
  out->challenge_digest = challenge_digest;
  out->plus_terms = std::move(plus_terms);
  out->minus_terms = std::move(minus_terms);
  out->plus_shift.resize(dimensions.gate_count, zero);
  out->minus_shift.resize(dimensions.gate_count, zero);

  for (std::size_t i = 0; i < dimensions.gate_count; ++i) {
    const FieldElement d_plus = out->plus_terms[i] * out->plus_terms[i];
    const FieldElement d_minus = d_plus.negate();
    const FieldElement e_plus = (left_coeffs[i] + right_coeffs[i]) * inv2;
    const FieldElement e_minus = (left_coeffs[i] - right_coeffs[i]) * inv2;

    out->plus_shift[i] = e_plus * (two * d_plus).inverse();
    out->minus_shift[i] = e_minus * (two * d_minus).inverse();
    constant = constant - ((e_plus * e_plus) * (four * d_plus).inverse());
    constant = constant - ((e_minus * e_minus) * (four * d_minus).inverse());
  }

  out->used_l = dimensions.used_l;
  out->n_vec_len = dimensions.n_vec_len;
  out->c_vec.assign(dimensions.l_vec_len, zero);
  for (std::size_t i = 0; i < dimensions.gate_count; ++i) {
    out->c_vec[i] = output_coeffs[i];
  }
  if (externalize_commitments) {
    out->public_commitment_coeffs = std::move(commitment_coeffs);
  } else {
    for (std::size_t i = 0; i < circuit.n_commitments; ++i) {
      out->c_vec[dimensions.gate_count + i] = commitment_coeffs[i];
    }
  }
  out->target = constant.negate();
  out->c_vec_bytes = scalar_bytes(out->c_vec);
  return out;
}

/**
 * Creates the raw generators and scales the i-th G generator by rho^(i+1)
 * over its multiplication term; the H generators stay raw.
 */
Status scale_reduction_generators(
    const std::shared_ptr<CircuitNormArgPublicData> &out,
    const CircuitNormArgDimensions &dimensions,
    const FieldElement &sqrt_minus_one, purify_secp_context *secp_context) {
  const FieldElement &rho = out->rho;
  const FieldElement &mul_scale = out->mul_scale;
  const FieldElement &mul_ratio = out->mul_ratio;

  std::size_t raw_n_value_count = 0;
  std::size_t generator_count = 0;
  if (!(CheckedSize(dimensions.gate_count) * 2).store(raw_n_value_count) ||
      !(CheckedSize(out->n_vec_len) + out->c_vec.size())
           .store(generator_count)) {
    return unexpected_error(ErrorCode::Overflow);
  }
  PURIFY_ASSIGN_OR_RETURN(auto generators,
                          create_generators(generator_count, secp_context));
  out->raw_generators = generators;
  out->generators = std::move(generators);
  out->raw_generator_points.reserve(raw_n_value_count);
  for (std::size_t i = 0; i < raw_n_value_count; ++i) {
    PURIFY_ASSIGN_OR_RETURN(
        auto point, generator_to_point(out->raw_generators[i], secp_context));
    out->raw_generator_points.push_back(point);
  }

  FieldElement rho_power = rho;
  FieldElement generator_term = mul_scale;
  for (std::size_t i = 0; i < out->n_vec_len; ++i) {
    const FieldElement term =
        (i % 2 == 0) ? generator_term : sqrt_minus_one * generator_term;
    PURIFY_ASSIGN_OR_RETURN(out->generators[i],
                            generator_scale(out->raw_generators[i],
                                            rho_power * term.inverse(),
                                            secp_context));
    if (i % 2 == 1) {
      generator_term = generator_term * mul_ratio;
    }
    rho_power = rho_power * rho;
  }
  return {};
}

Result<CircuitNormArgPublicDataPtr> build_circuit_norm_arg_public_data_impl(
    const NativeBulletproofCircuit &circuit,
    std::span<const unsigned char> statement_binding,
    const PointBytes *raw_commitment,
    purify_secp_context *secp_context,
    bool externalize_commitments = false,
    ExperimentalCircuitBackend *cache = nullptr,
    const CircuitNormArgChallenges *explicit_challenges = nullptr) {
  (void)cache;
  PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context));
  if (!circuit.has_valid_shape()) {
    return unexpected_error(ErrorCode::InvalidDimensions);
  }
  if (!is_power_of_two_size(circuit.n_gates)) {
    return unexpected_error(ErrorCode::InvalidDimensions);
  }

  PURIFY_ASSIGN_OR_RETURN(
      const auto &challenges,
      reduction_challenges(circuit, statement_binding, raw_commitment,
                           explicit_challenges));
  PURIFY_ASSIGN_OR_RETURN(
      const auto &dimensions,
      circuit_norm_arg_dimensions(circuit, externalize_commitments));
  PURIFY_ASSIGN_OR_RETURN(const auto &sqrt_minus_one,
                          detail::canonical_sqrt_minus_one());

  auto out = fold_circuit_constraints(circuit, dimensions, challenges,
                                      sqrt_minus_one, externalize_commitments);
  PURIFY_RETURN_IF_ERROR(scale_reduction_generators(out, dimensions,
                                                    sqrt_minus_one, secp_context));
  CircuitNormArgPublicDataPtr shared = out;
  return shared;
}

} // namespace

namespace detail {

Result<CircuitNormArgPublicDataPtr> build_circuit_norm_arg_public_data(
    const NativeBulletproofCircuit &circuit,
    std::span<const unsigned char> statement_binding,
    const PointBytes &raw_commitment,
    purify_secp_context *secp_context,
    bool externalize_commitments,
    ExperimentalCircuitBackend *cache,
    const CircuitNormArgChallenges *explicit_challenges) {
  return build_circuit_norm_arg_public_data_impl(
      circuit, statement_binding, &raw_commitment, secp_context,
      externalize_commitments, cache, explicit_challenges);
}

Result<CircuitNormArgPublicDataPtr>
build_circuit_norm_arg_public_data_from_challenges(
    const NativeBulletproofCircuit &circuit,
    purify_secp_context *secp_context, bool externalize_commitments,
    ExperimentalCircuitBackend *cache,
    const CircuitNormArgChallenges &explicit_challenges) {
  return build_circuit_norm_arg_public_data_impl(
      circuit, {}, nullptr, secp_context, externalize_commitments, cache,
      &explicit_challenges);
}

Result<CircuitNormArgReduction> reduce_experimental_circuit_to_norm_arg(
    const NativeBulletproofCircuit &circuit,
    const BulletproofAssignmentData &assignment,
    const PointBytes &raw_commitment,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    bool externalize_commitments,
    ExperimentalCircuitBackend *cache,
    const CircuitNormArgChallenges *explicit_challenges) {
  if (assignment.left.size() != circuit.n_gates ||
      assignment.right.size() != circuit.n_gates ||
      assignment.output.size() != circuit.n_gates ||
      assignment.commitments.size() != circuit.n_commitments) {
    return unexpected_error(ErrorCode::SizeMismatch);
  }

  PURIFY_ASSIGN_OR_RETURN(const auto &public_data,
                          build_circuit_norm_arg_public_data(
                              circuit, statement_binding, raw_commitment,
                              secp_context, externalize_commitments, cache,
                              explicit_challenges));

  CircuitNormArgReduction out;
  out.public_data = public_data;
  out.n_vec.assign(out.public_data->n_vec_len, FieldElement::zero());
  out.l_vec.assign(out.public_data->c_vec.size(), FieldElement::zero());

  const FieldElement rho_inv = out.public_data->rho.inverse();
  FieldElement rho_weight_inv = rho_inv;
  for (std::size_t i = 0; i < circuit.n_gates; ++i) {
    FieldElement plus_value = assignment.left[i] + assignment.right[i] +
                              out.public_data->plus_shift[i];
    WipeOnDestruction plus_value_wiper(plus_value);
    out.n_vec[2 * i] =
        out.public_data->plus_terms[i] * plus_value * rho_weight_inv;
    rho_weight_inv = rho_weight_inv * rho_inv;

    FieldElement minus_value = assignment.left[i] - assignment.right[i] +
                               out.public_data->minus_shift[i];
    WipeOnDestruction minus_value_wiper(minus_value);
    out.n_vec[2 * i + 1] =
        out.public_data->minus_terms[i] * minus_value * rho_weight_inv;
    rho_weight_inv = rho_weight_inv * rho_inv;

    out.l_vec[i] = assignment.output[i];
  }
  if (!externalize_commitments) {
    for (std::size_t i = 0; i < circuit.n_commitments; ++i) {
      out.l_vec[out.public_data->plus_terms.size() + i] =
          assignment.commitments[i];
    }
  }
  return out;
}

SecretNormArgInputs
build_norm_arg_inputs(const CircuitNormArgReduction &reduction) {
  SecretNormArgInputs inputs;
  inputs.rho = reduction.public_data->rho_bytes;
  inputs.generators = reduction.public_data->generators;
  inputs.n_vec = scalar_bytes(reduction.n_vec);
  inputs.l_vec = scalar_bytes(reduction.l_vec);
  inputs.c_vec = reduction.public_data->c_vec_bytes;
  return inputs;
}

} // namespace detail

} // namespace purify::bppp
