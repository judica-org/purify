// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file bppp_points.cpp
 * @brief Curve-point arithmetic and commitment construction over the secp256k1 bridge.
 */

#include "purify/bppp.hpp"

#include <algorithm>
#include <cstddef>
#include <span>
#include <utility>
#include <vector>

#include "bppp_bridge.h"
#include "bppp_circuit_reduction.hpp"
#include "bppp_points.hpp"
#include "bppp_support.hpp"
#include "purify/secp_bridge.h"

namespace purify::bppp::detail {

Result<PointBytes>
commit_norm_arg_witness_only(const NormArgInputs &inputs,
                             purify_secp_context *secp_context,
                             ExperimentalCircuitBackend *cache) {
  PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context));
  if (inputs.n_vec.empty() || inputs.l_vec.empty()) {
    return unexpected_error(ErrorCode::EmptyInput);
  }
  if (!inputs.generators.empty() &&
      inputs.generators.size() != inputs.n_vec.size() + inputs.l_vec.size()) {
    return unexpected_error(ErrorCode::SizeMismatch);
  }

  const std::vector<PointBytes> *generators = &inputs.generators;
  std::vector<PointBytes> generated_generators;
  if (generators->empty()) {
    PURIFY_ASSIGN_OR_RETURN(
        auto generated,
        create_generators(inputs.n_vec.size() + inputs.l_vec.size(),
                          secp_context));
    generated_generators = std::move(generated);
    generators = &generated_generators;
  }

  std::span<const unsigned char> n_vec = byte_span(inputs.n_vec);
  std::span<const unsigned char> l_vec = byte_span(inputs.l_vec);
  ResolvedBpppGeneratorBackend resolved =
      resolve_bppp_generator_backend(cache, *generators, secp_context);
  PointBytes commitment{};
  const int ok =
      resolved.backend_resources != nullptr
          ? purify_bppp_commit_witness_only_with_resources(
                resolved.backend_resources, n_vec.data(), inputs.n_vec.size(),
                l_vec.data(), inputs.l_vec.size(), commitment.data())
          : purify_bppp_commit_witness_only(
                secp_context, resolved.serialized_bytes.data(),
                resolved.generator_count,
                n_vec.data(), inputs.n_vec.size(), l_vec.data(),
                inputs.l_vec.size(), commitment.data());
  if (ok == 0) {
    return unexpected_error(ErrorCode::BackendRejectedInput);
  }
  return commitment;
}

namespace {

Result<PointBytes> offset_commitment(const PointBytes &commitment,
                                     const FieldElement &scalar,
                                     purify_secp_context *secp_context) {
  PointBytes out{};
  SecretScalarBytes scalar32;
  purify_scalar_get_b32(
      scalar32.value.data(),
      &::purify::detail::FieldElementAccess::raw(scalar));
  PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context));
  if (purify_bppp_offset_commitment(secp_context, commitment.data(),
                                scalar32.value.data(), out.data()) == 0) {
    return unexpected_error(ErrorCode::BackendRejectedInput);
  }
  return out;
}

} // namespace

Result<PointBytes> point_scale(const PointBytes &point,
                               const FieldElement &scalar,
                               purify_secp_context *secp_context) {
  PointBytes out{};
  SecretScalarBytes scalar32;
  purify_scalar_get_b32(
      scalar32.value.data(),
      &::purify::detail::FieldElementAccess::raw(scalar));
  PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context));
  if (purify_point_scale(secp_context, point.data(),
                         scalar32.value.data(), out.data()) == 0) {
    return unexpected_error(ErrorCode::BackendRejectedInput);
  }
  return out;
}

Result<PointBytes> generator_scale(const PointBytes &generator,
                                   const FieldElement &scalar,
                                   purify_secp_context *secp_context) {
  PointBytes out{};
  SecretScalarBytes scalar32;
  purify_scalar_get_b32(
      scalar32.value.data(),
      &::purify::detail::FieldElementAccess::raw(scalar));
  PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context));
  if (purify_bppp_scale_generator(
          secp_context, generator.data(), scalar32.value.data(),
          out.data()) == 0) {
    return unexpected_error(ErrorCode::BackendRejectedInput);
  }
  return out;
}

Result<PointBytes> generator_to_point(const PointBytes &generator,
                                      purify_secp_context *secp_context) {
  PointBytes out{};
  PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context));
  if (purify_bppp_generator_to_point(
          secp_context, generator.data(), out.data()) == 0) {
    return unexpected_error(ErrorCode::BackendRejectedInput);
  }
  return out;
}

Result<PointBytes> point_add(const PointBytes &lhs,
                             const PointBytes &rhs,
                             purify_secp_context *secp_context) {
  PointBytes out{};
  PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context));
  if (purify_point_add(secp_context, lhs.data(), rhs.data(), out.data()) == 0) {
    return unexpected_error(ErrorCode::BackendRejectedInput);
  }
  return out;
}

namespace {

Result<PointBytes> point_add_allow_infinity(
    const PointBytes &lhs, const PointBytes &rhs,
    purify_secp_context *secp_context) {
  PointBytes out{};
  PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context));
  if (purify_point_add_allow_infinity(
          secp_context, lhs.data(), rhs.data(), out.data()) == 0) {
    return unexpected_error(ErrorCode::BackendRejectedInput);
  }
  return out;
}

} // namespace

Result<PointBytes> point_subtract_allow_infinity(
    const PointBytes &lhs, const PointBytes &rhs,
    purify_secp_context *secp_context) {
  PointBytes out{};
  PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context));
  if (purify_point_subtract_allow_infinity(
          secp_context, lhs.data(), rhs.data(), out.data()) == 0) {
    return unexpected_error(ErrorCode::BackendRejectedInput);
  }
  return out;
}

Result<PointBytes> point_from_scalar_base(const FieldElement &scalar,
                                          purify_secp_context *secp_context) {
  ScalarBytes blind{};
  SecretScalarBytes value;
  purify_scalar_get_b32(
      value.value.data(),
      &::purify::detail::FieldElementAccess::raw(scalar));
  return pedersen_commit_char(blind, value.value, secp_context,
                              base_generator(secp_context),
                              base_generator(secp_context));
}

namespace {

Result<PointBytes> add_scaled_points_allow_infinity(
    const PointBytes &base_commitment,
    std::span<const PointBytes> points,
    std::span<const FieldElement> scalars,
    purify_secp_context *secp_context) {
  if (points.size() != scalars.size()) {
    return unexpected_error(ErrorCode::SizeMismatch);
  }
  PointBytes out = base_commitment;
  for (std::size_t i = 0; i < points.size(); ++i) {
    if (scalars[i].is_zero()) {
      continue;
    }
    PURIFY_ASSIGN_OR_RETURN(const auto &scaled,
                            point_scale(points[i], scalars[i], secp_context));
    PURIFY_ASSIGN_OR_RETURN(
        out, point_add_allow_infinity(out, scaled, secp_context));
  }
  return out;
}

} // namespace

Result<PointBytes> circuit_anchored_offset_v4(
    const CircuitNormArgPublicData &public_data,
    std::span<const PointBytes> public_commitments,
    purify_secp_context *secp_context) {
  if (public_commitments.size() !=
      public_data.public_commitment_coeffs.size()) {
    return unexpected_error(ErrorCode::SizeMismatch);
  }

  std::vector<PointBytes> points;
  std::vector<FieldElement> scalars;
  points.reserve(public_data.plus_shift.size() * 2 +
                 public_commitments.size() + 1);
  scalars.reserve(points.capacity());
  for (std::size_t i = 0; i < public_data.plus_shift.size(); ++i) {
    points.push_back(public_data.raw_generator_points[2 * i]);
    scalars.push_back(public_data.plus_shift[i]);
    points.push_back(public_data.raw_generator_points[2 * i + 1]);
    scalars.push_back(public_data.minus_shift[i]);
  }
  if (!public_data.target.is_zero()) {
    PURIFY_ASSIGN_OR_RETURN(
        auto target, point_from_scalar_base(public_data.target, secp_context));
    points.push_back(std::move(target));
    scalars.push_back(FieldElement::one());
  }
  for (std::size_t i = 0; i < public_commitments.size(); ++i) {
    points.push_back(public_commitments[i]);
    scalars.push_back(
        public_data.public_commitment_coeffs[i].negate());
  }
  return add_scaled_points_allow_infinity(
      PointBytes{}, points, scalars, secp_context);
}

Result<PointBytes>
anchor_zk_a_commitment(const PointBytes &a_witness_commitment,
                       const CircuitNormArgPublicData &public_data,
                       std::span<const PointBytes> public_commitments,
                       purify_secp_context *secp_context) {
  PURIFY_ASSIGN_OR_RETURN(const auto &offset,
                          circuit_anchored_offset_v4(
                              public_data, public_commitments, secp_context));
  PURIFY_ASSIGN_OR_RETURN(
      const auto &anchored,
      point_add_allow_infinity(a_witness_commitment, offset, secp_context));
  if (anchored == PointBytes{}) {
    return unexpected_error(ErrorCode::BackendRejectedInput);
  }
  return anchored;
}

Result<PointBytes> coefficient_commitment_v4(
    const CircuitNormArgPublicData &public_data,
    purify_secp_context *secp_context) {
  const bool all_zero =
      std::all_of(public_data.c_vec.begin(), public_data.c_vec.end(),
                  [](const FieldElement &value) { return value.is_zero(); });
  if (all_zero) {
    return PointBytes{};
  }

  NormArgInputs inputs;
  inputs.generators = public_data.raw_generators;
  inputs.n_vec.assign(public_data.n_vec_len, ScalarBytes{});
  inputs.l_vec = public_data.c_vec_bytes;
  return commit_norm_arg_witness_only(inputs, secp_context, nullptr);
}

Result<PointBytes>
commit_explicit_norm_arg(const NormArgInputs &inputs, const FieldElement &value,
                         purify_secp_context *secp_context,
                         ExperimentalCircuitBackend *cache) {
  PURIFY_ASSIGN_OR_RETURN(
      const auto &witness_commitment,
      commit_norm_arg_witness_only(inputs, secp_context, cache));
  return offset_commitment(witness_commitment, value, secp_context);
}

Result<PointBytes> combine_zk_commitments(const PointBytes &a_commitment,
                                          const PointBytes &s_commitment,
                                          const FieldElement &challenge,
                                          const FieldElement &t2,
                                          purify_secp_context *secp_context) {
  PURIFY_ASSIGN_OR_RETURN(const auto &scaled_s, point_scale(s_commitment, challenge, secp_context));
  PURIFY_ASSIGN_OR_RETURN(const auto &combined, point_add(a_commitment, scaled_s, secp_context));
  return offset_commitment(combined, challenge * challenge * t2, secp_context);
}

} // namespace purify::bppp::detail
