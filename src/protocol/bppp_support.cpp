// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file bppp_support.cpp
 * @brief Byte views, generator-backend resolution and challenge-scalar derivation for BPPP.
 */

#include "purify/bppp.hpp"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <vector>

#include "bppp_support.hpp"
#include "secure_cleanup.hpp"

namespace purify::bppp::detail {

ResolvedBpppGeneratorBackend resolve_bppp_generator_backend(
    ExperimentalCircuitBackend *cache,
    const std::vector<PointBytes> &serialized_generators,
    purify_secp_context *secp_context) {
  ResolvedBpppGeneratorBackend out;
  out.serialized_bytes = byte_span(serialized_generators);
  out.generator_count = serialized_generators.size();

  if (cache == nullptr || serialized_generators.empty()) {
    return out;
  }
  out.backend_resources =
      detail::ExperimentalCircuitBackendAccess::get_or_create_backend_resources(
          cache, serialized_generators, secp_context);
  return out;
}

Result<std::size_t> round_up_power_of_two(std::size_t value) {
  if (value == 0) {
    return unexpected_error(ErrorCode::Overflow);
  }
  std::size_t out = 1;
  while (out < value) {
    if (out > std::numeric_limits<std::size_t>::max() / 2) {
      return unexpected_error(ErrorCode::Overflow);
    }
    out <<= 1;
  }
  return out;
}

Result<FieldElement> derive_nonzero_scalar(std::span<const unsigned char> seed,
                                           const TaggedHash& tag,
                                           std::size_t index) {
  Bytes prefix(seed.begin(), seed.end());
  PURIFY_ASSIGN_OR_RETURN(const auto &encoded_index, narrow_size_to_u64(index));
  append_u64_le(prefix, encoded_index);
  for (std::uint64_t counter = 0; counter < 256; ++counter) {
    Bytes input = prefix;
    append_u64_le(input, counter);
    ScalarBytes candidate_bytes{};
    candidate_bytes =
        tag.digest(std::span<const unsigned char>(input.data(), input.size()));
    Result<FieldElement> candidate =
        FieldElement::try_from_bytes32(candidate_bytes);
    if (candidate.has_value() && !candidate->is_zero()) {
      return candidate;
    }
  }
  return unexpected_error(ErrorCode::InternalMismatch);
}

Status derive_scalar(FieldElement &out, std::span<const unsigned char> seed,
                     const TaggedHash &tag, std::size_t index,
                     std::uint64_t attempt) {
  SecretBytes prefix;
  prefix.reserve(seed.size() + 2 * sizeof(std::uint64_t));
  prefix.assign(seed.begin(), seed.end());
  PURIFY_ASSIGN_OR_RETURN(const auto &encoded_index, narrow_size_to_u64(index));
  append_u64_le(prefix, encoded_index);
  append_u64_le(prefix, attempt);
  for (std::uint64_t counter = 0; counter < 256; ++counter) {
    SecretBytes input;
    input.reserve(prefix.size() + sizeof(std::uint64_t));
    input.assign(prefix.begin(), prefix.end());
    append_u64_le(input, counter);
    SecretScalarBytes candidate_bytes;
    ScalarBytes digest =
        tag.digest(std::span<const unsigned char>(input.data(), input.size()));
    candidate_bytes.value = digest;
    ::purify::detail::secure_clear_bytes(digest.data(), digest.size());
    Result<FieldElement> candidate =
        FieldElement::try_from_bytes32(candidate_bytes.value);
    if (candidate.has_value()) {
      out = *candidate;
      ::purify::detail::secure_erase(*candidate);
      return {};
    }
  }
  return unexpected_error(ErrorCode::InternalMismatch);
}

Status derive_secret_nonzero_scalar(FieldElement &out,
                                    std::span<const unsigned char> seed,
                                    const TaggedHash &tag,
                                    std::size_t index) {
  SecretBytes prefix;
  prefix.reserve(seed.size() + sizeof(std::uint64_t));
  prefix.assign(seed.begin(), seed.end());
  PURIFY_ASSIGN_OR_RETURN(const auto &encoded_index, narrow_size_to_u64(index));
  append_u64_le(prefix, encoded_index);
  for (std::uint64_t counter = 0; counter < 256; ++counter) {
    SecretBytes input;
    input.reserve(prefix.size() + sizeof(std::uint64_t));
    input.assign(prefix.begin(), prefix.end());
    append_u64_le(input, counter);
    SecretScalarBytes candidate_bytes;
    ScalarBytes digest =
        tag.digest(std::span<const unsigned char>(input.data(), input.size()));
    candidate_bytes.value = digest;
    ::purify::detail::secure_clear_bytes(digest.data(), digest.size());
    Result<FieldElement> candidate =
        FieldElement::try_from_bytes32(candidate_bytes.value);
    if (candidate.has_value()) {
      if (!candidate->is_zero()) {
        out = *candidate;
        ::purify::detail::secure_erase(*candidate);
        return {};
      }
      ::purify::detail::secure_erase(*candidate);
    }
  }
  return unexpected_error(ErrorCode::InternalMismatch);
}

FieldElement weighted_bppp_inner_product(std::span<const FieldElement> lhs,
                                         std::span<const FieldElement> rhs,
                                         const FieldElement &rho) {
  assert(lhs.size() == rhs.size() &&
         "weighted_bppp_inner_product requires matching vector lengths");
  FieldElement mu = rho * rho;
  FieldElement weight = mu;
  FieldElement total = FieldElement::zero();
  for (std::size_t i = 0; i < lhs.size(); ++i) {
    total = total + (weight * lhs[i] * rhs[i]);
    weight = weight * mu;
  }
  return total;
}

} // namespace purify::bppp::detail
