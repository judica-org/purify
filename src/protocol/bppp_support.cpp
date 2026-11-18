// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file bppp_support.cpp
 * @brief Byte views, generator-backend resolution and challenge-scalar derivation for BPPP.
 */

#include "purify/bppp.hpp"

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <type_traits>
#include <vector>

#include "bppp_support.hpp"
#include "secure_cleanup.hpp"

namespace purify::bppp {

// Helpers shared between the translation units of this module live in detail.
using namespace detail;

namespace {

void secure_clear_field_element(FieldElement &value) noexcept {
  static_assert(std::is_trivially_destructible_v<FieldElement>);
  ::purify::detail::secure_clear_bytes(&value, sizeof(value));
}

using U64Le = std::array<unsigned char, sizeof(std::uint64_t)>;

U64Le u64_le(std::uint64_t value) {
  U64Le out{};
  for (std::size_t i = 0; i < out.size(); ++i) {
    out[i] = static_cast<unsigned char>((value >> (8 * i)) & 0xffU);
  }
  return out;
}

/**
 * Parses `tag(seed || labels...)` as one secret scalar candidate.
 *
 * The seed is hashed where it lies and never copied. A V4 seed carries the
 * whole witness, and one proof derives tens of thousands of scalars from it:
 * a copy per candidate costs more than the rest of the prover and leaves
 * that many more images of the witness to erase.
 */
template <typename... Labels>
Result<FieldElement>
secret_scalar_candidate(const TaggedHash &tag,
                        std::span<const unsigned char> seed,
                        const Labels &...labels) {
  SecretScalarBytes candidate_bytes;
  ScalarBytes digest = tag.digest_many<1 + sizeof...(Labels)>(
      {seed, std::span<const unsigned char>(labels)...});
  candidate_bytes.value = digest;
  ::purify::detail::secure_clear_bytes(digest.data(), digest.size());
  return FieldElement::try_from_bytes32(candidate_bytes.value);
}

} // namespace

namespace detail {

/** @brief Returns true when a bridge call signals success. */
bool require_ok(int ok) { return ok != 0; }

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
  PURIFY_ASSIGN_OR_RETURN(const auto &encoded_index, narrow_size_to_u64(index));
  const U64Le index_le = u64_le(encoded_index);
  for (std::uint64_t counter = 0; counter < 256; ++counter) {
    const U64Le counter_le = u64_le(counter);
    const ScalarBytes candidate_bytes =
        tag.digest_many<3>({seed, index_le, counter_le});
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
  PURIFY_ASSIGN_OR_RETURN(const auto &encoded_index, narrow_size_to_u64(index));
  const U64Le index_le = u64_le(encoded_index);
  const U64Le attempt_le = u64_le(attempt);
  for (std::uint64_t counter = 0; counter < 256; ++counter) {
    Result<FieldElement> candidate = secret_scalar_candidate(
        tag, seed, index_le, attempt_le, u64_le(counter));
    if (candidate.has_value()) {
      out = *candidate;
      secure_clear_field_element(*candidate);
      return {};
    }
  }
  return unexpected_error(ErrorCode::InternalMismatch);
}

Status derive_secret_nonzero_scalar(FieldElement &out,
                                    std::span<const unsigned char> seed,
                                    const TaggedHash &tag,
                                    std::size_t index) {
  PURIFY_ASSIGN_OR_RETURN(const auto &encoded_index, narrow_size_to_u64(index));
  const U64Le index_le = u64_le(encoded_index);
  for (std::uint64_t counter = 0; counter < 256; ++counter) {
    Result<FieldElement> candidate =
        secret_scalar_candidate(tag, seed, index_le, u64_le(counter));
    if (candidate.has_value()) {
      if (!candidate->is_zero()) {
        out = *candidate;
        secure_clear_field_element(*candidate);
        return {};
      }
      secure_clear_field_element(*candidate);
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

} // namespace detail

} // namespace purify::bppp
