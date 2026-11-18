// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file bppp_public_commitments.cpp
 * @brief Batching of public commitments and their discrete-log proofs.
 */

#include "purify/bppp.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <span>
#include <string_view>

#include "bppp_points.hpp"
#include "bppp_public_commitments.hpp"
#include "bppp_support.hpp"
#include "purify/secp_bridge.h"

namespace purify::bppp {

// Helpers shared between the translation units of this module live in detail.
using namespace detail;

namespace {

constexpr std::string_view kCircuitNormArgPublicCommitmentTag =
    "Purify/BPPP/CircuitNormArgV3/PublicCommitments";

constexpr std::string_view kCircuitDlogBatchTag =
    "Purify/BPPP/CircuitNormArgV3/DLogBatch";
constexpr std::string_view kCircuitDlogNonceTag =
    "Purify/BPPP/CircuitNormArgV3/DLogNonce";
constexpr std::string_view kCircuitDlogChallengeTag =
    "Purify/BPPP/CircuitNormArgV3/DLogChallenge";

const TaggedHash kCircuitDlogBatchTaggedHash(kCircuitDlogBatchTag);
const TaggedHash kCircuitDlogNonceTaggedHash(kCircuitDlogNonceTag);
const TaggedHash kCircuitDlogChallengeTaggedHash(kCircuitDlogChallengeTag);

} // namespace

namespace detail {

Result<BatchedPublicCommitment> batch_public_commitments_with_eta(
    std::span<const PointBytes> public_commitments,
    const FieldElement &eta,
    purify_secp_context *secp_context) {
  if (public_commitments.empty()) {
    return unexpected_error(ErrorCode::EmptyInput);
  }

  BatchedPublicCommitment out;
  out.point = public_commitments.front();
  out.weights.reserve(public_commitments.size());
  out.weights.push_back(FieldElement::one());
  FieldElement weight = eta;
  for (std::size_t i = 1; i < public_commitments.size(); ++i) {
    PURIFY_ASSIGN_OR_RETURN(
        const auto &scaled,
        point_scale(public_commitments[i], weight, secp_context));
    PURIFY_ASSIGN_OR_RETURN(out.point,
                            point_add(out.point, scaled, secp_context));
    out.weights.push_back(weight);
    weight = weight * eta;
  }
  return out;
}

Result<BatchedPublicCommitment> batch_public_commitments(
    std::span<const PointBytes> public_commitments,
    std::span<const unsigned char> challenge_digest,
    purify_secp_context *secp_context) {
  PURIFY_ASSIGN_OR_RETURN(
      const auto &eta,
      derive_nonzero_scalar(challenge_digest, kCircuitDlogBatchTaggedHash, 0));
  return batch_public_commitments_with_eta(public_commitments, eta,
                                           secp_context);
}

Result<FieldElement> dlog_challenge(
    std::span<const unsigned char> challenge_digest,
    const PointBytes &batched_commitment,
    const std::array<unsigned char, 32> &nonce_xonly) {
  Bytes seed(challenge_digest.begin(), challenge_digest.end());
  seed.insert(seed.end(), batched_commitment.begin(), batched_commitment.end());
  seed.insert(seed.end(), nonce_xonly.begin(), nonce_xonly.end());
  return derive_nonzero_scalar(seed, kCircuitDlogChallengeTaggedHash, 0);
}

Result<PublicCommitmentDlogProof> prove_public_commitment_dlog(
    const BatchedPublicCommitment &batched,
    std::span<const FieldElement> commitment_values,
    std::span<const unsigned char> challenge_digest,
    const ScalarBytes &secret_prover_seed,
    purify_secp_context *secp_context) {
  if (batched.weights.size() != commitment_values.size()) {
    return unexpected_error(ErrorCode::SizeMismatch);
  }
  FieldElement value = FieldElement::zero();
  WipeOnDestruction value_wiper(value);
  for (std::size_t i = 0; i < commitment_values.size(); ++i) {
    FieldElement term = batched.weights[i] * commitment_values[i];
    WipeOnDestruction term_wiper(term);
    FieldElement next = value + term;
    WipeOnDestruction next_wiper(next);
    value = next;
  }

  SecretScalarBytes value_bytes;
  purify_scalar_get_b32(
      value_bytes.value.data(),
      &::purify::detail::FieldElementAccess::raw(value));
  SecretBytes nonce_seed;
  nonce_seed.reserve(secret_prover_seed.size() + value_bytes.value.size() +
                     challenge_digest.size());
  nonce_seed.insert(nonce_seed.end(), secret_prover_seed.begin(),
                    secret_prover_seed.end());
  nonce_seed.insert(nonce_seed.end(), value_bytes.value.begin(),
                    value_bytes.value.end());
  nonce_seed.insert(nonce_seed.end(), challenge_digest.begin(),
                    challenge_digest.end());
  FieldElement nonce = FieldElement::zero();
  WipeOnDestruction nonce_wiper(nonce);
  PURIFY_RETURN_IF_ERROR(derive_secret_nonzero_scalar(
      nonce, nonce_seed, kCircuitDlogNonceTaggedHash, 0));
  PURIFY_ASSIGN_OR_RETURN(const auto &nonce_point,
                          point_from_scalar_base(nonce, secp_context));

  PublicCommitmentDlogProof out;
  int parity = 0;
  if (purify_bip340_xonly_from_point(
          secp_context, nonce_point.data(), out.nonce_xonly.data(), &parity) ==
      0) {
    return unexpected_error(ErrorCode::BackendRejectedInput);
  }
  FieldElement negated_nonce = nonce.negate();
  WipeOnDestruction negated_nonce_wiper(negated_nonce);
  nonce.conditional_assign(negated_nonce, parity != 0);
  PURIFY_ASSIGN_OR_RETURN(
      const auto &challenge,
      dlog_challenge(challenge_digest, batched.point, out.nonce_xonly));
  FieldElement challenge_value = challenge * value;
  WipeOnDestruction challenge_value_wiper(challenge_value);
  const FieldElement response = nonce + challenge_value;
  if (response.is_zero()) {
    return unexpected_error(ErrorCode::BackendRejectedInput);
  }
  out.response = scalar_bytes(response);
  return out;
}

Result<bool> verify_public_commitment_dlog(
    const BatchedPublicCommitment &batched,
    const FieldElement &challenge,
    const PublicCommitmentDlogProof &proof,
    purify_secp_context *secp_context) {
  PURIFY_ASSIGN_OR_RETURN(const auto &response,
                          FieldElement::try_from_bytes32(proof.response));
  if (response.is_zero()) {
    return false;
  }
  PointBytes nonce_point{};
  nonce_point[0] = 0x02;
  std::copy(proof.nonce_xonly.begin(), proof.nonce_xonly.end(),
            nonce_point.begin() + 1);
  PURIFY_ASSIGN_OR_RETURN(const auto &lhs,
                          point_from_scalar_base(response, secp_context));
  PURIFY_ASSIGN_OR_RETURN(const auto &scaled_commitment,
                          point_scale(batched.point, challenge, secp_context));
  Result<PointBytes> rhs =
      point_add(nonce_point, scaled_commitment, secp_context);
  return rhs.has_value() && lhs == *rhs;
}

Result<bool> verify_public_commitment_dlog(
    const BatchedPublicCommitment &batched,
    std::span<const unsigned char> challenge_digest,
    const PublicCommitmentDlogProof &proof,
    purify_secp_context *secp_context) {
  PURIFY_ASSIGN_OR_RETURN(
      const auto &challenge,
      dlog_challenge(challenge_digest, batched.point, proof.nonce_xonly));
  return verify_public_commitment_dlog(batched, challenge, proof,
                                       secp_context);
}

Result<Bytes> bind_public_commitments(
    std::span<const PointBytes> public_commitments,
    std::span<const unsigned char> statement_binding) {
  PURIFY_ASSIGN_OR_RETURN(const auto &encoded_commitment_count,
                          narrow_size_to_u64(public_commitments.size()));
  PURIFY_ASSIGN_OR_RETURN(const auto &encoded_binding_size,
                          narrow_size_to_u64(statement_binding.size()));

  std::size_t total_size = 0;
  Bytes out = bytes_from_ascii(kCircuitNormArgPublicCommitmentTag);
  if (!(CheckedSize(out.size()) + 8 +
        CheckedSize(public_commitments.size()) * sizeof(PointBytes) + 8 +
        statement_binding.size())
           .store(total_size)) {
    return unexpected_error(ErrorCode::Overflow);
  }
  out.reserve(total_size);
  append_u64_le(out, encoded_commitment_count);
  for (const PointBytes &point : public_commitments) {
    out.insert(out.end(), point.begin(), point.end());
  }
  append_u64_le(out, encoded_binding_size);
  out.insert(out.end(), statement_binding.begin(), statement_binding.end());
  return out;
}

Status
validate_public_commitments(std::span<const PointBytes> public_commitments,
                            std::span<const FieldElement> commitments,
                            purify_secp_context *secp_context) {
  if (public_commitments.size() != commitments.size()) {
    return unexpected_error(ErrorCode::SizeMismatch);
  }
  for (std::size_t i = 0; i < commitments.size(); ++i) {
    PURIFY_ASSIGN_OR_RETURN(
        const auto &expected,
        point_from_scalar_base(commitments[i], secp_context));
    if (expected != public_commitments[i]) {
      return unexpected_error(ErrorCode::BindingMismatch);
    }
  }
  return {};
}

} // namespace detail

} // namespace purify::bppp
