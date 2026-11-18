// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file bppp_circuit_v4.cpp
 * @brief V4 masked circuit proofs: encoding validation, publication reconstruction, preparation and verification.
 */

#include "purify/bppp.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <optional>
#include <span>
#include <utility>
#include <vector>

#include "algebraic_circuit_proof.hpp"
#include "bppp_backend_cache.hpp"
#include "bppp_circuit_reduction.hpp"
#include "bppp_circuit_v4.hpp"
#include "bppp_norm_arg.hpp"
#include "bppp_points.hpp"
#include "bppp_public_commitments.hpp"
#include "bppp_support.hpp"
#include "bulletproof_internal.hpp"
#include "purify/secp_bridge.h"

namespace purify::bppp {

// Helpers shared between the translation units of this module live in detail.
using namespace detail;

namespace detail {

Result<candidate::CircuitTranscriptShapeV4> circuit_shape_v4(
    const NativeBulletproofCircuit &circuit, bool externalize_commitments) {
  PURIFY_ASSIGN_OR_RETURN(
      const auto &dimensions,
      circuit_norm_arg_dimensions(circuit, externalize_commitments));
  const auto mode = externalize_commitments
                        ? candidate::CircuitCommitmentModeV4::Public
                        : candidate::CircuitCommitmentModeV4::Hidden;
  return candidate::CircuitTranscriptShapeV4::create(
      mode, dimensions.gate_count, circuit.n_commitments,
      dimensions.n_vec_len, dimensions.l_vec_len);
}

Result<candidate::TranscriptDigest> circuit_binding_digest_v4(
    const NativeBulletproofCircuit &circuit,
    std::span<const unsigned char> statement_binding) {
  PURIFY_ASSIGN_OR_RETURN(
      const auto &digest,
      experimental_circuit_binding_digest(circuit, statement_binding));
  candidate::TranscriptDigest out{};
  if (digest.size() != out.size()) {
    return unexpected_error(ErrorCode::InternalMismatch);
  }
  std::copy(digest.begin(), digest.end(), out.begin());
  return out;
}

} // namespace detail

namespace {

Result<candidate::TranscriptDigest> raw_generator_digest_v4(
    const candidate::CircuitTranscriptShapeV4 &shape,
    purify_secp_context *secp_context) {
  std::size_t generator_count = 0;
  if (!(CheckedSize(shape.n_vec_len()) + shape.l_vec_len())
           .store(generator_count)) {
    return unexpected_error(ErrorCode::Overflow);
  }
  PURIFY_ASSIGN_OR_RETURN(const auto &generators,
                          create_generators(generator_count, secp_context));
  return generator_backend_cache_key(generators);
}

bool is_identity_point_v4(const PointBytes &point) {
  return std::all_of(point.begin(), point.end(),
                     [](unsigned char byte) { return byte == 0; });
}

} // namespace

namespace detail {

Status validate_circuit_proof_v4_inputs(
    const NativeBulletproofCircuit &circuit,
    std::span<const PointBytes> public_commitments,
    purify_secp_context *secp_context, bool externalize_commitments) {
  PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context));
  if (!circuit.has_valid_shape() ||
      !is_power_of_two_size(circuit.n_gates)) {
    return unexpected_error(ErrorCode::InvalidDimensions);
  }
  if (externalize_commitments) {
    if (public_commitments.empty() ||
        public_commitments.size() != circuit.n_commitments) {
      return unexpected_error(ErrorCode::SizeMismatch);
    }
    if (std::any_of(public_commitments.begin(), public_commitments.end(),
                    is_identity_point_v4)) {
      return unexpected_error(ErrorCode::BackendRejectedInput);
    }
  } else if (!public_commitments.empty()) {
    return unexpected_error(ErrorCode::SizeMismatch);
  }
  return {};
}

} // namespace detail

namespace {

Status validate_finite_point_v4(const PointBytes &point,
                                purify_secp_context *secp_context) {
  std::array<unsigned char, 32> xonly{};
  int parity = 0;
  if (purify_bip340_xonly_from_point(
          secp_context, point.data(), xonly.data(), &parity) == 0) {
    return unexpected_error(ErrorCode::BackendRejectedInput);
  }
  return {};
}

Status validate_circuit_zk_norm_arg_proof_v4_fixed_encoding_impl(
    const candidate::CircuitZkNormArgProofV4 &proof,
    candidate::CircuitCommitmentModeV4 mode, std::size_t round_count,
    purify_secp_context *secp_context) {
  PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context));
  PURIFY_RETURN_IF_ERROR(
      validate_finite_point_v4(proof.raw_commitment, secp_context));
  PURIFY_RETURN_IF_ERROR(
      validate_finite_point_v4(proof.mask_commitment, secp_context));
  PURIFY_ASSIGN_OR_RETURN(const auto t2,
                          FieldElement::try_from_bytes32(proof.t2));
  (void)t2;

  if (mode == candidate::CircuitCommitmentModeV4::Public) {
    if (purify_bip340_validate_xonly_pubkey(
            secp_context,
            proof.public_commitment_dlog_nonce.data()) == 0) {
      return unexpected_error(ErrorCode::BackendRejectedInput);
    }
    PURIFY_ASSIGN_OR_RETURN(
        const auto response,
        FieldElement::try_from_bytes32(proof.public_commitment_dlog_response));
    if (response.is_zero()) {
      return unexpected_error(ErrorCode::RangeViolation);
    }
  } else if (mode != candidate::CircuitCommitmentModeV4::Hidden) {
    return unexpected_error(ErrorCode::UnsupportedSymbol);
  } else if (!std::all_of(
                 proof.public_commitment_dlog_nonce.begin(),
                 proof.public_commitment_dlog_nonce.end(),
                 [](unsigned char byte) { return byte == 0; }) ||
             !std::all_of(
                 proof.public_commitment_dlog_response.begin(),
                 proof.public_commitment_dlog_response.end(),
                 [](unsigned char byte) { return byte == 0; })) {
    return unexpected_error(ErrorCode::BindingMismatch);
  }

  ScalarBytes terminal_n{};
  ScalarBytes terminal_l{};
  PURIFY_ASSIGN_OR_RETURN(const auto rounds,
                          parse_norm_rounds_v4(proof.norm_proof, round_count,
                                               terminal_n, terminal_l));
  for (const auto &round : rounds) {
    PURIFY_RETURN_IF_ERROR(
        candidate::validate_packed_point_pair_v4(round, secp_context));
  }
  PURIFY_ASSIGN_OR_RETURN(const auto terminal_n_scalar,
                          FieldElement::try_from_bytes32(terminal_n));
  PURIFY_ASSIGN_OR_RETURN(const auto terminal_l_scalar,
                          FieldElement::try_from_bytes32(terminal_l));
  (void)terminal_n_scalar;
  (void)terminal_l_scalar;
  return {};
}

Status validate_circuit_zk_norm_arg_proof_v4_encoding_impl(
    const NativeBulletproofCircuit &circuit,
    const candidate::CircuitZkNormArgProofV4 &proof,
    std::span<const PointBytes> public_commitments,
    purify_secp_context *secp_context, bool externalize_commitments) {
  PURIFY_RETURN_IF_ERROR(validate_circuit_proof_v4_inputs(
      circuit, public_commitments, secp_context, externalize_commitments));
  PURIFY_ASSIGN_OR_RETURN(const auto shape,
                          circuit_shape_v4(circuit, externalize_commitments));
  return validate_circuit_zk_norm_arg_proof_v4_fixed_encoding_impl(
      proof, shape.mode(), shape.round_count(), secp_context);
}

Result<candidate::CircuitZkNormArgPublicationV4>
reconstruct_circuit_zk_norm_arg_publication_v4_impl(
    const NativeBulletproofCircuit &circuit,
    candidate::CircuitZkNormArgProofV4 proof,
    std::span<const PointBytes> public_commitments,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    bool externalize_commitments) {
  PURIFY_RETURN_IF_ERROR(validate_circuit_zk_norm_arg_proof_v4_encoding_impl(
      circuit, proof, public_commitments, secp_context,
      externalize_commitments));
  PURIFY_ASSIGN_OR_RETURN(const auto shape,
                          circuit_shape_v4(circuit, externalize_commitments));
  PURIFY_ASSIGN_OR_RETURN(
      const auto binding_digest,
      circuit_binding_digest_v4(circuit, statement_binding));
  PURIFY_ASSIGN_OR_RETURN(auto precommitment,
                          candidate::derive_circuit_precommitment_v4(
                              shape, binding_digest, public_commitments,
                              proof.raw_commitment, secp_context));
  return candidate::CircuitZkNormArgPublicationV4{
      std::move(precommitment.digest), std::move(proof)};
}

} // namespace

Status candidate::validate_circuit_zk_norm_arg_proof_v4_fixed_encoding(
    const CircuitZkNormArgProofV4 &proof,
    CircuitCommitmentModeV4 mode, std::size_t round_count,
    purify_secp_context *secp_context) {
  return validate_circuit_zk_norm_arg_proof_v4_fixed_encoding_impl(
      proof, mode, round_count, secp_context);
}

Status candidate::validate_circuit_zk_norm_arg_proof_v4_encoding(
    const NativeBulletproofCircuit &circuit,
    const CircuitZkNormArgProofV4 &proof,
    purify_secp_context *secp_context) {
  return validate_circuit_zk_norm_arg_proof_v4_encoding_impl(
      circuit, proof, {}, secp_context, false);
}

Status candidate::
validate_circuit_zk_norm_arg_proof_v4_encoding_with_public_commitments(
    const NativeBulletproofCircuit &circuit,
    const CircuitZkNormArgProofV4 &proof,
    std::span<const PointBytes> public_commitments,
    purify_secp_context *secp_context) {
  return validate_circuit_zk_norm_arg_proof_v4_encoding_impl(
      circuit, proof, public_commitments, secp_context, true);
}

Result<candidate::CircuitZkNormArgPublicationV4>
candidate::reconstruct_circuit_zk_norm_arg_publication_v4(
    const NativeBulletproofCircuit &circuit,
    CircuitZkNormArgProofV4 proof,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding) {
  return reconstruct_circuit_zk_norm_arg_publication_v4_impl(
      circuit, std::move(proof), {}, secp_context, statement_binding,
      false);
}

Result<candidate::CircuitZkNormArgPublicationV4>
candidate::
reconstruct_circuit_zk_norm_arg_publication_v4_with_public_commitments(
    const NativeBulletproofCircuit &circuit,
    CircuitZkNormArgProofV4 proof,
    std::span<const PointBytes> public_commitments,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding) {
  return reconstruct_circuit_zk_norm_arg_publication_v4_impl(
      circuit, std::move(proof), public_commitments, secp_context,
      statement_binding, true);
}

Result<std::optional<candidate::PreparedCircuitZkNormArgV4>>
candidate::prepare_circuit_zk_norm_arg_v4_impl(
    const NativeBulletproofCircuit &circuit,
    const candidate::CircuitZkNormArgPublicationV4 &publication,
    std::span<const PointBytes> public_commitments,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    bool externalize_commitments, ExperimentalCircuitBackend *) {
  PURIFY_RETURN_IF_ERROR(validate_circuit_proof_v4_inputs(
      circuit, public_commitments, secp_context, externalize_commitments));
  if (publication.proof.norm_proof.empty()) {
    return unexpected_error(ErrorCode::EmptyInput);
  }
  if (is_identity_point_v4(publication.proof.raw_commitment) ||
      is_identity_point_v4(publication.proof.mask_commitment)) {
    return std::optional<candidate::PreparedCircuitZkNormArgV4>{};
  }
  PURIFY_ASSIGN_OR_RETURN(const auto shape,
                          circuit_shape_v4(circuit, externalize_commitments));
  PURIFY_ASSIGN_OR_RETURN(
      const auto &binding_digest,
      circuit_binding_digest_v4(circuit, statement_binding));
  PURIFY_ASSIGN_OR_RETURN(const auto &expected_precommitment,
                          candidate::derive_circuit_precommitment_v4(
                              shape, binding_digest, public_commitments,
                              publication.proof.raw_commitment, secp_context));
  if (expected_precommitment.digest.bytes() !=
      publication.precommitment.bytes()) {
    return std::optional<candidate::PreparedCircuitZkNormArgV4>{};
  }
  PURIFY_ASSIGN_OR_RETURN(const auto &raw_generator_digest,
                          raw_generator_digest_v4(shape, secp_context));
  PURIFY_ASSIGN_OR_RETURN(
      auto transcript,
      candidate::CircuitProofTranscriptV4::create(
          shape, publication.precommitment, raw_generator_digest));
  const CircuitNormArgChallenges challenges{
      transcript.rho().scalar, transcript.mul_scale().scalar,
      transcript.mul_ratio().scalar, transcript.row_ratio().scalar};
  PURIFY_ASSIGN_OR_RETURN(const auto &public_data,
                          build_circuit_norm_arg_public_data(
                              circuit, statement_binding,
                              publication.proof.raw_commitment, secp_context,
                              externalize_commitments, &challenges));
  if (generator_backend_cache_key(public_data->raw_generators) !=
      raw_generator_digest) {
    return unexpected_error(ErrorCode::InternalMismatch);
  }
  PURIFY_ASSIGN_OR_RETURN(
      const auto &anchored_commitment,
      anchor_zk_a_commitment(publication.proof.raw_commitment, *public_data,
                             public_commitments, secp_context));
  if (is_identity_point_v4(anchored_commitment)) {
    return std::optional<candidate::PreparedCircuitZkNormArgV4>{};
  }
  PURIFY_ASSIGN_OR_RETURN(
      const auto &anchored_offset,
      point_subtract_allow_infinity(
          anchored_commitment, publication.proof.raw_commitment, secp_context));
  PURIFY_ASSIGN_OR_RETURN(
      const auto &coefficient_commitment,
      coefficient_commitment_v4(*public_data, secp_context));
  PURIFY_ASSIGN_OR_RETURN(const auto &eta,
                          transcript.append_anchored_commitments(
                              coefficient_commitment, anchored_offset,
                              anchored_commitment, secp_context));

  PointBytes batched_public_commitment{};
  std::optional<candidate::CircuitChallengeV4> staged_dlog_challenge;
  PublicCommitmentDlogProof dlog_proof{
      publication.proof.public_commitment_dlog_nonce,
      publication.proof.public_commitment_dlog_response};
  if (externalize_commitments) {
    PURIFY_ASSIGN_OR_RETURN(const auto &batched,
                            batch_public_commitments_with_eta(
                                public_commitments, eta.scalar, secp_context));
    batched_public_commitment = batched.point;
    PURIFY_ASSIGN_OR_RETURN(
        const auto &dlog_challenge,
        transcript.append_public_opening(batched.point, dlog_proof.nonce_xonly,
                                         secp_context));
    staged_dlog_challenge = dlog_challenge;
    PURIFY_ASSIGN_OR_RETURN(
        const bool dlog_valid,
        verify_public_commitment_dlog(batched, dlog_challenge.scalar,
                                      dlog_proof, secp_context));
    if (!dlog_valid) {
      return std::optional<candidate::PreparedCircuitZkNormArgV4>{};
    }
  } else {
    const auto all_zero = [](const auto &bytes) {
      return std::all_of(bytes.begin(), bytes.end(),
                         [](unsigned char byte) { return byte == 0; });
    };
    if (!all_zero(dlog_proof.nonce_xonly) ||
        !all_zero(dlog_proof.response)) {
      return std::optional<candidate::PreparedCircuitZkNormArgV4>{};
    }
    PURIFY_ASSIGN_OR_RETURN(
        const auto hidden_dlog_challenge,
        transcript.append_public_opening(batched_public_commitment,
                                         dlog_proof.nonce_xonly, secp_context));
    staged_dlog_challenge = hidden_dlog_challenge;
  }
  PURIFY_ASSIGN_OR_RETURN(const auto &dlog_response,
                          FieldElement::try_from_bytes32(dlog_proof.response));
  PURIFY_RETURN_IF_ERROR(transcript.append_dlog_response(dlog_response));

  PURIFY_ASSIGN_OR_RETURN(const auto &t2,
                          FieldElement::try_from_bytes32(publication.proof.t2));
  PURIFY_ASSIGN_OR_RETURN(
      const auto &alpha,
      transcript.append_mask(publication.proof.mask_commitment, t2,
                             secp_context));
  PURIFY_ASSIGN_OR_RETURN(
      const auto &combined_commitment,
      combine_zk_commitments(anchored_commitment,
                             publication.proof.mask_commitment, alpha.scalar,
                             t2, secp_context));
  if (is_identity_point_v4(combined_commitment)) {
    return std::optional<candidate::PreparedCircuitZkNormArgV4>{};
  }
  PURIFY_RETURN_IF_ERROR(
      transcript.append_combined_commitment(combined_commitment, secp_context));

  ScalarBytes terminal_n{};
  ScalarBytes terminal_l{};
  PURIFY_ASSIGN_OR_RETURN(const auto &rounds,
                          parse_norm_rounds_v4(publication.proof.norm_proof,
                                               shape.round_count(), terminal_n,
                                               terminal_l));
  std::vector<candidate::CircuitChallengeV4> staged_gammas;
  staged_gammas.reserve(rounds.size());
  for (const auto &round : rounds) {
    PURIFY_ASSIGN_OR_RETURN(auto gamma,
                            transcript.append_round(round, secp_context));
    staged_gammas.push_back(std::move(gamma));
  }
  PURIFY_ASSIGN_OR_RETURN(const auto &terminal_n_scalar,
                          FieldElement::try_from_bytes32(terminal_n));
  PURIFY_ASSIGN_OR_RETURN(const auto &terminal_l_scalar,
                          FieldElement::try_from_bytes32(terminal_l));
  PURIFY_ASSIGN_OR_RETURN(
      const auto prepared_binding,
      transcript.finish(terminal_n_scalar, terminal_l_scalar));

  NormArgProof norm{public_data->rho_bytes,
                    public_data->generators,
                    public_data->c_vec_bytes,
                    public_data->n_vec_len,
                    combined_commitment,
                    publication.proof.norm_proof};
  ScalarBytes prepared_n{};
  ScalarBytes prepared_l{};
  candidate::CircuitProofTranscriptInputV4 transcript_input{
      raw_generator_digest,
      coefficient_commitment,
      anchored_offset,
      anchored_commitment,
      batched_public_commitment,
      dlog_proof.nonce_xonly,
      dlog_proof.response,
      publication.proof.mask_commitment,
      publication.proof.t2,
      combined_commitment,
      rounds,
      terminal_n,
      terminal_l};
  PURIFY_ASSIGN_OR_RETURN(
      auto transcript_result,
      candidate::derive_circuit_proof_transcript_v4(
          shape, publication.precommitment, transcript_input, secp_context));
  const auto same_challenge = [](const auto &lhs, const auto &rhs) {
    return lhs.scalar == rhs.scalar;
  };
  const bool matching_gammas =
      staged_gammas.size() == transcript_result.gammas.size() &&
      std::equal(staged_gammas.begin(), staged_gammas.end(),
                 transcript_result.gammas.begin(), same_challenge);
  if (!staged_dlog_challenge.has_value() ||
      !same_challenge(transcript.rho(), transcript_result.rho) ||
      !same_challenge(transcript.mul_scale(), transcript_result.mul_scale) ||
      !same_challenge(transcript.mul_ratio(), transcript_result.mul_ratio) ||
      !same_challenge(transcript.row_ratio(), transcript_result.row_ratio) ||
      !same_challenge(eta, transcript_result.eta) ||
      !same_challenge(*staged_dlog_challenge,
                      transcript_result.dlog_challenge) ||
      !same_challenge(alpha, transcript_result.alpha) || !matching_gammas ||
      !same_challenge(prepared_binding,
                      transcript_result.prepared_binding)) {
    return unexpected_error(ErrorCode::InternalMismatch);
  }
  PURIFY_ASSIGN_OR_RETURN(const auto &residual,
                          prepare_norm_arg_v4(norm, transcript_result.gammas,
                                              prepared_n, prepared_l,
                                              secp_context));
  if (prepared_n != terminal_n || prepared_l != terminal_l) {
    return unexpected_error(ErrorCode::InternalMismatch);
  }
  return std::optional<candidate::PreparedCircuitZkNormArgV4>(
      candidate::PreparedCircuitZkNormArgV4(
          shape, public_data->raw_generators,
          std::move(transcript_input),
          std::move(transcript_result), std::move(norm), residual));
}

Result<std::optional<candidate::PreparedCircuitZkNormArgV4>>
candidate::prepare_circuit_zk_norm_arg_v4(
    const NativeBulletproofCircuit &circuit,
    const CircuitZkNormArgPublicationV4 &publication,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    ExperimentalCircuitBackend *cache) {
  return prepare_circuit_zk_norm_arg_v4_impl(
      circuit, publication, {}, secp_context, statement_binding, false,
      cache);
}

Result<std::optional<candidate::PreparedCircuitZkNormArgV4>>
candidate::prepare_circuit_zk_norm_arg_v4_with_public_commitments(
    const NativeBulletproofCircuit &circuit,
    const CircuitZkNormArgPublicationV4 &publication,
    std::span<const PointBytes> public_commitments,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    ExperimentalCircuitBackend *cache) {
  return prepare_circuit_zk_norm_arg_v4_impl(
      circuit, publication, public_commitments, secp_context,
      statement_binding, true, cache);
}

namespace {

Result<candidate::CircuitNormParentConstantsV4>
derive_circuit_norm_parent_constants_v4_impl(
    const NativeBulletproofCircuit &circuit,
    const candidate::CircuitPrecommitmentDigestV4 &precommitment,
    std::span<const PointBytes> public_commitments,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding) {
  PURIFY_RETURN_IF_ERROR(validate_circuit_proof_v4_inputs(
      circuit, public_commitments, secp_context, true));
  for (const auto &point : public_commitments) {
    PURIFY_RETURN_IF_ERROR(validate_finite_point_v4(point, secp_context));
  }
  PURIFY_ASSIGN_OR_RETURN(auto binding_digest, circuit_binding_digest_v4(
                                                   circuit, statement_binding));
  PURIFY_ASSIGN_OR_RETURN(const auto shape, circuit_shape_v4(circuit, true));
  PURIFY_ASSIGN_OR_RETURN(const auto raw_generator_digest,
                          raw_generator_digest_v4(shape, secp_context));
  PURIFY_ASSIGN_OR_RETURN(const auto transcript,
                          candidate::CircuitProofTranscriptV4::create(
                              shape, precommitment, raw_generator_digest));
  const CircuitNormArgChallenges challenges{
      transcript.rho().scalar, transcript.mul_scale().scalar,
      transcript.mul_ratio().scalar, transcript.row_ratio().scalar};
  PURIFY_ASSIGN_OR_RETURN(
      const auto public_data,
      build_circuit_norm_arg_public_data_from_challenges(
          circuit, secp_context, true, challenges));
  if (generator_backend_cache_key(public_data->raw_generators) !=
      raw_generator_digest) {
    return unexpected_error(ErrorCode::InternalMismatch);
  }
  PURIFY_ASSIGN_OR_RETURN(
      auto coefficient_commitment,
      coefficient_commitment_v4(*public_data, secp_context));
  PURIFY_ASSIGN_OR_RETURN(auto anchored_offset,
                          circuit_anchored_offset_v4(
                              *public_data, public_commitments, secp_context));
  return candidate::CircuitNormParentConstantsV4{
      std::move(binding_digest), std::move(raw_generator_digest),
      std::move(coefficient_commitment), std::move(anchored_offset)};
}

} // namespace

Result<candidate::CircuitNormParentConstantsV4>
candidate::derive_circuit_norm_parent_constants_v4_with_public_commitments(
    const NativeBulletproofCircuit &circuit,
    const CircuitPrecommitmentDigestV4 &precommitment,
    std::span<const PointBytes> public_commitments,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding) {
  return derive_circuit_norm_parent_constants_v4_impl(
      circuit, precommitment, public_commitments, secp_context,
      statement_binding);
}

Result<bool> candidate::verify_circuit_zk_norm_arg_v4(
    const NativeBulletproofCircuit &circuit,
    const CircuitZkNormArgPublicationV4 &publication,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    ExperimentalCircuitBackend *cache) {
  PURIFY_ASSIGN_OR_RETURN(auto prepared, prepare_circuit_zk_norm_arg_v4(
                                             circuit, publication, secp_context,
                                             statement_binding, cache));
  return prepared.has_value() &&
         verify_norm_arg_v4(prepared->norm(), prepared->transcript().gammas,
                            secp_context);
}

Result<bool>
candidate::verify_circuit_zk_norm_arg_v4_with_public_commitments(
    const NativeBulletproofCircuit &circuit,
    const CircuitZkNormArgPublicationV4 &publication,
    std::span<const PointBytes> public_commitments,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    ExperimentalCircuitBackend *cache) {
  PURIFY_ASSIGN_OR_RETURN(
      auto prepared, prepare_circuit_zk_norm_arg_v4_with_public_commitments(
                         circuit, publication, public_commitments, secp_context,
                         statement_binding, cache));
  return prepared.has_value() &&
         verify_norm_arg_v4(prepared->norm(), prepared->transcript().gammas,
                            secp_context);
}

} // namespace purify::bppp
