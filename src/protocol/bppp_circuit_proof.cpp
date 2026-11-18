// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file bppp_circuit_proof.cpp
 * @brief Experimental transparent and masked circuit proofs over the reduced BPPP relation.
 */

#include "purify/bppp.hpp"

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <utility>

#include "bppp_backend_cache.hpp"
#include "bppp_circuit_reduction.hpp"
#include "bppp_internal.hpp"
#include "bppp_masking.hpp"
#include "bppp_norm_arg.hpp"
#include "bppp_points.hpp"
#include "bppp_public_commitments.hpp"
#include "bppp_support.hpp"
#include "bulletproof_internal.hpp"

namespace purify::bppp {

// Helpers shared between the translation units of this module live in detail.
using namespace detail;

namespace {

constexpr std::string_view kCircuitZkBlindTag =
    "Purify/BPPP/CircuitNormArgV3/ZKBlind";
constexpr std::string_view kCircuitZkMaskNTag =
    "Purify/BPPP/CircuitNormArgV3/ZKMaskN";
constexpr std::string_view kCircuitZkMaskLTag =
    "Purify/BPPP/CircuitNormArgV3/ZKMaskL";
constexpr std::string_view kCircuitZkChallengeTag =
    "Purify/BPPP/CircuitNormArgV3/ZKChallenge";

const TaggedHash kCircuitZkBlindTaggedHash(kCircuitZkBlindTag);
const TaggedHash kCircuitZkMaskNTaggedHash(kCircuitZkMaskNTag);
const TaggedHash kCircuitZkMaskLTaggedHash(kCircuitZkMaskLTag);
const TaggedHash kCircuitZkChallengeTaggedHash(kCircuitZkChallengeTag);

Result<FieldElement>
derive_zk_challenge(std::span<const unsigned char> binding_digest,
                    const PointBytes &a_commitment,
                    const PointBytes &s_commitment, const FieldElement &t2) {
  Bytes seed(binding_digest.begin(), binding_digest.end());
  seed.insert(seed.end(), a_commitment.begin(), a_commitment.end());
  seed.insert(seed.end(), s_commitment.begin(), s_commitment.end());
  ScalarBytes t2_bytes = scalar_bytes(t2);
  seed.insert(seed.end(), t2_bytes.begin(), t2_bytes.end());
  return derive_nonzero_scalar(seed, kCircuitZkChallengeTaggedHash, 0);
}

} // namespace

Result<PointBytes> commit_experimental_circuit_witness(
    const NativeBulletproofCircuit &circuit,
    const BulletproofAssignmentData &assignment,
    purify_secp_context *secp_context,
    ExperimentalCircuitBackend *cache) {
  PURIFY_ASSIGN_OR_RETURN(auto raw_inputs,
                          build_raw_circuit_norm_arg_inputs(
                              circuit, assignment, {}, false, secp_context));
  return commit_norm_arg_witness_only(raw_inputs, secp_context, cache);
}

Result<ExperimentalCircuitNormArgProof>
prove_experimental_circuit_norm_arg_to_commitment(
    const NativeBulletproofCircuit &circuit,
    const BulletproofAssignmentData &assignment,
    const PointBytes &witness_commitment,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    ExperimentalCircuitBackend *cache) {
  if (!circuit.has_valid_shape()) {
    return unexpected_error(ErrorCode::InvalidDimensions);
  }
  if (!is_power_of_two_size(circuit.n_gates)) {
    return unexpected_error(ErrorCode::InvalidDimensions);
  }
  if (assignment.left.size() != circuit.n_gates ||
      assignment.right.size() != circuit.n_gates ||
      assignment.output.size() != circuit.n_gates ||
      assignment.commitments.size() != circuit.n_commitments) {
    return unexpected_error(ErrorCode::SizeMismatch);
  }
  if (!circuit.evaluate(assignment)) {
    return unexpected_error(ErrorCode::EquationMismatch);
  }

  PURIFY_ASSIGN_OR_RETURN(auto raw_inputs,
                          build_raw_circuit_norm_arg_inputs(
                              circuit, assignment, {}, false, secp_context));
  PURIFY_ASSIGN_OR_RETURN(
      const auto &computed_witness_commitment,
      commit_norm_arg_witness_only(raw_inputs, secp_context, cache));
  if (computed_witness_commitment != witness_commitment) {
    return unexpected_error(ErrorCode::BackendRejectedInput);
  }

  PURIFY_ASSIGN_OR_RETURN(auto reduction,
                          reduce_experimental_circuit_to_norm_arg(
                              circuit, assignment, witness_commitment,
                              secp_context, statement_binding, false));

  SecretNormArgInputs inputs = build_norm_arg_inputs(reduction);

  PURIFY_ASSIGN_OR_RETURN(const auto &anchored_commitment,
                          anchor_zk_a_commitment(witness_commitment,
                                                 *reduction.public_data, {},
                                                 secp_context));

  PURIFY_ASSIGN_OR_RETURN(
      auto proof, prove_norm_arg_to_commitment_with_cache(
                      inputs, anchored_commitment, secp_context, nullptr));
  return ExperimentalCircuitNormArgProof{witness_commitment,
                                         std::move(proof.proof)};
}

Result<ExperimentalCircuitNormArgProof> prove_experimental_circuit_norm_arg(
    const NativeBulletproofCircuit &circuit,
    const BulletproofAssignmentData &assignment,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    ExperimentalCircuitBackend *cache) {
  PURIFY_ASSIGN_OR_RETURN(const auto &witness_commitment,
                          commit_experimental_circuit_witness(
                              circuit, assignment, secp_context, cache));
  return prove_experimental_circuit_norm_arg_to_commitment(
      circuit, assignment, witness_commitment, secp_context, statement_binding, cache);
}

Result<bool> verify_experimental_circuit_norm_arg(
    const NativeBulletproofCircuit &circuit,
    const ExperimentalCircuitNormArgProof &proof,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    ExperimentalCircuitBackend *) {
  if (!circuit.has_valid_shape()) {
    return unexpected_error(ErrorCode::InvalidDimensions);
  }
  if (!is_power_of_two_size(circuit.n_gates)) {
    return unexpected_error(ErrorCode::InvalidDimensions);
  }
  if (proof.proof.empty()) {
    return unexpected_error(ErrorCode::EmptyInput);
  }

  PURIFY_ASSIGN_OR_RETURN(
      const auto &public_data,
      build_circuit_norm_arg_public_data(circuit, statement_binding,
                                         proof.witness_commitment, secp_context,
                                         false));
  PURIFY_ASSIGN_OR_RETURN(const auto &anchored_commitment,
                          anchor_zk_a_commitment(proof.witness_commitment,
                                                 *public_data, {},
                                                 secp_context));

  NormArgProof bundle;
  bundle.rho = public_data->rho_bytes;
  bundle.generators = public_data->generators;
  bundle.c_vec = public_data->c_vec_bytes;
  bundle.n_vec_len = public_data->n_vec_len;
  bundle.commitment = anchored_commitment;
  bundle.proof = proof.proof;
  return verify_norm_arg_with_cache(bundle, secp_context, nullptr);
}

namespace {

/** Checks the circuit shape and that the assignment fits and satisfies it. */
Status validate_masked_circuit_witness(
    const NativeBulletproofCircuit &circuit,
    const BulletproofAssignmentData &assignment,
    std::span<const PointBytes> public_commitments,
    bool externalize_commitments) {
  if (!circuit.has_valid_shape()) {
    return unexpected_error(ErrorCode::InvalidDimensions);
  }
  if (!is_power_of_two_size(circuit.n_gates)) {
    return unexpected_error(ErrorCode::InvalidDimensions);
  }
  if (assignment.left.size() != circuit.n_gates ||
      assignment.right.size() != circuit.n_gates ||
      assignment.output.size() != circuit.n_gates ||
      assignment.commitments.size() != circuit.n_commitments) {
    return unexpected_error(ErrorCode::SizeMismatch);
  }
  if (externalize_commitments &&
      public_commitments.size() != circuit.n_commitments) {
    return unexpected_error(ErrorCode::SizeMismatch);
  }
  if (!circuit.evaluate(assignment)) {
    return unexpected_error(ErrorCode::EquationMismatch);
  }
  return {};
}

/** What one proving run fixes before its first masking attempt. */
struct MaskedProverRun {
  const NativeBulletproofCircuit &circuit;
  const BulletproofAssignmentData &assignment;
  const ScalarBytes &secret_prover_seed;
  std::span<const PointBytes> public_commitments;
  purify_secp_context *secp_context;
  const Bytes &bound_statement_binding;
  bool externalize_commitments;
  ExperimentalCircuitBackend *cache;
  const CircuitNormArgDimensions &dimensions;
  const SecretBytes &seed;
};

/**
 * One masking attempt: commit to the padded witness, reduce it, open the
 * public commitments, mask the reduced witness, and prove the norm argument
 * to the combined commitment.
 */
Result<MaskingAttempt<ExperimentalCircuitZkNormArgProof>>
attempt_experimental_circuit_zk_norm_arg(const MaskedProverRun &run,
                                         std::uint64_t attempt) {
  using Attempt = MaskingAttempt<ExperimentalCircuitZkNormArgProof>;
  const auto &[circuit, assignment, secret_prover_seed, public_commitments,
               secp_context, bound_statement_binding, externalize_commitments,
               cache, dimensions, seed] = run;

  PURIFY_ASSIGN_OR_RETURN(
      const auto &padding,
      derive_secret_scalars(dimensions.l_vec_len - dimensions.used_l, seed,
                            kCircuitZkBlindTaggedHash, attempt));

  PURIFY_ASSIGN_OR_RETURN(auto raw_inputs,
                          build_raw_circuit_norm_arg_inputs(
                              circuit, assignment, padding,
                              externalize_commitments, secp_context));
  Result<PointBytes> raw_commitment =
      commit_norm_arg_witness_only(raw_inputs, secp_context, cache);
  if (!raw_commitment.has_value()) {
    return Attempt::rejected(raw_commitment.error());
  }

  PURIFY_ASSIGN_OR_RETURN(auto hidden,
                          reduce_experimental_circuit_to_norm_arg(
                              circuit, assignment, *raw_commitment,
                              secp_context, bound_statement_binding,
                              externalize_commitments));
  std::copy(padding.begin(), padding.end(),
            hidden.l_vec.begin() + dimensions.used_l);

  PublicCommitmentDlogProof dlog_proof;
  if (externalize_commitments) {
    Result<BatchedPublicCommitment> batched = batch_public_commitments(
        public_commitments, hidden.public_data->challenge_digest,
        secp_context);
    if (!batched.has_value()) {
      return Attempt::rejected(batched.error());
    }
    Result<PublicCommitmentDlogProof> dlog =
        prove_public_commitment_dlog(
            *batched, assignment.commitments,
            hidden.public_data->challenge_digest, secret_prover_seed,
            secp_context);
    if (!dlog.has_value()) {
      return Attempt::rejected(dlog.error());
    }
    dlog_proof = *dlog;
  }

  PURIFY_ASSIGN_OR_RETURN(
      const auto &mask_n,
      derive_secret_scalars(hidden.n_vec.size(), seed,
                            kCircuitZkMaskNTaggedHash, attempt));
  PURIFY_ASSIGN_OR_RETURN(
      const auto &mask_l,
      derive_secret_scalars(hidden.l_vec.size(), seed,
                            kCircuitZkMaskLTaggedHash, attempt));

  FieldElement t2 =
      weighted_bppp_inner_product(mask_n, mask_n, hidden.public_data->rho);
  WipeOnDestruction t2_wiper(t2);
  if (t2.is_zero()) {
    return Attempt::redraw();
  }
  FieldElement t1 = FieldElement::from_int(2) *
                    weighted_bppp_inner_product(hidden.n_vec, mask_n,
                                                hidden.public_data->rho);
  WipeOnDestruction t1_wiper(t1);
  for (std::size_t i = 0; i < mask_l.size(); ++i) {
    t1 = t1 + (mask_l[i] * hidden.public_data->c_vec[i]);
  }

  SecretNormArgInputs mask_inputs =
      build_mask_inputs(*hidden.public_data, mask_n, mask_l);

  Result<PointBytes> a_commitment = anchor_zk_a_commitment(
      *raw_commitment, *hidden.public_data, public_commitments, secp_context);
  if (!a_commitment.has_value()) {
    return Attempt::rejected(a_commitment.error());
  }
  Result<PointBytes> s_commitment =
      commit_explicit_norm_arg(mask_inputs, t1, secp_context, nullptr);
  if (!s_commitment.has_value()) {
    return Attempt::rejected(s_commitment.error());
  }
  PURIFY_ASSIGN_OR_RETURN(
      const auto &challenge,
      derive_zk_challenge(hidden.public_data->challenge_digest, *a_commitment,
                          *s_commitment, t2));

  CircuitNormArgReduction masked =
      mask_reduction(hidden, challenge, mask_n, mask_l);
  SecretNormArgInputs masked_inputs = build_norm_arg_inputs(masked);

  Result<PointBytes> combined_commitment =
      combine_zk_commitments(*a_commitment, *s_commitment, challenge, t2, secp_context);
  if (!combined_commitment.has_value()) {
    return Attempt::rejected(combined_commitment.error());
  }
  Result<PointBytes> direct_commitment =
      commit_norm_arg_with_cache(masked_inputs, secp_context, nullptr);
  if (!direct_commitment.has_value()) {
    return Attempt::rejected(direct_commitment.error());
  }
  if (*combined_commitment != *direct_commitment) {
    return unexpected_error(ErrorCode::InternalMismatch);
  }

  Result<NormArgProof> proof = prove_norm_arg_to_commitment_with_cache(
      masked_inputs, *combined_commitment, secp_context, nullptr);
  if (!proof.has_value()) {
    return Attempt::rejected(proof.error());
  }
  return Attempt::accepted(ExperimentalCircuitZkNormArgProof{
      *raw_commitment,
      *s_commitment,
      scalar_bytes(t2),
      dlog_proof.nonce_xonly,
      dlog_proof.response,
      std::move(proof->proof)});
}

} // namespace

Result<ExperimentalCircuitZkNormArgProof>
prove_experimental_circuit_zk_norm_arg_impl(
    const NativeBulletproofCircuit &circuit,
    const BulletproofAssignmentData &assignment,
    const ScalarBytes &secret_prover_seed,
    std::span<const PointBytes> public_commitments,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    bool externalize_commitments, ExperimentalCircuitBackend *cache) {
  PURIFY_RETURN_IF_ERROR(validate_masked_circuit_witness(
      circuit, assignment, public_commitments, externalize_commitments));

  Bytes bound_statement_binding;
  if (externalize_commitments) {
    PURIFY_ASSIGN_OR_RETURN(
        bound_statement_binding,
        bind_public_commitments(public_commitments, statement_binding));
  } else {
    bound_statement_binding =
        Bytes(statement_binding.begin(), statement_binding.end());
  }
  if (externalize_commitments) {
    if (public_commitments.empty()) {
      return unexpected_error(ErrorCode::EmptyInput);
    }
    PURIFY_RETURN_IF_ERROR(validate_public_commitments(
        public_commitments, assignment.commitments, secp_context));
  }

  PURIFY_ASSIGN_OR_RETURN(
      const auto &binding_digest,
      experimental_circuit_binding_digest(circuit, bound_statement_binding));
  SecretBytes seed;
  seed.reserve(binding_digest.size() + secret_prover_seed.size());
  seed.insert(seed.end(), binding_digest.begin(), binding_digest.end());
  seed.insert(seed.end(), secret_prover_seed.begin(), secret_prover_seed.end());
  PURIFY_ASSIGN_OR_RETURN(
      const auto &dimensions,
      circuit_norm_arg_dimensions(circuit, externalize_commitments));

  const MaskedProverRun run{circuit,
                            assignment,
                            secret_prover_seed,
                            public_commitments,
                            secp_context,
                            bound_statement_binding,
                            externalize_commitments,
                            cache,
                            dimensions,
                            seed};
  return first_accepted_masking<ExperimentalCircuitZkNormArgProof>(
      [&run](std::uint64_t attempt) {
        return attempt_experimental_circuit_zk_norm_arg(run, attempt);
      });
}

namespace {

Status validate_prepared_circuit_proof(
    const NativeBulletproofCircuit &circuit,
    const ExperimentalCircuitZkNormArgProof &proof) {
  if (!circuit.has_valid_shape()) {
    return unexpected_error(ErrorCode::InvalidDimensions);
  }
  if (!is_power_of_two_size(circuit.n_gates)) {
    return unexpected_error(ErrorCode::InvalidDimensions);
  }
  if (proof.proof.empty()) {
    return unexpected_error(ErrorCode::EmptyInput);
  }
  return {};
}

bool has_zero_public_commitment_dlog(
    const ExperimentalCircuitZkNormArgProof &proof) {
  const auto all_zero = [](const auto &bytes) {
    return std::all_of(bytes.begin(), bytes.end(),
                       [](unsigned char byte) { return byte == 0; });
  };
  return all_zero(proof.public_commitment_dlog_nonce) &&
         all_zero(proof.public_commitment_dlog_response);
}

Result<detail::PreparedExperimentalCircuitZkNormArg>
finish_prepared_circuit_proof(
    const ExperimentalCircuitZkNormArgProof &proof,
    const CircuitNormArgPublicDataPtr &public_data,
    std::span<const PointBytes> public_commitments,
    purify_secp_context *secp_context) {
  PURIFY_ASSIGN_OR_RETURN(const auto &t2,
                          FieldElement::try_from_bytes32(proof.t2));
  PURIFY_ASSIGN_OR_RETURN(
      const auto &a_commitment,
      anchor_zk_a_commitment(proof.a_commitment, *public_data,
                             public_commitments, secp_context));
  PURIFY_ASSIGN_OR_RETURN(const auto &challenge,
                          derive_zk_challenge(public_data->challenge_digest,
                                              a_commitment, proof.s_commitment,
                                              t2));
  PURIFY_ASSIGN_OR_RETURN(const auto &commitment,
                          combine_zk_commitments(a_commitment,
                                                 proof.s_commitment, challenge,
                                                 t2, secp_context));

  detail::PreparedExperimentalCircuitZkNormArg out;
  out.norm.rho = public_data->rho_bytes;
  out.norm.generators = public_data->generators;
  out.norm.c_vec = public_data->c_vec_bytes;
  out.norm.n_vec_len = public_data->n_vec_len;
  out.norm.commitment = commitment;
  out.norm.proof = proof.proof;
  out.raw_generator_digest =
      generator_backend_cache_key(public_data->raw_generators);
  assert(public_data->challenge_digest.size() ==
         out.challenge_digest.size());
  std::copy(public_data->challenge_digest.begin(),
            public_data->challenge_digest.end(),
            out.challenge_digest.begin());
  out.mul_scale = public_data->mul_scale;
  out.mul_ratio = public_data->mul_ratio;
  return out;
}

} // namespace

Result<std::optional<detail::PreparedExperimentalCircuitZkNormArg>>
detail::prepare_experimental_circuit_zk_norm_arg_with_public_commitments(
    const NativeBulletproofCircuit &circuit,
    const ExperimentalCircuitZkNormArgProof &proof,
    std::span<const PointBytes> public_commitments,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding) {
  PURIFY_RETURN_IF_ERROR(validate_prepared_circuit_proof(circuit, proof));
  if (public_commitments.empty()) {
    return unexpected_error(ErrorCode::EmptyInput);
  }
  if (public_commitments.size() != circuit.n_commitments) {
    return unexpected_error(ErrorCode::SizeMismatch);
  }
  PURIFY_ASSIGN_OR_RETURN(
      const auto &bound_statement_binding,
      bind_public_commitments(public_commitments, statement_binding));
  PURIFY_ASSIGN_OR_RETURN(const auto &public_data,
                          build_circuit_norm_arg_public_data(
                              circuit, bound_statement_binding,
                              proof.a_commitment, secp_context, true));
  PURIFY_ASSIGN_OR_RETURN(
      const auto &batched,
      batch_public_commitments(public_commitments,
                               public_data->challenge_digest, secp_context));
  const PublicCommitmentDlogProof dlog_proof{
      proof.public_commitment_dlog_nonce,
      proof.public_commitment_dlog_response};
  PURIFY_ASSIGN_OR_RETURN(
      const auto &dlog_ok,
      verify_public_commitment_dlog(batched, public_data->challenge_digest,
                                    dlog_proof, secp_context));
  if (!dlog_ok) {
    return std::optional<PreparedExperimentalCircuitZkNormArg>{};
  }
  PURIFY_ASSIGN_OR_RETURN(
      auto out, finish_prepared_circuit_proof(
                    proof, public_data, public_commitments, secp_context));
  return std::optional<PreparedExperimentalCircuitZkNormArg>(std::move(out));
}

Result<std::optional<detail::PreparedExperimentalCircuitZkNormArg>>
detail::prepare_experimental_circuit_zk_norm_arg(
    const NativeBulletproofCircuit &circuit,
    const ExperimentalCircuitZkNormArgProof &proof,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding) {
  PURIFY_RETURN_IF_ERROR(validate_prepared_circuit_proof(circuit, proof));

  const Bytes bound_statement_binding(statement_binding.begin(),
                                      statement_binding.end());
  PURIFY_ASSIGN_OR_RETURN(const auto &public_data,
                          build_circuit_norm_arg_public_data(
                              circuit, bound_statement_binding,
                              proof.a_commitment, secp_context, false));
  if (!has_zero_public_commitment_dlog(proof)) {
    return std::optional<PreparedExperimentalCircuitZkNormArg>{};
  }
  PURIFY_ASSIGN_OR_RETURN(auto out, finish_prepared_circuit_proof(
                                        proof, public_data, {}, secp_context));
  return std::optional<PreparedExperimentalCircuitZkNormArg>(std::move(out));
}

Result<ExperimentalCircuitZkNormArgProof>
prove_experimental_circuit_zk_norm_arg(
    const NativeBulletproofCircuit &circuit,
    const BulletproofAssignmentData &assignment,
    const ScalarBytes &secret_prover_seed,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    ExperimentalCircuitBackend *cache) {
  return prove_experimental_circuit_zk_norm_arg_impl(
      circuit, assignment, secret_prover_seed, {}, secp_context,
      statement_binding, false, cache);
}

Result<bool> verify_experimental_circuit_zk_norm_arg(
    const NativeBulletproofCircuit &circuit,
    const ExperimentalCircuitZkNormArgProof &proof,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    ExperimentalCircuitBackend *) {
  PURIFY_ASSIGN_OR_RETURN(
      auto prepared,
      detail::prepare_experimental_circuit_zk_norm_arg(
          circuit, proof, secp_context, statement_binding));
  if (!prepared.has_value()) {
    return false;
  }
  return verify_norm_arg_with_cache(prepared->norm, secp_context, nullptr);
}

Result<ExperimentalCircuitZkNormArgProof>
prove_experimental_circuit_zk_norm_arg_with_public_commitments(
    const NativeBulletproofCircuit &circuit,
    const BulletproofAssignmentData &assignment,
    const ScalarBytes &secret_prover_seed,
    std::span<const PointBytes> public_commitments,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    ExperimentalCircuitBackend *cache) {
  return prove_experimental_circuit_zk_norm_arg_impl(
      circuit, assignment, secret_prover_seed, public_commitments,
      secp_context, statement_binding, true, cache);
}

Result<bool> verify_experimental_circuit_zk_norm_arg_with_public_commitments(
    const NativeBulletproofCircuit &circuit,
    const ExperimentalCircuitZkNormArgProof &proof,
    std::span<const PointBytes> public_commitments,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    ExperimentalCircuitBackend *) {
  PURIFY_ASSIGN_OR_RETURN(
      auto prepared,
      detail::prepare_experimental_circuit_zk_norm_arg_with_public_commitments(
          circuit, proof, public_commitments, secp_context, statement_binding));
  if (!prepared.has_value()) {
    return false;
  }
  return verify_norm_arg_with_cache(prepared->norm, secp_context, nullptr);
}

} // namespace purify::bppp
