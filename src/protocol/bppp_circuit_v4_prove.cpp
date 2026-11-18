// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file bppp_circuit_v4_prove.cpp
 * @brief The V4 masked circuit prover.
 */

#include "purify/bppp.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <utility>

#include "algebraic_circuit_proof.hpp"
#include "bppp_backend_cache.hpp"
#include "bppp_circuit_reduction.hpp"
#include "bppp_circuit_v4.hpp"
#include "bppp_masking.hpp"
#include "bppp_norm_arg.hpp"
#include "bppp_points.hpp"
#include "bppp_public_commitments.hpp"
#include "bppp_support.hpp"
#include "purify/secp_bridge.h"

namespace purify::bppp {

// Helpers shared between the translation units of this module live in detail.
using namespace detail;

namespace {

constexpr std::string_view kCircuitZkBlindV4Tag =
    "Purify/BPPP/CircuitNormArg/v4/ZKBlind";
constexpr std::string_view kCircuitZkMaskNV4Tag =
    "Purify/BPPP/CircuitNormArg/v4/ZKMaskN";
constexpr std::string_view kCircuitZkMaskLV4Tag =
    "Purify/BPPP/CircuitNormArg/v4/ZKMaskL";
constexpr std::string_view kCircuitDlogNonceV4Tag =
    "Purify/BPPP/CircuitNormArg/v4/DLogNonce";

const TaggedHash kCircuitZkBlindV4TaggedHash(kCircuitZkBlindV4Tag);
const TaggedHash kCircuitZkMaskNV4TaggedHash(kCircuitZkMaskNV4Tag);
const TaggedHash kCircuitZkMaskLV4TaggedHash(kCircuitZkMaskLV4Tag);
const TaggedHash kCircuitDlogNonceV4TaggedHash(kCircuitDlogNonceV4Tag);

template <typename ChallengeCallback>
Result<PublicCommitmentDlogProof> prove_public_commitment_dlog_v4(
    const BatchedPublicCommitment &batched,
    std::span<const FieldElement> commitment_values,
    std::span<const unsigned char> nonce_binding,
    const ScalarBytes &secret_prover_seed,
    purify_secp_context *secp_context,
    ChallengeCallback &&challenge_callback) {
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
                     nonce_binding.size());
  nonce_seed.insert(nonce_seed.end(), secret_prover_seed.begin(),
                    secret_prover_seed.end());
  nonce_seed.insert(nonce_seed.end(), value_bytes.value.begin(),
                    value_bytes.value.end());
  nonce_seed.insert(nonce_seed.end(), nonce_binding.begin(),
                    nonce_binding.end());
  FieldElement nonce = FieldElement::zero();
  WipeOnDestruction nonce_wiper(nonce);
  PURIFY_RETURN_IF_ERROR(derive_secret_nonzero_scalar(
      nonce, nonce_seed, kCircuitDlogNonceV4TaggedHash, 0));
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
  PURIFY_ASSIGN_OR_RETURN(const auto &challenge,
                          challenge_callback(out.nonce_xonly));
  FieldElement challenge_value = challenge * value;
  WipeOnDestruction challenge_value_wiper(challenge_value);
  const FieldElement response = nonce + challenge_value;
  if (response.is_zero()) {
    return unexpected_error(ErrorCode::BackendRejectedInput);
  }
  out.response = scalar_bytes(response);
  return out;
}

/** Checks the proof inputs, that the assignment satisfies the circuit, and that it opens the public commitments. */
Status validate_circuit_witness_v4(
    const NativeBulletproofCircuit &circuit,
    const BulletproofAssignmentData &assignment,
    std::span<const PointBytes> public_commitments,
    purify_secp_context *secp_context, bool externalize_commitments) {
  PURIFY_RETURN_IF_ERROR(validate_circuit_proof_v4_inputs(
      circuit, public_commitments, secp_context, externalize_commitments));
  if (assignment.left.size() != circuit.n_gates ||
      assignment.right.size() != circuit.n_gates ||
      assignment.output.size() != circuit.n_gates ||
      assignment.commitments.size() != circuit.n_commitments) {
    return unexpected_error(ErrorCode::SizeMismatch);
  }
  if (!circuit.evaluate(assignment)) {
    return unexpected_error(ErrorCode::EquationMismatch);
  }
  if (externalize_commitments) {
    PURIFY_RETURN_IF_ERROR(validate_public_commitments(
        public_commitments, assignment.commitments, secp_context));
  }
  return {};
}

/**
 * The seed every blinding scalar of one proof is derived from: the binding
 * digest, the prover seed, the commitment mode, the public commitments, and
 * each assignment column behind its length.
 */
Result<SecretBytes> derive_prover_seed_v4(
    const candidate::TranscriptDigest &binding_digest,
    const ScalarBytes &secret_prover_seed,
    std::span<const PointBytes> public_commitments,
    const BulletproofAssignmentData &assignment,
    bool externalize_commitments) {
  const CheckedSize assignment_scalar_count =
      CheckedSize(assignment.left.size()) + assignment.right.size() +
      assignment.output.size() + assignment.commitments.size();
  std::size_t seed_size = 0;
  if (!(CheckedSize(binding_digest.size()) + secret_prover_seed.size() + 1 +
        CheckedSize(public_commitments.size()) * sizeof(PointBytes) +
        assignment_scalar_count * sizeof(ScalarBytes) +
        4 * sizeof(std::uint64_t))
           .store(seed_size)) {
    return unexpected_error(ErrorCode::Overflow);
  }
  SecretBytes seed;
  seed.reserve(seed_size);
  seed.insert(seed.end(), binding_digest.begin(), binding_digest.end());
  seed.insert(seed.end(), secret_prover_seed.begin(), secret_prover_seed.end());
  seed.push_back(externalize_commitments ? 1 : 0);
  for (const auto &point : public_commitments) {
    seed.insert(seed.end(), point.begin(), point.end());
  }
  const auto append_assignment_values =
      [&](std::span<const FieldElement> values) -> Status {
    PURIFY_ASSIGN_OR_RETURN(const auto &count,
                            narrow_size_to_u64(values.size()));
    append_u64_le(seed, count);
    for (const auto &value : values) {
      SecretScalarBytes encoded;
      purify_scalar_get_b32(
          encoded.value.data(),
          &::purify::detail::FieldElementAccess::raw(value));
      seed.insert(seed.end(), encoded.value.begin(), encoded.value.end());
    }
    return {};
  };
  PURIFY_RETURN_IF_ERROR(append_assignment_values(assignment.left));
  PURIFY_RETURN_IF_ERROR(append_assignment_values(assignment.right));
  PURIFY_RETURN_IF_ERROR(append_assignment_values(assignment.output));
  PURIFY_RETURN_IF_ERROR(append_assignment_values(assignment.commitments));
  assert(seed.size() == seed_size);
  return seed;
}

/** The prover seed followed by the precommitment: the seed of the mask vectors. */
Result<SecretBytes> derive_mask_seed_v4(const SecretBytes &seed,
                                        const ScalarBytes &precommitment_bytes) {
std::size_t mask_seed_size = 0;
if (!(CheckedSize(seed.size()) + precommitment_bytes.size())
         .store(mask_seed_size)) {
  return unexpected_error(ErrorCode::Overflow);
}
SecretBytes mask_seed;
mask_seed.reserve(mask_seed_size);
mask_seed.insert(mask_seed.end(), seed.begin(), seed.end());
mask_seed.insert(mask_seed.end(), precommitment_bytes.begin(),
                 precommitment_bytes.end());
assert(mask_seed.size() == mask_seed_size);
  return mask_seed;
}

/** What one proving run fixes before its first masking attempt. */
struct ProverRunV4 {
  const NativeBulletproofCircuit &circuit;
  const BulletproofAssignmentData &assignment;
  const ScalarBytes &secret_prover_seed;
  std::span<const PointBytes> public_commitments;
  purify_secp_context *secp_context;
  std::span<const unsigned char> statement_binding;
  bool externalize_commitments;
  ExperimentalCircuitBackend *cache;
  const candidate::TranscriptDigest &binding_digest;
  const CircuitNormArgDimensions &dimensions;
  const candidate::CircuitTranscriptShapeV4 &shape;
  const SecretBytes &seed;
};

/**
 * One masking attempt: commit to the padded witness, replay the transcript
 * through the anchored commitments and the public opening, mask the reduced
 * witness, and prove the norm argument to the combined commitment.
 */
Result<MaskingAttempt<candidate::CircuitZkNormArgPublicationV4>>
attempt_circuit_zk_norm_arg_v4(const ProverRunV4 &run, std::uint64_t attempt) {
  using Attempt = MaskingAttempt<candidate::CircuitZkNormArgPublicationV4>;
  const auto &[circuit, assignment, secret_prover_seed, public_commitments,
               secp_context, statement_binding, externalize_commitments, cache,
               binding_digest, dimensions, shape, seed] = run;

  PURIFY_ASSIGN_OR_RETURN(
      const auto &padding,
      derive_secret_scalars(dimensions.l_vec_len - dimensions.used_l, seed,
                            kCircuitZkBlindV4TaggedHash, attempt));

  PURIFY_ASSIGN_OR_RETURN(auto raw_inputs,
                          build_raw_circuit_norm_arg_inputs(
                              circuit, assignment, padding,
                              externalize_commitments, secp_context));
  auto raw_commitment =
      commit_norm_arg_witness_only(raw_inputs, secp_context, cache);
  if (!raw_commitment.has_value()) {
    return Attempt::rejected(raw_commitment.error());
  }

  PURIFY_ASSIGN_OR_RETURN(const auto precommitment,
                          candidate::derive_circuit_precommitment_v4(
                              shape, binding_digest, public_commitments,
                              *raw_commitment, secp_context));
  const candidate::TranscriptDigest raw_generator_digest =
      generator_backend_cache_key(raw_inputs.generators);
  PURIFY_ASSIGN_OR_RETURN(
      auto transcript,
      candidate::CircuitProofTranscriptV4::create(shape, precommitment.digest,
                                                  raw_generator_digest));
  const CircuitNormArgChallenges challenges{
      transcript.rho().scalar, transcript.mul_scale().scalar,
      transcript.mul_ratio().scalar, transcript.row_ratio().scalar};
  PURIFY_ASSIGN_OR_RETURN(auto hidden,
                          reduce_experimental_circuit_to_norm_arg(
                              circuit, assignment, *raw_commitment,
                              secp_context, statement_binding,
                              externalize_commitments, cache, &challenges));
  if (generator_backend_cache_key(hidden.public_data->raw_generators) !=
      raw_generator_digest) {
    return unexpected_error(ErrorCode::InternalMismatch);
  }
  std::copy(padding.begin(), padding.end(),
            hidden.l_vec.begin() + dimensions.used_l);

  PURIFY_ASSIGN_OR_RETURN(
      const auto &anchored_commitment,
      anchor_zk_a_commitment(*raw_commitment, *hidden.public_data,
                             public_commitments, secp_context));
  PURIFY_ASSIGN_OR_RETURN(const auto &anchored_offset,
                          point_subtract_allow_infinity(anchored_commitment,
                                                        *raw_commitment,
                                                        secp_context));
  PURIFY_ASSIGN_OR_RETURN(
      const auto &coefficient_commitment,
      coefficient_commitment_v4(*hidden.public_data, secp_context));
  PURIFY_ASSIGN_OR_RETURN(const auto &eta,
                          transcript.append_anchored_commitments(
                              coefficient_commitment, anchored_offset,
                              anchored_commitment, secp_context));

  PublicCommitmentDlogProof dlog_proof;
  if (externalize_commitments) {
    PURIFY_ASSIGN_OR_RETURN(
        const auto &batched,
        batch_public_commitments_with_eta(public_commitments, eta.scalar,
                                          secp_context));
    const ScalarBytes nonce_binding = precommitment.digest.bytes();
    auto dlog = prove_public_commitment_dlog_v4(
        batched, assignment.commitments, nonce_binding,
        secret_prover_seed, secp_context,
        [&](const std::array<unsigned char, 32> &nonce)
            -> Result<FieldElement> {
          auto challenge = transcript.append_public_opening(
              batched.point, nonce, run.secp_context);
          if (!challenge.has_value()) {
            return unexpected_error(challenge.error());
          }
          return challenge->scalar;
        });
    if (!dlog.has_value()) {
      return Attempt::rejected(dlog.error());
    }
    dlog_proof = *dlog;
  } else {
    PURIFY_ASSIGN_OR_RETURN(
        const auto ignored,
        transcript.append_public_opening(PointBytes{}, dlog_proof.nonce_xonly,
                                         secp_context));
    (void)ignored;
  }
  PURIFY_ASSIGN_OR_RETURN(
      const auto &dlog_response,
      FieldElement::try_from_bytes32(dlog_proof.response));
  PURIFY_RETURN_IF_ERROR(transcript.append_dlog_response(dlog_response));

  const ScalarBytes precommitment_bytes = precommitment.digest.bytes();
  PURIFY_ASSIGN_OR_RETURN(const auto &mask_seed,
                          derive_mask_seed_v4(seed, precommitment_bytes));
  PURIFY_ASSIGN_OR_RETURN(
      const auto &mask_n,
      derive_secret_scalars(hidden.n_vec.size(), mask_seed,
                            kCircuitZkMaskNV4TaggedHash, attempt));
  PURIFY_ASSIGN_OR_RETURN(
      const auto &mask_l,
      derive_secret_scalars(hidden.l_vec.size(), mask_seed,
                            kCircuitZkMaskLV4TaggedHash, attempt));

  FieldElement t2 = weighted_bppp_inner_product(
      mask_n, mask_n, hidden.public_data->rho);
  WipeOnDestruction t2_wiper(t2);
  if (t2.is_zero()) return Attempt::redraw();
  FieldElement t1 =
      FieldElement::from_int(2) *
      weighted_bppp_inner_product(hidden.n_vec, mask_n,
                                  hidden.public_data->rho);
  WipeOnDestruction t1_wiper(t1);
  for (std::size_t i = 0; i < mask_l.size(); ++i) {
    t1 = t1 + mask_l[i] * hidden.public_data->c_vec[i];
  }

  SecretNormArgInputs mask_inputs =
      build_mask_inputs(*hidden.public_data, mask_n, mask_l);
  auto mask_commitment =
      commit_explicit_norm_arg(mask_inputs, t1, secp_context, nullptr);
  if (!mask_commitment.has_value()) {
    return Attempt::rejected(mask_commitment.error());
  }
  PURIFY_ASSIGN_OR_RETURN(
      const auto &alpha,
      transcript.append_mask(*mask_commitment, t2, secp_context));

  CircuitNormArgReduction masked =
      mask_reduction(hidden, alpha.scalar, mask_n, mask_l);
  SecretNormArgInputs masked_inputs = build_norm_arg_inputs(masked);
  auto combined_commitment = combine_zk_commitments(
      anchored_commitment, *mask_commitment, alpha.scalar, t2,
      secp_context);
  if (!combined_commitment.has_value()) {
    return Attempt::rejected(combined_commitment.error());
  }
  PURIFY_ASSIGN_OR_RETURN(
      const auto &direct_commitment,
      commit_norm_arg_with_cache(masked_inputs, secp_context, nullptr));
  if (*combined_commitment != direct_commitment) {
    return unexpected_error(ErrorCode::InternalMismatch);
  }
  PURIFY_RETURN_IF_ERROR(transcript.append_combined_commitment(
      *combined_commitment, secp_context));

  auto norm = prove_norm_arg_to_commitment_v4(
      masked_inputs, *combined_commitment, transcript, secp_context);
  if (!norm.has_value()) {
    return Attempt::rejected(norm.error());
  }
  ScalarBytes terminal_n{};
  ScalarBytes terminal_l{};
  PURIFY_ASSIGN_OR_RETURN(const auto &rounds,
                          parse_norm_rounds_v4(norm->proof,
                                               shape.round_count(),
                                               terminal_n, terminal_l));
  (void)rounds;
  PURIFY_ASSIGN_OR_RETURN(const auto &terminal_n_scalar,
                          FieldElement::try_from_bytes32(terminal_n));
  PURIFY_ASSIGN_OR_RETURN(const auto &terminal_l_scalar,
                          FieldElement::try_from_bytes32(terminal_l));
  PURIFY_ASSIGN_OR_RETURN(
      const auto finished,
      transcript.finish(terminal_n_scalar, terminal_l_scalar));
  (void)finished;

  candidate::CircuitZkNormArgProofV4 proof{
      *raw_commitment,
      *mask_commitment,
      scalar_bytes(t2),
      dlog_proof.nonce_xonly,
      dlog_proof.response,
      std::move(norm->proof)};
  return Attempt::accepted(candidate::CircuitZkNormArgPublicationV4{
      precommitment.digest, std::move(proof)});
}

Result<candidate::CircuitZkNormArgPublicationV4>
prove_circuit_zk_norm_arg_v4_impl(
    const NativeBulletproofCircuit &circuit,
    const BulletproofAssignmentData &assignment,
    const ScalarBytes &secret_prover_seed,
    std::span<const PointBytes> public_commitments,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    bool externalize_commitments, ExperimentalCircuitBackend *cache) {
  PURIFY_RETURN_IF_ERROR(validate_circuit_witness_v4(
      circuit, assignment, public_commitments, secp_context,
      externalize_commitments));

  PURIFY_ASSIGN_OR_RETURN(
      const auto &binding_digest,
      circuit_binding_digest_v4(circuit, statement_binding));
  PURIFY_ASSIGN_OR_RETURN(
      const auto &dimensions,
      circuit_norm_arg_dimensions(circuit, externalize_commitments));
  PURIFY_ASSIGN_OR_RETURN(const auto shape,
                          circuit_shape_v4(circuit, externalize_commitments));
  PURIFY_ASSIGN_OR_RETURN(
      const auto &seed,
      derive_prover_seed_v4(binding_digest, secret_prover_seed,
                            public_commitments, assignment,
                            externalize_commitments));

  const ProverRunV4 run{circuit,
                        assignment,
                        secret_prover_seed,
                        public_commitments,
                        secp_context,
                        statement_binding,
                        externalize_commitments,
                        cache,
                        binding_digest,
                        dimensions,
                        shape,
                        seed};
  return first_accepted_masking<candidate::CircuitZkNormArgPublicationV4>(
      [&run](std::uint64_t attempt) {
        return attempt_circuit_zk_norm_arg_v4(run, attempt);
      });
}

} // namespace

Result<candidate::CircuitZkNormArgPublicationV4>
candidate::prove_circuit_zk_norm_arg_v4(
    const NativeBulletproofCircuit &circuit,
    const BulletproofAssignmentData &assignment,
    const ScalarBytes &secret_prover_seed,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    ExperimentalCircuitBackend *cache) {
  return prove_circuit_zk_norm_arg_v4_impl(
      circuit, assignment, secret_prover_seed, {}, secp_context,
      statement_binding, false, cache);
}

Result<candidate::CircuitZkNormArgPublicationV4>
candidate::prove_circuit_zk_norm_arg_v4_with_public_commitments(
    const NativeBulletproofCircuit &circuit,
    const BulletproofAssignmentData &assignment,
    const ScalarBytes &secret_prover_seed,
    std::span<const PointBytes> public_commitments,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    ExperimentalCircuitBackend *cache) {
  return prove_circuit_zk_norm_arg_v4_impl(
      circuit, assignment, secret_prover_seed, public_commitments,
      secp_context, statement_binding, true, cache);
}

} // namespace purify::bppp
