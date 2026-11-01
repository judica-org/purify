// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include <array>
#include <optional>
#include <span>
#include <vector>

#include "algebraic_circuit_transcript.hpp"

namespace purify::bppp::accumulation::internal {
struct PreparedCircuitZkNormArgV4AdapterAccess;
}

namespace purify::bppp::candidate {

namespace detail {
struct PreparedCircuitZkNormArgV4Builder;
}

/**
 * V4 wire proof, intentionally distinct from the V3 proof.
 *
 * Native BP++ proofs use the backend's finite initial-commitment language.
 * Raw A, S, derived A_anch/P, public-mode commitment points, and every
 * intermediate public batch operation therefore must stay finite.
 * Reconstructed Cc and Q_off may use canonical zero33 identity encoding.
 * The constrained leaf permits more algebraic identity fixtures, but this
 * producer/verifier pair intentionally exposes the finite native subset
 * until the underlying norm encoding supports infinity.
 */
struct CircuitZkNormArgProofV4 {
  PointBytes raw_commitment{};
  PointBytes mask_commitment{};
  ScalarBytes t2{};
  std::array<unsigned char, 32> public_commitment_dlog_nonce{};
  ScalarBytes public_commitment_dlog_response{};
  Bytes norm_proof;
};

/** Public precommitment and the proof whose transcript it fixes. */
struct CircuitZkNormArgPublicationV4 {
  CircuitPrecommitmentDigestV4 precommitment;
  CircuitZkNormArgProofV4 proof;
};

/**
 * Outer-authenticated V4 statement with a pending inner norm obligation.
 *
 * `transcript_input` and `transcript` are the exact public witness and
 * challenges consumed by the recursive leaf relation. The pending residual
 * intentionally excludes the authenticated coefficient-opening term; it is
 * not an acceptance result and is normally nonzero.
 *
 * The public commitments and raw generators are verifier-reconstructed
 * inputs for the outer leaf/basis bridge. The coefficient commitment and
 * anchored offset in `transcript_input` are likewise reconstructed here;
 * neither is accepted as a prover-supplied constant.
 */
class PreparedCircuitZkNormArgV4 {
public:
  [[nodiscard]] const CircuitPrecommitmentDigestV4 &
  precommitment() const noexcept {
    return precommitment_;
  }
  [[nodiscard]] const CircuitTranscriptShapeV4 &shape() const noexcept {
    return shape_;
  }
  [[nodiscard]] const TranscriptDigest &
  circuit_binding_digest() const noexcept {
    return circuit_binding_digest_;
  }
  [[nodiscard]] const PointBytes &raw_commitment() const noexcept {
    return raw_commitment_;
  }
  [[nodiscard]] const std::vector<PointBytes> &
  trusted_public_commitments() const noexcept {
    return trusted_public_commitments_;
  }
  [[nodiscard]] const std::vector<PointBytes> &
  raw_generators() const noexcept {
    return raw_generators_;
  }
  [[nodiscard]] const CircuitProofTranscriptInputV4 &
  transcript_input() const noexcept {
    return transcript_input_;
  }
  [[nodiscard]] const CircuitProofTranscriptResultV4 &
  transcript() const noexcept {
    return transcript_;
  }
  [[nodiscard]] const NormArgProof &norm() const noexcept { return norm_; }
  [[nodiscard]] const PointBytes &pending_norm_residual() const noexcept {
    return pending_norm_residual_;
  }

private:
  PreparedCircuitZkNormArgV4(
      CircuitPrecommitmentDigestV4 precommitment,
      CircuitTranscriptShapeV4 shape,
      TranscriptDigest circuit_binding_digest,
      PointBytes raw_commitment,
      std::vector<PointBytes> trusted_public_commitments,
      std::vector<PointBytes> raw_generators,
      CircuitProofTranscriptInputV4 transcript_input,
      CircuitProofTranscriptResultV4 transcript, NormArgProof norm,
      PointBytes pending_norm_residual)
      : precommitment_(std::move(precommitment)), shape_(std::move(shape)),
        circuit_binding_digest_(circuit_binding_digest),
        raw_commitment_(raw_commitment),
        trusted_public_commitments_(
            std::move(trusted_public_commitments)),
        raw_generators_(std::move(raw_generators)),
        transcript_input_(std::move(transcript_input)),
        transcript_(std::move(transcript)), norm_(std::move(norm)),
        pending_norm_residual_(pending_norm_residual) {}

  CircuitPrecommitmentDigestV4 precommitment_;
  CircuitTranscriptShapeV4 shape_;
  TranscriptDigest circuit_binding_digest_{};
  PointBytes raw_commitment_{};
  std::vector<PointBytes> trusted_public_commitments_;
  std::vector<PointBytes> raw_generators_;
  CircuitProofTranscriptInputV4 transcript_input_;
  CircuitProofTranscriptResultV4 transcript_;
  NormArgProof norm_;
  PointBytes pending_norm_residual_{};

  friend struct detail::PreparedCircuitZkNormArgV4Builder;
  friend struct accumulation::internal::
      PreparedCircuitZkNormArgV4AdapterAccess;
};

/**
 * Produce a hidden-commitment V4 proof.
 *
 * `secret_prover_seed` must be secret and uniformly unpredictable. The
 * synthetic randomness binds the complete ordered assignment and statement,
 * so one seed may be reused safely; an identical input tuple is deterministic.
 * Seed disclosure compromises witness-hiding randomness.
 */
[[nodiscard]] Result<CircuitZkNormArgPublicationV4>
prove_circuit_zk_norm_arg_v4(
    const NativeBulletproofCircuit &circuit,
    const BulletproofAssignmentData &assignment,
    const ScalarBytes &secret_prover_seed,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    ExperimentalCircuitBackend *cache = nullptr);

/**
 * Produce a public-commitment V4 proof.
 *
 * `secret_prover_seed` has the same secret, uniformly unpredictable contract
 * as the hidden prover. Synthetic randomness binds the complete assignment,
 * ordered public points, and statement, so reuse is safe. The DLog nonce is
 * additionally hedged with the public precommitment, but seed disclosure
 * still compromises witness hiding.
 */
[[nodiscard]] Result<CircuitZkNormArgPublicationV4>
prove_circuit_zk_norm_arg_v4_with_public_commitments(
    const NativeBulletproofCircuit &circuit,
    const BulletproofAssignmentData &assignment,
    const ScalarBytes &secret_prover_seed,
    std::span<const PointBytes> public_commitments,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    ExperimentalCircuitBackend *cache = nullptr);

[[nodiscard]] Result<std::optional<PreparedCircuitZkNormArgV4>>
prepare_circuit_zk_norm_arg_v4(
    const NativeBulletproofCircuit &circuit,
    const CircuitZkNormArgPublicationV4 &publication,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    ExperimentalCircuitBackend *cache = nullptr);

[[nodiscard]] Result<std::optional<PreparedCircuitZkNormArgV4>>
prepare_circuit_zk_norm_arg_v4_with_public_commitments(
    const NativeBulletproofCircuit &circuit,
    const CircuitZkNormArgPublicationV4 &publication,
    std::span<const PointBytes> public_commitments,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    ExperimentalCircuitBackend *cache = nullptr);

[[nodiscard]] Result<bool> verify_circuit_zk_norm_arg_v4(
    const NativeBulletproofCircuit &circuit,
    const CircuitZkNormArgPublicationV4 &publication,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    ExperimentalCircuitBackend *cache = nullptr);

[[nodiscard]] Result<bool>
verify_circuit_zk_norm_arg_v4_with_public_commitments(
    const NativeBulletproofCircuit &circuit,
    const CircuitZkNormArgPublicationV4 &publication,
    std::span<const PointBytes> public_commitments,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    ExperimentalCircuitBackend *cache = nullptr);

} // namespace purify::bppp::candidate
