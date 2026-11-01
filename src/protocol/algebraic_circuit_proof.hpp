// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include <array>
#include <optional>
#include <span>
#include <vector>

#include "algebraic_circuit_transcript.hpp"

namespace purify::bppp::candidate {

/**
 * V4 wire proof, intentionally distinct from the V3 proof.
 *
 * Native BP++ proofs use the backend's finite initial-commitment language.
 * Raw A, S, derived A_anch/P, and public-mode commitment points therefore
 * must be finite. Reconstructed Cc and Q_off may use canonical zero33
 * identity encoding. The constrained leaf permits more algebraic identity
 * fixtures, but this producer/verifier pair intentionally exposes the
 * finite native subset until the underlying norm encoding supports infinity.
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
 * Verified outer V4 statement with the remaining inner norm obligation.
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
struct PreparedCircuitZkNormArgV4 {
  CircuitPrecommitmentDigestV4 precommitment;
  CircuitTranscriptShapeV4 shape;
  TranscriptDigest circuit_binding_digest{};
  PointBytes raw_commitment{};
  std::vector<PointBytes> trusted_public_commitments;
  std::vector<PointBytes> raw_generators;
  CircuitProofTranscriptInputV4 transcript_input;
  CircuitProofTranscriptResultV4 transcript;
  NormArgProof norm;
  PointBytes pending_norm_residual{};
};

[[nodiscard]] Result<CircuitZkNormArgPublicationV4>
prove_circuit_zk_norm_arg_v4(
    const NativeBulletproofCircuit &circuit,
    const BulletproofAssignmentData &assignment,
    const ScalarBytes &secret_prover_seed,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    ExperimentalCircuitBackend *cache = nullptr);

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
