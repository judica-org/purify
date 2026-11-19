// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

#include "sha256_transcript.hpp"
#include "purify/bppp.hpp"

namespace purify::bppp::candidate {

/** Whether circuit commitment values remain hidden or use public points. */
enum class CircuitCommitmentModeV4 : std::uint64_t {
  Hidden = 0,
  Public = 1,
};

/** Validated dimensions shared by both V4 transcript stages. */
class CircuitTranscriptShapeV4 {
public:
  [[nodiscard]] static Result<CircuitTranscriptShapeV4>
  create(CircuitCommitmentModeV4 mode, std::size_t gate_count,
         std::size_t commitment_count, std::size_t n_vec_len,
         std::size_t l_vec_len);

  [[nodiscard]] CircuitCommitmentModeV4 mode() const noexcept { return mode_; }
  [[nodiscard]] std::size_t gate_count() const noexcept { return gate_count_; }
  [[nodiscard]] std::size_t commitment_count() const noexcept {
    return commitment_count_;
  }
  [[nodiscard]] std::size_t n_vec_len() const noexcept { return n_vec_len_; }
  [[nodiscard]] std::size_t l_vec_len() const noexcept { return l_vec_len_; }
  [[nodiscard]] std::size_t round_count() const noexcept;
  [[nodiscard]] std::size_t public_commitment_count() const noexcept;

private:
  CircuitTranscriptShapeV4(CircuitCommitmentModeV4 mode, std::size_t gate_count,
                           std::size_t commitment_count, std::size_t n_vec_len,
                           std::size_t l_vec_len)
      : mode_(mode), gate_count_(gate_count),
        commitment_count_(commitment_count), n_vec_len_(n_vec_len),
        l_vec_len_(l_vec_len) {}

  CircuitCommitmentModeV4 mode_{};
  std::size_t gate_count_{0};
  std::size_t commitment_count_{0};
  std::size_t n_vec_len_{0};
  std::size_t l_vec_len_{0};
};

/** A canonical nonzero scalar produced only by the V4 precommitment stage. */
class CircuitPrecommitmentDigestV4 {
public:
  [[nodiscard]] static Result<CircuitPrecommitmentDigestV4>
  parse(const ScalarBytes &encoded);

  [[nodiscard]] const FieldElement &scalar() const noexcept { return scalar_; }
  [[nodiscard]] ScalarBytes bytes() const { return scalar_.to_bytes_be(); }

private:
  explicit CircuitPrecommitmentDigestV4(FieldElement scalar)
      : scalar_(std::move(scalar)) {}

  FieldElement scalar_;
};

/** One canonical nonzero scalar produced by the typed SHA-256 transcript. */
struct CircuitChallengeV4 {
  FieldElement scalar;
};

struct CircuitPrecommitmentResultV4 {
  CircuitPrecommitmentDigestV4 digest;
};

using PackedPointPairV4 = std::array<unsigned char, 65>;

/** Validate one canonical packed V4 norm-round point pair. */
[[nodiscard]] Status validate_packed_point_pair_v4(
    const PackedPointPairV4 &encoded,
    purify_secp_context *secp_context);

/** All proof fields consumed after the public precommitment digest. */
struct CircuitProofTranscriptInputV4 {
  TranscriptDigest raw_generator_digest{};
  PointBytes coefficient_commitment{};
  PointBytes anchored_offset{};
  PointBytes anchored_commitment{};
  PointBytes batched_public_commitment{};
  std::array<unsigned char, 32> dlog_nonce{};
  ScalarBytes dlog_response{};
  PointBytes mask_commitment{};
  ScalarBytes t2{};
  PointBytes combined_commitment{};
  std::vector<PackedPointPairV4> rounds;
  ScalarBytes terminal_n{};
  ScalarBytes terminal_l{};
};

/** Every selected proof challenge in exact transcript order. */
struct CircuitProofTranscriptResultV4 {
  CircuitChallengeV4 rho;
  CircuitChallengeV4 mul_scale;
  CircuitChallengeV4 mul_ratio;
  CircuitChallengeV4 row_ratio;
  CircuitChallengeV4 eta;
  CircuitChallengeV4 dlog_challenge;
  CircuitChallengeV4 alpha;
  std::vector<CircuitChallengeV4> gammas;
  CircuitChallengeV4 prepared_binding;
};

/**
 * Incremental V4 proof transcript used while the inner proof is produced.
 *
 * Each method consumes exactly the next protocol stage. The type derives
 * challenges only; callers still have to verify every corresponding group
 * and norm equation.
 */
class CircuitProofTranscriptV4 {
public:
  [[nodiscard]] static Result<CircuitProofTranscriptV4>
  create(const CircuitTranscriptShapeV4 &shape,
         const CircuitPrecommitmentDigestV4 &precommitment,
         const TranscriptDigest &raw_generator_digest);

  [[nodiscard]] const CircuitChallengeV4 &rho() const noexcept {
    return rho_;
  }
  [[nodiscard]] const CircuitTranscriptShapeV4 &shape() const noexcept {
    return shape_;
  }
  [[nodiscard]] const CircuitChallengeV4 &mul_scale() const noexcept {
    return mul_scale_;
  }
  [[nodiscard]] const CircuitChallengeV4 &mul_ratio() const noexcept {
    return mul_ratio_;
  }
  [[nodiscard]] const CircuitChallengeV4 &row_ratio() const noexcept {
    return row_ratio_;
  }

  [[nodiscard]] Result<CircuitChallengeV4>
  append_anchored_commitments(const PointBytes &coefficient_commitment,
                              const PointBytes &anchored_offset,
                              const PointBytes &anchored_commitment,
                              purify_secp_context *secp_context);

  [[nodiscard]] Result<CircuitChallengeV4>
  append_public_opening(
      const PointBytes &batched_public_commitment,
      const std::array<unsigned char, 32> &dlog_nonce,
      purify_secp_context *secp_context);

  [[nodiscard]] Status append_dlog_response(
      const FieldElement &dlog_response);

  [[nodiscard]] Result<CircuitChallengeV4>
  append_mask(const PointBytes &mask_commitment, const FieldElement &t2,
              purify_secp_context *secp_context);

  [[nodiscard]] Status append_combined_commitment(
      const PointBytes &combined_commitment,
      purify_secp_context *secp_context);

  [[nodiscard]] Result<CircuitChallengeV4>
  append_round(const PackedPointPairV4 &round,
               purify_secp_context *secp_context);

  [[nodiscard]] Result<CircuitChallengeV4>
  finish(const FieldElement &terminal_n, const FieldElement &terminal_l);

private:
  enum class Stage {
    AnchoredCommitments,
    PublicOpening,
    DlogResponse,
    Mask,
    CombinedCommitment,
    Rounds,
    Terminal,
    Finished,
  };

  CircuitProofTranscriptV4(CircuitTranscriptShapeV4 shape,
                           Sha256Transcript transcript,
                           CircuitChallengeV4 rho,
                           CircuitChallengeV4 mul_scale,
                           CircuitChallengeV4 mul_ratio,
                           CircuitChallengeV4 row_ratio)
      : shape_(shape), transcript_(std::move(transcript)),
        rho_(std::move(rho)), mul_scale_(std::move(mul_scale)),
        mul_ratio_(std::move(mul_ratio)), row_ratio_(std::move(row_ratio)) {}

  CircuitTranscriptShapeV4 shape_;
  Sha256Transcript transcript_;
  CircuitChallengeV4 rho_;
  CircuitChallengeV4 mul_scale_;
  CircuitChallengeV4 mul_ratio_;
  CircuitChallengeV4 row_ratio_;
  Stage stage_{Stage::AnchoredCommitments};
  std::size_t next_round_{0};
};

/**
 * Bind verifier-known circuit data and the hidden raw commitment.
 *
 * The returned digest is public parent input. This function does not verify a
 * circuit proof or authenticate any later proof field.
 */
[[nodiscard]] Result<CircuitPrecommitmentResultV4>
derive_circuit_precommitment_v4(const CircuitTranscriptShapeV4 &shape,
                                const TranscriptDigest &circuit_binding_digest,
                                std::span<const PointBytes> public_commitments,
                                const PointBytes &raw_commitment,
                                purify_secp_context *secp_context);

/** Replay the fixed V4 proof transcript and return its public challenges. */
[[nodiscard]] Result<CircuitProofTranscriptResultV4>
derive_circuit_proof_transcript_v4(
    const CircuitTranscriptShapeV4 &shape,
    const CircuitPrecommitmentDigestV4 &precommitment,
    const CircuitProofTranscriptInputV4 &proof,
    purify_secp_context *secp_context);

} // namespace purify::bppp::candidate
