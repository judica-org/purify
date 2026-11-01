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

#include "algebraic_transcript.hpp"
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

/** One selected scalar together with the exact two squeezed field lanes. */
struct CircuitChallengeV4 {
  std::array<CoordinateFieldElement, 2> lanes;
  FieldElement scalar;
};

struct CircuitPrecommitmentResultV4 {
  std::array<CoordinateFieldElement, 2> lanes;
  CircuitPrecommitmentDigestV4 digest;
};

using PackedPointPairV4 = std::array<unsigned char, 65>;

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
