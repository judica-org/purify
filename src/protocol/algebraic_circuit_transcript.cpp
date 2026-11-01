// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "algebraic_circuit_transcript.hpp"

#include <algorithm>
#include <bit>
#include <string_view>

#include "purify/secp_bridge.h"

namespace purify::bppp::candidate {
namespace {

constexpr std::string_view kPrecommitDomain =
    "Purify/BPPP/CircuitNormArg/v4/precommit";
constexpr std::string_view kProofDomain = "Purify/BPPP/CircuitNormArg/v4/proof";

struct ParsedPoint {
  unsigned char prefix{0};
  CoordinateFieldElement x;
};

struct ParsedPair {
  unsigned char parity{0};
  CoordinateFieldElement first_x;
  CoordinateFieldElement second_x;
};

bool all_zero(std::span<const unsigned char> bytes) {
  return std::all_of(bytes.begin(), bytes.end(),
                     [](unsigned char value) { return value == 0; });
}

Result<ParsedPoint> parse_point(const PointBytes &encoded,
                                purify_secp_context *secp_context) {
  if (all_zero(encoded)) {
    return ParsedPoint{0, CoordinateFieldElement::zero()};
  }
  if ((encoded[0] != 2 && encoded[0] != 3) ||
      purify_bip340_validate_xonly_pubkey(secp_context, encoded.data() + 1) ==
          0) {
    return unexpected_error(ErrorCode::BackendRejectedInput,
                            "circuit_v4:point");
  }
  CoordinateFieldElement::Encoding x{};
  std::copy(encoded.begin() + 1, encoded.end(), x.begin());
  PURIFY_ASSIGN_OR_RETURN(auto coordinate,
                          CoordinateFieldElement::from_bytes_be(x),
                          "circuit_v4:point_coordinate");
  return ParsedPoint{encoded[0], std::move(coordinate)};
}

Result<ParsedPair> parse_pair(const PackedPointPairV4 &encoded,
                              purify_secp_context *secp_context) {
  if (encoded[0] > 3) {
    return unexpected_error(ErrorCode::RangeViolation,
                            "circuit_v4:pair_parity");
  }
  ParsedPair out;
  out.parity = encoded[0];
  const std::array offsets{std::size_t{1}, std::size_t{33}};
  std::array<CoordinateFieldElement *, 2> outputs{&out.first_x, &out.second_x};
  for (std::size_t index = 0; index < offsets.size(); ++index) {
    const std::span<const unsigned char, 32> x(encoded.data() + offsets[index],
                                               32);
    const unsigned char parity_mask = static_cast<unsigned char>(2U >> index);
    if (all_zero(x)) {
      if ((encoded[0] & parity_mask) != 0) {
        return unexpected_error(ErrorCode::BindingMismatch,
                                "circuit_v4:pair_identity");
      }
      *outputs[index] = CoordinateFieldElement::zero();
      continue;
    }
    if (purify_bip340_validate_xonly_pubkey(secp_context, x.data()) == 0) {
      return unexpected_error(ErrorCode::BackendRejectedInput,
                              "circuit_v4:pair_point");
    }
    CoordinateFieldElement::Encoding coordinate{};
    std::copy(x.begin(), x.end(), coordinate.begin());
    PURIFY_ASSIGN_OR_RETURN(auto parsed,
                            CoordinateFieldElement::from_bytes_be(coordinate),
                            "circuit_v4:pair_coordinate");
    *outputs[index] = std::move(parsed);
  }
  return out;
}

Status append_bytes(AlgebraicTranscript &transcript, std::string_view bytes) {
  return transcript.append_bytes(std::span(
      reinterpret_cast<const unsigned char *>(bytes.data()), bytes.size()));
}

Status append_shape(AlgebraicTranscript &transcript,
                    const CircuitTranscriptShapeV4 &shape,
                    std::size_t public_commitment_count) {
  PURIFY_ASSIGN_OR_RETURN(
      const auto gate_count,
      narrow_size_to_u64(shape.gate_count(), "circuit_v4:gate_count"),
      "circuit_v4:gate_count");
  PURIFY_ASSIGN_OR_RETURN(const auto commitment_count,
                          narrow_size_to_u64(shape.commitment_count(),
                                             "circuit_v4:commitment_count"),
                          "circuit_v4:commitment_count");
  PURIFY_ASSIGN_OR_RETURN(
      const auto n_vec_len,
      narrow_size_to_u64(shape.n_vec_len(), "circuit_v4:n_vec_len"),
      "circuit_v4:n_vec_len");
  PURIFY_ASSIGN_OR_RETURN(
      const auto l_vec_len,
      narrow_size_to_u64(shape.l_vec_len(), "circuit_v4:l_vec_len"),
      "circuit_v4:l_vec_len");
  PURIFY_ASSIGN_OR_RETURN(
      const auto public_count,
      narrow_size_to_u64(public_commitment_count, "circuit_v4:public_count"),
      "circuit_v4:public_count");
  transcript.append_u64(static_cast<std::uint64_t>(shape.mode()));
  transcript.append_u64(gate_count);
  transcript.append_u64(commitment_count);
  transcript.append_u64(n_vec_len);
  transcript.append_u64(l_vec_len);
  transcript.append_u64(public_count);
  return {};
}

Status append_point(AlgebraicTranscript &transcript, const PointBytes &encoded,
                    purify_secp_context *secp_context) {
  PURIFY_ASSIGN_OR_RETURN(const auto point, parse_point(encoded, secp_context),
                          "circuit_v4:append_point");
  return transcript.append_point(point.prefix, point.x);
}

Result<CircuitChallengeV4> append_challenge(AlgebraicTranscript &transcript,
                                            std::uint64_t index) {
  CircuitChallengeV4 out{transcript.challenge(index), FieldElement::zero()};
  PURIFY_ASSIGN_OR_RETURN(out.scalar, select_nonzero_scalar(out.lanes),
                          "circuit_v4:challenge");
  transcript.append_scalar(out.scalar);
  return out;
}

Status validate_public_mode(const CircuitTranscriptShapeV4 &shape,
                            std::size_t public_commitment_count) {
  if (public_commitment_count != shape.public_commitment_count()) {
    return unexpected_error(ErrorCode::SizeMismatch, "circuit_v4:public_count");
  }
  return {};
}

} // namespace

Status validate_packed_point_pair_v4(
    const PackedPointPairV4 &encoded,
    purify_secp_context *secp_context) {
  PURIFY_ASSIGN_OR_RETURN(const auto parsed,
                          parse_pair(encoded, secp_context),
                          "circuit_v4:validate_pair");
  (void)parsed;
  return {};
}

Result<CircuitTranscriptShapeV4>
CircuitTranscriptShapeV4::create(CircuitCommitmentModeV4 mode,
                                 std::size_t gate_count,
                                 std::size_t commitment_count,
                                 std::size_t n_vec_len, std::size_t l_vec_len) {
  if (mode != CircuitCommitmentModeV4::Hidden &&
      mode != CircuitCommitmentModeV4::Public) {
    return unexpected_error(ErrorCode::UnsupportedSymbol, "circuit_v4:mode");
  }
  if (mode == CircuitCommitmentModeV4::Public && commitment_count == 0) {
    return unexpected_error(ErrorCode::InvalidDimensions,
                            "circuit_v4:public_commitments");
  }
  std::size_t expected_n = 0;
  if (!is_power_of_two_size(gate_count) ||
      (mode == CircuitCommitmentModeV4::Hidden &&
       commitment_count >= gate_count) ||
      !checked_mul_size(gate_count, 2, expected_n) || n_vec_len != expected_n ||
      l_vec_len != n_vec_len || !size_fits_u64(gate_count) ||
      !size_fits_u64(commitment_count) || !size_fits_u64(n_vec_len) ||
      !size_fits_u64(l_vec_len)) {
    return unexpected_error(ErrorCode::InvalidDimensions, "circuit_v4:shape");
  }
  return CircuitTranscriptShapeV4(mode, gate_count, commitment_count, n_vec_len,
                                  l_vec_len);
}

std::size_t CircuitTranscriptShapeV4::round_count() const noexcept {
  return static_cast<std::size_t>(std::bit_width(n_vec_len_) - 1);
}

std::size_t CircuitTranscriptShapeV4::public_commitment_count() const noexcept {
  return mode_ == CircuitCommitmentModeV4::Public ? commitment_count_ : 0;
}

Result<CircuitPrecommitmentDigestV4>
CircuitPrecommitmentDigestV4::parse(const ScalarBytes &encoded) {
  PURIFY_ASSIGN_OR_RETURN(auto scalar, FieldElement::try_from_bytes32(encoded),
                          "circuit_v4:precommitment_digest");
  if (scalar.is_zero()) {
    return unexpected_error(ErrorCode::RangeViolation,
                            "circuit_v4:precommitment_zero");
  }
  return CircuitPrecommitmentDigestV4(std::move(scalar));
}

Result<CircuitPrecommitmentResultV4>
derive_circuit_precommitment_v4(const CircuitTranscriptShapeV4 &shape,
                                const TranscriptDigest &circuit_binding_digest,
                                std::span<const PointBytes> public_commitments,
                                const PointBytes &raw_commitment,
                                purify_secp_context *secp_context) {
  PURIFY_RETURN_IF_ERROR(
      require_secp_context(secp_context, "circuit_v4:context"),
      "circuit_v4:context");
  PURIFY_RETURN_IF_ERROR(validate_public_mode(shape, public_commitments.size()),
                         "circuit_v4:public_mode");

  AlgebraicTranscript transcript;
  PURIFY_RETURN_IF_ERROR(append_bytes(transcript, kPrecommitDomain),
                         "circuit_v4:precommit_domain");
  PURIFY_RETURN_IF_ERROR(transcript.append_bytes(circuit_binding_digest),
                         "circuit_v4:circuit_binding");
  PURIFY_RETURN_IF_ERROR(
      append_shape(transcript, shape, public_commitments.size()),
      "circuit_v4:precommit_shape");
  for (const auto &point : public_commitments) {
    PURIFY_RETURN_IF_ERROR(append_point(transcript, point, secp_context),
                           "circuit_v4:public_commitment");
  }
  PURIFY_RETURN_IF_ERROR(append_point(transcript, raw_commitment, secp_context),
                         "circuit_v4:raw_commitment");

  const auto lanes = transcript.challenge(0);
  PURIFY_ASSIGN_OR_RETURN(const auto selected, select_nonzero_scalar(lanes),
                          "circuit_v4:precommitment_challenge");
  PURIFY_ASSIGN_OR_RETURN(
      auto digest, CircuitPrecommitmentDigestV4::parse(selected.to_bytes_be()),
      "circuit_v4:precommitment_digest");
  return CircuitPrecommitmentResultV4{lanes, std::move(digest)};
}

Result<CircuitProofTranscriptV4> CircuitProofTranscriptV4::create(
    const CircuitTranscriptShapeV4 &shape,
    const CircuitPrecommitmentDigestV4 &precommitment,
    const TranscriptDigest &raw_generator_digest) {
  AlgebraicTranscript transcript;
  PURIFY_RETURN_IF_ERROR(append_bytes(transcript, kProofDomain),
                         "circuit_v4:proof_domain");
  transcript.append_scalar(precommitment.scalar());
  PURIFY_RETURN_IF_ERROR(transcript.append_bytes(raw_generator_digest),
                         "circuit_v4:raw_generator_digest");
  PURIFY_RETURN_IF_ERROR(
      append_shape(transcript, shape, shape.public_commitment_count()),
      "circuit_v4:proof_shape");
  PURIFY_ASSIGN_OR_RETURN(auto rho, append_challenge(transcript, 0),
                          "circuit_v4:rho");
  PURIFY_ASSIGN_OR_RETURN(auto mul_scale, append_challenge(transcript, 1),
                          "circuit_v4:mul_scale");
  PURIFY_ASSIGN_OR_RETURN(auto mul_ratio, append_challenge(transcript, 2),
                          "circuit_v4:mul_ratio");
  PURIFY_ASSIGN_OR_RETURN(auto row_ratio, append_challenge(transcript, 3),
                          "circuit_v4:row_ratio");
  return CircuitProofTranscriptV4(
      shape, std::move(transcript), std::move(rho), std::move(mul_scale),
      std::move(mul_ratio), std::move(row_ratio));
}

Result<CircuitChallengeV4>
CircuitProofTranscriptV4::append_anchored_commitments(
    const PointBytes &coefficient_commitment,
    const PointBytes &anchored_offset,
    const PointBytes &anchored_commitment,
    purify_secp_context *secp_context) {
  if (stage_ != Stage::AnchoredCommitments) {
    return unexpected_error(ErrorCode::InternalMismatch,
                            "circuit_v4:anchored_stage");
  }
  AlgebraicTranscript transcript = transcript_;
  PURIFY_RETURN_IF_ERROR(
      append_point(transcript, coefficient_commitment, secp_context),
      "circuit_v4:coefficient_commitment");
  PURIFY_RETURN_IF_ERROR(
      append_point(transcript, anchored_offset, secp_context),
      "circuit_v4:anchored_offset");
  PURIFY_RETURN_IF_ERROR(
      append_point(transcript, anchored_commitment, secp_context),
      "circuit_v4:anchored_commitment");
  PURIFY_ASSIGN_OR_RETURN(auto eta, append_challenge(transcript, 4),
                          "circuit_v4:eta");
  transcript_ = std::move(transcript);
  stage_ = Stage::PublicOpening;
  return eta;
}

Result<CircuitChallengeV4>
CircuitProofTranscriptV4::append_public_opening(
    const PointBytes &batched_public_commitment,
    const std::array<unsigned char, 32> &dlog_nonce,
    purify_secp_context *secp_context) {
  if (stage_ != Stage::PublicOpening) {
    return unexpected_error(ErrorCode::InternalMismatch,
                            "circuit_v4:public_opening_stage");
  }
  if (shape_.mode() == CircuitCommitmentModeV4::Hidden) {
    if (!all_zero(batched_public_commitment) || !all_zero(dlog_nonce)) {
      return unexpected_error(ErrorCode::BindingMismatch,
                              "circuit_v4:hidden_dlog");
    }
  } else if (purify_bip340_validate_xonly_pubkey(
                 secp_context, dlog_nonce.data()) == 0) {
    return unexpected_error(ErrorCode::BackendRejectedInput,
                            "circuit_v4:dlog_nonce");
  }
  AlgebraicTranscript transcript = transcript_;
  PURIFY_RETURN_IF_ERROR(
      append_point(transcript, batched_public_commitment, secp_context),
      "circuit_v4:batched_commitment");
  PURIFY_RETURN_IF_ERROR(transcript.append_bytes(dlog_nonce),
                         "circuit_v4:dlog_nonce");
  PURIFY_ASSIGN_OR_RETURN(auto challenge, append_challenge(transcript, 5),
                          "circuit_v4:dlog_challenge");
  transcript_ = std::move(transcript);
  stage_ = Stage::DlogResponse;
  return challenge;
}

Status CircuitProofTranscriptV4::append_dlog_response(
    const FieldElement &dlog_response) {
  if (stage_ != Stage::DlogResponse) {
    return unexpected_error(ErrorCode::InternalMismatch,
                            "circuit_v4:dlog_response_stage");
  }
  if (shape_.mode() == CircuitCommitmentModeV4::Hidden &&
      !dlog_response.is_zero()) {
    return unexpected_error(ErrorCode::BindingMismatch,
                            "circuit_v4:hidden_dlog");
  }
  transcript_.append_scalar(dlog_response);
  stage_ = Stage::Mask;
  return {};
}

Result<CircuitChallengeV4> CircuitProofTranscriptV4::append_mask(
    const PointBytes &mask_commitment, const FieldElement &t2,
    purify_secp_context *secp_context) {
  if (stage_ != Stage::Mask) {
    return unexpected_error(ErrorCode::InternalMismatch,
                            "circuit_v4:mask_stage");
  }
  AlgebraicTranscript transcript = transcript_;
  PURIFY_RETURN_IF_ERROR(
      append_point(transcript, mask_commitment, secp_context),
      "circuit_v4:mask_commitment");
  transcript.append_scalar(t2);
  PURIFY_ASSIGN_OR_RETURN(auto alpha, append_challenge(transcript, 6),
                          "circuit_v4:alpha");
  transcript_ = std::move(transcript);
  stage_ = Stage::CombinedCommitment;
  return alpha;
}

Status CircuitProofTranscriptV4::append_combined_commitment(
    const PointBytes &combined_commitment,
    purify_secp_context *secp_context) {
  if (stage_ != Stage::CombinedCommitment) {
    return unexpected_error(ErrorCode::InternalMismatch,
                            "circuit_v4:combined_stage");
  }
  AlgebraicTranscript transcript = transcript_;
  PURIFY_RETURN_IF_ERROR(
      append_point(transcript, combined_commitment, secp_context),
      "circuit_v4:combined_commitment");
  transcript_ = std::move(transcript);
  stage_ = shape_.round_count() == 0 ? Stage::Terminal : Stage::Rounds;
  return {};
}

Result<CircuitChallengeV4> CircuitProofTranscriptV4::append_round(
    const PackedPointPairV4 &round,
    purify_secp_context *secp_context) {
  if (stage_ != Stage::Rounds || next_round_ >= shape_.round_count()) {
    return unexpected_error(ErrorCode::InternalMismatch,
                            "circuit_v4:round_stage");
  }
  AlgebraicTranscript transcript = transcript_;
  PURIFY_ASSIGN_OR_RETURN(const auto pair, parse_pair(round, secp_context),
                          "circuit_v4:round_pair");
  PURIFY_RETURN_IF_ERROR(
      transcript.append_point_pair(pair.parity, pair.first_x, pair.second_x),
      "circuit_v4:round_pair");
  PURIFY_ASSIGN_OR_RETURN(
      auto gamma,
      append_challenge(transcript,
                       7 + static_cast<std::uint64_t>(next_round_)),
      "circuit_v4:gamma");
  transcript_ = std::move(transcript);
  ++next_round_;
  if (next_round_ == shape_.round_count()) stage_ = Stage::Terminal;
  return gamma;
}

Result<CircuitChallengeV4> CircuitProofTranscriptV4::finish(
    const FieldElement &terminal_n, const FieldElement &terminal_l) {
  if (stage_ != Stage::Terminal) {
    return unexpected_error(ErrorCode::InternalMismatch,
                            "circuit_v4:terminal_stage");
  }
  AlgebraicTranscript transcript = transcript_;
  transcript.append_scalar(terminal_n);
  transcript.append_scalar(terminal_l);
  CircuitChallengeV4 prepared{
      transcript.challenge(7 + static_cast<std::uint64_t>(next_round_)),
      FieldElement::zero()};
  PURIFY_ASSIGN_OR_RETURN(prepared.scalar,
                          select_nonzero_scalar(prepared.lanes),
                          "circuit_v4:prepared_binding");
  transcript_ = std::move(transcript);
  stage_ = Stage::Finished;
  return prepared;
}

Result<CircuitProofTranscriptResultV4> derive_circuit_proof_transcript_v4(
    const CircuitTranscriptShapeV4 &shape,
    const CircuitPrecommitmentDigestV4 &precommitment,
    const CircuitProofTranscriptInputV4 &proof,
    purify_secp_context *secp_context) {
  PURIFY_RETURN_IF_ERROR(
      require_secp_context(secp_context, "circuit_v4:context"),
      "circuit_v4:context");
  if (proof.rounds.size() != shape.round_count()) {
    return unexpected_error(ErrorCode::SizeMismatch, "circuit_v4:round_count");
  }

  PURIFY_ASSIGN_OR_RETURN(const auto dlog_response,
                          FieldElement::try_from_bytes32(proof.dlog_response),
                          "circuit_v4:dlog_response");
  PURIFY_ASSIGN_OR_RETURN(
      const auto t2, FieldElement::try_from_bytes32(proof.t2), "circuit_v4:t2");
  PURIFY_ASSIGN_OR_RETURN(const auto terminal_n,
                          FieldElement::try_from_bytes32(proof.terminal_n),
                          "circuit_v4:terminal_n");
  PURIFY_ASSIGN_OR_RETURN(const auto terminal_l,
                          FieldElement::try_from_bytes32(proof.terminal_l),
                          "circuit_v4:terminal_l");

  PURIFY_ASSIGN_OR_RETURN(
      auto transcript,
      CircuitProofTranscriptV4::create(
          shape, precommitment, proof.raw_generator_digest),
      "circuit_v4:proof_prefix");
  CircuitProofTranscriptResultV4 out;
  out.rho = transcript.rho();
  out.mul_scale = transcript.mul_scale();
  out.mul_ratio = transcript.mul_ratio();
  out.row_ratio = transcript.row_ratio();
  PURIFY_ASSIGN_OR_RETURN(
      out.eta,
      transcript.append_anchored_commitments(
          proof.coefficient_commitment, proof.anchored_offset,
          proof.anchored_commitment, secp_context),
      "circuit_v4:anchored_commitments");
  PURIFY_ASSIGN_OR_RETURN(
      out.dlog_challenge,
      transcript.append_public_opening(
          proof.batched_public_commitment, proof.dlog_nonce, secp_context),
      "circuit_v4:public_opening");
  PURIFY_RETURN_IF_ERROR(transcript.append_dlog_response(dlog_response),
                         "circuit_v4:dlog_response");
  PURIFY_ASSIGN_OR_RETURN(
      out.alpha,
      transcript.append_mask(proof.mask_commitment, t2, secp_context),
      "circuit_v4:mask");
  PURIFY_RETURN_IF_ERROR(
      transcript.append_combined_commitment(
          proof.combined_commitment, secp_context),
      "circuit_v4:combined_commitment");

  out.gammas.reserve(proof.rounds.size());
  for (const auto &round : proof.rounds) {
    PURIFY_ASSIGN_OR_RETURN(
        auto gamma, transcript.append_round(round, secp_context),
        "circuit_v4:gamma");
    out.gammas.push_back(std::move(gamma));
  }
  PURIFY_ASSIGN_OR_RETURN(
      out.prepared_binding, transcript.finish(terminal_n, terminal_l),
      "circuit_v4:prepared_binding");
  return out;
}

} // namespace purify::bppp::candidate
