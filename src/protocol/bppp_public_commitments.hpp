// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file bppp_public_commitments.hpp
 * @brief Batched public commitments and their discrete-log proofs.
 */

#pragma once

#include <array>
#include <span>
#include <vector>

#include "bppp_points.hpp"
#include "bppp_support.hpp"
#include "purify/bppp.hpp"

namespace purify::bppp {

namespace detail {

struct BatchedPublicCommitment {
  PointBytes point{};
  std::vector<FieldElement> weights;
};

Result<BatchedPublicCommitment> batch_public_commitments_with_eta(
    std::span<const PointBytes> public_commitments,
    const FieldElement &eta,
    purify_secp_context *secp_context);

Result<BatchedPublicCommitment> batch_public_commitments(
    std::span<const PointBytes> public_commitments,
    std::span<const unsigned char> challenge_digest,
    purify_secp_context *secp_context);

Result<FieldElement> dlog_challenge(
    std::span<const unsigned char> challenge_digest,
    const PointBytes &batched_commitment,
    const std::array<unsigned char, 32> &nonce_xonly);

struct PublicCommitmentDlogProof {
  std::array<unsigned char, 32> nonce_xonly{};
  ScalarBytes response{};
};

Result<PublicCommitmentDlogProof> prove_public_commitment_dlog(
    const BatchedPublicCommitment &batched,
    std::span<const FieldElement> commitment_values,
    std::span<const unsigned char> challenge_digest,
    const ScalarBytes &secret_prover_seed,
    purify_secp_context *secp_context);

Result<bool> verify_public_commitment_dlog(
    const BatchedPublicCommitment &batched,
    const FieldElement &challenge,
    const PublicCommitmentDlogProof &proof,
    purify_secp_context *secp_context);

Result<bool> verify_public_commitment_dlog(
    const BatchedPublicCommitment &batched,
    std::span<const unsigned char> challenge_digest,
    const PublicCommitmentDlogProof &proof,
    purify_secp_context *secp_context);

Result<Bytes> bind_public_commitments(
    std::span<const PointBytes> public_commitments,
    std::span<const unsigned char> statement_binding);

Status
validate_public_commitments(std::span<const PointBytes> public_commitments,
                            std::span<const FieldElement> commitments,
                            purify_secp_context *secp_context);

} // namespace detail

} // namespace purify::bppp
