// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file accumulation_ipa.hpp
 * @brief Inner-product opening arguments used by accumulation steps and norm reductions.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "accumulation_support.hpp"
#include "bppp_bridge.h"
#include "purify/accumulation.hpp"
#include "sha256_transcript.hpp"

namespace purify::bppp::accumulation {

namespace internal {

template <typename Proof>
Status validate_ipa_encoding(std::size_t dimension, const Proof& proof,
                             purify_secp_context* context) {
    PURIFY_RETURN_IF_ERROR(require_secp_context(context));
    if (!is_power_of_two_size(dimension)) {
        return unexpected_error(ErrorCode::InvalidDimensions);
    }
    const auto rounds = log2_dimension(dimension);
    if (proof.left.size() != rounds || proof.right.size() != rounds) {
        return unexpected_error(ErrorCode::SizeMismatch);
    }
    PURIFY_ASSIGN_OR_RETURN(auto terminal, FieldElement::try_from_bytes32(proof.terminal_scalar));
    (void)terminal;
    const auto is_canonical_point = [](const PointBytes& point) {
        return purify_bppp_public_point_validate(point.data()) != 0;
    };
    for (std::size_t round = 0; round < rounds; ++round) {
        if (!is_canonical_point(proof.left[round]) ||
            !is_canonical_point(proof.right[round])) {
            return unexpected_error(ErrorCode::BackendRejectedInput);
        }
    }
    if (!is_canonical_point(proof.folded_generator)) {
        return unexpected_error(ErrorCode::BackendRejectedInput);
    }
    return {};
}

template <typename Proof>
void append_ipa(Bytes& out, const Proof& proof) {
    for (std::size_t round = 0; round < proof.left.size(); ++round) {
        append(out, proof.left[round]);
        append(out, proof.right[round]);
    }
    append(out, proof.terminal_scalar);
    append(out, proof.folded_generator);
}

template <typename Proof>
Result<Proof> parse_ipa(std::size_t dimension,
                       std::span<const unsigned char> encoded,
                       purify_secp_context* context) {
    const auto rounds = log2_dimension(dimension);
    if (encoded.size() != 66 * rounds + 65) {
        return unexpected_error(ErrorCode::InvalidFixedSize);
    }
    Proof proof;
    proof.left.resize(rounds);
    proof.right.resize(rounds);
    std::size_t offset = 0;
    for (std::size_t round = 0; round < rounds; ++round) {
        std::copy_n(encoded.data() + offset, 33, proof.left[round].begin());
        offset += 33;
        std::copy_n(encoded.data() + offset, 33, proof.right[round].begin());
        offset += 33;
    }
    std::copy_n(encoded.data() + offset, 32, proof.terminal_scalar.begin());
    offset += 32;
    std::copy_n(encoded.data() + offset, 33, proof.folded_generator.begin());
    PURIFY_RETURN_IF_ERROR(validate_ipa_encoding(dimension, proof, context));
    return proof;
}

PolynomialTerm geometric_tensor(const FieldElement& x, std::size_t dimension);

Result<StepProof> prove_ipa(
    std::span<const PointBytes> basis, std::vector<FieldElement> a,
    const PolynomialTerm& weights, const PointBytes& opening_base,
    Digest transcript, purify_secp_context* context);

struct IpaVerification {
    PolynomialTerm folded;
    PointBytes residual;
};

Result<PolynomialTerm> verify_ipa(
    std::size_t dimension, const StepProof& proof,
    const PolynomialTerm& weights, const PointBytes& commitment,
    const FieldElement& evaluation, const PointBytes& opening_base,
    Digest transcript, purify_secp_context* context);

Result<AlgebraicStepProof> prove_algebraic_ipa(
    std::span<const PointBytes> basis, std::vector<FieldElement> a,
    const PolynomialTerm& weights, const PointBytes& opening_base,
    candidate::Sha256Transcript& transcript,
    std::uint64_t first_round, purify_secp_context* context);

Result<IpaVerification> evaluate_algebraic_ipa(
    std::size_t dimension, const AlgebraicStepProof& proof,
    const PolynomialTerm& weights, const PointBytes& commitment,
    const FieldElement& evaluation, const PointBytes& opening_base,
    candidate::Sha256Transcript& transcript,
    std::uint64_t first_round, purify_secp_context* context);

Result<PolynomialTerm> verify_algebraic_ipa(
    std::size_t dimension, const AlgebraicStepProof& proof,
    const PolynomialTerm& weights, const PointBytes& commitment,
    const FieldElement& evaluation, const PointBytes& opening_base,
    candidate::Sha256Transcript& transcript,
    std::uint64_t first_round, purify_secp_context* context);

} // namespace internal

} // namespace purify::bppp::accumulation
