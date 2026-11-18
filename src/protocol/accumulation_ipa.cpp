// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file accumulation_ipa.cpp
 * @brief Inner-product opening arguments used by accumulation steps and norm reductions.
 */

#include "purify/accumulation.hpp"

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

#include "accumulation_ipa.hpp"
#include "accumulation_support.hpp"
#include "sha256_transcript.hpp"

namespace purify::bppp::accumulation {

// Helpers shared between the translation units of this module live in internal.
using namespace internal;

namespace {

const TaggedHash kRoundHash("Purify/BPPP/AccumRoundV1");

Result<FieldElement> round_challenge(Digest& transcript, std::size_t round,
                                     const PointBytes& left, const PointBytes& right) {
    Bytes encoded;
    append(encoded, transcript);
    append_size(encoded, round);
    append(encoded, left);
    append(encoded, right);
    PURIFY_ASSIGN_OR_RETURN(auto t, challenge(kRoundHash, encoded));
    append(encoded, t.to_bytes_be());
    transcript = kRoundHash.digest(encoded);
    return t;
}

} // namespace

namespace internal {

PolynomialTerm geometric_tensor(const FieldElement& x, std::size_t dimension) {
    PolynomialTerm out{FieldElement::one(), 0, {}};
    auto power = x;
    for (std::size_t i = 0; i < log2_dimension(dimension); ++i) {
        out.factors.push_back(power);
        power = power * power;
    }
    return out;
}

} // namespace internal

namespace {

FieldElement tensor_inner_product(const PolynomialTerm& lhs, const PolynomialTerm& rhs) {
    assert(lhs.offset == 0 && rhs.offset == 0 && lhs.factors.size() == rhs.factors.size());
    auto out = lhs.scale * rhs.scale;
    for (std::size_t i = 0; i < lhs.factors.size(); ++i) {
        out = out * (FieldElement::one() + lhs.factors[i] * rhs.factors[i]);
    }
    return out;
}

template <typename Proof, typename RoundChallenge>
Result<Proof> prove_ipa_with_challenges(
    std::span<const PointBytes> basis, std::vector<FieldElement> a,
    const PolynomialTerm& weights, const PointBytes& opening_base,
    RoundChallenge&& round_challenge, purify_secp_context* context) {
    assert(a.size() == basis.size() && is_power_of_two_size(a.size()));
    assert(weights.offset == 0 && weights.factors.size() == log2_dimension(a.size()));
    std::vector<FieldElement> b(a.size(), FieldElement::zero());
    const std::array<PolynomialTerm, 1> tensor{weights};
    add_coefficients(b, tensor, FieldElement::one());
    std::vector<PointBytes> generators(basis.begin(), basis.end());
    Proof proof;
    const auto rounds = log2_dimension(a.size());
    proof.left.reserve(rounds);
    proof.right.reserve(rounds);
    for (std::size_t round = 0; round < rounds; ++round) {
        const auto half = a.size() / 2;
        std::vector<PointBytes> left_points, right_points;
        std::vector<FieldElement> left_scalars, right_scalars;
        left_points.reserve(half + 1);
        right_points.reserve(half + 1);
        left_scalars.reserve(half + 1);
        right_scalars.reserve(half + 1);
        auto left_inner = FieldElement::zero();
        auto right_inner = FieldElement::zero();
        for (std::size_t i = 0; i < half; ++i) {
            left_points.push_back(generators[half + i]);
            left_scalars.push_back(a[i]);
            right_points.push_back(generators[i]);
            right_scalars.push_back(a[half + i]);
            left_inner = left_inner + a[i] * b[half + i];
            right_inner = right_inner + a[half + i] * b[i];
        }
        left_points.push_back(opening_base);
        right_points.push_back(opening_base);
        left_scalars.push_back(left_inner);
        right_scalars.push_back(right_inner);
        PURIFY_ASSIGN_OR_RETURN(auto left, msm(left_points, left_scalars, context));
        PURIFY_ASSIGN_OR_RETURN(auto right, msm(right_points, right_scalars, context));
        proof.left.push_back(left);
        proof.right.push_back(right);
        PURIFY_ASSIGN_OR_RETURN(auto t, round_challenge(round, left, right));
        const auto t_inv = t.inverse();
        for (std::size_t i = 0; i < half; ++i) {
            a[i] = t * a[i] + t_inv * a[half + i];
            b[i] = t_inv * b[i] + t * b[half + i];
            const std::array<PointBytes, 2> pair{generators[i], generators[half + i]};
            const std::array<FieldElement, 2> fold_weights{t_inv, t};
            PURIFY_ASSIGN_OR_RETURN(generators[i], msm(pair, fold_weights, context));
        }
        a.resize(half);
        b.resize(half);
        generators.resize(half);
    }
    proof.terminal_scalar = a[0].to_bytes_be();
    proof.folded_generator = generators[0];
    return proof;
}

} // namespace

namespace internal {

Result<StepProof> prove_ipa(
    std::span<const PointBytes> basis, std::vector<FieldElement> a,
    const PolynomialTerm& weights, const PointBytes& opening_base,
    Digest transcript, purify_secp_context* context) {
    return prove_ipa_with_challenges<StepProof>(
        basis, std::move(a), weights, opening_base,
        [&transcript](std::size_t round, const PointBytes& left,
                      const PointBytes& right) {
            return round_challenge(transcript, round, left, right);
        },
        context);
}

} // namespace internal

namespace {

template <typename Proof, typename RoundChallenge>
Result<IpaVerification> evaluate_ipa_with_challenges(
    std::size_t dimension, const Proof& proof,
    const PolynomialTerm& weights, const PointBytes& commitment,
    const FieldElement& evaluation, const PointBytes& opening_base,
    RoundChallenge&& round_challenge, purify_secp_context* context) {
    assert(is_power_of_two_size(dimension));
    assert(weights.offset == 0 && weights.factors.size() == log2_dimension(dimension));
    const auto rounds = log2_dimension(dimension);
    if (proof.left.size() != rounds || proof.right.size() != rounds) {
        return unexpected_error(ErrorCode::SizeMismatch);
    }
    PURIFY_ASSIGN_OR_RETURN(auto a, FieldElement::try_from_bytes32(proof.terminal_scalar));
    PolynomialTerm folded{FieldElement::one(), 0, {}};
    folded.factors.resize(rounds);
    std::vector<PointBytes> points{commitment};
    std::vector<FieldElement> scalars{FieldElement::one()};
    for (std::size_t round = 0; round < rounds; ++round) {
        PURIFY_ASSIGN_OR_RETURN(auto t,
                                round_challenge(round, proof.left[round], proof.right[round]));
        const auto t_inv = t.inverse();
        const auto t_squared = t * t;
        folded.scale = folded.scale * t_inv;
        // Half-splitting uses the most significant index bit first.
        folded.factors[rounds - 1 - round] = t_squared;
        points.push_back(proof.left[round]);
        scalars.push_back(t_squared);
        points.push_back(proof.right[round]);
        scalars.push_back(t_inv * t_inv);
    }
    const auto b_final = tensor_inner_product(weights, folded);
    points.push_back(opening_base);
    scalars.push_back(evaluation - a * b_final);
    points.push_back(proof.folded_generator);
    scalars.push_back(a.negate());
    PURIFY_ASSIGN_OR_RETURN(auto residual, msm(points, scalars, context));
    return IpaVerification{std::move(folded), residual};
}

template <typename Proof, typename RoundChallenge>
Result<PolynomialTerm> verify_ipa_with_challenges(
    std::size_t dimension, const Proof& proof,
    const PolynomialTerm& weights, const PointBytes& commitment,
    const FieldElement& evaluation, const PointBytes& opening_base,
    RoundChallenge&& round_challenge, purify_secp_context* context) {
    PURIFY_ASSIGN_OR_RETURN(
        auto verified,
        evaluate_ipa_with_challenges(
            dimension, proof, weights, commitment, evaluation, opening_base,
            std::forward<RoundChallenge>(round_challenge), context));
    if (verified.residual != PointBytes{}) {
        return unexpected_error(ErrorCode::EquationMismatch);
    }
    return std::move(verified.folded);
}

} // namespace

namespace internal {

Result<PolynomialTerm> verify_ipa(
    std::size_t dimension, const StepProof& proof,
    const PolynomialTerm& weights, const PointBytes& commitment,
    const FieldElement& evaluation, const PointBytes& opening_base,
    Digest transcript, purify_secp_context* context) {
    return verify_ipa_with_challenges(
        dimension, proof, weights, commitment, evaluation, opening_base,
        [&transcript](std::size_t round, const PointBytes& left,
                      const PointBytes& right) {
            return round_challenge(transcript, round, left, right);
        },
        context);
}

Result<AlgebraicStepProof> prove_algebraic_ipa(
    std::span<const PointBytes> basis, std::vector<FieldElement> a,
    const PolynomialTerm& weights, const PointBytes& opening_base,
    candidate::Sha256Transcript& transcript,
    std::uint64_t first_round, purify_secp_context* context) {
    return prove_ipa_with_challenges<AlgebraicStepProof>(
        basis, std::move(a), weights, opening_base,
        [&transcript,
         first_round](std::size_t round, const PointBytes& left,
                      const PointBytes& right) -> Result<FieldElement> {
            PURIFY_RETURN_IF_ERROR(append_algebraic_point(transcript, left));
            PURIFY_RETURN_IF_ERROR(append_algebraic_point(transcript, right));
            return append_algebraic_challenge(
                transcript,
                first_round + static_cast<std::uint64_t>(round));
        },
        context);
}

Result<IpaVerification> evaluate_algebraic_ipa(
    std::size_t dimension, const AlgebraicStepProof& proof,
    const PolynomialTerm& weights, const PointBytes& commitment,
    const FieldElement& evaluation, const PointBytes& opening_base,
    candidate::Sha256Transcript& transcript,
    std::uint64_t first_round, purify_secp_context* context) {
    return evaluate_ipa_with_challenges(
        dimension, proof, weights, commitment, evaluation, opening_base,
        [&transcript,
         first_round](std::size_t round, const PointBytes& left,
                      const PointBytes& right) -> Result<FieldElement> {
            PURIFY_RETURN_IF_ERROR(append_algebraic_point(transcript, left));
            PURIFY_RETURN_IF_ERROR(append_algebraic_point(transcript, right));
            return append_algebraic_challenge(
                transcript,
                first_round + static_cast<std::uint64_t>(round));
        },
        context);
}

Result<PolynomialTerm> verify_algebraic_ipa(
    std::size_t dimension, const AlgebraicStepProof& proof,
    const PolynomialTerm& weights, const PointBytes& commitment,
    const FieldElement& evaluation, const PointBytes& opening_base,
    candidate::Sha256Transcript& transcript,
    std::uint64_t first_round, purify_secp_context* context) {
    PURIFY_ASSIGN_OR_RETURN(
        auto verified, evaluate_algebraic_ipa(
                           dimension, proof, weights, commitment, evaluation,
                           opening_base, transcript, first_round, context));
    if (verified.residual != PointBytes{}) {
        return unexpected_error(ErrorCode::EquationMismatch);
    }
    return std::move(verified.folded);
}

} // namespace internal

} // namespace purify::bppp::accumulation
