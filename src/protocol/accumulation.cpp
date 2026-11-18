// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file accumulation.cpp
 * @brief Accumulation bases, accumulation steps and the final decision.
 */

#include "purify/accumulation.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

#include "accumulation_ipa.hpp"
#include "accumulation_support.hpp"
#include "bppp_bridge.h"
#include "sha256_transcript.hpp"
#if defined(PURIFY_INTERNAL_TEST_SUPPORT)
#include "accumulation_test_support.hpp"
#endif

namespace purify::bppp::accumulation {

// Helpers shared between the translation units of this module live in internal.
using namespace internal;

namespace {

const TaggedHash kBasisHash("Purify/BPPP/NormAccumBasisV2");

constexpr std::size_t kMaxAlgebraicClaims = 1024;

constexpr std::string_view kAlgebraicStepDomain =
    "Purify/BPPP/CandidateAccumStep/v1";

struct AlgebraicStepContext {
    FieldElement beta;
    FieldElement x;
    FieldElement y;
    PointBytes commitment;
    PointBytes opening_base;
    candidate::Sha256Transcript transcript;
};

Result<AlgebraicStepContext> make_algebraic_step_context(
    const Basis& basis, std::span<const PendingClaim> claims,
    purify_secp_context* context) {
    PURIFY_RETURN_IF_ERROR(require_secp_context(context));
    PURIFY_RETURN_IF_ERROR(validate_basis(basis));
    if (claims.empty()) {
        return unexpected_error(ErrorCode::EmptyInput);
    }
    const auto rounds = log2_dimension(basis.dimension());
    if (claims.size() > kMaxAlgebraicClaims) {
        return unexpected_error(ErrorCode::InvalidDimensions);
    }
    PURIFY_RETURN_IF_ERROR(validate_algebraic_dimension(basis.dimension()));
    AlgebraicStepContext out;
    const auto domain = std::span(
        reinterpret_cast<const unsigned char*>(
            kAlgebraicStepDomain.data()),
        kAlgebraicStepDomain.size());
    PURIFY_RETURN_IF_ERROR(out.transcript.append_bytes(domain));
    PURIFY_RETURN_IF_ERROR(out.transcript.append_bytes(basis.digest()));
    out.transcript.append_u64(
        static_cast<std::uint64_t>(rounds));
    out.transcript.append_u64(
        static_cast<std::uint64_t>(claims.size()));
    for (const auto& claim : claims) {
        PURIFY_RETURN_IF_ERROR(validate_claim(basis, claim));
        PURIFY_RETURN_IF_ERROR(
            append_algebraic_point(out.transcript, claim.point()));
        PURIFY_RETURN_IF_ERROR(
            append_algebraic_polynomial(out.transcript, claim.polynomial()));
    }

    PURIFY_ASSIGN_OR_RETURN(out.beta,
                            append_algebraic_challenge(out.transcript, 0));
    std::vector<PointBytes> commitments;
    std::vector<FieldElement> weights;
    commitments.reserve(claims.size());
    weights.reserve(claims.size());
    auto weight = FieldElement::one();
    for (const auto& claim : claims) {
        commitments.push_back(claim.point());
        weights.push_back(weight);
        weight = weight * out.beta;
    }
    PURIFY_ASSIGN_OR_RETURN(out.commitment, msm(commitments, weights, context));
    PURIFY_RETURN_IF_ERROR(
        append_algebraic_point(out.transcript, out.commitment));

    PURIFY_ASSIGN_OR_RETURN(out.x,
                            append_algebraic_challenge(out.transcript, 1));
    out.y = FieldElement::zero();
    for (std::size_t i = 0; i < claims.size(); ++i) {
        out.y = out.y +
            weights[i] * evaluate(claims[i].polynomial(), out.x);
    }
    out.transcript.append_scalar(out.y);

    PURIFY_ASSIGN_OR_RETURN(
        out.opening_base,
        derive_algebraic_opening_base(basis, out.transcript,
                                      kAccumulationOpeningRole, context));
    PURIFY_RETURN_IF_ERROR(
        append_algebraic_point(out.transcript, out.opening_base));
    return out;
}

} // namespace

Result<Basis> Basis::create(std::size_t n_vec_len, std::size_t l_vec_len,
                            std::string_view semantic_domain, purify_secp_context* context) {
    PURIFY_RETURN_IF_ERROR(require_secp_context(context));
    std::size_t dimension = 0;
    if (!is_power_of_two_size(n_vec_len) || !is_power_of_two_size(l_vec_len) ||
        l_vec_len > n_vec_len || !(CheckedSize(n_vec_len) * 2).store(dimension)) {
        return unexpected_error(ErrorCode::InvalidDimensions);
    }
    if (semantic_domain.empty()) {
        return unexpected_error(ErrorCode::EmptyInput);
    }
    Basis out;
    out.n_vec_len_ = n_vec_len;
    out.l_vec_len_ = l_vec_len;
    PURIFY_ASSIGN_OR_RETURN(auto generators, create_generators(dimension, context));
    out.points_.resize(dimension);
    if (purify_bppp_generators_to_points(context,
            reinterpret_cast<const unsigned char*>(generators.data()), generators.size(),
            reinterpret_cast<unsigned char*>(out.points_.data())) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput);
    }
    generators.resize(n_vec_len + l_vec_len);
    out.norm_generators_ = std::move(generators);
    Bytes encoded;
    append_size(encoded, semantic_domain.size());
    append(encoded, std::span(reinterpret_cast<const unsigned char*>(semantic_domain.data()),
                             semantic_domain.size()));
    append_size(encoded, n_vec_len);
    append_size(encoded, l_vec_len);
    for (const auto& point : out.points_) append(encoded, point);
    out.digest_ = kBasisHash.digest(encoded);
    return out;
}

Result<AlgebraicStepProof> prove_algebraic_step(
    const Basis& basis, std::span<const PendingClaim> claims,
    purify_secp_context* context) {
    PURIFY_ASSIGN_OR_RETURN(
        auto state, make_algebraic_step_context(basis, claims, context));
    std::vector<FieldElement> coefficients(
        basis.dimension(), FieldElement::zero());
    auto weight = FieldElement::one();
    for (const auto& claim : claims) {
        add_coefficients(
            coefficients, claim.polynomial(), weight);
        weight = weight * state.beta;
    }
    const auto weights =
        geometric_tensor(state.x, basis.dimension());
    PURIFY_ASSIGN_OR_RETURN(
        auto proof,
        prove_algebraic_ipa(basis.points(), std::move(coefficients), weights,
                            state.opening_base, state.transcript, 2, context));
    PURIFY_RETURN_IF_ERROR(
        verify_algebraic_step(basis, claims, proof, context));
    return proof;
}

Result<PendingClaim> verify_algebraic_step(
    const Basis& basis, std::span<const PendingClaim> claims,
    const AlgebraicStepProof& proof,
    purify_secp_context* context) {
    PURIFY_RETURN_IF_ERROR(validate_basis(basis));
    const auto rounds = log2_dimension(basis.dimension());
    if (proof.left.size() != rounds ||
        proof.right.size() != rounds) {
        return unexpected_error(ErrorCode::SizeMismatch);
    }
    PURIFY_RETURN_IF_ERROR(
        FieldElement::try_from_bytes32(proof.terminal_scalar));
    PURIFY_ASSIGN_OR_RETURN(
        auto state, make_algebraic_step_context(basis, claims, context));
    const auto weights =
        geometric_tensor(state.x, basis.dimension());
    PURIFY_ASSIGN_OR_RETURN(auto folded,
                            verify_algebraic_ipa(basis.dimension(), proof,
                                                 weights, state.commitment,
                                                 state.y, state.opening_base,
                                                 state.transcript, 2, context));
    return PendingClaim(
        basis.digest(), proof.folded_generator,
        {std::move(folded)});
}

#if defined(PURIFY_INTERNAL_TEST_SUPPORT)
namespace test_support {

Result<PointBytes> algebraic_step_equation_residual(
    const Basis& basis, std::span<const PendingClaim> claims,
    const AlgebraicStepProof& proof,
    purify_secp_context* context) {
    PURIFY_RETURN_IF_ERROR(validate_basis(basis));
    const auto rounds = log2_dimension(basis.dimension());
    if (proof.left.size() != rounds ||
        proof.right.size() != rounds) {
        return unexpected_error(ErrorCode::SizeMismatch);
    }
    PURIFY_ASSIGN_OR_RETURN(
        auto state, make_algebraic_step_context(basis, claims, context));
    const auto weights =
        geometric_tensor(state.x, basis.dimension());
    PURIFY_ASSIGN_OR_RETURN(
        auto evaluated,
        evaluate_algebraic_ipa(basis.dimension(), proof, weights,
                               state.commitment, state.y, state.opening_base,
                               state.transcript, 2, context));
    return evaluated.residual;
}

} // namespace test_support
#endif

Status decide(const Basis& basis, const PendingClaim& claim, purify_secp_context* context) {
    PURIFY_RETURN_IF_ERROR(require_secp_context(context));
    PURIFY_RETURN_IF_ERROR(validate_basis(basis));
    PURIFY_RETURN_IF_ERROR(validate_claim(basis, claim));
    std::vector<FieldElement> coefficients(basis.dimension(), FieldElement::zero());
    add_coefficients(coefficients, claim.polynomial(), FieldElement::one());
    PURIFY_ASSIGN_OR_RETURN(auto expected, msm(basis.points(), coefficients, context));
    if (expected != claim.point()) {
        return unexpected_error(ErrorCode::EquationMismatch);
    }
    return {};
}

} // namespace purify::bppp::accumulation
