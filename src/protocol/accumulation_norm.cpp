// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file accumulation_norm.cpp
 * @brief Preparation of norm proofs as accumulation obligations, and their norm reductions.
 */

#include "purify/accumulation.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <numeric>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

#include "accumulation_ipa.hpp"
#include "accumulation_support.hpp"
#include "algebraic_circuit_accumulation.hpp"
#include "bppp_bridge.h"
#include "bppp_internal.hpp"
#include "sha256_transcript.hpp"

namespace purify::bppp::accumulation {

// Helpers shared between the translation units of this module live in internal.
using namespace internal;

namespace {

constexpr std::string_view kAlgebraicNormDomain =
    "Purify/BPPP/CandidateNormReduction/v2";

struct AlgebraicNormOpeningContext {
    FieldElement evaluation;
    PolynomialTerm weights;
    PointBytes opening_base;
    candidate::Sha256Transcript transcript;
};

Result<AlgebraicNormOpeningContext> make_algebraic_norm_context(
    const Basis& basis, const AlgebraicPreparedNorm& norm,
    const ScalarBytes& evaluation, purify_secp_context* context) {
    PURIFY_RETURN_IF_ERROR(require_secp_context(context));
    PURIFY_RETURN_IF_ERROR(validate_basis(basis));
    PURIFY_RETURN_IF_ERROR(validate_algebraic_prepared(basis, norm));

    AlgebraicNormOpeningContext out;
    const auto rounds = log2_dimension(basis.l_vec_len());
    PURIFY_RETURN_IF_ERROR(validate_algebraic_dimension(basis.l_vec_len()));
    PURIFY_ASSIGN_OR_RETURN(out.evaluation,
                            FieldElement::try_from_bytes32(evaluation));
    out.weights = PolynomialTerm{
        FieldElement::one(), 0,
        norm.polynomial()[1].factors};

    const auto domain = std::span(
        reinterpret_cast<const unsigned char*>(
            kAlgebraicNormDomain.data()),
        kAlgebraicNormDomain.size());
    PURIFY_RETURN_IF_ERROR(out.transcript.append_bytes(domain));
    PURIFY_RETURN_IF_ERROR(out.transcript.append_bytes(basis.digest()));
    out.transcript.append_u64(
        static_cast<std::uint64_t>(rounds));
    out.transcript.append_scalar(norm.prepared_binding());
    PURIFY_RETURN_IF_ERROR(
        append_algebraic_point(out.transcript, norm.coefficient_commitment()));
    const std::array<PolynomialTerm, 1> weights{out.weights};
    PURIFY_RETURN_IF_ERROR(
        append_algebraic_polynomial(out.transcript, weights));
    out.transcript.append_scalar(out.evaluation);

    PURIFY_ASSIGN_OR_RETURN(out.opening_base,
                            derive_algebraic_opening_base(basis, out.transcript,
                                                          kReductionOpeningRole,
                                                          context));
    PURIFY_RETURN_IF_ERROR(
        append_algebraic_point(out.transcript, out.opening_base));
    return out;
}

/**
 * The two compact polynomial terms a folded norm opening leaves behind: g over
 * the first `n_vec_len` basis points and h over the rest.
 *
 * The i-th g factor is gamma_i divided by sqrt(-1) for i = 0 and by
 * mul_ratio^(2^(i-1)) after that. The gammas are the h factors.
 */
std::array<PolynomialTerm, 2> folded_norm_terms(
    const FieldElement& g_scale, const FieldElement& terminal_l,
    std::size_t n_vec_len, const FieldElement& mul_ratio,
    const FieldElement& sqrt_minus_one, std::span<const FieldElement> gammas) {
    PolynomialTerm g{g_scale, 0, {}};
    PolynomialTerm h{terminal_l, n_vec_len, {gammas.begin(), gammas.end()}};
    g.factors.reserve(gammas.size());
    auto ratio_inverse_power = mul_ratio.inverse();
    for (std::size_t i = 0; i < gammas.size(); ++i) {
        const auto& gamma = gammas[i];
        if (i == 0) {
            g.factors.push_back(gamma * sqrt_minus_one.inverse());
        } else {
            g.factors.push_back(gamma * ratio_inverse_power);
            ratio_inverse_power = ratio_inverse_power * ratio_inverse_power;
        }
    }
    return {std::move(g), std::move(h)};
}

/** Commits to a norm proof's public coefficients over the basis's coefficient generators. */
Result<PointBytes> commit_public_coefficients(
    const Basis& basis, std::span<const ScalarBytes> c_vec,
    purify_secp_context* context) {
    std::vector<FieldElement> coefficients;
    coefficients.reserve(c_vec.size());
    for (const auto& encoded : c_vec) {
        PURIFY_ASSIGN_OR_RETURN(const auto& coefficient,
                                FieldElement::try_from_bytes32(encoded));
        coefficients.push_back(coefficient);
    }
    const auto coefficient_basis =
        std::span(basis.points()).subspan(basis.n_vec_len(), basis.l_vec_len());
    return msm(coefficient_basis, coefficients, context);
}

/** Checks that a prepared V4 statement is over exactly this basis and is internally consistent. */
Status check_v4_statement_matches_basis(
    const Basis& basis, const candidate::PreparedCircuitZkNormArgV4& prepared) {
    const auto& shape = prepared.shape();
    const auto& transcript_input = prepared.transcript_input();
    const auto& transcript = prepared.transcript();
    const auto& norm = prepared.norm();
    const auto rounds = shape.round_count();
    std::size_t generator_count = 0;
    if (!(CheckedSize(shape.n_vec_len()) + shape.l_vec_len()).store(generator_count)) {
        return unexpected_error(ErrorCode::Overflow);
    }
    // The V4 transcript binds this raw digest. Exact generator equality
    // bridges it to the purpose owner's selected semantic basis.
    if (shape.n_vec_len() != basis.n_vec_len() ||
        shape.l_vec_len() != basis.l_vec_len() ||
        prepared.raw_generators().size() != generator_count ||
        prepared.raw_generators() != basis.norm_generators()) {
        return unexpected_error(ErrorCode::BindingMismatch);
    }
    const auto raw_generator_digest =
        generator_digest(prepared.raw_generators());
    if (transcript_input.raw_generator_digest != raw_generator_digest ||
        generator_digest(basis.norm_generators()) != raw_generator_digest) {
        return unexpected_error(ErrorCode::BindingMismatch);
    }
    if (norm.n_vec_len != shape.n_vec_len() ||
        norm.generators.size() != generator_count ||
        norm.c_vec.size() != shape.l_vec_len() ||
        norm.rho != transcript.rho.scalar.to_bytes_be() ||
        norm.commitment != transcript_input.combined_commitment ||
        transcript_input.rounds.size() != rounds ||
        transcript.gammas.size() != rounds) {
        return unexpected_error(ErrorCode::InternalMismatch);
    }

    if (transcript.rho.scalar.is_zero() ||
        transcript.mul_scale.scalar.is_zero() ||
        transcript.mul_ratio.scalar.is_zero() ||
        transcript.prepared_binding.scalar.is_zero() ||
        std::any_of(
            transcript.gammas.begin(), transcript.gammas.end(),
            [](const candidate::CircuitChallengeV4& gamma) {
                return gamma.scalar.is_zero();
            })) {
        return unexpected_error(ErrorCode::InternalMismatch);
    }
    return {};
}

/** Checks the prepared norm's generators: G scaled as the transcript dictates, H exactly raw. */
Status check_v4_norm_generators(
    const candidate::PreparedCircuitZkNormArgV4& prepared,
    const FieldElement& sqrt_minus_one, purify_secp_context* context) {
    const auto& shape = prepared.shape();
    const auto& transcript = prepared.transcript();
    const auto& norm = prepared.norm();
    // Reconstruct every transformed G generator rather than trusting the
    // prepared object's duplicate list. The H suffix stays exactly raw.
    auto rho_power = transcript.rho.scalar;
    auto generator_term = transcript.mul_scale.scalar;
    for (std::size_t i = 0; i < shape.n_vec_len(); ++i) {
        const auto term = (i % 2 == 0)
            ? generator_term
            : sqrt_minus_one * generator_term;
        const auto scale = rho_power * term.inverse();
        const auto encoded_scale = scale.to_bytes_be();
        PointBytes expected_generator{};
        if (purify_bppp_scale_generator(
                context, prepared.raw_generators()[i].data(),
                encoded_scale.data(), expected_generator.data()) == 0) {
            return unexpected_error(ErrorCode::BackendRejectedInput);
        }
        if (norm.generators[i] != expected_generator) {
            return unexpected_error(ErrorCode::InternalMismatch);
        }
        if (i % 2 == 1) {
            generator_term =
                generator_term * transcript.mul_ratio.scalar;
        }
        rho_power = rho_power * transcript.rho.scalar;
    }
    if (!std::equal(
            norm.generators.begin() +
                static_cast<std::ptrdiff_t>(shape.n_vec_len()),
            norm.generators.end(),
            prepared.raw_generators().begin() +
                static_cast<std::ptrdiff_t>(shape.n_vec_len()))) {
        return unexpected_error(ErrorCode::InternalMismatch);
    }
    return {};
}

/** Checks that the norm proof bytes are exactly the rounds and terminal scalars the transcript absorbed. */
Status check_v4_norm_proof_layout(
    const candidate::PreparedCircuitZkNormArgV4& prepared) {
    const auto& shape = prepared.shape();
    const auto& transcript_input = prepared.transcript_input();
    const auto& norm = prepared.norm();
    const auto rounds = shape.round_count();
    std::size_t round_bytes = 0;
    std::size_t expected_proof_size = 0;
    const CheckedSize checked_round_bytes =
        CheckedSize(rounds) * sizeof(candidate::PackedPointPairV4);
    if (!checked_round_bytes.store(round_bytes) ||
        !(checked_round_bytes + 2 * sizeof(ScalarBytes)).store(expected_proof_size)) {
        return unexpected_error(ErrorCode::Overflow);
    }
    if (norm.proof.size() != expected_proof_size) {
        return unexpected_error(ErrorCode::InternalMismatch);
    }
    for (std::size_t i = 0; i < rounds; ++i) {
        const auto offset = i * sizeof(candidate::PackedPointPairV4);
        if (!std::equal(
                transcript_input.rounds[i].begin(),
                transcript_input.rounds[i].end(),
                norm.proof.begin() +
                    static_cast<std::ptrdiff_t>(offset))) {
            return unexpected_error(ErrorCode::InternalMismatch);
        }
    }
    if (!std::equal(
            transcript_input.terminal_n.begin(),
            transcript_input.terminal_n.end(),
            norm.proof.begin() +
                static_cast<std::ptrdiff_t>(round_bytes)) ||
        !std::equal(
            transcript_input.terminal_l.begin(),
            transcript_input.terminal_l.end(),
            norm.proof.begin() + static_cast<std::ptrdiff_t>(
                                     round_bytes + sizeof(ScalarBytes)))) {
        return unexpected_error(ErrorCode::InternalMismatch);
    }
    return {};
}

/** The pending short norm equation of a prepared V4 proof. */
struct PendingNormClaimV4 {
    FieldElement terminal_n;
    FieldElement terminal_l;
    PointBytes residual{};
};

/** Reconstructs the pending norm claim under the authenticated V4 challenges and checks it against the prepared one. */
Result<PendingNormClaimV4> reconstruct_v4_norm_claim(
    const candidate::PreparedCircuitZkNormArgV4& prepared,
    purify_secp_context* context) {
    const auto& shape = prepared.shape();
    const auto& transcript_input = prepared.transcript_input();
    const auto& transcript = prepared.transcript();
    const auto& norm = prepared.norm();
    const auto rounds = shape.round_count();
    std::vector<ScalarBytes> encoded_gammas;
    encoded_gammas.reserve(rounds);
    for (const auto& gamma : transcript.gammas) {
        encoded_gammas.push_back(gamma.scalar.to_bytes_be());
    }
    ScalarBytes terminal_n_bytes{};
    ScalarBytes terminal_l_bytes{};
    PointBytes residual{};
    // This reconstructs the pending short equation with authenticated V4
    // challenges. It is not norm-proof acceptance.
    if (purify_bppp_prepare_norm_arg_claim_with_challenges(
            context, norm.rho.data(),
            reinterpret_cast<const unsigned char*>(
                norm.generators.data()),
            norm.generators.size(),
            reinterpret_cast<const unsigned char*>(norm.c_vec.data()),
            norm.c_vec.size(), norm.n_vec_len, norm.commitment.data(),
            norm.proof.data(), norm.proof.size(),
            reinterpret_cast<const unsigned char*>(
                encoded_gammas.data()),
            encoded_gammas.size(), terminal_n_bytes.data(),
            terminal_l_bytes.data(), residual.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput);
    }
    if (terminal_n_bytes != transcript_input.terminal_n ||
        terminal_l_bytes != transcript_input.terminal_l ||
        residual != prepared.pending_norm_residual()) {
        return unexpected_error(ErrorCode::InternalMismatch);
    }

    PURIFY_ASSIGN_OR_RETURN(const auto& terminal_n,
                            FieldElement::try_from_bytes32(terminal_n_bytes));
    PURIFY_ASSIGN_OR_RETURN(const auto& terminal_l,
                            FieldElement::try_from_bytes32(terminal_l_bytes));
    return PendingNormClaimV4{terminal_n, terminal_l, residual};
}

} // namespace

Result<AlgebraicPreparedNorm>
prepare_v4_circuit_norm_for_algebraic_reduction(
    const Basis& basis, candidate::PreparedCircuitZkNormArgV4 prepared,
    purify_secp_context* context) {
    PURIFY_RETURN_IF_ERROR(require_secp_context(context));
    PURIFY_RETURN_IF_ERROR(validate_basis(basis));
    PURIFY_RETURN_IF_ERROR(validate_algebraic_dimension(basis.dimension()));

    PURIFY_RETURN_IF_ERROR(check_v4_statement_matches_basis(basis, prepared));
    PURIFY_ASSIGN_OR_RETURN(const auto& sqrt_minus_one,
                            detail::canonical_sqrt_minus_one());
    PURIFY_RETURN_IF_ERROR(
        check_v4_norm_generators(prepared, sqrt_minus_one, context));
    PURIFY_RETURN_IF_ERROR(check_v4_norm_proof_layout(prepared));
    PURIFY_ASSIGN_OR_RETURN(const auto& claim,
                            reconstruct_v4_norm_claim(prepared, context));

    const auto& shape = prepared.shape();
    const auto& transcript = prepared.transcript();
    std::vector<FieldElement> gammas;
    gammas.reserve(transcript.gammas.size());
    for (const auto& gamma : transcript.gammas) {
        gammas.push_back(gamma.scalar);
    }
    // These are the two compact terms installed by the constrained V4 leaf.
    auto polynomial = folded_norm_terms(
        claim.terminal_n * pow_size(transcript.rho.scalar, shape.n_vec_len()) *
            transcript.mul_scale.scalar.inverse(),
        claim.terminal_l, shape.n_vec_len(), transcript.mul_ratio.scalar,
        sqrt_minus_one, gammas);

    PURIFY_ASSIGN_OR_RETURN(
        const auto coefficient_commitment,
        commit_public_coefficients(basis, prepared.norm().c_vec, context));
    if (coefficient_commitment !=
        prepared.transcript_input().coefficient_commitment) {
        return unexpected_error(ErrorCode::InternalMismatch);
    }

    const auto prepared_binding = transcript.prepared_binding.scalar;
    auto norm_data = std::move(prepared).take_norm();
    auto c_vec = std::move(norm_data.c_vec);
    return AlgebraicPreparedNorm(
        basis.digest(), prepared_binding, std::move(c_vec),
        coefficient_commitment, claim.residual, std::move(polynomial));
}

Result<AlgebraicNormReductionProof>
prove_algebraic_norm_reduction(
    const Basis& basis, const AlgebraicPreparedNorm& norm,
    purify_secp_context* context) {
    PURIFY_RETURN_IF_ERROR(require_secp_context(context));
    PURIFY_RETURN_IF_ERROR(validate_basis(basis));
    PURIFY_RETURN_IF_ERROR(validate_algebraic_prepared(basis, norm));

    std::vector<FieldElement> coefficients;
    coefficients.reserve(norm.c_vec().size());
    for (const auto& encoded : norm.c_vec()) {
        PURIFY_ASSIGN_OR_RETURN(auto coefficient,
                                FieldElement::try_from_bytes32(encoded));
        coefficients.push_back(coefficient);
    }
    const PolynomialTerm weights{
        FieldElement::one(), 0,
        norm.polynomial()[1].factors};
    const std::array<PolynomialTerm, 1> tensor{weights};
    std::vector<FieldElement> expanded_weights(
        basis.l_vec_len(), FieldElement::zero());
    add_coefficients(
        expanded_weights, tensor, FieldElement::one());
    const auto evaluation = std::inner_product(
        coefficients.begin(), coefficients.end(), expanded_weights.begin(),
        FieldElement::zero());

    AlgebraicNormReductionProof proof;
    proof.coefficient_evaluation = evaluation.to_bytes_be();
    PURIFY_ASSIGN_OR_RETURN(
        auto state, make_algebraic_norm_context(
                        basis, norm, proof.coefficient_evaluation, context));
    const auto h_basis = std::span(basis.points()).subspan(
        basis.n_vec_len(), basis.l_vec_len());
    PURIFY_ASSIGN_OR_RETURN(
        proof.coefficient_opening,
        prove_algebraic_ipa(h_basis, std::move(coefficients), state.weights,
                            state.opening_base, state.transcript, 0, context));
    PURIFY_RETURN_IF_ERROR(
        verify_algebraic_norm_reduction(basis, norm, proof, context));
    return proof;
}

Result<PendingClaim> verify_algebraic_norm_reduction(
    const Basis& basis, const AlgebraicPreparedNorm& norm,
    const AlgebraicNormReductionProof& proof,
    purify_secp_context* context) {
    PURIFY_RETURN_IF_ERROR(validate_basis(basis));
    PURIFY_RETURN_IF_ERROR(validate_algebraic_prepared(basis, norm));
    const auto rounds = log2_dimension(basis.l_vec_len());
    const auto& opening = proof.coefficient_opening;
    if (opening.left.size() != rounds ||
        opening.right.size() != rounds) {
        return unexpected_error(ErrorCode::SizeMismatch);
    }
    PURIFY_ASSIGN_OR_RETURN(
        auto terminal, FieldElement::try_from_bytes32(opening.terminal_scalar));
    PURIFY_ASSIGN_OR_RETURN(
        auto state, make_algebraic_norm_context(
                        basis, norm, proof.coefficient_evaluation, context));
    PURIFY_ASSIGN_OR_RETURN(
        auto folded,
        verify_algebraic_ipa(basis.l_vec_len(), opening, state.weights,
                             norm.coefficient_commitment(), state.evaluation,
                             state.opening_base, state.transcript, 0, context));
    folded.offset = basis.n_vec_len();

    const auto generator_encoding = base_generator(context);
    PointBytes generator{};
    if (purify_bppp_generators_to_points(
            context, generator_encoding.data(), 1,
            generator.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput);
    }
    const std::array<PointBytes, 2> norm_points{
        norm.residual(), generator};
    const std::array<FieldElement, 2> norm_scalars{
        FieldElement::one(),
        (norm.polynomial()[1].scale * state.evaluation).negate()};
    PURIFY_ASSIGN_OR_RETURN(auto norm_point,
                            msm(norm_points, norm_scalars, context));

    // The fusion challenge follows the complete coefficient opening and
    // both pending equations.
    state.transcript.append_scalar(terminal);
    PURIFY_RETURN_IF_ERROR(
        append_algebraic_point(state.transcript, opening.folded_generator));
    PURIFY_RETURN_IF_ERROR(
        append_algebraic_point(state.transcript, norm_point));
    PURIFY_RETURN_IF_ERROR(
        append_algebraic_polynomial(state.transcript, norm.polynomial()));
    const std::array<PolynomialTerm, 1> folded_polynomial{folded};
    PURIFY_RETURN_IF_ERROR(
        append_algebraic_polynomial(state.transcript, folded_polynomial));
    PURIFY_ASSIGN_OR_RETURN(
        auto chi, append_algebraic_challenge(
                      state.transcript, static_cast<std::uint64_t>(rounds)));

    const std::array<PointBytes, 2> fusion_points{
        norm_point, opening.folded_generator};
    const std::array<FieldElement, 2> fusion_scalars{
        FieldElement::one(), chi};
    PURIFY_ASSIGN_OR_RETURN(auto combined_point,
                            msm(fusion_points, fusion_scalars, context));
    std::vector<PolynomialTerm> polynomial(
        norm.polynomial().begin(), norm.polynomial().end());
    folded.scale = folded.scale * chi;
    polynomial.push_back(std::move(folded));
    return PendingClaim(
        basis.digest(), combined_point, std::move(polynomial));
}

} // namespace purify::bppp::accumulation
