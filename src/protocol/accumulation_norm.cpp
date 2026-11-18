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

const TaggedHash kNormBindingHash("Purify/BPPP/NormReduction/StatementV1");
const TaggedHash kCircuitNormBindingHash(
    "Purify/BPPP/CircuitNormReduction/StatementV3");
const TaggedHash kNormOpeningBaseHash("Purify/BPPP/NormReduction/OpeningBaseV1");
const TaggedHash kNormOpeningHash("Purify/BPPP/NormReduction/OpeningV1");
const TaggedHash kNormFusionHash("Purify/BPPP/NormReduction/FusionV1");

constexpr std::string_view kAlgebraicNormDomain =
    "Purify/BPPP/CandidateNormReduction/v2";

struct NormOpeningContext {
    FieldElement evaluation;
    PolynomialTerm weights;
    PointBytes opening_base;
    Digest transcript;
};

Result<NormOpeningContext> make_norm_context(const Basis& basis, const PreparedNorm& norm,
                                            const ScalarBytes& evaluation,
                                            purify_secp_context* context) {
    PURIFY_RETURN_IF_ERROR(require_secp_context(context));
    PURIFY_RETURN_IF_ERROR(validate_basis(basis));
    PURIFY_RETURN_IF_ERROR(validate_prepared(basis, norm));
    NormOpeningContext out;
    PURIFY_ASSIGN_OR_RETURN(out.evaluation, FieldElement::try_from_bytes32(evaluation));
    out.weights = PolynomialTerm{FieldElement::one(), 0, norm.polynomial()[1].factors};
    Bytes encoded;
    append(encoded, basis.digest());
    append(encoded, norm.transcript_digest());
    append(encoded, norm.coefficient_commitment());
    const std::array<PolynomialTerm, 1> weights{out.weights};
    append_polynomial(encoded, weights);
    append(encoded, evaluation);
    // C_c and the claimed tensor evaluation are fixed before choosing U.
    const auto seed = kNormOpeningBaseHash.digest(encoded);
    if (purify_bppp_public_hash_to_point(context, seed.data(), seed.size(), out.opening_base.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput);
    }
    append(encoded, out.opening_base);
    out.transcript = kNormOpeningHash.digest(encoded);
    return out;
}

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

struct CircuitPreparedNorm {
    Digest transcript_digest{};
    std::vector<ScalarBytes> c_vec;
    PointBytes coefficient_commitment{};
    PointBytes residual{};
    std::array<PolynomialTerm, 2> polynomial;
};

Result<CircuitPreparedNorm> prepare_circuit_norm_components(
    const Basis& basis,
    const detail::PreparedExperimentalCircuitZkNormArg& prepared,
    const ExperimentalCircuitZkNormArgProof& proof,
    std::span<const PointBytes> public_commitments,
    purify_secp_context* context,
    std::span<const unsigned char> statement_binding) {
    const auto& norm = prepared.norm;
    if (norm.n_vec_len != basis.n_vec_len() ||
        norm.c_vec.size() != basis.l_vec_len() ||
        norm.generators.size() !=
            basis.n_vec_len() + basis.l_vec_len() ||
        prepared.raw_generator_digest !=
            generator_digest(basis.norm_generators())) {
        return unexpected_error(ErrorCode::BindingMismatch);
    }

    const auto rounds = log2_dimension(basis.n_vec_len());
    std::vector<ScalarBytes> gammas(rounds);
    ScalarBytes n_bytes{}, l_bytes{};
    PointBytes residual{};
    if (purify_bppp_prepare_norm_arg_claim(
            context, norm.rho.data(),
            reinterpret_cast<const unsigned char*>(norm.generators.data()),
            norm.generators.size(),
            reinterpret_cast<const unsigned char*>(norm.c_vec.data()),
            norm.c_vec.size(), norm.n_vec_len, norm.commitment.data(),
            norm.proof.data(), norm.proof.size(), n_bytes.data(),
            l_bytes.data(),
            reinterpret_cast<unsigned char*>(gammas.data()), gammas.size(),
            residual.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput);
    }

    PURIFY_ASSIGN_OR_RETURN(const auto& n,
                            FieldElement::try_from_bytes32(n_bytes));
    PURIFY_ASSIGN_OR_RETURN(const auto& l,
                            FieldElement::try_from_bytes32(l_bytes));
    PURIFY_ASSIGN_OR_RETURN(const auto& rho,
                            FieldElement::try_from_bytes32(norm.rho));
    PURIFY_ASSIGN_OR_RETURN(const auto& sqrt_minus_one,
                            detail::canonical_sqrt_minus_one());

    PolynomialTerm g{
        n * pow_size(rho, basis.n_vec_len()) *
            prepared.mul_scale.inverse(),
        0,
        {}};
    PolynomialTerm h{l, basis.n_vec_len(), {}};
    const auto h_rounds = log2_dimension(basis.l_vec_len());
    auto ratio_inv_power = prepared.mul_ratio.inverse();
    for (std::size_t j = 0; j < rounds; ++j) {
        PURIFY_ASSIGN_OR_RETURN(const auto& gamma,
                                FieldElement::try_from_bytes32(gammas[j]));
        if (j == 0) {
            g.factors.push_back(gamma * sqrt_minus_one.inverse());
        } else {
            g.factors.push_back(gamma * ratio_inv_power);
            ratio_inv_power = ratio_inv_power * ratio_inv_power;
        }
        if (j < h_rounds) h.factors.push_back(gamma);
    }

    std::vector<FieldElement> coefficients;
    coefficients.reserve(norm.c_vec.size());
    for (const auto& encoded : norm.c_vec) {
        PURIFY_ASSIGN_OR_RETURN(const auto& coefficient,
                                FieldElement::try_from_bytes32(encoded));
        coefficients.push_back(coefficient);
    }
    const auto h_basis = std::span(basis.points())
                             .subspan(basis.n_vec_len(),
                                      basis.l_vec_len());
    PURIFY_ASSIGN_OR_RETURN(auto coefficient_commitment,
                            msm(h_basis, coefficients, context));

    Bytes encoded;
    append(encoded, basis.digest());
    append(encoded, prepared.raw_generator_digest);
    append(encoded, prepared.challenge_digest);
    append(encoded, norm.rho);
    append(encoded, prepared.mul_scale.to_bytes_be());
    append(encoded, prepared.mul_ratio.to_bytes_be());
    append_size(encoded, statement_binding.size());
    append(encoded, statement_binding);
    append_size(encoded, public_commitments.size());
    for (const auto& point : public_commitments) append(encoded, point);
    append(encoded, proof.a_commitment);
    append(encoded, proof.s_commitment);
    append(encoded, proof.t2);
    append(encoded, proof.public_commitment_dlog_nonce);
    append(encoded, proof.public_commitment_dlog_response);
    append(encoded, norm.commitment);
    for (const auto& coefficient : norm.c_vec) append(encoded, coefficient);
    append(encoded, coefficient_commitment);
    append_size(encoded, norm.proof.size());
    append(encoded, norm.proof);

    return CircuitPreparedNorm{
        kCircuitNormBindingHash.digest(encoded), norm.c_vec,
        coefficient_commitment, residual,
        {std::move(g), std::move(h)}};
}

} // namespace

Result<PreparedNorm> prepare_norm(const Basis& basis, const NormArgProof& proof,
                                  purify_secp_context* context) {
    PURIFY_RETURN_IF_ERROR(require_secp_context(context));
    PURIFY_RETURN_IF_ERROR(validate_basis(basis));
    if (proof.n_vec_len != basis.n_vec_len() || proof.c_vec.size() != basis.l_vec_len() ||
        proof.generators != basis.norm_generators()) {
        return unexpected_error(ErrorCode::BindingMismatch);
    }
    const auto rounds = log2_dimension(basis.n_vec_len());
    std::vector<ScalarBytes> gammas(rounds);
    ScalarBytes n_bytes{}, l_bytes{};
    PointBytes residual{};
    if (purify_bppp_prepare_norm_arg_claim(context, proof.rho.data(),
            reinterpret_cast<const unsigned char*>(proof.generators.data()), proof.generators.size(),
            reinterpret_cast<const unsigned char*>(proof.c_vec.data()), proof.c_vec.size(),
            proof.n_vec_len, proof.commitment.data(), proof.proof.data(), proof.proof.size(),
            n_bytes.data(), l_bytes.data(), reinterpret_cast<unsigned char*>(gammas.data()),
            gammas.size(), residual.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput);
    }
    PURIFY_ASSIGN_OR_RETURN(auto n, FieldElement::try_from_bytes32(n_bytes));
    PURIFY_ASSIGN_OR_RETURN(auto l, FieldElement::try_from_bytes32(l_bytes));
    PURIFY_ASSIGN_OR_RETURN(auto rho, FieldElement::try_from_bytes32(proof.rho));
    PolynomialTerm g{n * pow_size(rho, basis.n_vec_len() - 1), 0, {}};
    PolynomialTerm h{l, basis.n_vec_len(), {}};
    auto rho_inv_power = rho.inverse();
    const auto h_rounds = log2_dimension(basis.l_vec_len());
    for (std::size_t j = 0; j < rounds; ++j) {
        PURIFY_ASSIGN_OR_RETURN(auto gamma, FieldElement::try_from_bytes32(gammas[j]));
        g.factors.push_back(gamma * rho_inv_power);
        if (j < h_rounds) h.factors.push_back(gamma);
        rho_inv_power = rho_inv_power * rho_inv_power;
    }
    std::vector<FieldElement> coefficients;
    coefficients.reserve(proof.c_vec.size());
    for (const auto& encoded : proof.c_vec) {
        PURIFY_ASSIGN_OR_RETURN(auto coefficient, FieldElement::try_from_bytes32(encoded));
        coefficients.push_back(coefficient);
    }
    const auto h_basis = std::span(basis.points()).subspan(basis.n_vec_len(), basis.l_vec_len());
    PURIFY_ASSIGN_OR_RETURN(auto commitment, msm(h_basis, coefficients, context));
    Bytes encoded;
    append(encoded, basis.digest());
    append(encoded, proof.rho);
    append(encoded, proof.commitment);
    for (const auto& coefficient : proof.c_vec) append(encoded, coefficient);
    append(encoded, commitment);
    append_size(encoded, proof.proof.size());
    append(encoded, proof.proof);
    return PreparedNorm(basis.digest(), kNormBindingHash.digest(encoded), proof.c_vec,
                        commitment, residual, {std::move(g), std::move(h)});
}

Result<PreparedNorm>
prepare_experimental_circuit_zk_norm_arg(
    const Basis& basis, const NativeBulletproofCircuit& circuit,
    const ExperimentalCircuitZkNormArgProof& proof,
    purify_secp_context* context,
    std::span<const unsigned char> statement_binding,
    ExperimentalCircuitBackend* cache) {
    PURIFY_RETURN_IF_ERROR(require_secp_context(context));
    PURIFY_RETURN_IF_ERROR(validate_basis(basis));
    PURIFY_ASSIGN_OR_RETURN(
        auto prepared, detail::prepare_experimental_circuit_zk_norm_arg(
                           circuit, proof, context, statement_binding, cache));
    if (!prepared.has_value()) {
        return unexpected_error(ErrorCode::EquationMismatch);
    }
    PURIFY_ASSIGN_OR_RETURN(auto components, prepare_circuit_norm_components(
                                                 basis, *prepared, proof, {},
                                                 context, statement_binding));
    return PreparedNorm(
        basis.digest(), components.transcript_digest,
        std::move(components.c_vec), components.coefficient_commitment,
        components.residual, std::move(components.polynomial));
}

Result<PreparedNorm>
prepare_experimental_circuit_zk_norm_arg_with_public_commitments(
    const Basis& basis, const NativeBulletproofCircuit& circuit,
    const ExperimentalCircuitZkNormArgProof& proof,
    std::span<const PointBytes> public_commitments,
    purify_secp_context* context,
    std::span<const unsigned char> statement_binding,
    ExperimentalCircuitBackend* cache) {
    PURIFY_RETURN_IF_ERROR(require_secp_context(context));
    PURIFY_RETURN_IF_ERROR(validate_basis(basis));
    PURIFY_ASSIGN_OR_RETURN(
        auto prepared,
        detail::
            prepare_experimental_circuit_zk_norm_arg_with_public_commitments(
                circuit, proof, public_commitments, context, statement_binding,
                cache));
    if (!prepared.has_value()) {
        return unexpected_error(ErrorCode::EquationMismatch);
    }
    PURIFY_ASSIGN_OR_RETURN(auto components,
                            prepare_circuit_norm_components(
                                basis, *prepared, proof, public_commitments,
                                context, statement_binding));
    return PreparedNorm(
        basis.digest(), components.transcript_digest,
        std::move(components.c_vec), components.coefficient_commitment,
        components.residual, std::move(components.polynomial));
}

Result<AlgebraicPreparedNorm>
prepare_v4_circuit_norm_for_algebraic_reduction(
    const Basis& basis, candidate::PreparedCircuitZkNormArgV4 prepared,
    purify_secp_context* context) {
    PURIFY_RETURN_IF_ERROR(require_secp_context(context));
    PURIFY_RETURN_IF_ERROR(validate_basis(basis));
    PURIFY_RETURN_IF_ERROR(validate_algebraic_dimension(basis.dimension()));

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
    PURIFY_ASSIGN_OR_RETURN(const auto& sqrt_minus_one,
                            detail::canonical_sqrt_minus_one());

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
    // These are the two compact terms installed by the constrained V4 leaf.
    PolynomialTerm g{
        terminal_n *
            pow_size(transcript.rho.scalar, shape.n_vec_len()) *
            transcript.mul_scale.scalar.inverse(),
        0,
        {}};
    PolynomialTerm h{terminal_l, shape.n_vec_len(), {}};
    g.factors.reserve(rounds);
    h.factors.reserve(rounds);
    auto ratio_inverse_power =
        transcript.mul_ratio.scalar.inverse();
    for (std::size_t i = 0; i < rounds; ++i) {
        const auto& gamma = transcript.gammas[i].scalar;
        if (i == 0) {
            g.factors.push_back(gamma * sqrt_minus_one.inverse());
        } else {
            g.factors.push_back(gamma * ratio_inverse_power);
            ratio_inverse_power =
                ratio_inverse_power * ratio_inverse_power;
        }
        h.factors.push_back(gamma);
    }

    std::vector<FieldElement> coefficients;
    coefficients.reserve(norm.c_vec.size());
    for (const auto& encoded : norm.c_vec) {
        PURIFY_ASSIGN_OR_RETURN(auto coefficient,
                                FieldElement::try_from_bytes32(encoded));
        coefficients.push_back(std::move(coefficient));
    }
    const auto coefficient_basis =
        std::span(basis.points())
            .subspan(basis.n_vec_len(), basis.l_vec_len());
    PURIFY_ASSIGN_OR_RETURN(const auto coefficient_commitment,
                            msm(coefficient_basis, coefficients, context));
    if (coefficient_commitment !=
        transcript_input.coefficient_commitment) {
        return unexpected_error(ErrorCode::InternalMismatch);
    }

    const auto prepared_binding =
        transcript.prepared_binding.scalar;
    auto norm_data = std::move(prepared).take_norm();
    auto c_vec = std::move(norm_data.c_vec);
    return AlgebraicPreparedNorm(
        basis.digest(), prepared_binding, std::move(c_vec),
        coefficient_commitment, residual,
        std::array<PolynomialTerm, 2>{std::move(g), std::move(h)});
}

Result<NormReductionProof> prove_norm_reduction(const Basis& basis, const PreparedNorm& norm,
                                               purify_secp_context* context) {
    PURIFY_RETURN_IF_ERROR(require_secp_context(context));
    PURIFY_RETURN_IF_ERROR(validate_basis(basis));
    PURIFY_RETURN_IF_ERROR(validate_prepared(basis, norm));
    std::vector<FieldElement> coefficients;
    coefficients.reserve(norm.c_vec().size());
    for (const auto& encoded : norm.c_vec()) {
        PURIFY_ASSIGN_OR_RETURN(auto coefficient, FieldElement::try_from_bytes32(encoded));
        coefficients.push_back(coefficient);
    }
    const PolynomialTerm weights{FieldElement::one(), 0, norm.polynomial()[1].factors};
    const std::array<PolynomialTerm, 1> tensor{weights};
    std::vector<FieldElement> expanded_weights(basis.l_vec_len(), FieldElement::zero());
    add_coefficients(expanded_weights, tensor, FieldElement::one());
    auto evaluation = FieldElement::zero();
    for (std::size_t i = 0; i < coefficients.size(); ++i) {
        evaluation = evaluation + coefficients[i] * expanded_weights[i];
    }
    NormReductionProof proof;
    proof.coefficient_evaluation = evaluation.to_bytes_be();
    PURIFY_ASSIGN_OR_RETURN(auto state, make_norm_context(basis, norm, proof.coefficient_evaluation, context));
    const auto h_basis = std::span(basis.points()).subspan(basis.n_vec_len(), basis.l_vec_len());
    PURIFY_ASSIGN_OR_RETURN(proof.coefficient_opening, prove_ipa(h_basis, std::move(coefficients), state.weights,
                                                                 state.opening_base, state.transcript, context));
    // This checks only the short reduction, never accepts the original norm.
    PURIFY_ASSIGN_OR_RETURN(auto pending, verify_norm_reduction(basis, norm, proof, context));
    (void)pending;
    return proof;
}

Result<PendingClaim> verify_norm_reduction(const Basis& basis, const PreparedNorm& norm,
                                          const NormReductionProof& proof, purify_secp_context* context) {
    PURIFY_RETURN_IF_ERROR(validate_basis(basis));
    PURIFY_RETURN_IF_ERROR(validate_prepared(basis, norm));
    const auto rounds = log2_dimension(basis.l_vec_len());
    const auto& opening = proof.coefficient_opening;
    if (opening.left.size() != rounds || opening.right.size() != rounds) {
        return unexpected_error(ErrorCode::SizeMismatch);
    }
    PURIFY_ASSIGN_OR_RETURN(auto terminal, FieldElement::try_from_bytes32(opening.terminal_scalar));
    (void)terminal;
    PURIFY_ASSIGN_OR_RETURN(auto state, make_norm_context(basis, norm, proof.coefficient_evaluation, context));
    PURIFY_ASSIGN_OR_RETURN(auto folded,
                            verify_ipa(basis.l_vec_len(), opening, state.weights, norm.coefficient_commitment(),
                                       state.evaluation, state.opening_base, state.transcript, context));
    folded.offset = basis.n_vec_len();

    const auto generator_encoding = base_generator(context);
    PointBytes generator{};
    if (purify_bppp_generators_to_points(context, generator_encoding.data(), 1, generator.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput);
    }
    const std::array<PointBytes, 2> norm_points{norm.residual(), generator};
    const std::array<FieldElement, 2> norm_scalars{
        FieldElement::one(), (norm.polynomial()[1].scale * state.evaluation).negate()};
    PURIFY_ASSIGN_OR_RETURN(auto norm_point, msm(norm_points, norm_scalars, context));

    // Both equations and the complete opening transcript are fixed before chi.
    // Returning their random combination prevents dropping the opening side.
    Bytes encoded;
    append(encoded, basis.digest());
    append(encoded, norm.transcript_digest());
    append(encoded, state.transcript);
    append(encoded, proof.coefficient_evaluation);
    append_ipa(encoded, opening);
    append(encoded, norm_point);
    append_polynomial(encoded, norm.polynomial());
    append(encoded, opening.folded_generator);
    const std::array<PolynomialTerm, 1> folded_polynomial{folded};
    append_polynomial(encoded, folded_polynomial);
    PURIFY_ASSIGN_OR_RETURN(auto chi, challenge(kNormFusionHash, encoded));
    const std::array<PointBytes, 2> fusion_points{norm_point, opening.folded_generator};
    const std::array<FieldElement, 2> fusion_scalars{FieldElement::one(), chi};
    PURIFY_ASSIGN_OR_RETURN(auto combined_point, msm(fusion_points, fusion_scalars, context));
    std::vector<PolynomialTerm> polynomial(norm.polynomial().begin(), norm.polynomial().end());
    folded.scale = folded.scale * chi;
    polynomial.push_back(std::move(folded));
    return PendingClaim(basis.digest(), combined_point, std::move(polynomial));
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
    auto evaluation = FieldElement::zero();
    for (std::size_t i = 0; i < coefficients.size(); ++i) {
        evaluation = evaluation +
            coefficients[i] * expanded_weights[i];
    }

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
    PURIFY_ASSIGN_OR_RETURN(auto pending, verify_algebraic_norm_reduction(
                                              basis, norm, proof, context));
    (void)pending;
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
    // both pending equations. No field is encoded by untyped concatenation.
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
