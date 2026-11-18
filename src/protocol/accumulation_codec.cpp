// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file accumulation_codec.cpp
 * @brief Wire encodings of accumulation steps, root claims and norm reductions.
 */

#include "purify/accumulation.hpp"

#include <cstddef>
#include <span>
#include <utility>
#include <vector>

#include "accumulation_ipa.hpp"
#include "accumulation_support.hpp"

namespace purify::bppp::accumulation {

// Helpers shared between the translation units of this module live in internal.
using namespace internal;

Result<Bytes> serialize_step(const Basis& basis, const StepProof& proof,
                             purify_secp_context* context) {
    PURIFY_RETURN_IF_ERROR(validate_basis(basis));
    PURIFY_RETURN_IF_ERROR(validate_ipa_encoding(basis.dimension(), proof, context));
    Bytes out;
    out.reserve(66 * log2_dimension(basis.dimension()) + 66);
    out.push_back(1);
    append_ipa(out, proof);
    return out;
}

Result<StepProof> parse_step(const Basis& basis, std::span<const unsigned char> encoded,
                             purify_secp_context* context) {
    PURIFY_RETURN_IF_ERROR(require_secp_context(context));
    PURIFY_RETURN_IF_ERROR(validate_basis(basis));
    if (encoded.size() != 66 * log2_dimension(basis.dimension()) + 66) {
        return unexpected_error(ErrorCode::InvalidFixedSize);
    }
    if (encoded[0] != 1) {
        return unexpected_error(ErrorCode::UnsupportedSymbol);
    }
    return parse_ipa<StepProof>(
        basis.dimension(), encoded.subspan(1), context);
}

Result<Bytes> serialize_algebraic_step(
    const Basis& basis, const AlgebraicStepProof& proof,
    purify_secp_context* context) {
    PURIFY_RETURN_IF_ERROR(validate_basis(basis));
    PURIFY_RETURN_IF_ERROR(validate_algebraic_dimension(basis.dimension()));
    PURIFY_RETURN_IF_ERROR(
        validate_ipa_encoding(basis.dimension(), proof, context));
    Bytes out;
    out.reserve(
        66 * log2_dimension(basis.dimension()) + 66);
    out.push_back(2);
    append_ipa(out, proof);
    return out;
}

Result<AlgebraicStepProof> parse_algebraic_step(
    const Basis& basis, std::span<const unsigned char> encoded,
    purify_secp_context* context) {
    PURIFY_RETURN_IF_ERROR(require_secp_context(context));
    PURIFY_RETURN_IF_ERROR(validate_basis(basis));
    PURIFY_RETURN_IF_ERROR(validate_algebraic_dimension(basis.dimension()));
    if (encoded.size() !=
        66 * log2_dimension(basis.dimension()) + 66) {
        return unexpected_error(ErrorCode::InvalidFixedSize);
    }
    if (encoded[0] != 2) {
        return unexpected_error(ErrorCode::UnsupportedSymbol);
    }
    return parse_ipa<AlgebraicStepProof>(
        basis.dimension(), encoded.subspan(1), context);
}

Result<Bytes> serialize_root_claim(const Basis& basis,
                                   const PendingClaim& claim,
                                   purify_secp_context* context) {
    PURIFY_RETURN_IF_ERROR(validate_basis(basis));
    PURIFY_RETURN_IF_ERROR(validate_root_claim(basis, claim, context));
    const auto& polynomial = claim.polynomial()[0];
    Bytes out;
    out.reserve(65 + 32 * polynomial.factors.size());
    append(out, claim.point());
    append(out, polynomial.scale.to_bytes_be());
    for (const auto& factor : polynomial.factors) {
        append(out, factor.to_bytes_be());
    }
    return out;
}

Result<PendingClaim> parse_root_claim(
    const Basis& basis, std::span<const unsigned char> encoded,
    purify_secp_context* context) {
    PURIFY_RETURN_IF_ERROR(validate_basis(basis));
    const auto factor_count = log2_dimension(basis.dimension());
    if (encoded.size() != 65 + 32 * factor_count) {
        return unexpected_error(ErrorCode::InvalidFixedSize);
    }

    PointBytes point{};
    std::copy_n(encoded.begin(), point.size(), point.begin());
    ScalarBytes scalar{};
    std::copy_n(encoded.begin() + static_cast<std::ptrdiff_t>(point.size()),
                scalar.size(), scalar.begin());
    PURIFY_ASSIGN_OR_RETURN(auto scale, FieldElement::try_from_bytes32(scalar));
    std::vector<FieldElement> factors;
    factors.reserve(factor_count);
    std::size_t offset = point.size() + scalar.size();
    for (std::size_t i = 0; i < factor_count; ++i) {
        std::copy_n(encoded.begin() + static_cast<std::ptrdiff_t>(offset),
                    scalar.size(), scalar.begin());
        offset += scalar.size();
        PURIFY_ASSIGN_OR_RETURN(auto factor,
                                FieldElement::try_from_bytes32(scalar));
        factors.push_back(factor);
    }
    PendingClaim out(basis.digest(), point,
                     {PolynomialTerm{scale, 0, std::move(factors)}});
    PURIFY_RETURN_IF_ERROR(validate_root_claim(basis, out, context));
    return out;
}

Result<Bytes> serialize_norm_reduction(const Basis& basis, const NormReductionProof& proof,
                                       purify_secp_context* context) {
    PURIFY_RETURN_IF_ERROR(validate_basis(basis));
    PURIFY_ASSIGN_OR_RETURN(auto evaluation, FieldElement::try_from_bytes32(proof.coefficient_evaluation));
    (void)evaluation;
    PURIFY_RETURN_IF_ERROR(validate_ipa_encoding(basis.l_vec_len(), proof.coefficient_opening, context));
    Bytes out;
    out.reserve(66 * log2_dimension(basis.l_vec_len()) + 98);
    out.push_back(1);
    append(out, proof.coefficient_evaluation);
    append_ipa(out, proof.coefficient_opening);
    return out;
}

Result<NormReductionProof> parse_norm_reduction(const Basis& basis, std::span<const unsigned char> encoded,
                                               purify_secp_context* context) {
    PURIFY_RETURN_IF_ERROR(require_secp_context(context));
    PURIFY_RETURN_IF_ERROR(validate_basis(basis));
    if (encoded.size() != 66 * log2_dimension(basis.l_vec_len()) + 98) {
        return unexpected_error(ErrorCode::InvalidFixedSize);
    }
    if (encoded[0] != 1) {
        return unexpected_error(ErrorCode::UnsupportedSymbol);
    }
    NormReductionProof proof;
    std::copy_n(encoded.data() + 1, 32, proof.coefficient_evaluation.begin());
    PURIFY_ASSIGN_OR_RETURN(auto evaluation, FieldElement::try_from_bytes32(proof.coefficient_evaluation));
    (void)evaluation;
    PURIFY_ASSIGN_OR_RETURN(proof.coefficient_opening,
                            parse_ipa<StepProof>(basis.l_vec_len(), encoded.subspan(33), context));
    return proof;
}

Result<Bytes> serialize_algebraic_norm_reduction(
    const Basis& basis,
    const AlgebraicNormReductionProof& proof,
    purify_secp_context* context) {
    PURIFY_RETURN_IF_ERROR(validate_basis(basis));
    PURIFY_RETURN_IF_ERROR(validate_algebraic_dimension(basis.dimension()));
    PURIFY_RETURN_IF_ERROR(validate_algebraic_dimension(basis.l_vec_len()));
    PURIFY_ASSIGN_OR_RETURN(auto evaluation, FieldElement::try_from_bytes32(
                                                 proof.coefficient_evaluation));
    (void)evaluation;
    PURIFY_RETURN_IF_ERROR(validate_ipa_encoding(
        basis.l_vec_len(), proof.coefficient_opening, context));
    Bytes out;
    out.reserve(
        66 * log2_dimension(basis.l_vec_len()) + 98);
    out.push_back(2);
    append(out, proof.coefficient_evaluation);
    append_ipa(out, proof.coefficient_opening);
    return out;
}

Result<AlgebraicNormReductionProof>
parse_algebraic_norm_reduction(
    const Basis& basis, std::span<const unsigned char> encoded,
    purify_secp_context* context) {
    PURIFY_RETURN_IF_ERROR(require_secp_context(context));
    PURIFY_RETURN_IF_ERROR(validate_basis(basis));
    PURIFY_RETURN_IF_ERROR(validate_algebraic_dimension(basis.dimension()));
    PURIFY_RETURN_IF_ERROR(validate_algebraic_dimension(basis.l_vec_len()));
    if (encoded.size() !=
        66 * log2_dimension(basis.l_vec_len()) + 98) {
        return unexpected_error(ErrorCode::InvalidFixedSize);
    }
    if (encoded[0] != 2) {
        return unexpected_error(ErrorCode::UnsupportedSymbol);
    }
    AlgebraicNormReductionProof proof;
    std::copy_n(
        encoded.data() + 1, 32,
        proof.coefficient_evaluation.begin());
    PURIFY_ASSIGN_OR_RETURN(auto evaluation, FieldElement::try_from_bytes32(
                                                 proof.coefficient_evaluation));
    (void)evaluation;
    PURIFY_ASSIGN_OR_RETURN(proof.coefficient_opening,
                            parse_ipa<AlgebraicStepProof>(basis.l_vec_len(),
                                                          encoded.subspan(33),
                                                          context));
    return proof;
}

} // namespace purify::bppp::accumulation
