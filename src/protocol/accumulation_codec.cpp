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
#include "byte_io.hpp"

namespace purify::bppp::accumulation {

// Helpers shared between the translation units of this module live in internal.
using namespace internal;
using ::purify::detail::take_bytes;

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
    return parse_ipa(basis.dimension(), encoded.subspan(1), context);
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
    take_bytes(encoded, point);
    ScalarBytes scalar{};
    take_bytes(encoded, scalar);
    PURIFY_ASSIGN_OR_RETURN(auto scale, FieldElement::try_from_bytes32(scalar));
    std::vector<FieldElement> factors;
    factors.reserve(factor_count);
    for (std::size_t i = 0; i < factor_count; ++i) {
        take_bytes(encoded, scalar);
        PURIFY_ASSIGN_OR_RETURN(auto factor,
                                FieldElement::try_from_bytes32(scalar));
        factors.push_back(factor);
    }
    PendingClaim out(basis.digest(), point,
                     {PolynomialTerm{scale, 0, std::move(factors)}});
    PURIFY_RETURN_IF_ERROR(validate_root_claim(basis, out, context));
    return out;
}

Result<Bytes> serialize_algebraic_norm_reduction(
    const Basis& basis,
    const AlgebraicNormReductionProof& proof,
    purify_secp_context* context) {
    PURIFY_RETURN_IF_ERROR(validate_basis(basis));
    PURIFY_RETURN_IF_ERROR(validate_algebraic_dimension(basis.dimension()));
    PURIFY_RETURN_IF_ERROR(validate_algebraic_dimension(basis.l_vec_len()));
    PURIFY_RETURN_IF_ERROR(
        FieldElement::try_from_bytes32(proof.coefficient_evaluation));
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
    auto remaining = encoded.subspan(1);
    take_bytes(remaining, proof.coefficient_evaluation);
    PURIFY_RETURN_IF_ERROR(
        FieldElement::try_from_bytes32(proof.coefficient_evaluation));
    PURIFY_ASSIGN_OR_RETURN(proof.coefficient_opening,
                            parse_ipa(basis.l_vec_len(), remaining, context));
    return proof;
}

} // namespace purify::bppp::accumulation
