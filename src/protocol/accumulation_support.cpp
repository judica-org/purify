// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file accumulation_support.cpp
 * @brief Basis and claim validation, transcript absorption and multi-scalar helpers for norm accumulation.
 */

#include "purify/accumulation.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <utility>
#include <vector>

#include "accumulation_support.hpp"
#include "bppp_bridge.h"
#include "purify/secp_bridge.h"
#include "sha256_transcript.hpp"

namespace purify::bppp::accumulation {

// Helpers shared between the translation units of this module live in internal.
using namespace internal;

namespace {

const TaggedHash kOpeningPairHash(
    "Purify/BPPP/OpeningGeneratorPairV2");

constexpr std::size_t kMaxAlgebraicRounds = 24;

} // namespace

namespace internal {

void append_size(Bytes& out, std::size_t value) {
    static_assert(sizeof(std::size_t) <= sizeof(std::uint64_t));
    const auto wide = static_cast<std::uint64_t>(value);
    for (unsigned int i = 0; i < 8; ++i) {
        out.push_back(static_cast<unsigned char>((wide >> (8 * i)) & 0xffU));
    }
}

void append(Bytes& out, std::span<const unsigned char> bytes) {
    out.insert(out.end(), bytes.begin(), bytes.end());
}

Digest generator_digest(std::span<const PointBytes> generators) {
    Digest out{};
    const auto bytes = std::as_bytes(generators);
    purify_sha256(out.data(),
                  reinterpret_cast<const unsigned char*>(bytes.data()),
                  bytes.size());
    return out;
}

std::size_t log2_dimension(std::size_t size) {
    assert(is_power_of_two_size(size));
    return static_cast<std::size_t>(std::bit_width(size) - 1);
}

Status validate_algebraic_dimension(std::size_t dimension) {
    if (!is_power_of_two_size(dimension) ||
        log2_dimension(dimension) > kMaxAlgebraicRounds) {
        return unexpected_error(ErrorCode::InvalidDimensions);
    }
    return {};
}

FieldElement pow_size(FieldElement base, std::size_t exponent) {
    auto out = FieldElement::one();
    while (exponent != 0) {
        if ((exponent & 1U) != 0) out = out * base;
        base = base * base;
        exponent >>= 1;
    }
    return out;
}

Result<FieldElement> challenge(const TaggedHash& hash, std::span<const unsigned char> seed) {
    Bytes input(seed.begin(), seed.end());
    for (std::size_t counter = 0; counter < 256; ++counter) {
        input.resize(seed.size());
        append_size(input, counter);
        auto candidate = FieldElement::try_from_bytes32(hash.digest(input));
        if (candidate.has_value() && !candidate->is_zero()) return candidate;
    }
    return unexpected_error(ErrorCode::InternalMismatch);
}

Status validate_basis(const Basis& basis) {
    std::size_t dimension = 0;
    std::size_t generators = 0;
    if (!is_power_of_two_size(basis.n_vec_len()) ||
        !is_power_of_two_size(basis.l_vec_len()) ||
        basis.l_vec_len() > basis.n_vec_len() ||
        !(CheckedSize(basis.n_vec_len()) * 2).store(dimension) ||
        !(CheckedSize(basis.n_vec_len()) + basis.l_vec_len()).store(generators) ||
        basis.dimension() != dimension || basis.norm_generators().size() != generators) {
        return unexpected_error(ErrorCode::InvalidDimensions);
    }
    return {};
}

Status validate_prepared(const Basis& basis, const PreparedNorm& norm) {
    if (norm.basis_digest() != basis.digest()) {
        return unexpected_error(ErrorCode::BindingMismatch);
    }
    const auto& g = norm.polynomial()[0];
    const auto& h = norm.polynomial()[1];
    if (norm.c_vec().size() != basis.l_vec_len() || g.offset != 0 || h.offset != basis.n_vec_len() ||
        g.factors.size() != log2_dimension(basis.n_vec_len()) ||
        h.factors.size() != log2_dimension(basis.l_vec_len())) {
        return unexpected_error(ErrorCode::InvalidDimensions);
    }
    return {};
}

Status validate_algebraic_prepared(
    const Basis& basis, const AlgebraicPreparedNorm& norm) {
    PURIFY_RETURN_IF_ERROR(validate_algebraic_dimension(basis.dimension()));
    if (norm.basis_digest() != basis.digest()) {
        return unexpected_error(ErrorCode::BindingMismatch);
    }
    if (norm.prepared_binding().is_zero()) {
        return unexpected_error(ErrorCode::RangeViolation);
    }
    const auto& g = norm.polynomial()[0];
    const auto& h = norm.polynomial()[1];
    if (norm.c_vec().size() != basis.l_vec_len() ||
        g.offset != 0 || h.offset != basis.n_vec_len() ||
        g.factors.size() != log2_dimension(basis.n_vec_len()) ||
        h.factors.size() != log2_dimension(basis.l_vec_len())) {
        return unexpected_error(ErrorCode::InvalidDimensions);
    }
    return {};
}

void append_polynomial(Bytes& encoded, std::span<const PolynomialTerm> polynomial) {
    append_size(encoded, polynomial.size());
    for (const auto& term : polynomial) {
        append(encoded, term.scale.to_bytes_be());
        append_size(encoded, term.offset);
        append_size(encoded, term.factors.size());
        for (const auto& factor : term.factors) append(encoded, factor.to_bytes_be());
    }
}

Status append_algebraic_point(
    candidate::Sha256Transcript& transcript, const PointBytes& point) {
    if (purify_bppp_public_point_validate(point.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput);
    }
    candidate::TranscriptBytes32 x{};
    std::copy(point.begin() + 1, point.end(), x.begin());
    return transcript.append_point(point[0], x);
}

Status append_algebraic_polynomial(
    candidate::Sha256Transcript& transcript,
    std::span<const PolynomialTerm> polynomial) {
    if (!size_fits_u64(polynomial.size())) {
        return unexpected_error(ErrorCode::Overflow);
    }
    transcript.append_u64(static_cast<std::uint64_t>(polynomial.size()));
    for (const auto& term : polynomial) {
        if (!size_fits_u64(term.offset) ||
            !size_fits_u64(term.factors.size())) {
            return unexpected_error(ErrorCode::Overflow);
        }
        transcript.append_scalar(term.scale);
        transcript.append_u64(static_cast<std::uint64_t>(term.offset));
        transcript.append_u64(
            static_cast<std::uint64_t>(term.factors.size()));
        for (const auto& factor : term.factors) {
            transcript.append_scalar(factor);
        }
    }
    return {};
}

Status validate_claim(const Basis& basis, const PendingClaim& claim) {
    if (claim.basis_digest() != basis.digest()) {
        return unexpected_error(ErrorCode::BindingMismatch);
    }
    // A reduced norm has three coupled terms; an accumulated IPA has one.
    if (claim.polynomial().empty() || claim.polynomial().size() > 3) {
        return unexpected_error(ErrorCode::InvalidDimensions);
    }
    for (const auto& term : claim.polynomial()) {
        if (term.factors.size() >= std::numeric_limits<std::size_t>::digits) {
            return unexpected_error(ErrorCode::Overflow);
        }
        const std::size_t width = std::size_t{1} << term.factors.size();
        if (width > basis.dimension() || term.offset > basis.dimension() - width) {
            return unexpected_error(ErrorCode::InvalidDimensions);
        }
    }
    return {};
}

FieldElement evaluate(std::span<const PolynomialTerm> polynomial, const FieldElement& x) {
    auto sum = FieldElement::zero();
    for (const auto& term : polynomial) {
        auto value = term.scale * pow_size(x, term.offset);
        auto x_power = x;
        for (const auto& factor : term.factors) {
            value = value * (FieldElement::one() + factor * x_power);
            x_power = x_power * x_power;
        }
        sum = sum + value;
    }
    return sum;
}

void add_coefficients(std::vector<FieldElement>& out, std::span<const PolynomialTerm> polynomial,
                      const FieldElement& weight) {
    for (const auto& term : polynomial) {
        std::vector<FieldElement> coefficients{weight * term.scale};
        for (const auto& factor : term.factors) {
            const auto size = coefficients.size();
            coefficients.resize(2 * size);
            for (std::size_t i = 0; i < size; ++i) {
                coefficients[size + i] = coefficients[i] * factor;
            }
        }
        for (std::size_t i = 0; i < coefficients.size(); ++i) {
            out[term.offset + i] = out[term.offset + i] + coefficients[i];
        }
    }
}

Result<PointBytes> msm(std::span<const PointBytes> points, std::span<const FieldElement> scalars,
                      purify_secp_context* context) {
    if (points.size() != scalars.size()) {
        return unexpected_error(ErrorCode::SizeMismatch);
    }
    std::vector<ScalarBytes> encoded;
    encoded.reserve(scalars.size());
    for (const auto& scalar : scalars) encoded.push_back(scalar.to_bytes_be());
    PointBytes out{};
    if (purify_bppp_public_msm(context,
            reinterpret_cast<const unsigned char*>(points.data()),
            reinterpret_cast<const unsigned char*>(encoded.data()), points.size(), out.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput);
    }
    return out;
}

Result<FieldElement> append_algebraic_challenge(
    candidate::Sha256Transcript& transcript, std::uint64_t round) {
    PURIFY_ASSIGN_OR_RETURN(auto challenge, transcript.challenge(round));
    return std::move(challenge.scalar);
}

Result<PointBytes> derive_algebraic_opening_base(
    const Basis& basis, const candidate::Sha256Transcript& transcript,
    std::uint64_t role, purify_secp_context* context) {
    if (role != kReductionOpeningRole &&
        role != kAccumulationOpeningRole) {
        return unexpected_error(ErrorCode::UnsupportedSymbol);
    }
    PURIFY_ASSIGN_OR_RETURN(
        auto challenge, transcript.opening_base_scalar(basis.digest(), role));

    std::array<PointBytes, 2> pair{};
    for (std::size_t index = 0; index < pair.size(); ++index) {
        Bytes message;
        message.reserve(basis.digest().size() + 9);
        append(message, basis.digest());
        append_size(message, static_cast<std::size_t>(role));
        message.push_back(static_cast<unsigned char>(index));
        const auto seed = kOpeningPairHash.digest(message);
        if (purify_bppp_public_hash_to_point(
                context, seed.data(), seed.size(),
                pair[index].data()) == 0 ||
            pair[index] == PointBytes{}) {
            return unexpected_error(ErrorCode::BackendRejectedInput);
        }
    }
    if (pair[0] == pair[1]) {
        return unexpected_error(ErrorCode::InternalMismatch);
    }
    const std::array<FieldElement, 2> scalars{
        FieldElement::one(), challenge.scalar};
    PURIFY_ASSIGN_OR_RETURN(auto opening_base, msm(pair, scalars, context));
    if (opening_base == PointBytes{}) {
        return unexpected_error(ErrorCode::EquationMismatch);
    }
    return opening_base;
}

Status validate_root_claim(const Basis& basis, const PendingClaim& claim,
                           purify_secp_context* context) {
    PURIFY_RETURN_IF_ERROR(require_secp_context(context));
    PURIFY_RETURN_IF_ERROR(validate_claim(basis, claim));
    if (claim.polynomial().size() != 1 ||
        claim.polynomial()[0].offset != 0 ||
        claim.polynomial()[0].factors.size() !=
            log2_dimension(basis.dimension())) {
        return unexpected_error(ErrorCode::InvalidDimensions);
    }
    const std::array<PointBytes, 1> points{claim.point()};
    const std::array<FieldElement, 1> scalars{FieldElement::zero()};
    PURIFY_ASSIGN_OR_RETURN(const auto& identity,
                            msm(points, scalars, context));
    (void)identity;
    return {};
}

} // namespace internal

} // namespace purify::bppp::accumulation
