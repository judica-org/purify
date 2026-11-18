// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file accumulation_support.hpp
 * @brief Validation, transcript and multi-scalar helpers shared by the accumulation translation units.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "checked_size.hpp"
#include "purify/accumulation.hpp"
#include "sha256_transcript.hpp"

namespace purify::bppp::accumulation {

namespace internal {

using ::purify::detail::CheckedSize;

constexpr std::uint64_t kReductionOpeningRole = 1;

constexpr std::uint64_t kAccumulationOpeningRole = 2;

void append_size(Bytes& out, std::size_t value);

void append(Bytes& out, std::span<const unsigned char> bytes);

Digest generator_digest(std::span<const PointBytes> generators);

std::size_t log2_dimension(std::size_t size);

Status validate_algebraic_dimension(std::size_t dimension);

FieldElement pow_size(FieldElement base, std::size_t exponent);

Result<FieldElement> challenge(const TaggedHash& hash, std::span<const unsigned char> seed);

Status validate_basis(const Basis& basis);

Status validate_prepared(const Basis& basis, const PreparedNorm& norm);

Status validate_algebraic_prepared(
    const Basis& basis, const AlgebraicPreparedNorm& norm);

void append_polynomial(Bytes& encoded, std::span<const PolynomialTerm> polynomial);

Status append_algebraic_point(
    candidate::Sha256Transcript& transcript, const PointBytes& point);

Status append_algebraic_polynomial(
    candidate::Sha256Transcript& transcript,
    std::span<const PolynomialTerm> polynomial);

Status validate_claim(const Basis& basis, const PendingClaim& claim);

FieldElement evaluate(std::span<const PolynomialTerm> polynomial, const FieldElement& x);

void add_coefficients(std::vector<FieldElement>& out, std::span<const PolynomialTerm> polynomial,
                      const FieldElement& weight);

Result<PointBytes> msm(std::span<const PointBytes> points, std::span<const FieldElement> scalars,
                      purify_secp_context* context);

Result<FieldElement> append_algebraic_challenge(
    candidate::Sha256Transcript& transcript, std::uint64_t round);

Result<PointBytes> derive_algebraic_opening_base(
    const Basis& basis, const candidate::Sha256Transcript& transcript,
    std::uint64_t role, purify_secp_context* context);

Status validate_root_claim(const Basis& basis, const PendingClaim& claim,
                           purify_secp_context* context);

} // namespace internal

} // namespace purify::bppp::accumulation
