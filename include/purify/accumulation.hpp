// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include "purify/bppp.hpp"

namespace purify::bppp::accumulation {

using Digest = std::array<unsigned char, 32>;

/** A public coefficient polynomial: scale * X^offset * product(1+factor[j]*X^(2^j)). */
struct PolynomialTerm {
    FieldElement scale;
    std::size_t offset = 0;
    std::vector<FieldElement> factors;
};

/**
 * A deterministic, transparent norm basis with an exact semantic domain and
 * c-vector. Different c-vectors require different accumulation buckets.
 */
class Basis {
public:
    static Result<Basis> create(std::size_t n_vec_len,
                                std::span<const ScalarBytes> c_vec,
                                std::string_view semantic_domain,
                                purify_secp_context* context);

    [[nodiscard]] std::size_t n_vec_len() const { return n_vec_len_; }
    [[nodiscard]] std::size_t dimension() const { return points_.size(); }
    [[nodiscard]] const Digest& digest() const { return digest_; }
    [[nodiscard]] const std::vector<ScalarBytes>& c_vec() const { return c_vec_; }
    [[nodiscard]] const std::vector<PointBytes>& norm_generators() const { return norm_generators_; }
    [[nodiscard]] const std::vector<PointBytes>& points() const { return points_; }

private:
    Basis() = default;
    std::size_t n_vec_len_ = 0;
    std::vector<ScalarBytes> c_vec_;
    std::vector<PointBytes> norm_generators_;
    std::vector<PointBytes> points_;
    Digest digest_{};
};

struct StepProof;

/**
 * An UNVERIFIED obligation point = MSM(basis, polynomial coefficients).
 * Obtaining this value is never proof acceptance: a caller must retain the
 * authenticated transition chain and finish with decide(). No child proof
 * bytes or partial-verifier checks are compressed by this native API.
 */
class PendingClaim {
public:
    [[nodiscard]] const Digest& basis_digest() const { return basis_digest_; }
    [[nodiscard]] const PointBytes& point() const { return point_; }
    [[nodiscard]] const std::vector<PolynomialTerm>& polynomial() const { return polynomial_; }

private:
    PendingClaim(Digest basis_digest, PointBytes point, std::vector<PolynomialTerm> polynomial)
        : basis_digest_(basis_digest), point_(point), polynomial_(std::move(polynomial)) {}

    Digest basis_digest_{};
    PointBytes point_{};
    std::vector<PolynomialTerm> polynomial_;

    friend Result<PendingClaim> prepare_norm(const Basis&, const NormArgProof&, purify_secp_context*);
    friend Result<PendingClaim> verify_step(const Basis&, std::span<const PendingClaim>,
                                           const StepProof&, purify_secp_context*);
};

/** Public one-vector IPA transcript; all-zero33 encodes the point at infinity. */
struct StepProof {
    std::vector<PointBytes> left;
    std::vector<PointBytes> right;
    ScalarBytes terminal_scalar{};
    PointBytes folded_generator{};
};

/**
 * Canonical version-1 encoding: version byte, interleaved L/R points, terminal
 * scalar, folded generator. The authenticated basis determines the exact
 * round count. Encoding/decoding checks syntax only, never proof acceptance.
 */
Result<Bytes> serialize_step(const Basis& basis, const StepProof& proof,
                             purify_secp_context* context);
Result<StepProof> parse_step(const Basis& basis, std::span<const unsigned char> encoded,
                             purify_secp_context* context);

/** Checks the standalone norm encodings/transcript, leaving its fixed-basis MSM pending. */
Result<PendingClaim> prepare_norm(const Basis& basis, const NormArgProof& proof,
                                  purify_secp_context* context);

/** Proves a step using only public claims and deterministic public basis points. */
Result<StepProof> prove_step(const Basis& basis, std::span<const PendingClaim> claims,
                             purify_secp_context* context);

/** Checks the short step equation; success returns a NEW UNVERIFIED obligation. */
Result<PendingClaim> verify_step(const Basis& basis, std::span<const PendingClaim> claims,
                                 const StepProof& proof, purify_secp_context* context);

/** Final required linear-size MSM. Only success here discharges the supplied obligation. */
Status decide(const Basis& basis, const PendingClaim& claim, purify_secp_context* context);

} // namespace purify::bppp::accumulation
