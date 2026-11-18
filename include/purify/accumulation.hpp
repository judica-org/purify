// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include "purify/bppp.hpp"

namespace purify::accountable {
class ConstructionReceiptAccumulator;
}

namespace purify::bppp::candidate {
class PreparedCircuitZkNormArgV4;
}

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
 * fixed dimensions. Canonical c-vectors are authenticated separately per norm.
 */
class Basis {
public:
    static Result<Basis> create(std::size_t n_vec_len,
                                std::size_t l_vec_len,
                                std::string_view semantic_domain,
                                purify_secp_context* context);

    [[nodiscard]] std::size_t n_vec_len() const { return n_vec_len_; }
    [[nodiscard]] std::size_t l_vec_len() const { return l_vec_len_; }
    [[nodiscard]] std::size_t dimension() const { return points_.size(); }
    [[nodiscard]] const Digest& digest() const { return digest_; }
    [[nodiscard]] const std::vector<PointBytes>& norm_generators() const { return norm_generators_; }
    [[nodiscard]] const std::vector<PointBytes>& points() const { return points_; }

private:
    Basis() = default;
    std::size_t n_vec_len_ = 0;
    std::size_t l_vec_len_ = 0;
    std::vector<PointBytes> norm_generators_;
    std::vector<PointBytes> points_;
    Digest digest_{};
};

struct AlgebraicStepProof;
struct AlgebraicNormReductionProof;

/**
 * A V4 pending norm obligation bridged to a caller-selected accumulation
 * basis. Construction authenticates the exact raw points, not the basis's
 * application semantic domain. The algebraic reduction must still verify,
 * and its returned pending claim must pass decide().
 */
class AlgebraicPreparedNorm {
public:
    [[nodiscard]] const Digest& basis_digest() const {
        return basis_digest_;
    }
    [[nodiscard]] const FieldElement& prepared_binding() const {
        return prepared_binding_;
    }
    [[nodiscard]] const std::vector<ScalarBytes>& c_vec() const {
        return c_vec_;
    }
    [[nodiscard]] const PointBytes& coefficient_commitment() const {
        return coefficient_commitment_;
    }
    [[nodiscard]] const PointBytes& residual() const { return residual_; }
    [[nodiscard]] const std::array<PolynomialTerm, 2>& polynomial() const {
        return polynomial_;
    }

private:
    AlgebraicPreparedNorm(
        Digest basis_digest, FieldElement prepared_binding,
        std::vector<ScalarBytes> c_vec,
        PointBytes coefficient_commitment, PointBytes residual,
        std::array<PolynomialTerm, 2> polynomial)
        : basis_digest_(basis_digest),
          prepared_binding_(prepared_binding), c_vec_(std::move(c_vec)),
          coefficient_commitment_(coefficient_commitment),
          residual_(residual), polynomial_(std::move(polynomial)) {}

    Digest basis_digest_{};
    FieldElement prepared_binding_;
    std::vector<ScalarBytes> c_vec_;
    PointBytes coefficient_commitment_{};
    PointBytes residual_{};
    std::array<PolynomialTerm, 2> polynomial_;

    friend Result<AlgebraicPreparedNorm>
    prepare_v4_circuit_norm_for_algebraic_reduction(
        const Basis&, candidate::PreparedCircuitZkNormArgV4,
        purify_secp_context*);
};

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

    friend Result<PendingClaim> verify_algebraic_norm_reduction(
        const Basis&, const AlgebraicPreparedNorm&,
        const AlgebraicNormReductionProof&, purify_secp_context*);
    friend Result<PendingClaim> verify_algebraic_step(
        const Basis&, std::span<const PendingClaim>,
        const AlgebraicStepProof&, purify_secp_context*);
    friend Result<PendingClaim> parse_root_claim(
        const Basis&, std::span<const unsigned char>,
        purify_secp_context*);
    friend class purify::accountable::ConstructionReceiptAccumulator;
};

/** Typed-SHA-256 IPA proof. A 33-byte zero encodes the point at infinity. */
struct AlgebraicStepProof {
    std::vector<PointBytes> left;
    std::vector<PointBytes> right;
    ScalarBytes terminal_scalar{};
    PointBytes folded_generator{};
};

/** Typed-SHA-256 coefficient reduction. */
struct AlgebraicNormReductionProof {
    ScalarBytes coefficient_evaluation{};
    AlgebraicStepProof coefficient_opening;
};

/**
 * Canonical version-2 encoding: version byte, interleaved L/R points,
 * terminal scalar, folded generator. The basis determines the round count.
 */
Result<Bytes> serialize_algebraic_step(
    const Basis& basis, const AlgebraicStepProof& proof,
    purify_secp_context* context);
Result<AlgebraicStepProof> parse_algebraic_step(
    const Basis& basis, std::span<const unsigned char> encoded,
    purify_secp_context* context);

/**
 * Canonical unframed final-claim encoding:
 * point33 || scale32 || factors[log2(basis.dimension())]32.
 *
 * The sole polynomial term has implicit offset zero, as in a claim returned
 * by verify_algebraic_step. Parsing validates syntax and binds the supplied
 * basis digest. The caller must verify the parent and call decide().
 */
Result<Bytes> serialize_root_claim(const Basis& basis,
                                   const PendingClaim& claim,
                                   purify_secp_context* context);
Result<PendingClaim> parse_root_claim(
    const Basis& basis, std::span<const unsigned char> encoded,
    purify_secp_context* context);

/** Version-2 typed-SHA-256 coefficient-reduction encoding. */
Result<Bytes> serialize_algebraic_norm_reduction(
    const Basis& basis, const AlgebraicNormReductionProof& proof,
    purify_secp_context* context);
Result<AlgebraicNormReductionProof> parse_algebraic_norm_reduction(
    const Basis& basis, std::span<const unsigned char> encoded,
    purify_secp_context* context);

/** Constructs the version-2 reduction from public prepared norm data. */
Result<AlgebraicNormReductionProof> prove_algebraic_norm_reduction(
    const Basis& basis, const AlgebraicPreparedNorm& norm,
    purify_secp_context* context);

/** Checks the version-2 reduction and returns both pending obligations. */
Result<PendingClaim> verify_algebraic_norm_reduction(
    const Basis& basis, const AlgebraicPreparedNorm& norm,
    const AlgebraicNormReductionProof& proof,
    purify_secp_context* context);

/** Proves a step with the version-2 typed SHA-256 transcript. */
Result<AlgebraicStepProof> prove_algebraic_step(
    const Basis& basis, std::span<const PendingClaim> claims,
    purify_secp_context* context);

/** Checks the version-2 short equation and returns a pending obligation. */
Result<PendingClaim> verify_algebraic_step(
    const Basis& basis, std::span<const PendingClaim> claims,
    const AlgebraicStepProof& proof, purify_secp_context* context);

/** Final required linear-size MSM. Only success here discharges the supplied obligation. */
Status decide(const Basis& basis, const PendingClaim& claim, purify_secp_context* context);

} // namespace purify::bppp::accumulation
