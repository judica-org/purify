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

struct StepProof;
struct NormReductionProof;

/**
 * Parsed public norm data, including the coefficient commitment computed from
 * its exact canonical c-vector. This object is not an accepted proof or an
 * accumulator claim. Its private constructor prevents substituting a claimed
 * coefficient commitment without authenticating it from c.
 */
class PreparedNorm {
public:
    [[nodiscard]] const Digest& basis_digest() const { return basis_digest_; }
    [[nodiscard]] const Digest& transcript_digest() const { return transcript_digest_; }
    [[nodiscard]] const std::vector<ScalarBytes>& c_vec() const { return c_vec_; }
    [[nodiscard]] const PointBytes& coefficient_commitment() const { return coefficient_commitment_; }
    [[nodiscard]] const PointBytes& residual() const { return residual_; }
    [[nodiscard]] const std::array<PolynomialTerm, 2>& polynomial() const { return polynomial_; }

private:
    PreparedNorm(Digest basis_digest, Digest transcript_digest, std::vector<ScalarBytes> c_vec,
                 PointBytes coefficient_commitment, PointBytes residual,
                 std::array<PolynomialTerm, 2> polynomial)
        : basis_digest_(basis_digest), transcript_digest_(transcript_digest), c_vec_(std::move(c_vec)),
          coefficient_commitment_(coefficient_commitment), residual_(residual),
          polynomial_(std::move(polynomial)) {}

    Digest basis_digest_{};
    Digest transcript_digest_{};
    std::vector<ScalarBytes> c_vec_;
    PointBytes coefficient_commitment_{};
    PointBytes residual_{};
    std::array<PolynomialTerm, 2> polynomial_;

    friend Result<PreparedNorm> prepare_norm(const Basis&, const NormArgProof&, purify_secp_context*);
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

    friend Result<PendingClaim> verify_norm_reduction(const Basis&, const PreparedNorm&,
                                                     const NormReductionProof&, purify_secp_context*);
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
 * Public opening of <c, tensor(norm challenges)> on the h-dimensional H basis.
 * The IPA uses a separate statement domain from an accumulation step. A short
 * verification always fuses both remaining equations into one pending claim.
 */
struct NormReductionProof {
    ScalarBytes coefficient_evaluation{};
    StepProof coefficient_opening;
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

/** Parses the norm transcript and computes C_c from its exact required public coefficients. */
Result<PreparedNorm> prepare_norm(const Basis& basis, const NormArgProof& proof,
                                  purify_secp_context* context);

/** Constructs the tensor opening using only the prepared public c-vector and transcript. */
Result<NormReductionProof> prove_norm_reduction(const Basis& basis, const PreparedNorm& norm,
                                               purify_secp_context* context);

/** Returns one pending claim containing BOTH the norm and coefficient-opening obligations. */
Result<PendingClaim> verify_norm_reduction(const Basis& basis, const PreparedNorm& norm,
                                          const NormReductionProof& proof, purify_secp_context* context);

/** Version 1: version byte, evaluation scalar, h-dimensional IPA transcript without another version. */
Result<Bytes> serialize_norm_reduction(const Basis& basis, const NormReductionProof& proof,
                                       purify_secp_context* context);
Result<NormReductionProof> parse_norm_reduction(const Basis& basis, std::span<const unsigned char> encoded,
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
