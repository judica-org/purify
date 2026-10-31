// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "purify/accumulation.hpp"

#include "bppp_bridge.h"

namespace purify::bppp::accumulation {
namespace {

const TaggedHash kBasisHash("Purify/BPPP/NormAccumBasisV1");
const TaggedHash kClaimsHash("Purify/BPPP/AccumClaimsV1");
const TaggedHash kBatchHash("Purify/BPPP/AccumBatchV1");
const TaggedHash kEvaluationHash("Purify/BPPP/AccumEvaluationV1");
const TaggedHash kOpeningBaseHash("Purify/BPPP/AccumOpeningBaseV1");
const TaggedHash kOpeningHash("Purify/BPPP/AccumOpeningV1");
const TaggedHash kRoundHash("Purify/BPPP/AccumRoundV1");

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

std::size_t log2_dimension(std::size_t size) {
    assert(is_power_of_two_size(size));
    return static_cast<std::size_t>(std::bit_width(size) - 1);
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
    return unexpected_error(ErrorCode::InternalMismatch, "accumulation:challenge_exhausted");
}

Status validate_basis(const Basis& basis) {
    std::size_t dimension = 0;
    std::size_t generators = 0;
    if (!is_power_of_two_size(basis.n_vec_len()) ||
        !is_power_of_two_size(basis.c_vec().size()) ||
        basis.c_vec().size() > basis.n_vec_len() ||
        !checked_mul_size(basis.n_vec_len(), 2, dimension) ||
        !checked_add_size(basis.n_vec_len(), basis.c_vec().size(), generators) ||
        basis.dimension() != dimension || basis.norm_generators().size() != generators) {
        return unexpected_error(ErrorCode::InvalidDimensions, "accumulation:basis_shape");
    }
    return {};
}

Status validate_claim(const Basis& basis, const PendingClaim& claim) {
    if (claim.basis_digest() != basis.digest()) {
        return unexpected_error(ErrorCode::BindingMismatch, "accumulation:claim_basis");
    }
    // The only constructors produce a norm's two terms or an IPA's one term.
    if (claim.polynomial().empty() || claim.polynomial().size() > 2) {
        return unexpected_error(ErrorCode::InvalidDimensions, "accumulation:polynomial_shape");
    }
    for (const auto& term : claim.polynomial()) {
        if (term.factors.size() >= std::numeric_limits<std::size_t>::digits) {
            return unexpected_error(ErrorCode::Overflow, "accumulation:polynomial_degree");
        }
        const std::size_t width = std::size_t{1} << term.factors.size();
        if (width > basis.dimension() || term.offset > basis.dimension() - width) {
            return unexpected_error(ErrorCode::InvalidDimensions, "accumulation:polynomial_degree");
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
        return unexpected_error(ErrorCode::SizeMismatch, "accumulation:msm_shape");
    }
    std::vector<ScalarBytes> encoded;
    encoded.reserve(scalars.size());
    for (const auto& scalar : scalars) encoded.push_back(scalar.to_bytes_be());
    PointBytes out{};
    if (purify_bppp_public_msm(context,
            reinterpret_cast<const unsigned char*>(points.data()),
            reinterpret_cast<const unsigned char*>(encoded.data()), points.size(), out.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput, "accumulation:public_msm");
    }
    return out;
}

Status validate_step_encoding(const Basis& basis, const StepProof& proof,
                              purify_secp_context* context) {
    PURIFY_RETURN_IF_ERROR(require_secp_context(context, "accumulation:context"),
                            "accumulation:context");
    PURIFY_RETURN_IF_ERROR(validate_basis(basis), "accumulation:basis");
    const auto rounds = log2_dimension(basis.dimension());
    if (proof.left.size() != rounds || proof.right.size() != rounds) {
        return unexpected_error(ErrorCode::SizeMismatch, "accumulation:step_encoding_rounds");
    }
    PURIFY_ASSIGN_OR_RETURN(auto terminal, FieldElement::try_from_bytes32(proof.terminal_scalar),
                            "accumulation:step_encoding_scalar");
    (void)terminal;
    std::vector<PointBytes> points;
    points.reserve(2 * rounds + 1);
    for (std::size_t round = 0; round < rounds; ++round) {
        points.push_back(proof.left[round]);
        points.push_back(proof.right[round]);
    }
    points.push_back(proof.folded_generator);
    // The bridge callback parses every point before any zero-scalar skipping.
    // This validates canonical encodings, including the unique identity form.
    const std::vector<FieldElement> zeros(points.size(), FieldElement::zero());
    PURIFY_ASSIGN_OR_RETURN(auto identity, msm(points, zeros, context),
                            "accumulation:step_encoding_points");
    (void)identity;
    return {};
}

struct StepContext {
    FieldElement beta;
    FieldElement x;
    FieldElement y;
    PointBytes commitment;
    PointBytes opening_base;
    Digest transcript;
};

Result<StepContext> make_step_context(const Basis& basis, std::span<const PendingClaim> claims,
                                      purify_secp_context* context) {
    PURIFY_RETURN_IF_ERROR(require_secp_context(context, "accumulation:context"),
                            "accumulation:context");
    PURIFY_RETURN_IF_ERROR(validate_basis(basis), "accumulation:basis");
    if (claims.empty()) {
        return unexpected_error(ErrorCode::EmptyInput, "accumulation:claims");
    }
    Bytes encoded;
    append(encoded, basis.digest());
    append_size(encoded, claims.size());
    for (const auto& claim : claims) {
        PURIFY_RETURN_IF_ERROR(validate_claim(basis, claim), "accumulation:claim");
        append(encoded, claim.point());
        append_size(encoded, claim.polynomial().size());
        for (const auto& term : claim.polynomial()) {
            append(encoded, term.scale.to_bytes_be());
            append_size(encoded, term.offset);
            append_size(encoded, term.factors.size());
            for (const auto& factor : term.factors) append(encoded, factor.to_bytes_be());
        }
    }
    const auto claims_digest = kClaimsHash.digest(encoded);
    StepContext out;
    PURIFY_ASSIGN_OR_RETURN(out.beta, challenge(kBatchHash, claims_digest),
                            "accumulation:batch_challenge");
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
    PURIFY_ASSIGN_OR_RETURN(out.commitment, msm(commitments, weights, context),
                            "accumulation:batch_commitment");
    encoded.clear();
    append(encoded, claims_digest);
    append(encoded, out.beta.to_bytes_be());
    append(encoded, out.commitment);
    PURIFY_ASSIGN_OR_RETURN(out.x, challenge(kEvaluationHash, encoded),
                            "accumulation:evaluation_challenge");
    out.y = FieldElement::zero();
    for (std::size_t i = 0; i < claims.size(); ++i) {
        out.y = out.y + weights[i] * evaluate(claims[i].polynomial(), out.x);
    }
    append(encoded, out.x.to_bytes_be());
    append(encoded, out.y.to_bytes_be());
    // This independent generator is chosen AFTER the claimed evaluation is
    // fixed. Hash-to-scalar times the standard generator is not a substitute.
    const auto opening_seed = kOpeningBaseHash.digest(encoded);
    if (purify_bppp_public_hash_to_point(context, opening_seed.data(), opening_seed.size(),
                                        out.opening_base.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput, "accumulation:opening_base");
    }
    append(encoded, out.opening_base);
    out.transcript = kOpeningHash.digest(encoded);
    return out;
}

Result<FieldElement> round_challenge(Digest& transcript, std::size_t round,
                                     const PointBytes& left, const PointBytes& right) {
    Bytes encoded;
    append(encoded, transcript);
    append_size(encoded, round);
    append(encoded, left);
    append(encoded, right);
    PURIFY_ASSIGN_OR_RETURN(auto t, challenge(kRoundHash, encoded), "accumulation:round_challenge");
    append(encoded, t.to_bytes_be());
    transcript = kRoundHash.digest(encoded);
    return t;
}

PolynomialTerm geometric_tensor(const FieldElement& x, std::size_t dimension) {
    PolynomialTerm out{FieldElement::one(), 0, {}};
    auto power = x;
    for (std::size_t i = 0; i < log2_dimension(dimension); ++i) {
        out.factors.push_back(power);
        power = power * power;
    }
    return out;
}

FieldElement tensor_inner_product(const PolynomialTerm& lhs, const PolynomialTerm& rhs) {
    assert(lhs.offset == 0 && rhs.offset == 0 && lhs.factors.size() == rhs.factors.size());
    auto out = lhs.scale * rhs.scale;
    for (std::size_t i = 0; i < lhs.factors.size(); ++i) {
        out = out * (FieldElement::one() + lhs.factors[i] * rhs.factors[i]);
    }
    return out;
}

Result<StepProof> prove_ipa(std::span<const PointBytes> basis, std::vector<FieldElement> a,
                            const PolynomialTerm& weights, const PointBytes& opening_base,
                            Digest transcript, purify_secp_context* context) {
    assert(a.size() == basis.size() && is_power_of_two_size(a.size()));
    assert(weights.offset == 0 && weights.factors.size() == log2_dimension(a.size()));
    std::vector<FieldElement> b(a.size(), FieldElement::zero());
    const std::array<PolynomialTerm, 1> tensor{weights};
    add_coefficients(b, tensor, FieldElement::one());
    std::vector<PointBytes> generators(basis.begin(), basis.end());
    StepProof proof;
    const auto rounds = log2_dimension(a.size());
    proof.left.reserve(rounds);
    proof.right.reserve(rounds);
    for (std::size_t round = 0; round < rounds; ++round) {
        const auto half = a.size() / 2;
        std::vector<PointBytes> left_points, right_points;
        std::vector<FieldElement> left_scalars, right_scalars;
        left_points.reserve(half + 1);
        right_points.reserve(half + 1);
        left_scalars.reserve(half + 1);
        right_scalars.reserve(half + 1);
        auto left_inner = FieldElement::zero();
        auto right_inner = FieldElement::zero();
        for (std::size_t i = 0; i < half; ++i) {
            left_points.push_back(generators[half + i]);
            left_scalars.push_back(a[i]);
            right_points.push_back(generators[i]);
            right_scalars.push_back(a[half + i]);
            left_inner = left_inner + a[i] * b[half + i];
            right_inner = right_inner + a[half + i] * b[i];
        }
        left_points.push_back(opening_base);
        right_points.push_back(opening_base);
        left_scalars.push_back(left_inner);
        right_scalars.push_back(right_inner);
        PURIFY_ASSIGN_OR_RETURN(auto left, msm(left_points, left_scalars, context),
                                "accumulation:prove_left");
        PURIFY_ASSIGN_OR_RETURN(auto right, msm(right_points, right_scalars, context),
                                "accumulation:prove_right");
        proof.left.push_back(left);
        proof.right.push_back(right);
        PURIFY_ASSIGN_OR_RETURN(auto t, round_challenge(transcript, round, left, right),
                                "accumulation:prove_round");
        const auto t_inv = t.inverse();
        for (std::size_t i = 0; i < half; ++i) {
            a[i] = t * a[i] + t_inv * a[half + i];
            b[i] = t_inv * b[i] + t * b[half + i];
            const std::array<PointBytes, 2> pair{generators[i], generators[half + i]};
            const std::array<FieldElement, 2> fold_weights{t_inv, t};
            PURIFY_ASSIGN_OR_RETURN(generators[i], msm(pair, fold_weights, context),
                                    "accumulation:prove_fold_basis");
        }
        a.resize(half);
        b.resize(half);
        generators.resize(half);
    }
    proof.terminal_scalar = a[0].to_bytes_be();
    proof.folded_generator = generators[0];
    return proof;
}

Result<PolynomialTerm> verify_ipa(std::size_t dimension, const StepProof& proof,
                                  const PolynomialTerm& weights, const PointBytes& commitment,
                                  const FieldElement& evaluation, const PointBytes& opening_base,
                                  Digest transcript, purify_secp_context* context) {
    assert(is_power_of_two_size(dimension));
    assert(weights.offset == 0 && weights.factors.size() == log2_dimension(dimension));
    const auto rounds = log2_dimension(dimension);
    if (proof.left.size() != rounds || proof.right.size() != rounds) {
        return unexpected_error(ErrorCode::SizeMismatch, "accumulation:step_proof_rounds");
    }
    PURIFY_ASSIGN_OR_RETURN(auto a, FieldElement::try_from_bytes32(proof.terminal_scalar),
                            "accumulation:step_terminal_scalar");
    PolynomialTerm folded{FieldElement::one(), 0, {}};
    folded.factors.resize(rounds);
    std::vector<PointBytes> points{commitment};
    std::vector<FieldElement> scalars{FieldElement::one()};
    for (std::size_t round = 0; round < rounds; ++round) {
        PURIFY_ASSIGN_OR_RETURN(auto t, round_challenge(transcript, round,
                                                        proof.left[round], proof.right[round]),
                                "accumulation:verify_round");
        const auto t_inv = t.inverse();
        const auto t_squared = t * t;
        folded.scale = folded.scale * t_inv;
        // Half-splitting uses the most significant index bit first.
        folded.factors[rounds - 1 - round] = t_squared;
        points.push_back(proof.left[round]);
        scalars.push_back(t_squared);
        points.push_back(proof.right[round]);
        scalars.push_back(t_inv * t_inv);
    }
    const auto b_final = tensor_inner_product(weights, folded);
    points.push_back(opening_base);
    scalars.push_back(evaluation - a * b_final);
    points.push_back(proof.folded_generator);
    scalars.push_back(a.negate());
    PURIFY_ASSIGN_OR_RETURN(auto residual, msm(points, scalars, context),
                            "accumulation:verify_equation");
    if (residual != PointBytes{}) {
        return unexpected_error(ErrorCode::EquationMismatch, "accumulation:step_equation");
    }
    return folded;
}

} // namespace

Result<Basis> Basis::create(std::size_t n_vec_len, std::span<const ScalarBytes> c_vec,
                            std::string_view semantic_domain, purify_secp_context* context) {
    PURIFY_RETURN_IF_ERROR(require_secp_context(context, "accumulation:context"),
                            "accumulation:context");
    std::size_t dimension = 0;
    if (!is_power_of_two_size(n_vec_len) || !is_power_of_two_size(c_vec.size()) ||
        c_vec.size() > n_vec_len || !checked_mul_size(n_vec_len, 2, dimension)) {
        return unexpected_error(ErrorCode::InvalidDimensions, "accumulation:create_basis_shape");
    }
    if (semantic_domain.empty()) {
        return unexpected_error(ErrorCode::EmptyInput, "accumulation:basis_semantic_domain");
    }
    Basis out;
    out.n_vec_len_ = n_vec_len;
    out.c_vec_.assign(c_vec.begin(), c_vec.end());
    PURIFY_ASSIGN_OR_RETURN(auto generators, create_generators(dimension, context),
                            "accumulation:deterministic_generators");
    out.points_.resize(dimension);
    if (purify_bppp_shift_norm_basis(context,
            reinterpret_cast<const unsigned char*>(generators.data()), generators.size(),
            reinterpret_cast<const unsigned char*>(c_vec.data()), c_vec.size(), n_vec_len,
            reinterpret_cast<unsigned char*>(out.points_.data())) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput, "accumulation:shift_basis");
    }
    generators.resize(n_vec_len + c_vec.size());
    out.norm_generators_ = std::move(generators);
    Bytes encoded;
    append_size(encoded, semantic_domain.size());
    append(encoded, std::span(reinterpret_cast<const unsigned char*>(semantic_domain.data()),
                             semantic_domain.size()));
    append_size(encoded, n_vec_len);
    append_size(encoded, c_vec.size());
    for (const auto& coefficient : c_vec) append(encoded, coefficient);
    for (const auto& point : out.points_) append(encoded, point);
    out.digest_ = kBasisHash.digest(encoded);
    return out;
}

Result<Bytes> serialize_step(const Basis& basis, const StepProof& proof,
                             purify_secp_context* context) {
    PURIFY_RETURN_IF_ERROR(validate_step_encoding(basis, proof, context),
                            "accumulation:serialize_step");
    const auto rounds = log2_dimension(basis.dimension());
    Bytes out;
    // Valid power-of-two size_t dimensions bound rounds below 64.
    out.reserve(66 * rounds + 66);
    out.push_back(1);
    for (std::size_t round = 0; round < rounds; ++round) {
        append(out, proof.left[round]);
        append(out, proof.right[round]);
    }
    append(out, proof.terminal_scalar);
    append(out, proof.folded_generator);
    return out;
}

Result<StepProof> parse_step(const Basis& basis, std::span<const unsigned char> encoded,
                             purify_secp_context* context) {
    PURIFY_RETURN_IF_ERROR(require_secp_context(context, "accumulation:context"),
                            "accumulation:context");
    PURIFY_RETURN_IF_ERROR(validate_basis(basis), "accumulation:basis");
    const auto rounds = log2_dimension(basis.dimension());
    if (encoded.size() != 66 * rounds + 66) {
        return unexpected_error(ErrorCode::InvalidFixedSize, "accumulation:parse_step_size");
    }
    if (encoded[0] != 1) {
        return unexpected_error(ErrorCode::UnsupportedSymbol, "accumulation:parse_step_version");
    }
    StepProof proof;
    proof.left.resize(rounds);
    proof.right.resize(rounds);
    std::size_t offset = 1;
    for (std::size_t round = 0; round < rounds; ++round) {
        std::copy_n(encoded.data() + offset, 33, proof.left[round].begin());
        offset += 33;
        std::copy_n(encoded.data() + offset, 33, proof.right[round].begin());
        offset += 33;
    }
    std::copy_n(encoded.data() + offset, 32, proof.terminal_scalar.begin());
    offset += 32;
    std::copy_n(encoded.data() + offset, 33, proof.folded_generator.begin());
    PURIFY_RETURN_IF_ERROR(validate_step_encoding(basis, proof, context),
                            "accumulation:parse_step");
    return proof;
}

Result<PendingClaim> prepare_norm(const Basis& basis, const NormArgProof& proof,
                                  purify_secp_context* context) {
    PURIFY_RETURN_IF_ERROR(require_secp_context(context, "accumulation:context"),
                            "accumulation:context");
    PURIFY_RETURN_IF_ERROR(validate_basis(basis), "accumulation:basis");
    if (proof.n_vec_len != basis.n_vec_len() || proof.c_vec != basis.c_vec() ||
        proof.generators != basis.norm_generators()) {
        return unexpected_error(ErrorCode::BindingMismatch, "accumulation:norm_basis");
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
        return unexpected_error(ErrorCode::BackendRejectedInput, "accumulation:prepare_norm");
    }
    PURIFY_ASSIGN_OR_RETURN(auto n, FieldElement::try_from_bytes32(n_bytes), "accumulation:norm_n");
    PURIFY_ASSIGN_OR_RETURN(auto l, FieldElement::try_from_bytes32(l_bytes), "accumulation:norm_l");
    PURIFY_ASSIGN_OR_RETURN(auto rho, FieldElement::try_from_bytes32(proof.rho), "accumulation:norm_rho");
    PolynomialTerm g{n * pow_size(rho, basis.n_vec_len() - 1), 0, {}};
    PolynomialTerm h{l, basis.n_vec_len(), {}};
    auto rho_inv_power = rho.inverse();
    const auto h_rounds = log2_dimension(basis.c_vec().size());
    for (std::size_t j = 0; j < rounds; ++j) {
        PURIFY_ASSIGN_OR_RETURN(auto gamma, FieldElement::try_from_bytes32(gammas[j]),
                                "accumulation:norm_gamma");
        g.factors.push_back(gamma * rho_inv_power);
        if (j < h_rounds) h.factors.push_back(gamma);
        rho_inv_power = rho_inv_power * rho_inv_power;
    }
    return PendingClaim(basis.digest(), residual, {std::move(g), std::move(h)});
}

Result<StepProof> prove_step(const Basis& basis, std::span<const PendingClaim> claims,
                             purify_secp_context* context) {
    PURIFY_ASSIGN_OR_RETURN(auto state, make_step_context(basis, claims, context),
                            "accumulation:prove_context");
    std::vector<FieldElement> a(basis.dimension(), FieldElement::zero());
    auto weight = FieldElement::one();
    for (const auto& claim : claims) {
        add_coefficients(a, claim.polynomial(), weight);
        weight = weight * state.beta;
    }
    const auto weights = geometric_tensor(state.x, basis.dimension());
    PURIFY_ASSIGN_OR_RETURN(auto proof,
        prove_ipa(basis.points(), std::move(a), weights, state.opening_base, state.transcript, context),
        "accumulation:prove_ipa");
    // Check the aggregated short equation before returning a generated proof.
    // This needs no additional fixed-basis MSM; batching is probabilistic.
    PURIFY_ASSIGN_OR_RETURN(auto pending, verify_step(basis, claims, proof, context),
                            "accumulation:prove_check");
    (void)pending;
    return proof;
}

Result<PendingClaim> verify_step(const Basis& basis, std::span<const PendingClaim> claims,
                                 const StepProof& proof, purify_secp_context* context) {
    PURIFY_RETURN_IF_ERROR(validate_basis(basis), "accumulation:basis");
    const auto rounds = log2_dimension(basis.dimension());
    if (proof.left.size() != rounds || proof.right.size() != rounds) {
        return unexpected_error(ErrorCode::SizeMismatch, "accumulation:step_proof_rounds");
    }
    PURIFY_ASSIGN_OR_RETURN(auto terminal, FieldElement::try_from_bytes32(proof.terminal_scalar),
                            "accumulation:step_terminal_scalar");
    (void)terminal;
    PURIFY_ASSIGN_OR_RETURN(auto state, make_step_context(basis, claims, context),
                            "accumulation:verify_context");
    const auto weights = geometric_tensor(state.x, basis.dimension());
    PURIFY_ASSIGN_OR_RETURN(auto folded,
        verify_ipa(basis.dimension(), proof, weights, state.commitment, state.y,
                   state.opening_base, state.transcript, context), "accumulation:verify_ipa");
    return PendingClaim(basis.digest(), proof.folded_generator, {std::move(folded)});
}

Status decide(const Basis& basis, const PendingClaim& claim, purify_secp_context* context) {
    PURIFY_RETURN_IF_ERROR(require_secp_context(context, "accumulation:context"),
                            "accumulation:context");
    PURIFY_RETURN_IF_ERROR(validate_basis(basis), "accumulation:basis");
    PURIFY_RETURN_IF_ERROR(validate_claim(basis, claim), "accumulation:claim");
    std::vector<FieldElement> coefficients(basis.dimension(), FieldElement::zero());
    add_coefficients(coefficients, claim.polynomial(), FieldElement::one());
    PURIFY_ASSIGN_OR_RETURN(auto expected, msm(basis.points(), coefficients, context),
                            "accumulation:decide_msm");
    if (expected != claim.point()) {
        return unexpected_error(ErrorCode::EquationMismatch, "accumulation:final_decider");
    }
    return {};
}

} // namespace purify::bppp::accumulation
