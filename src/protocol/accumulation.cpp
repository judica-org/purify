// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "purify/accumulation.hpp"

#include "algebraic_circuit_accumulation.hpp"
#include "algebraic_transcript.hpp"
#include "bppp_bridge.h"
#include "bppp_internal.hpp"
#if defined(PURIFY_INTERNAL_TEST_SUPPORT)
#include "accumulation_test_support.hpp"
#endif

namespace purify::bppp::accumulation {

namespace {

const TaggedHash kBasisHash("Purify/BPPP/NormAccumBasisV2");
const TaggedHash kClaimsHash("Purify/BPPP/AccumClaimsV1");
const TaggedHash kBatchHash("Purify/BPPP/AccumBatchV1");
const TaggedHash kEvaluationHash("Purify/BPPP/AccumEvaluationV1");
const TaggedHash kOpeningBaseHash("Purify/BPPP/AccumOpeningBaseV1");
const TaggedHash kOpeningHash("Purify/BPPP/AccumOpeningV1");
const TaggedHash kRoundHash("Purify/BPPP/AccumRoundV1");
const TaggedHash kNormBindingHash("Purify/BPPP/NormReduction/StatementV1");
const TaggedHash kCircuitNormBindingHash(
    "Purify/BPPP/CircuitNormReduction/StatementV3");
const TaggedHash kNormOpeningBaseHash("Purify/BPPP/NormReduction/OpeningBaseV1");
const TaggedHash kNormOpeningHash("Purify/BPPP/NormReduction/OpeningV1");
const TaggedHash kNormFusionHash("Purify/BPPP/NormReduction/FusionV1");
const TaggedHash kOpeningPairHash(
    "Purify/BPPP/OpeningGeneratorPairV2");

constexpr std::uint64_t kReductionOpeningRole = 1;
constexpr std::uint64_t kAccumulationOpeningRole = 2;
constexpr std::size_t kMaxAlgebraicClaims = 1024;
constexpr std::size_t kMaxAlgebraicRounds = 24;
constexpr std::string_view kAlgebraicStepDomain =
    "Purify/BPPP/CandidateAccumStep/v1";
constexpr std::string_view kAlgebraicNormDomain =
    "Purify/BPPP/CandidateNormReduction/v2";

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
        return unexpected_error(
            ErrorCode::InvalidDimensions,
            "accumulation:algebraic_dimension");
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
    return unexpected_error(ErrorCode::InternalMismatch, "accumulation:challenge_exhausted");
}

Status validate_basis(const Basis& basis) {
    std::size_t dimension = 0;
    std::size_t generators = 0;
    if (!is_power_of_two_size(basis.n_vec_len()) ||
        !is_power_of_two_size(basis.l_vec_len()) ||
        basis.l_vec_len() > basis.n_vec_len() ||
        !checked_mul_size(basis.n_vec_len(), 2, dimension) ||
        !checked_add_size(basis.n_vec_len(), basis.l_vec_len(), generators) ||
        basis.dimension() != dimension || basis.norm_generators().size() != generators) {
        return unexpected_error(ErrorCode::InvalidDimensions, "accumulation:basis_shape");
    }
    return {};
}

Status validate_prepared(const Basis& basis, const PreparedNorm& norm) {
    if (norm.basis_digest() != basis.digest()) {
        return unexpected_error(ErrorCode::BindingMismatch, "accumulation:prepared_basis");
    }
    const auto& g = norm.polynomial()[0];
    const auto& h = norm.polynomial()[1];
    if (norm.c_vec().size() != basis.l_vec_len() || g.offset != 0 || h.offset != basis.n_vec_len() ||
        g.factors.size() != log2_dimension(basis.n_vec_len()) ||
        h.factors.size() != log2_dimension(basis.l_vec_len())) {
        return unexpected_error(ErrorCode::InvalidDimensions, "accumulation:prepared_shape");
    }
    return {};
}

Status validate_algebraic_prepared(
    const Basis& basis, const AlgebraicPreparedNorm& norm) {
    PURIFY_RETURN_IF_ERROR(
        validate_algebraic_dimension(basis.dimension()),
        "accumulation:algebraic_prepared_dimension");
    if (norm.basis_digest() != basis.digest()) {
        return unexpected_error(
            ErrorCode::BindingMismatch,
            "accumulation:algebraic_prepared_basis");
    }
    if (norm.prepared_binding().is_zero()) {
        return unexpected_error(
            ErrorCode::RangeViolation,
            "accumulation:algebraic_prepared_binding_zero");
    }
    const auto& g = norm.polynomial()[0];
    const auto& h = norm.polynomial()[1];
    if (norm.c_vec().size() != basis.l_vec_len() ||
        g.offset != 0 || h.offset != basis.n_vec_len() ||
        g.factors.size() != log2_dimension(basis.n_vec_len()) ||
        h.factors.size() != log2_dimension(basis.l_vec_len())) {
        return unexpected_error(
            ErrorCode::InvalidDimensions,
            "accumulation:algebraic_prepared_shape");
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
    candidate::AlgebraicTranscript& transcript, const PointBytes& point) {
    if (purify_bppp_public_point_validate(point.data()) == 0) {
        return unexpected_error(
            ErrorCode::BackendRejectedInput,
            "accumulation:algebraic_point");
    }
    candidate::CoordinateFieldElement::Encoding x{};
    std::copy(point.begin() + 1, point.end(), x.begin());
    PURIFY_ASSIGN_OR_RETURN(
        auto coordinate,
        candidate::CoordinateFieldElement::from_bytes_be(x),
        "accumulation:algebraic_coordinate");
    return transcript.append_point(point[0], coordinate);
}

Status append_algebraic_polynomial(
    candidate::AlgebraicTranscript& transcript,
    std::span<const PolynomialTerm> polynomial) {
    if (!size_fits_u64(polynomial.size())) {
        return unexpected_error(
            ErrorCode::Overflow,
            "accumulation:algebraic_polynomial_size");
    }
    transcript.append_u64(static_cast<std::uint64_t>(polynomial.size()));
    for (const auto& term : polynomial) {
        if (!size_fits_u64(term.offset) ||
            !size_fits_u64(term.factors.size())) {
            return unexpected_error(
                ErrorCode::Overflow,
                "accumulation:algebraic_term_size");
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
        return unexpected_error(ErrorCode::BindingMismatch, "accumulation:claim_basis");
    }
    // A reduced norm has three coupled terms; an accumulated IPA has one.
    if (claim.polynomial().empty() || claim.polynomial().size() > 3) {
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

Result<FieldElement> append_algebraic_challenge(
    candidate::AlgebraicTranscript& transcript, std::uint64_t round) {
    PURIFY_ASSIGN_OR_RETURN(
        auto challenge,
        candidate::select_nonzero_scalar(transcript.challenge(round)),
        "accumulation:algebraic_challenge");
    transcript.append_scalar(challenge);
    return challenge;
}

Result<PointBytes> derive_algebraic_opening_base(
    const Basis& basis, const candidate::AlgebraicTranscript& transcript,
    std::uint64_t role, purify_secp_context* context) {
    if (role != kReductionOpeningRole &&
        role != kAccumulationOpeningRole) {
        return unexpected_error(
            ErrorCode::UnsupportedSymbol,
            "accumulation:opening_role");
    }
    PURIFY_ASSIGN_OR_RETURN(
        auto scalar,
        candidate::select_nonzero_scalar(
            transcript.opening_base_scalar(basis.digest(), role)),
        "accumulation:opening_scalar");

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
            return unexpected_error(
                ErrorCode::BackendRejectedInput,
                "accumulation:opening_pair");
        }
    }
    if (pair[0] == pair[1]) {
        return unexpected_error(
            ErrorCode::InternalMismatch,
            "accumulation:opening_pair_duplicate");
    }
    const std::array<FieldElement, 2> scalars{
        FieldElement::one(), scalar};
    PURIFY_ASSIGN_OR_RETURN(
        auto opening_base, msm(pair, scalars, context),
        "accumulation:opening_pair_msm");
    if (opening_base == PointBytes{}) {
        return unexpected_error(
            ErrorCode::EquationMismatch,
            "accumulation:opening_pair_identity");
    }
    return opening_base;
}

Status validate_root_claim(const Basis& basis, const PendingClaim& claim,
                           purify_secp_context* context) {
    PURIFY_RETURN_IF_ERROR(
        require_secp_context(context, "accumulation:root_claim_context"),
        "accumulation:root_claim_context");
    PURIFY_RETURN_IF_ERROR(validate_claim(basis, claim),
                           "accumulation:root_claim");
    if (claim.polynomial().size() != 1 ||
        claim.polynomial()[0].offset != 0 ||
        claim.polynomial()[0].factors.size() !=
            log2_dimension(basis.dimension())) {
        return unexpected_error(ErrorCode::InvalidDimensions,
                                "accumulation:root_claim_shape");
    }
    const std::array<PointBytes, 1> points{claim.point()};
    const std::array<FieldElement, 1> scalars{FieldElement::zero()};
    PURIFY_ASSIGN_OR_RETURN(
        const auto& identity, msm(points, scalars, context),
        "accumulation:root_claim_point");
    (void)identity;
    return {};
}

template <typename Proof>
Status validate_ipa_encoding(std::size_t dimension, const Proof& proof,
                             purify_secp_context* context) {
    PURIFY_RETURN_IF_ERROR(require_secp_context(context, "accumulation:context"),
                            "accumulation:context");
    if (!is_power_of_two_size(dimension)) {
        return unexpected_error(ErrorCode::InvalidDimensions, "accumulation:ipa_encoding_dimension");
    }
    const auto rounds = log2_dimension(dimension);
    if (proof.left.size() != rounds || proof.right.size() != rounds) {
        return unexpected_error(ErrorCode::SizeMismatch, "accumulation:step_encoding_rounds");
    }
    PURIFY_ASSIGN_OR_RETURN(auto terminal, FieldElement::try_from_bytes32(proof.terminal_scalar),
                            "accumulation:step_encoding_scalar");
    (void)terminal;
    const auto is_canonical_point = [](const PointBytes& point) {
        return purify_bppp_public_point_validate(point.data()) != 0;
    };
    for (std::size_t round = 0; round < rounds; ++round) {
        if (!is_canonical_point(proof.left[round]) ||
            !is_canonical_point(proof.right[round])) {
            return unexpected_error(
                ErrorCode::BackendRejectedInput,
                "accumulation:step_encoding_points");
        }
    }
    if (!is_canonical_point(proof.folded_generator)) {
        return unexpected_error(
            ErrorCode::BackendRejectedInput,
            "accumulation:step_encoding_points");
    }
    return {};
}

template <typename Proof>
void append_ipa(Bytes& out, const Proof& proof) {
    for (std::size_t round = 0; round < proof.left.size(); ++round) {
        append(out, proof.left[round]);
        append(out, proof.right[round]);
    }
    append(out, proof.terminal_scalar);
    append(out, proof.folded_generator);
}

template <typename Proof>
Result<Proof> parse_ipa(std::size_t dimension,
                       std::span<const unsigned char> encoded,
                       purify_secp_context* context) {
    const auto rounds = log2_dimension(dimension);
    if (encoded.size() != 66 * rounds + 65) {
        return unexpected_error(ErrorCode::InvalidFixedSize, "accumulation:parse_ipa_size");
    }
    Proof proof;
    proof.left.resize(rounds);
    proof.right.resize(rounds);
    std::size_t offset = 0;
    for (std::size_t round = 0; round < rounds; ++round) {
        std::copy_n(encoded.data() + offset, 33, proof.left[round].begin());
        offset += 33;
        std::copy_n(encoded.data() + offset, 33, proof.right[round].begin());
        offset += 33;
    }
    std::copy_n(encoded.data() + offset, 32, proof.terminal_scalar.begin());
    offset += 32;
    std::copy_n(encoded.data() + offset, 33, proof.folded_generator.begin());
    PURIFY_RETURN_IF_ERROR(validate_ipa_encoding(dimension, proof, context), "accumulation:parse_ipa");
    return proof;
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
        append_polynomial(encoded, claim.polynomial());
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

struct AlgebraicStepContext {
    FieldElement beta;
    FieldElement x;
    FieldElement y;
    PointBytes commitment;
    PointBytes opening_base;
    candidate::AlgebraicTranscript transcript;
};

Result<AlgebraicStepContext> make_algebraic_step_context(
    const Basis& basis, std::span<const PendingClaim> claims,
    purify_secp_context* context) {
    PURIFY_RETURN_IF_ERROR(
        require_secp_context(context, "accumulation:context"),
        "accumulation:context");
    PURIFY_RETURN_IF_ERROR(
        validate_basis(basis), "accumulation:basis");
    if (claims.empty()) {
        return unexpected_error(
            ErrorCode::EmptyInput, "accumulation:claims");
    }
    const auto rounds = log2_dimension(basis.dimension());
    if (claims.size() > kMaxAlgebraicClaims) {
        return unexpected_error(
            ErrorCode::InvalidDimensions,
            "accumulation:algebraic_step_shape");
    }
    PURIFY_RETURN_IF_ERROR(
        validate_algebraic_dimension(basis.dimension()),
        "accumulation:algebraic_step_shape");
    AlgebraicStepContext out;
    const auto domain = std::span(
        reinterpret_cast<const unsigned char*>(
            kAlgebraicStepDomain.data()),
        kAlgebraicStepDomain.size());
    PURIFY_RETURN_IF_ERROR(
        out.transcript.append_bytes(domain),
        "accumulation:algebraic_step_domain");
    PURIFY_RETURN_IF_ERROR(
        out.transcript.append_bytes(basis.digest()),
        "accumulation:algebraic_step_basis");
    out.transcript.append_u64(
        static_cast<std::uint64_t>(rounds));
    out.transcript.append_u64(
        static_cast<std::uint64_t>(claims.size()));
    for (const auto& claim : claims) {
        PURIFY_RETURN_IF_ERROR(
            validate_claim(basis, claim), "accumulation:claim");
        PURIFY_RETURN_IF_ERROR(
            append_algebraic_point(out.transcript, claim.point()),
            "accumulation:algebraic_claim_point");
        PURIFY_RETURN_IF_ERROR(
            append_algebraic_polynomial(
                out.transcript, claim.polynomial()),
            "accumulation:algebraic_claim_polynomial");
    }

    PURIFY_ASSIGN_OR_RETURN(
        out.beta, append_algebraic_challenge(out.transcript, 0),
        "accumulation:algebraic_batch_challenge");
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
    PURIFY_ASSIGN_OR_RETURN(
        out.commitment, msm(commitments, weights, context),
        "accumulation:algebraic_batch_commitment");
    PURIFY_RETURN_IF_ERROR(
        append_algebraic_point(out.transcript, out.commitment),
        "accumulation:algebraic_commitment");

    PURIFY_ASSIGN_OR_RETURN(
        out.x, append_algebraic_challenge(out.transcript, 1),
        "accumulation:algebraic_evaluation_challenge");
    out.y = FieldElement::zero();
    for (std::size_t i = 0; i < claims.size(); ++i) {
        out.y = out.y +
            weights[i] * evaluate(claims[i].polynomial(), out.x);
    }
    out.transcript.append_scalar(out.y);

    PURIFY_ASSIGN_OR_RETURN(
        out.opening_base,
        derive_algebraic_opening_base(
            basis, out.transcript, kAccumulationOpeningRole,
            context),
        "accumulation:algebraic_opening_base");
    PURIFY_RETURN_IF_ERROR(
        append_algebraic_point(out.transcript, out.opening_base),
        "accumulation:algebraic_opening_point");
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

template <typename Proof, typename RoundChallenge>
Result<Proof> prove_ipa_with_challenges(
    std::span<const PointBytes> basis, std::vector<FieldElement> a,
    const PolynomialTerm& weights, const PointBytes& opening_base,
    RoundChallenge&& round_challenge, purify_secp_context* context) {
    assert(a.size() == basis.size() && is_power_of_two_size(a.size()));
    assert(weights.offset == 0 && weights.factors.size() == log2_dimension(a.size()));
    std::vector<FieldElement> b(a.size(), FieldElement::zero());
    const std::array<PolynomialTerm, 1> tensor{weights};
    add_coefficients(b, tensor, FieldElement::one());
    std::vector<PointBytes> generators(basis.begin(), basis.end());
    Proof proof;
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
        PURIFY_ASSIGN_OR_RETURN(auto t,
                                round_challenge(round, left, right),
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

Result<StepProof> prove_ipa(
    std::span<const PointBytes> basis, std::vector<FieldElement> a,
    const PolynomialTerm& weights, const PointBytes& opening_base,
    Digest transcript, purify_secp_context* context) {
    return prove_ipa_with_challenges<StepProof>(
        basis, std::move(a), weights, opening_base,
        [&transcript](std::size_t round, const PointBytes& left,
                      const PointBytes& right) {
            return round_challenge(transcript, round, left, right);
        },
        context);
}

struct IpaVerification {
    PolynomialTerm folded;
    PointBytes residual;
};

template <typename Proof, typename RoundChallenge>
Result<IpaVerification> evaluate_ipa_with_challenges(
    std::size_t dimension, const Proof& proof,
    const PolynomialTerm& weights, const PointBytes& commitment,
    const FieldElement& evaluation, const PointBytes& opening_base,
    RoundChallenge&& round_challenge, purify_secp_context* context) {
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
        PURIFY_ASSIGN_OR_RETURN(auto t,
                                round_challenge(round, proof.left[round],
                                                proof.right[round]),
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
    return IpaVerification{std::move(folded), residual};
}

template <typename Proof, typename RoundChallenge>
Result<PolynomialTerm> verify_ipa_with_challenges(
    std::size_t dimension, const Proof& proof,
    const PolynomialTerm& weights, const PointBytes& commitment,
    const FieldElement& evaluation, const PointBytes& opening_base,
    RoundChallenge&& round_challenge, purify_secp_context* context) {
    PURIFY_ASSIGN_OR_RETURN(
        auto verified,
        evaluate_ipa_with_challenges(
            dimension, proof, weights, commitment, evaluation,
            opening_base, std::forward<RoundChallenge>(round_challenge),
            context),
        "accumulation:evaluate_ipa");
    if (verified.residual != PointBytes{}) {
        return unexpected_error(
            ErrorCode::EquationMismatch, "accumulation:step_equation");
    }
    return std::move(verified.folded);
}

Result<PolynomialTerm> verify_ipa(
    std::size_t dimension, const StepProof& proof,
    const PolynomialTerm& weights, const PointBytes& commitment,
    const FieldElement& evaluation, const PointBytes& opening_base,
    Digest transcript, purify_secp_context* context) {
    return verify_ipa_with_challenges(
        dimension, proof, weights, commitment, evaluation, opening_base,
        [&transcript](std::size_t round, const PointBytes& left,
                      const PointBytes& right) {
            return round_challenge(transcript, round, left, right);
        },
        context);
}

Result<AlgebraicStepProof> prove_algebraic_ipa(
    std::span<const PointBytes> basis, std::vector<FieldElement> a,
    const PolynomialTerm& weights, const PointBytes& opening_base,
    candidate::AlgebraicTranscript& transcript,
    std::uint64_t first_round, purify_secp_context* context) {
    return prove_ipa_with_challenges<AlgebraicStepProof>(
        basis, std::move(a), weights, opening_base,
        [&transcript, first_round](
            std::size_t round, const PointBytes& left,
            const PointBytes& right) -> Result<FieldElement> {
            PURIFY_RETURN_IF_ERROR(
                append_algebraic_point(transcript, left),
                "accumulation:algebraic_left");
            PURIFY_RETURN_IF_ERROR(
                append_algebraic_point(transcript, right),
                "accumulation:algebraic_right");
            return append_algebraic_challenge(
                transcript,
                first_round + static_cast<std::uint64_t>(round));
        },
        context);
}

Result<IpaVerification> evaluate_algebraic_ipa(
    std::size_t dimension, const AlgebraicStepProof& proof,
    const PolynomialTerm& weights, const PointBytes& commitment,
    const FieldElement& evaluation, const PointBytes& opening_base,
    candidate::AlgebraicTranscript& transcript,
    std::uint64_t first_round, purify_secp_context* context) {
    return evaluate_ipa_with_challenges(
        dimension, proof, weights, commitment, evaluation, opening_base,
        [&transcript, first_round](
            std::size_t round, const PointBytes& left,
            const PointBytes& right) -> Result<FieldElement> {
            PURIFY_RETURN_IF_ERROR(
                append_algebraic_point(transcript, left),
                "accumulation:algebraic_left");
            PURIFY_RETURN_IF_ERROR(
                append_algebraic_point(transcript, right),
                "accumulation:algebraic_right");
            return append_algebraic_challenge(
                transcript,
                first_round + static_cast<std::uint64_t>(round));
        },
        context);
}

Result<PolynomialTerm> verify_algebraic_ipa(
    std::size_t dimension, const AlgebraicStepProof& proof,
    const PolynomialTerm& weights, const PointBytes& commitment,
    const FieldElement& evaluation, const PointBytes& opening_base,
    candidate::AlgebraicTranscript& transcript,
    std::uint64_t first_round, purify_secp_context* context) {
    PURIFY_ASSIGN_OR_RETURN(
        auto verified,
        evaluate_algebraic_ipa(
            dimension, proof, weights, commitment, evaluation,
            opening_base, transcript, first_round, context),
        "accumulation:evaluate_algebraic_ipa");
    if (verified.residual != PointBytes{}) {
        return unexpected_error(
            ErrorCode::EquationMismatch, "accumulation:step_equation");
    }
    return std::move(verified.folded);
}

struct NormOpeningContext {
    FieldElement evaluation;
    PolynomialTerm weights;
    PointBytes opening_base;
    Digest transcript;
};

Result<NormOpeningContext> make_norm_context(const Basis& basis, const PreparedNorm& norm,
                                            const ScalarBytes& evaluation,
                                            purify_secp_context* context) {
    PURIFY_RETURN_IF_ERROR(require_secp_context(context, "accumulation:context"), "accumulation:context");
    PURIFY_RETURN_IF_ERROR(validate_basis(basis), "accumulation:basis");
    PURIFY_RETURN_IF_ERROR(validate_prepared(basis, norm), "accumulation:prepared");
    NormOpeningContext out;
    PURIFY_ASSIGN_OR_RETURN(out.evaluation, FieldElement::try_from_bytes32(evaluation),
                            "accumulation:coefficient_evaluation");
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
        return unexpected_error(ErrorCode::BackendRejectedInput, "accumulation:coefficient_opening_base");
    }
    append(encoded, out.opening_base);
    out.transcript = kNormOpeningHash.digest(encoded);
    return out;
}

struct AlgebraicNormOpeningContext {
    FieldElement evaluation;
    PolynomialTerm weights;
    PointBytes opening_base;
    candidate::AlgebraicTranscript transcript;
};

Result<AlgebraicNormOpeningContext> make_algebraic_norm_context(
    const Basis& basis, const AlgebraicPreparedNorm& norm,
    const ScalarBytes& evaluation, purify_secp_context* context) {
    PURIFY_RETURN_IF_ERROR(
        require_secp_context(context, "accumulation:context"),
        "accumulation:context");
    PURIFY_RETURN_IF_ERROR(
        validate_basis(basis), "accumulation:basis");
    PURIFY_RETURN_IF_ERROR(
        validate_algebraic_prepared(basis, norm),
        "accumulation:algebraic_prepared");

    AlgebraicNormOpeningContext out;
    const auto rounds = log2_dimension(basis.l_vec_len());
    PURIFY_RETURN_IF_ERROR(
        validate_algebraic_dimension(basis.l_vec_len()),
        "accumulation:algebraic_norm_shape");
    PURIFY_ASSIGN_OR_RETURN(
        out.evaluation,
        FieldElement::try_from_bytes32(evaluation),
        "accumulation:coefficient_evaluation");
    out.weights = PolynomialTerm{
        FieldElement::one(), 0,
        norm.polynomial()[1].factors};

    const auto domain = std::span(
        reinterpret_cast<const unsigned char*>(
            kAlgebraicNormDomain.data()),
        kAlgebraicNormDomain.size());
    PURIFY_RETURN_IF_ERROR(
        out.transcript.append_bytes(domain),
        "accumulation:algebraic_norm_domain");
    PURIFY_RETURN_IF_ERROR(
        out.transcript.append_bytes(basis.digest()),
        "accumulation:algebraic_norm_basis");
    out.transcript.append_u64(
        static_cast<std::uint64_t>(rounds));
    out.transcript.append_scalar(norm.prepared_binding());
    PURIFY_RETURN_IF_ERROR(
        append_algebraic_point(
            out.transcript, norm.coefficient_commitment()),
        "accumulation:algebraic_norm_commitment");
    const std::array<PolynomialTerm, 1> weights{out.weights};
    PURIFY_RETURN_IF_ERROR(
        append_algebraic_polynomial(out.transcript, weights),
        "accumulation:algebraic_norm_weights");
    out.transcript.append_scalar(out.evaluation);

    PURIFY_ASSIGN_OR_RETURN(
        out.opening_base,
        derive_algebraic_opening_base(
            basis, out.transcript, kReductionOpeningRole,
            context),
        "accumulation:algebraic_norm_opening_base");
    PURIFY_RETURN_IF_ERROR(
        append_algebraic_point(out.transcript, out.opening_base),
        "accumulation:algebraic_norm_opening_point");
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
        return unexpected_error(ErrorCode::BindingMismatch,
                                "accumulation:circuit_raw_basis");
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
        return unexpected_error(ErrorCode::BackendRejectedInput,
                                "accumulation:circuit_inner_norm");
    }

    PURIFY_ASSIGN_OR_RETURN(
        const auto& n, FieldElement::try_from_bytes32(n_bytes),
        "accumulation:circuit_norm_n");
    PURIFY_ASSIGN_OR_RETURN(
        const auto& l, FieldElement::try_from_bytes32(l_bytes),
        "accumulation:circuit_norm_l");
    PURIFY_ASSIGN_OR_RETURN(
        const auto& rho, FieldElement::try_from_bytes32(norm.rho),
        "accumulation:circuit_norm_rho");
    PURIFY_ASSIGN_OR_RETURN(
        const auto& sqrt_minus_one,
        detail::canonical_sqrt_minus_one(),
        "accumulation:circuit_sqrt_minus_one");

    PolynomialTerm g{
        n * pow_size(rho, basis.n_vec_len()) *
            prepared.mul_scale.inverse(),
        0,
        {}};
    PolynomialTerm h{l, basis.n_vec_len(), {}};
    const auto h_rounds = log2_dimension(basis.l_vec_len());
    auto ratio_inv_power = prepared.mul_ratio.inverse();
    for (std::size_t j = 0; j < rounds; ++j) {
        PURIFY_ASSIGN_OR_RETURN(
            const auto& gamma, FieldElement::try_from_bytes32(gammas[j]),
            "accumulation:circuit_norm_gamma");
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
        PURIFY_ASSIGN_OR_RETURN(
            const auto& coefficient,
            FieldElement::try_from_bytes32(encoded),
            "accumulation:circuit_norm_coefficient");
        coefficients.push_back(coefficient);
    }
    const auto h_basis = std::span(basis.points())
                             .subspan(basis.n_vec_len(),
                                      basis.l_vec_len());
    PURIFY_ASSIGN_OR_RETURN(
        auto coefficient_commitment,
        msm(h_basis, coefficients, context),
        "accumulation:circuit_coefficient_commitment");

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

Result<Basis> Basis::create(std::size_t n_vec_len, std::size_t l_vec_len,
                            std::string_view semantic_domain, purify_secp_context* context) {
    PURIFY_RETURN_IF_ERROR(require_secp_context(context, "accumulation:context"),
                            "accumulation:context");
    std::size_t dimension = 0;
    if (!is_power_of_two_size(n_vec_len) || !is_power_of_two_size(l_vec_len) ||
        l_vec_len > n_vec_len || !checked_mul_size(n_vec_len, 2, dimension)) {
        return unexpected_error(ErrorCode::InvalidDimensions, "accumulation:create_basis_shape");
    }
    if (semantic_domain.empty()) {
        return unexpected_error(ErrorCode::EmptyInput, "accumulation:basis_semantic_domain");
    }
    Basis out;
    out.n_vec_len_ = n_vec_len;
    out.l_vec_len_ = l_vec_len;
    PURIFY_ASSIGN_OR_RETURN(auto generators, create_generators(dimension, context),
                            "accumulation:deterministic_generators");
    out.points_.resize(dimension);
    if (purify_bppp_generators_to_points(context,
            reinterpret_cast<const unsigned char*>(generators.data()), generators.size(),
            reinterpret_cast<unsigned char*>(out.points_.data())) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput, "accumulation:raw_basis");
    }
    generators.resize(n_vec_len + l_vec_len);
    out.norm_generators_ = std::move(generators);
    Bytes encoded;
    append_size(encoded, semantic_domain.size());
    append(encoded, std::span(reinterpret_cast<const unsigned char*>(semantic_domain.data()),
                             semantic_domain.size()));
    append_size(encoded, n_vec_len);
    append_size(encoded, l_vec_len);
    for (const auto& point : out.points_) append(encoded, point);
    out.digest_ = kBasisHash.digest(encoded);
    return out;
}

Result<Bytes> serialize_step(const Basis& basis, const StepProof& proof,
                             purify_secp_context* context) {
    PURIFY_RETURN_IF_ERROR(validate_basis(basis), "accumulation:basis");
    PURIFY_RETURN_IF_ERROR(validate_ipa_encoding(basis.dimension(), proof, context),
                            "accumulation:serialize_step");
    Bytes out;
    out.reserve(66 * log2_dimension(basis.dimension()) + 66);
    out.push_back(1);
    append_ipa(out, proof);
    return out;
}

Result<StepProof> parse_step(const Basis& basis, std::span<const unsigned char> encoded,
                             purify_secp_context* context) {
    PURIFY_RETURN_IF_ERROR(require_secp_context(context, "accumulation:context"), "accumulation:context");
    PURIFY_RETURN_IF_ERROR(validate_basis(basis), "accumulation:basis");
    if (encoded.size() != 66 * log2_dimension(basis.dimension()) + 66) {
        return unexpected_error(ErrorCode::InvalidFixedSize, "accumulation:parse_step_size");
    }
    if (encoded[0] != 1) {
        return unexpected_error(ErrorCode::UnsupportedSymbol, "accumulation:parse_step_version");
    }
    return parse_ipa<StepProof>(
        basis.dimension(), encoded.subspan(1), context);
}

Result<Bytes> serialize_algebraic_step(
    const Basis& basis, const AlgebraicStepProof& proof,
    purify_secp_context* context) {
    PURIFY_RETURN_IF_ERROR(
        validate_basis(basis), "accumulation:basis");
    PURIFY_RETURN_IF_ERROR(
        validate_algebraic_dimension(basis.dimension()),
        "accumulation:algebraic_step_dimension");
    PURIFY_RETURN_IF_ERROR(
        validate_ipa_encoding(
            basis.dimension(), proof, context),
        "accumulation:serialize_algebraic_step");
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
    PURIFY_RETURN_IF_ERROR(
        require_secp_context(context, "accumulation:context"),
        "accumulation:context");
    PURIFY_RETURN_IF_ERROR(
        validate_basis(basis), "accumulation:basis");
    PURIFY_RETURN_IF_ERROR(
        validate_algebraic_dimension(basis.dimension()),
        "accumulation:algebraic_step_dimension");
    if (encoded.size() !=
        66 * log2_dimension(basis.dimension()) + 66) {
        return unexpected_error(
            ErrorCode::InvalidFixedSize,
            "accumulation:parse_algebraic_step_size");
    }
    if (encoded[0] != 2) {
        return unexpected_error(
            ErrorCode::UnsupportedSymbol,
            "accumulation:parse_algebraic_step_version");
    }
    return parse_ipa<AlgebraicStepProof>(
        basis.dimension(), encoded.subspan(1), context);
}

Result<Bytes> serialize_root_claim(const Basis& basis,
                                   const PendingClaim& claim,
                                   purify_secp_context* context) {
    PURIFY_RETURN_IF_ERROR(validate_basis(basis), "accumulation:basis");
    PURIFY_RETURN_IF_ERROR(
        validate_root_claim(basis, claim, context),
        "accumulation:serialize_root_claim");
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
    PURIFY_RETURN_IF_ERROR(validate_basis(basis), "accumulation:basis");
    const auto factor_count = log2_dimension(basis.dimension());
    if (encoded.size() != 65 + 32 * factor_count) {
        return unexpected_error(ErrorCode::InvalidFixedSize,
                                "accumulation:parse_root_claim_size");
    }

    PointBytes point{};
    std::copy_n(encoded.begin(), point.size(), point.begin());
    ScalarBytes scalar{};
    std::copy_n(encoded.begin() + static_cast<std::ptrdiff_t>(point.size()),
                scalar.size(), scalar.begin());
    PURIFY_ASSIGN_OR_RETURN(
        auto scale, FieldElement::try_from_bytes32(scalar),
        "accumulation:parse_root_claim_scale");
    std::vector<FieldElement> factors;
    factors.reserve(factor_count);
    std::size_t offset = point.size() + scalar.size();
    for (std::size_t i = 0; i < factor_count; ++i) {
        std::copy_n(encoded.begin() + static_cast<std::ptrdiff_t>(offset),
                    scalar.size(), scalar.begin());
        offset += scalar.size();
        PURIFY_ASSIGN_OR_RETURN(
            auto factor, FieldElement::try_from_bytes32(scalar),
            "accumulation:parse_root_claim_factor");
        factors.push_back(factor);
    }
    PendingClaim out(basis.digest(), point,
                     {PolynomialTerm{scale, 0, std::move(factors)}});
    PURIFY_RETURN_IF_ERROR(
        validate_root_claim(basis, out, context),
        "accumulation:parse_root_claim");
    return out;
}

Result<Bytes> serialize_norm_reduction(const Basis& basis, const NormReductionProof& proof,
                                       purify_secp_context* context) {
    PURIFY_RETURN_IF_ERROR(validate_basis(basis), "accumulation:basis");
    PURIFY_ASSIGN_OR_RETURN(auto evaluation, FieldElement::try_from_bytes32(proof.coefficient_evaluation),
                            "accumulation:serialize_reduction_evaluation");
    (void)evaluation;
    PURIFY_RETURN_IF_ERROR(validate_ipa_encoding(basis.l_vec_len(), proof.coefficient_opening, context),
                            "accumulation:serialize_reduction");
    Bytes out;
    out.reserve(66 * log2_dimension(basis.l_vec_len()) + 98);
    out.push_back(1);
    append(out, proof.coefficient_evaluation);
    append_ipa(out, proof.coefficient_opening);
    return out;
}

Result<NormReductionProof> parse_norm_reduction(const Basis& basis, std::span<const unsigned char> encoded,
                                               purify_secp_context* context) {
    PURIFY_RETURN_IF_ERROR(require_secp_context(context, "accumulation:context"), "accumulation:context");
    PURIFY_RETURN_IF_ERROR(validate_basis(basis), "accumulation:basis");
    if (encoded.size() != 66 * log2_dimension(basis.l_vec_len()) + 98) {
        return unexpected_error(ErrorCode::InvalidFixedSize, "accumulation:parse_reduction_size");
    }
    if (encoded[0] != 1) {
        return unexpected_error(ErrorCode::UnsupportedSymbol, "accumulation:parse_reduction_version");
    }
    NormReductionProof proof;
    std::copy_n(encoded.data() + 1, 32, proof.coefficient_evaluation.begin());
    PURIFY_ASSIGN_OR_RETURN(auto evaluation, FieldElement::try_from_bytes32(proof.coefficient_evaluation),
                            "accumulation:parse_reduction_evaluation");
    (void)evaluation;
    PURIFY_ASSIGN_OR_RETURN(proof.coefficient_opening,
        parse_ipa<StepProof>(basis.l_vec_len(), encoded.subspan(33),
                             context),
        "accumulation:parse_reduction_ipa");
    return proof;
}

Result<Bytes> serialize_algebraic_norm_reduction(
    const Basis& basis,
    const AlgebraicNormReductionProof& proof,
    purify_secp_context* context) {
    PURIFY_RETURN_IF_ERROR(
        validate_basis(basis), "accumulation:basis");
    PURIFY_RETURN_IF_ERROR(
        validate_algebraic_dimension(basis.dimension()),
        "accumulation:algebraic_reduction_dimension");
    PURIFY_RETURN_IF_ERROR(
        validate_algebraic_dimension(basis.l_vec_len()),
        "accumulation:algebraic_reduction_dimension");
    PURIFY_ASSIGN_OR_RETURN(
        auto evaluation,
        FieldElement::try_from_bytes32(
            proof.coefficient_evaluation),
        "accumulation:serialize_algebraic_evaluation");
    (void)evaluation;
    PURIFY_RETURN_IF_ERROR(
        validate_ipa_encoding(
            basis.l_vec_len(), proof.coefficient_opening,
            context),
        "accumulation:serialize_algebraic_reduction");
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
    PURIFY_RETURN_IF_ERROR(
        require_secp_context(context, "accumulation:context"),
        "accumulation:context");
    PURIFY_RETURN_IF_ERROR(
        validate_basis(basis), "accumulation:basis");
    PURIFY_RETURN_IF_ERROR(
        validate_algebraic_dimension(basis.dimension()),
        "accumulation:algebraic_reduction_dimension");
    PURIFY_RETURN_IF_ERROR(
        validate_algebraic_dimension(basis.l_vec_len()),
        "accumulation:algebraic_reduction_dimension");
    if (encoded.size() !=
        66 * log2_dimension(basis.l_vec_len()) + 98) {
        return unexpected_error(
            ErrorCode::InvalidFixedSize,
            "accumulation:parse_algebraic_reduction_size");
    }
    if (encoded[0] != 2) {
        return unexpected_error(
            ErrorCode::UnsupportedSymbol,
            "accumulation:parse_algebraic_reduction_version");
    }
    AlgebraicNormReductionProof proof;
    std::copy_n(
        encoded.data() + 1, 32,
        proof.coefficient_evaluation.begin());
    PURIFY_ASSIGN_OR_RETURN(
        auto evaluation,
        FieldElement::try_from_bytes32(
            proof.coefficient_evaluation),
        "accumulation:parse_algebraic_evaluation");
    (void)evaluation;
    PURIFY_ASSIGN_OR_RETURN(
        proof.coefficient_opening,
        parse_ipa<AlgebraicStepProof>(
            basis.l_vec_len(), encoded.subspan(33), context),
        "accumulation:parse_algebraic_reduction_ipa");
    return proof;
}

Result<PreparedNorm> prepare_norm(const Basis& basis, const NormArgProof& proof,
                                  purify_secp_context* context) {
    PURIFY_RETURN_IF_ERROR(require_secp_context(context, "accumulation:context"),
                            "accumulation:context");
    PURIFY_RETURN_IF_ERROR(validate_basis(basis), "accumulation:basis");
    if (proof.n_vec_len != basis.n_vec_len() || proof.c_vec.size() != basis.l_vec_len() ||
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
    const auto h_rounds = log2_dimension(basis.l_vec_len());
    for (std::size_t j = 0; j < rounds; ++j) {
        PURIFY_ASSIGN_OR_RETURN(auto gamma, FieldElement::try_from_bytes32(gammas[j]),
                                "accumulation:norm_gamma");
        g.factors.push_back(gamma * rho_inv_power);
        if (j < h_rounds) h.factors.push_back(gamma);
        rho_inv_power = rho_inv_power * rho_inv_power;
    }
    std::vector<FieldElement> coefficients;
    coefficients.reserve(proof.c_vec.size());
    for (const auto& encoded : proof.c_vec) {
        PURIFY_ASSIGN_OR_RETURN(auto coefficient, FieldElement::try_from_bytes32(encoded),
                                "accumulation:norm_coefficient");
        coefficients.push_back(coefficient);
    }
    const auto h_basis = std::span(basis.points()).subspan(basis.n_vec_len(), basis.l_vec_len());
    PURIFY_ASSIGN_OR_RETURN(auto commitment, msm(h_basis, coefficients, context),
                            "accumulation:coefficient_commitment");
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
    PURIFY_RETURN_IF_ERROR(
        require_secp_context(context, "accumulation:circuit_context"),
        "accumulation:circuit_context");
    PURIFY_RETURN_IF_ERROR(validate_basis(basis),
                           "accumulation:circuit_basis");
    PURIFY_ASSIGN_OR_RETURN(
        auto prepared,
        detail::prepare_experimental_circuit_zk_norm_arg(
            circuit, proof, context, statement_binding, cache),
        "accumulation:circuit_prepare");
    if (!prepared.has_value()) {
        return unexpected_error(ErrorCode::EquationMismatch,
                                "accumulation:circuit_zero_dlog");
    }
    PURIFY_ASSIGN_OR_RETURN(
        auto components,
        prepare_circuit_norm_components(
            basis, *prepared, proof, {}, context, statement_binding),
        "accumulation:circuit_components");
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
    PURIFY_RETURN_IF_ERROR(
        require_secp_context(context, "accumulation:circuit_context"),
        "accumulation:circuit_context");
    PURIFY_RETURN_IF_ERROR(validate_basis(basis),
                           "accumulation:circuit_basis");
    PURIFY_ASSIGN_OR_RETURN(
        auto prepared,
        detail::prepare_experimental_circuit_zk_norm_arg_with_public_commitments(
            circuit, proof, public_commitments, context, statement_binding,
            cache),
        "accumulation:circuit_prepare");
    if (!prepared.has_value()) {
        return unexpected_error(ErrorCode::EquationMismatch,
                                "accumulation:circuit_public_dlog");
    }
    PURIFY_ASSIGN_OR_RETURN(
        auto components,
        prepare_circuit_norm_components(
            basis, *prepared, proof, public_commitments, context,
            statement_binding),
        "accumulation:circuit_components");
    return PreparedNorm(
        basis.digest(), components.transcript_digest,
        std::move(components.c_vec), components.coefficient_commitment,
        components.residual, std::move(components.polynomial));
}

Result<AlgebraicPreparedNorm>
prepare_v4_circuit_norm_for_algebraic_reduction(
    const Basis& basis, candidate::PreparedCircuitZkNormArgV4 prepared,
    purify_secp_context* context) {
    PURIFY_RETURN_IF_ERROR(
        require_secp_context(context, "accumulation:v4_context"),
        "accumulation:v4_context");
    PURIFY_RETURN_IF_ERROR(
        validate_basis(basis), "accumulation:v4_basis");
    PURIFY_RETURN_IF_ERROR(
        validate_algebraic_dimension(basis.dimension()),
        "accumulation:v4_dimension");

    const auto& shape = prepared.shape();
    const auto& transcript_input = prepared.transcript_input();
    const auto& transcript = prepared.transcript();
    const auto& norm = prepared.norm();
    const auto rounds = shape.round_count();
    std::size_t generator_count = 0;
    if (!checked_add_size(shape.n_vec_len(), shape.l_vec_len(),
                          generator_count)) {
        return unexpected_error(
            ErrorCode::Overflow,
            "accumulation:v4_generator_count");
    }
    // The V4 transcript binds this raw digest. Exact generator equality
    // bridges it to the purpose owner's selected semantic basis.
    if (shape.n_vec_len() != basis.n_vec_len() ||
        shape.l_vec_len() != basis.l_vec_len() ||
        prepared.raw_generators().size() != generator_count ||
        prepared.raw_generators() != basis.norm_generators()) {
        return unexpected_error(
            ErrorCode::BindingMismatch,
            "accumulation:v4_raw_basis");
    }
    const auto raw_generator_digest =
        generator_digest(prepared.raw_generators());
    if (transcript_input.raw_generator_digest != raw_generator_digest ||
        generator_digest(basis.norm_generators()) != raw_generator_digest) {
        return unexpected_error(
            ErrorCode::BindingMismatch,
            "accumulation:v4_raw_basis_digest");
    }
    if (norm.n_vec_len != shape.n_vec_len() ||
        norm.generators.size() != generator_count ||
        norm.c_vec.size() != shape.l_vec_len() ||
        norm.rho != transcript.rho.scalar.to_bytes_be() ||
        norm.commitment != transcript_input.combined_commitment ||
        transcript_input.rounds.size() != rounds ||
        transcript.gammas.size() != rounds) {
        return unexpected_error(
            ErrorCode::InternalMismatch,
            "accumulation:v4_prepared_shape");
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
        return unexpected_error(
            ErrorCode::InternalMismatch,
            "accumulation:v4_zero_challenge");
    }
    PURIFY_ASSIGN_OR_RETURN(
        const auto& sqrt_minus_one,
        detail::canonical_sqrt_minus_one(),
        "accumulation:v4_sqrt_minus_one");

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
            return unexpected_error(
                ErrorCode::BackendRejectedInput,
                "accumulation:v4_scale_generator");
        }
        if (norm.generators[i] != expected_generator) {
            return unexpected_error(
                ErrorCode::InternalMismatch,
                "accumulation:v4_scaled_basis");
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
        return unexpected_error(
            ErrorCode::InternalMismatch,
            "accumulation:v4_linear_basis");
    }

    std::size_t round_bytes = 0;
    std::size_t expected_proof_size = 0;
    if (!checked_mul_size(rounds,
                          sizeof(candidate::PackedPointPairV4),
                          round_bytes) ||
        !checked_add_size(round_bytes, 2 * sizeof(ScalarBytes),
                          expected_proof_size)) {
        return unexpected_error(
            ErrorCode::Overflow,
            "accumulation:v4_proof_size");
    }
    if (norm.proof.size() != expected_proof_size) {
        return unexpected_error(
            ErrorCode::InternalMismatch,
            "accumulation:v4_proof_size");
    }
    for (std::size_t i = 0; i < rounds; ++i) {
        const auto offset = i * sizeof(candidate::PackedPointPairV4);
        if (!std::equal(
                transcript_input.rounds[i].begin(),
                transcript_input.rounds[i].end(),
                norm.proof.begin() +
                    static_cast<std::ptrdiff_t>(offset))) {
            return unexpected_error(
                ErrorCode::InternalMismatch,
                "accumulation:v4_round_payload");
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
        return unexpected_error(
            ErrorCode::InternalMismatch,
            "accumulation:v4_terminal_payload");
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
        return unexpected_error(
            ErrorCode::BackendRejectedInput,
            "accumulation:v4_inner_norm");
    }
    if (terminal_n_bytes != transcript_input.terminal_n ||
        terminal_l_bytes != transcript_input.terminal_l ||
        residual != prepared.pending_norm_residual()) {
        return unexpected_error(
            ErrorCode::InternalMismatch,
            "accumulation:v4_prepared_norm");
    }

    PURIFY_ASSIGN_OR_RETURN(
        const auto& terminal_n,
        FieldElement::try_from_bytes32(terminal_n_bytes),
        "accumulation:v4_terminal_n");
    PURIFY_ASSIGN_OR_RETURN(
        const auto& terminal_l,
        FieldElement::try_from_bytes32(terminal_l_bytes),
        "accumulation:v4_terminal_l");
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
        PURIFY_ASSIGN_OR_RETURN(
            auto coefficient,
            FieldElement::try_from_bytes32(encoded),
            "accumulation:v4_coefficient");
        coefficients.push_back(std::move(coefficient));
    }
    const auto coefficient_basis =
        std::span(basis.points())
            .subspan(basis.n_vec_len(), basis.l_vec_len());
    PURIFY_ASSIGN_OR_RETURN(
        const auto coefficient_commitment,
        msm(coefficient_basis, coefficients, context),
        "accumulation:v4_coefficient_commitment");
    if (coefficient_commitment !=
        transcript_input.coefficient_commitment) {
        return unexpected_error(
            ErrorCode::InternalMismatch,
            "accumulation:v4_coefficient_binding");
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
    PURIFY_RETURN_IF_ERROR(require_secp_context(context, "accumulation:context"), "accumulation:context");
    PURIFY_RETURN_IF_ERROR(validate_basis(basis), "accumulation:basis");
    PURIFY_RETURN_IF_ERROR(validate_prepared(basis, norm), "accumulation:prepared");
    std::vector<FieldElement> coefficients;
    coefficients.reserve(norm.c_vec().size());
    for (const auto& encoded : norm.c_vec()) {
        PURIFY_ASSIGN_OR_RETURN(auto coefficient, FieldElement::try_from_bytes32(encoded),
                                "accumulation:coefficient_scalar");
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
    PURIFY_ASSIGN_OR_RETURN(auto state, make_norm_context(basis, norm, proof.coefficient_evaluation, context),
                            "accumulation:prove_reduction_context");
    const auto h_basis = std::span(basis.points()).subspan(basis.n_vec_len(), basis.l_vec_len());
    PURIFY_ASSIGN_OR_RETURN(proof.coefficient_opening,
        prove_ipa(h_basis, std::move(coefficients), state.weights, state.opening_base,
                  state.transcript, context), "accumulation:prove_coefficient_ipa");
    // This checks only the short reduction, never accepts the original norm.
    PURIFY_ASSIGN_OR_RETURN(auto pending, verify_norm_reduction(basis, norm, proof, context),
                            "accumulation:prove_reduction_check");
    (void)pending;
    return proof;
}

Result<PendingClaim> verify_norm_reduction(const Basis& basis, const PreparedNorm& norm,
                                          const NormReductionProof& proof, purify_secp_context* context) {
    PURIFY_RETURN_IF_ERROR(validate_basis(basis), "accumulation:basis");
    PURIFY_RETURN_IF_ERROR(validate_prepared(basis, norm), "accumulation:prepared");
    const auto rounds = log2_dimension(basis.l_vec_len());
    const auto& opening = proof.coefficient_opening;
    if (opening.left.size() != rounds || opening.right.size() != rounds) {
        return unexpected_error(ErrorCode::SizeMismatch, "accumulation:reduction_rounds");
    }
    PURIFY_ASSIGN_OR_RETURN(auto terminal, FieldElement::try_from_bytes32(opening.terminal_scalar),
                            "accumulation:reduction_terminal");
    (void)terminal;
    PURIFY_ASSIGN_OR_RETURN(auto state, make_norm_context(basis, norm, proof.coefficient_evaluation, context),
                            "accumulation:verify_reduction_context");
    PURIFY_ASSIGN_OR_RETURN(auto folded,
        verify_ipa(basis.l_vec_len(), opening, state.weights, norm.coefficient_commitment(),
                   state.evaluation, state.opening_base, state.transcript, context),
        "accumulation:verify_coefficient_ipa");
    folded.offset = basis.n_vec_len();

    const auto generator_encoding = base_generator(context);
    PointBytes generator{};
    if (purify_bppp_generators_to_points(context, generator_encoding.data(), 1, generator.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput, "accumulation:standard_generator");
    }
    const std::array<PointBytes, 2> norm_points{norm.residual(), generator};
    const std::array<FieldElement, 2> norm_scalars{
        FieldElement::one(), (norm.polynomial()[1].scale * state.evaluation).negate()};
    PURIFY_ASSIGN_OR_RETURN(auto norm_point, msm(norm_points, norm_scalars, context),
                            "accumulation:unshifted_norm_claim");

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
    PURIFY_ASSIGN_OR_RETURN(auto chi, challenge(kNormFusionHash, encoded), "accumulation:reduction_fusion");
    const std::array<PointBytes, 2> fusion_points{norm_point, opening.folded_generator};
    const std::array<FieldElement, 2> fusion_scalars{FieldElement::one(), chi};
    PURIFY_ASSIGN_OR_RETURN(auto combined_point, msm(fusion_points, fusion_scalars, context),
                            "accumulation:combined_reduction_claim");
    std::vector<PolynomialTerm> polynomial(norm.polynomial().begin(), norm.polynomial().end());
    folded.scale = folded.scale * chi;
    polynomial.push_back(std::move(folded));
    return PendingClaim(basis.digest(), combined_point, std::move(polynomial));
}

Result<AlgebraicNormReductionProof>
prove_algebraic_norm_reduction(
    const Basis& basis, const AlgebraicPreparedNorm& norm,
    purify_secp_context* context) {
    PURIFY_RETURN_IF_ERROR(
        require_secp_context(context, "accumulation:context"),
        "accumulation:context");
    PURIFY_RETURN_IF_ERROR(
        validate_basis(basis), "accumulation:basis");
    PURIFY_RETURN_IF_ERROR(
        validate_algebraic_prepared(basis, norm),
        "accumulation:algebraic_prepared");

    std::vector<FieldElement> coefficients;
    coefficients.reserve(norm.c_vec().size());
    for (const auto& encoded : norm.c_vec()) {
        PURIFY_ASSIGN_OR_RETURN(
            auto coefficient,
            FieldElement::try_from_bytes32(encoded),
            "accumulation:algebraic_coefficient_scalar");
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
        auto state,
        make_algebraic_norm_context(
            basis, norm, proof.coefficient_evaluation, context),
        "accumulation:prove_algebraic_reduction_context");
    const auto h_basis = std::span(basis.points()).subspan(
        basis.n_vec_len(), basis.l_vec_len());
    PURIFY_ASSIGN_OR_RETURN(
        proof.coefficient_opening,
        prove_algebraic_ipa(
            h_basis, std::move(coefficients), state.weights,
            state.opening_base, state.transcript, 0, context),
        "accumulation:prove_algebraic_coefficient_ipa");
    PURIFY_ASSIGN_OR_RETURN(
        auto pending,
        verify_algebraic_norm_reduction(
            basis, norm, proof, context),
        "accumulation:prove_algebraic_reduction_check");
    (void)pending;
    return proof;
}

Result<PendingClaim> verify_algebraic_norm_reduction(
    const Basis& basis, const AlgebraicPreparedNorm& norm,
    const AlgebraicNormReductionProof& proof,
    purify_secp_context* context) {
    PURIFY_RETURN_IF_ERROR(
        validate_basis(basis), "accumulation:basis");
    PURIFY_RETURN_IF_ERROR(
        validate_algebraic_prepared(basis, norm),
        "accumulation:algebraic_prepared");
    const auto rounds = log2_dimension(basis.l_vec_len());
    const auto& opening = proof.coefficient_opening;
    if (opening.left.size() != rounds ||
        opening.right.size() != rounds) {
        return unexpected_error(
            ErrorCode::SizeMismatch,
            "accumulation:algebraic_reduction_rounds");
    }
    PURIFY_ASSIGN_OR_RETURN(
        auto terminal,
        FieldElement::try_from_bytes32(opening.terminal_scalar),
        "accumulation:algebraic_reduction_terminal");
    PURIFY_ASSIGN_OR_RETURN(
        auto state,
        make_algebraic_norm_context(
            basis, norm, proof.coefficient_evaluation, context),
        "accumulation:verify_algebraic_reduction_context");
    PURIFY_ASSIGN_OR_RETURN(
        auto folded,
        verify_algebraic_ipa(
            basis.l_vec_len(), opening, state.weights,
            norm.coefficient_commitment(), state.evaluation,
            state.opening_base, state.transcript, 0, context),
        "accumulation:verify_algebraic_coefficient_ipa");
    folded.offset = basis.n_vec_len();

    const auto generator_encoding = base_generator(context);
    PointBytes generator{};
    if (purify_bppp_generators_to_points(
            context, generator_encoding.data(), 1,
            generator.data()) == 0) {
        return unexpected_error(
            ErrorCode::BackendRejectedInput,
            "accumulation:algebraic_standard_generator");
    }
    const std::array<PointBytes, 2> norm_points{
        norm.residual(), generator};
    const std::array<FieldElement, 2> norm_scalars{
        FieldElement::one(),
        (norm.polynomial()[1].scale * state.evaluation).negate()};
    PURIFY_ASSIGN_OR_RETURN(
        auto norm_point, msm(norm_points, norm_scalars, context),
        "accumulation:algebraic_unshifted_norm_claim");

    // The fusion challenge follows the complete coefficient opening and
    // both pending equations. No field is encoded by untyped concatenation.
    state.transcript.append_scalar(terminal);
    PURIFY_RETURN_IF_ERROR(
        append_algebraic_point(
            state.transcript, opening.folded_generator),
        "accumulation:algebraic_folded_generator");
    PURIFY_RETURN_IF_ERROR(
        append_algebraic_point(state.transcript, norm_point),
        "accumulation:algebraic_norm_point");
    PURIFY_RETURN_IF_ERROR(
        append_algebraic_polynomial(
            state.transcript, norm.polynomial()),
        "accumulation:algebraic_norm_polynomial");
    const std::array<PolynomialTerm, 1> folded_polynomial{folded};
    PURIFY_RETURN_IF_ERROR(
        append_algebraic_polynomial(
            state.transcript, folded_polynomial),
        "accumulation:algebraic_folded_polynomial");
    PURIFY_ASSIGN_OR_RETURN(
        auto chi,
        append_algebraic_challenge(
            state.transcript,
            static_cast<std::uint64_t>(rounds)),
        "accumulation:algebraic_reduction_fusion");

    const std::array<PointBytes, 2> fusion_points{
        norm_point, opening.folded_generator};
    const std::array<FieldElement, 2> fusion_scalars{
        FieldElement::one(), chi};
    PURIFY_ASSIGN_OR_RETURN(
        auto combined_point,
        msm(fusion_points, fusion_scalars, context),
        "accumulation:algebraic_combined_reduction_claim");
    std::vector<PolynomialTerm> polynomial(
        norm.polynomial().begin(), norm.polynomial().end());
    folded.scale = folded.scale * chi;
    polynomial.push_back(std::move(folded));
    return PendingClaim(
        basis.digest(), combined_point, std::move(polynomial));
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

Result<AlgebraicStepProof> prove_algebraic_step(
    const Basis& basis, std::span<const PendingClaim> claims,
    purify_secp_context* context) {
    PURIFY_ASSIGN_OR_RETURN(
        auto state,
        make_algebraic_step_context(basis, claims, context),
        "accumulation:prove_algebraic_context");
    std::vector<FieldElement> coefficients(
        basis.dimension(), FieldElement::zero());
    auto weight = FieldElement::one();
    for (const auto& claim : claims) {
        add_coefficients(
            coefficients, claim.polynomial(), weight);
        weight = weight * state.beta;
    }
    const auto weights =
        geometric_tensor(state.x, basis.dimension());
    PURIFY_ASSIGN_OR_RETURN(
        auto proof,
        prove_algebraic_ipa(
            basis.points(), std::move(coefficients), weights,
            state.opening_base, state.transcript, 2, context),
        "accumulation:prove_algebraic_ipa");
    PURIFY_ASSIGN_OR_RETURN(
        auto pending,
        verify_algebraic_step(basis, claims, proof, context),
        "accumulation:prove_algebraic_check");
    (void)pending;
    return proof;
}

Result<PendingClaim> verify_algebraic_step(
    const Basis& basis, std::span<const PendingClaim> claims,
    const AlgebraicStepProof& proof,
    purify_secp_context* context) {
    PURIFY_RETURN_IF_ERROR(
        validate_basis(basis), "accumulation:basis");
    const auto rounds = log2_dimension(basis.dimension());
    if (proof.left.size() != rounds ||
        proof.right.size() != rounds) {
        return unexpected_error(
            ErrorCode::SizeMismatch,
            "accumulation:algebraic_step_rounds");
    }
    PURIFY_ASSIGN_OR_RETURN(
        auto terminal,
        FieldElement::try_from_bytes32(proof.terminal_scalar),
        "accumulation:algebraic_step_terminal_scalar");
    (void)terminal;
    PURIFY_ASSIGN_OR_RETURN(
        auto state,
        make_algebraic_step_context(basis, claims, context),
        "accumulation:verify_algebraic_context");
    const auto weights =
        geometric_tensor(state.x, basis.dimension());
    PURIFY_ASSIGN_OR_RETURN(
        auto folded,
        verify_algebraic_ipa(
            basis.dimension(), proof, weights,
            state.commitment, state.y, state.opening_base,
            state.transcript, 2, context),
        "accumulation:verify_algebraic_ipa");
    return PendingClaim(
        basis.digest(), proof.folded_generator,
        {std::move(folded)});
}

#if defined(PURIFY_INTERNAL_TEST_SUPPORT)
namespace test_support {

Result<PointBytes> algebraic_step_equation_residual(
    const Basis& basis, std::span<const PendingClaim> claims,
    const AlgebraicStepProof& proof,
    purify_secp_context* context) {
    PURIFY_RETURN_IF_ERROR(
        validate_basis(basis), "accumulation:test_basis");
    const auto rounds = log2_dimension(basis.dimension());
    if (proof.left.size() != rounds ||
        proof.right.size() != rounds) {
        return unexpected_error(
            ErrorCode::SizeMismatch,
            "accumulation:test_step_rounds");
    }
    PURIFY_ASSIGN_OR_RETURN(
        auto state,
        make_algebraic_step_context(basis, claims, context),
        "accumulation:test_step_context");
    const auto weights =
        geometric_tensor(state.x, basis.dimension());
    PURIFY_ASSIGN_OR_RETURN(
        auto evaluated,
        evaluate_algebraic_ipa(
            basis.dimension(), proof, weights,
            state.commitment, state.y, state.opening_base,
            state.transcript, 2, context),
        "accumulation:test_step_evaluate");
    return evaluated.residual;
}

} // namespace test_support
#endif

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
