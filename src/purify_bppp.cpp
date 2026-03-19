// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file purify_bppp.cpp
 * @brief C++ convenience wrappers over the low-level BPPP C bridge.
 */

#include "purify_bppp.hpp"

#include <algorithm>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <unordered_map>
#include <vector>

#include "purify_bulletproof_internal.hpp"
#include "purify_bppp_bridge.h"

namespace purify::bppp {
namespace {

template <typename ByteArray>
constexpr void assert_packed_byte_array_layout() {
    static_assert(std::is_same_v<typename ByteArray::value_type, unsigned char>,
                  "byte-span bridge helpers require unsigned-char array elements");
    static_assert(std::is_trivially_copyable_v<ByteArray>,
                  "byte-span bridge helpers require trivially copyable array wrappers");
    static_assert(std::is_standard_layout_v<ByteArray>,
                  "byte-span bridge helpers require standard-layout array wrappers");
    static_assert(alignof(ByteArray) == alignof(unsigned char),
                  "byte-span bridge helpers require byte-aligned array wrappers");
    static_assert(sizeof(ByteArray) == std::tuple_size_v<ByteArray>,
                  "byte-span bridge helpers require tightly packed byte arrays with no padding");
}

template <typename ByteArray>
std::span<const unsigned char> byte_span(const std::vector<ByteArray>& values) {
    assert_packed_byte_array_layout<ByteArray>();
    auto bytes = std::as_bytes(std::span<const ByteArray>(values.data(), values.size()));
    return {reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size()};
}

template <typename ByteArray>
std::span<unsigned char> writable_byte_span(std::vector<ByteArray>& values) {
    assert_packed_byte_array_layout<ByteArray>();
    auto bytes = std::as_writable_bytes(std::span<ByteArray>(values.data(), values.size()));
    return {reinterpret_cast<unsigned char*>(bytes.data()), bytes.size()};
}

/** @brief Returns true when a bridge call signals success. */
bool require_ok(int ok) {
    return ok != 0;
}

struct BpppBackendResourceDeleter {
    void operator()(purify_bppp_backend_resources* resources) const noexcept {
        purify_bppp_backend_resources_destroy(resources);
    }
};

using BpppBackendResourcePtr = std::unique_ptr<purify_bppp_backend_resources, BpppBackendResourceDeleter>;

constexpr std::string_view kCircuitNormArgRhoTag = "Purify/BPPP/CircuitNormArg/Rho";
constexpr std::string_view kCircuitNormArgMulTag = "Purify/BPPP/CircuitNormArg/Mul";
constexpr std::string_view kCircuitNormArgConstraintTag = "Purify/BPPP/CircuitNormArg/Constraint";
constexpr std::string_view kCircuitNormArgPublicCommitmentTag = "Purify/BPPP/CircuitNormArg/PublicCommitments";
constexpr std::string_view kCircuitZkBlindTag = "Purify/BPPP/CircuitNormArg/ZKBlind";
constexpr std::string_view kCircuitZkMaskNTag = "Purify/BPPP/CircuitNormArg/ZKMaskN";
constexpr std::string_view kCircuitZkMaskLTag = "Purify/BPPP/CircuitNormArg/ZKMaskL";
constexpr std::string_view kCircuitZkChallengeTag = "Purify/BPPP/CircuitNormArg/ZKChallenge";

std::string generator_cache_key(std::span<const PointBytes> generators) {
    const auto* begin = reinterpret_cast<const char*>(generators.data());
    return std::string(begin, begin + generators.size() * sizeof(PointBytes));
}

purify_bppp_backend_resources* cached_bppp_backend_resources(const std::vector<PointBytes>& generators) {
    thread_local std::unordered_map<std::string, BpppBackendResourcePtr> cache;

    if (generators.empty()) {
        return nullptr;
    }
    std::string key = generator_cache_key(generators);
    auto it = cache.find(key);
    if (it == cache.end()) {
        std::span<const unsigned char> serialized = byte_span(generators);
        purify_bppp_backend_resources* created =
            purify_bppp_backend_resources_create(serialized.data(), generators.size());
        if (created == nullptr) {
            return nullptr;
        }
        it = cache.emplace(std::move(key), BpppBackendResourcePtr(created)).first;
    }
    return it->second.get();
}

bool is_power_of_two(std::size_t value) {
    return value != 0 && (value & (value - 1)) == 0;
}

std::size_t round_up_power_of_two(std::size_t value) {
    std::size_t out = 1;
    while (out < value) {
        out <<= 1;
    }
    return out;
}

std::string circuit_norm_arg_public_data_cache_key(std::span<const unsigned char> binding_digest,
                                                   bool externalize_commitments) {
    std::string key;
    key.reserve(1 + binding_digest.size());
    key.push_back(externalize_commitments ? '\x01' : '\x00');
    key.append(reinterpret_cast<const char*>(binding_digest.data()),
               reinterpret_cast<const char*>(binding_digest.data() + binding_digest.size()));
    return key;
}

void append_u64_le(Bytes& out, std::uint64_t value) {
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<unsigned char>((value >> (8 * i)) & 0xffU));
    }
}

Result<FieldElement> derive_nonzero_scalar(std::span<const unsigned char> seed, std::string_view tag, std::size_t index) {
    Bytes prefix(seed.begin(), seed.end());
    append_u64_le(prefix, static_cast<std::uint64_t>(index));
    for (std::uint64_t counter = 0; counter < 256; ++counter) {
        Bytes input = prefix;
        append_u64_le(input, counter);
        Bytes digest = hmac_sha256(bytes_from_ascii(tag), input);
        if (digest.size() != 32) {
            return unexpected_error(ErrorCode::UnexpectedSize, "derive_nonzero_scalar:digest_size");
        }
        ScalarBytes candidate_bytes{};
        std::copy(digest.begin(), digest.end(), candidate_bytes.begin());
        Result<FieldElement> candidate = FieldElement::try_from_bytes32(candidate_bytes);
        if (candidate.has_value() && !candidate->is_zero()) {
            return candidate;
        }
    }
    return unexpected_error(ErrorCode::InternalMismatch, "derive_nonzero_scalar:exhausted");
}

Result<FieldElement> derive_scalar(std::span<const unsigned char> seed, std::string_view tag,
                                   std::size_t index, std::uint64_t attempt = 0) {
    Bytes prefix(seed.begin(), seed.end());
    append_u64_le(prefix, static_cast<std::uint64_t>(index));
    append_u64_le(prefix, attempt);
    for (std::uint64_t counter = 0; counter < 256; ++counter) {
        Bytes input = prefix;
        append_u64_le(input, counter);
        Bytes digest = hmac_sha256(bytes_from_ascii(tag), input);
        if (digest.size() != 32) {
            return unexpected_error(ErrorCode::UnexpectedSize, "derive_scalar:digest_size");
        }
        ScalarBytes candidate_bytes{};
        std::copy(digest.begin(), digest.end(), candidate_bytes.begin());
        Result<FieldElement> candidate = FieldElement::try_from_bytes32(candidate_bytes);
        if (candidate.has_value()) {
            return candidate;
        }
    }
    return unexpected_error(ErrorCode::InternalMismatch, "derive_scalar:exhausted");
}

FieldElement weighted_bppp_inner_product(std::span<const FieldElement> lhs, std::span<const FieldElement> rhs,
                                         const FieldElement& rho) {
    assert(lhs.size() == rhs.size() && "weighted_bppp_inner_product requires matching vector lengths");
    FieldElement mu = rho * rho;
    FieldElement weight = mu;
    FieldElement total = FieldElement::zero();
    for (std::size_t i = 0; i < lhs.size(); ++i) {
        total = total + (weight * lhs[i] * rhs[i]);
        weight = weight * mu;
    }
    return total;
}

struct CircuitNormArgPublicData {
    FieldElement rho = FieldElement::zero();
    ScalarBytes rho_bytes{};
    FieldElement target = FieldElement::zero();
    std::vector<PointBytes> generators;
    std::vector<FieldElement> c_vec;
    std::vector<ScalarBytes> c_vec_bytes;
    std::vector<FieldElement> public_commitment_coeffs;
    std::vector<std::array<FieldElement, 2>> plus_terms;
    std::vector<std::array<FieldElement, 2>> minus_terms;
    std::vector<FieldElement> plus_shift;
    std::vector<FieldElement> minus_shift;
};

using CircuitNormArgPublicDataPtr = std::shared_ptr<const CircuitNormArgPublicData>;

struct CircuitNormArgReduction {
    CircuitNormArgPublicDataPtr public_data;
    std::vector<FieldElement> n_vec;
    std::vector<FieldElement> l_vec;
};

Result<CircuitNormArgPublicDataPtr> build_circuit_norm_arg_public_data(
    const NativeBulletproofCircuit& circuit,
    std::span<const unsigned char> statement_binding,
    bool externalize_commitments = false) {
    thread_local std::unordered_map<std::string, CircuitNormArgPublicDataPtr> cache;

    if (!circuit.has_valid_shape()) {
        return unexpected_error(ErrorCode::InvalidDimensions, "build_circuit_norm_arg_public_data:circuit_shape");
    }
    if (!is_power_of_two(circuit.n_gates)) {
        return unexpected_error(ErrorCode::InvalidDimensions, "build_circuit_norm_arg_public_data:n_gates_power_of_two");
    }

    Bytes binding_digest = experimental_circuit_binding_digest(circuit, statement_binding);
    Result<FieldElement> rho = derive_nonzero_scalar(binding_digest, kCircuitNormArgRhoTag, 0);
    if (!rho.has_value()) {
        return unexpected_error(rho.error(), "build_circuit_norm_arg_public_data:rho");
    }
    std::string cache_key = circuit_norm_arg_public_data_cache_key(binding_digest, externalize_commitments);
    auto cached = cache.find(cache_key);
    if (cached != cache.end()) {
        return cached->second;
    }

    std::optional<FieldElement> sqrt_minus_one = FieldElement::one().negate().sqrt();
    if (!sqrt_minus_one.has_value()) {
        return unexpected_error(ErrorCode::InternalMismatch, "build_circuit_norm_arg_public_data:sqrt_minus_one");
    }

    const FieldElement zero = FieldElement::zero();
    const FieldElement one = FieldElement::one();
    const FieldElement two = FieldElement::from_int(2);
    const FieldElement four = FieldElement::from_int(4);
    const FieldElement inv2 = two.inverse();
    const FieldElement inv4 = four.inverse();

    std::vector<FieldElement> mul_weights(circuit.n_gates, zero);
    for (std::size_t i = 0; i < circuit.n_gates; ++i) {
        Result<FieldElement> challenge = derive_nonzero_scalar(binding_digest, kCircuitNormArgMulTag, i);
        if (!challenge.has_value()) {
            return unexpected_error(challenge.error(), "build_circuit_norm_arg_public_data:mul_weight");
        }
        mul_weights[i] = *challenge;
    }

    std::vector<FieldElement> row_weights(circuit.c.size(), zero);
    for (std::size_t i = 0; i < circuit.c.size(); ++i) {
        Result<FieldElement> challenge = derive_nonzero_scalar(binding_digest, kCircuitNormArgConstraintTag, i);
        if (!challenge.has_value()) {
            return unexpected_error(challenge.error(), "build_circuit_norm_arg_public_data:constraint_weight");
        }
        row_weights[i] = *challenge;
    }

    std::vector<FieldElement> left_coeffs(circuit.n_gates, zero);
    std::vector<FieldElement> right_coeffs(circuit.n_gates, zero);
    std::vector<FieldElement> output_coeffs(circuit.n_gates, zero);
    std::vector<FieldElement> commitment_coeffs(circuit.n_commitments, zero);
    for (std::size_t i = 0; i < circuit.n_gates; ++i) {
        output_coeffs[i] = mul_weights[i].negate();
    }

    FieldElement constant = zero;
    for (std::size_t j = 0; j < circuit.c.size(); ++j) {
        constant = constant - (row_weights[j] * circuit.c[j]);
    }

    auto accumulate_coeffs = [&](const std::vector<NativeBulletproofCircuitRow>& rows,
                                 std::vector<FieldElement>& coeffs,
                                 bool negate_entries) {
        for (std::size_t i = 0; i < rows.size(); ++i) {
            for (const NativeBulletproofCircuitTerm& entry : rows[i].entries) {
                const FieldElement scalar = negate_entries ? entry.scalar.negate() : entry.scalar;
                coeffs[i] = coeffs[i] + (row_weights[entry.idx] * scalar);
            }
        }
    };
    accumulate_coeffs(circuit.wl, left_coeffs, false);
    accumulate_coeffs(circuit.wr, right_coeffs, false);
    accumulate_coeffs(circuit.wo, output_coeffs, false);
    accumulate_coeffs(circuit.wv, commitment_coeffs, true);

    auto out = std::make_shared<CircuitNormArgPublicData>();
    out->rho = *rho;
    out->rho_bytes = scalar_bytes(*rho);
    out->plus_terms.resize(circuit.n_gates);
    out->minus_terms.resize(circuit.n_gates);
    out->plus_shift.resize(circuit.n_gates, zero);
    out->minus_shift.resize(circuit.n_gates, zero);

    auto two_square_terms = [&](const FieldElement& coefficient) {
        const FieldElement first = (coefficient + one) * inv2;
        const FieldElement second = *sqrt_minus_one * (coefficient - one) * inv2;
        return std::array<FieldElement, 2>{first, second};
    };

    for (std::size_t i = 0; i < circuit.n_gates; ++i) {
        const FieldElement d_plus = mul_weights[i] * inv4;
        const FieldElement d_minus = d_plus.negate();
        const FieldElement e_plus = (left_coeffs[i] + right_coeffs[i]) * inv2;
        const FieldElement e_minus = (left_coeffs[i] - right_coeffs[i]) * inv2;

        out->plus_shift[i] = e_plus * (two * d_plus).inverse();
        out->minus_shift[i] = e_minus * (two * d_minus).inverse();
        constant = constant - ((e_plus * e_plus) * (four * d_plus).inverse());
        constant = constant - ((e_minus * e_minus) * (four * d_minus).inverse());
        out->plus_terms[i] = two_square_terms(d_plus);
        out->minus_terms[i] = two_square_terms(d_minus);
    }

    const std::size_t l_value_count = circuit.n_gates + (externalize_commitments ? 0 : circuit.n_commitments) + 1;
    const std::size_t l_vec_len = round_up_power_of_two(std::max<std::size_t>(1, l_value_count));
    out->c_vec.assign(l_vec_len, zero);
    for (std::size_t i = 0; i < circuit.n_gates; ++i) {
        out->c_vec[i] = output_coeffs[i];
    }
    if (externalize_commitments) {
        out->public_commitment_coeffs = std::move(commitment_coeffs);
    } else {
        for (std::size_t i = 0; i < circuit.n_commitments; ++i) {
            out->c_vec[circuit.n_gates + i] = commitment_coeffs[i];
        }
    }
    out->target = constant.negate();
    out->c_vec_bytes = scalar_bytes(out->c_vec);

    Result<std::vector<PointBytes>> generators = create_generators(4 * circuit.n_gates + out->c_vec.size());
    if (!generators.has_value()) {
        return unexpected_error(generators.error(), "build_circuit_norm_arg_public_data:create_generators");
    }
    out->generators = std::move(*generators);
    CircuitNormArgPublicDataPtr shared = out;
    cache.emplace(std::move(cache_key), shared);
    return shared;
}

Result<CircuitNormArgReduction> reduce_experimental_circuit_to_norm_arg(
    const NativeBulletproofCircuit& circuit,
    const BulletproofAssignmentData& assignment,
    std::span<const unsigned char> statement_binding,
    bool externalize_commitments = false) {
    if (assignment.left.size() != circuit.n_gates
        || assignment.right.size() != circuit.n_gates
        || assignment.output.size() != circuit.n_gates
        || assignment.commitments.size() != circuit.n_commitments) {
        return unexpected_error(ErrorCode::SizeMismatch, "reduce_experimental_circuit_to_norm_arg:assignment_shape");
    }

    Result<CircuitNormArgPublicDataPtr> public_data =
        build_circuit_norm_arg_public_data(circuit, statement_binding, externalize_commitments);
    if (!public_data.has_value()) {
        return unexpected_error(public_data.error(), "reduce_experimental_circuit_to_norm_arg:public_data");
    }

    CircuitNormArgReduction out;
    out.public_data = *public_data;
    out.n_vec.reserve(4 * circuit.n_gates);
    out.l_vec.assign(out.public_data->c_vec.size(), FieldElement::zero());

    const FieldElement rho_inv = out.public_data->rho.inverse();
    FieldElement rho_weight_inv = rho_inv;
    for (std::size_t i = 0; i < circuit.n_gates; ++i) {
        const FieldElement plus_value = assignment.left[i] + assignment.right[i] + out.public_data->plus_shift[i];
        for (const FieldElement& term : out.public_data->plus_terms[i]) {
            out.n_vec.push_back(term * plus_value * rho_weight_inv);
            rho_weight_inv = rho_weight_inv * rho_inv;
        }

        const FieldElement minus_value = assignment.left[i] - assignment.right[i] + out.public_data->minus_shift[i];
        for (const FieldElement& term : out.public_data->minus_terms[i]) {
            out.n_vec.push_back(term * minus_value * rho_weight_inv);
            rho_weight_inv = rho_weight_inv * rho_inv;
        }

        out.l_vec[i] = assignment.output[i];
    }
    if (!externalize_commitments) {
        for (std::size_t i = 0; i < circuit.n_commitments; ++i) {
            out.l_vec[circuit.n_gates + i] = assignment.commitments[i];
        }
    }
    return out;
}

NormArgInputs build_norm_arg_inputs(const CircuitNormArgReduction& reduction) {
    NormArgInputs inputs;
    inputs.rho = reduction.public_data->rho_bytes;
    inputs.generators = reduction.public_data->generators;
    inputs.n_vec = scalar_bytes(reduction.n_vec);
    inputs.l_vec = scalar_bytes(reduction.l_vec);
    inputs.c_vec = reduction.public_data->c_vec_bytes;
    return inputs;
}

Result<PointBytes> commit_norm_arg_witness_only(const NormArgInputs& inputs) {
    if (inputs.n_vec.empty() || inputs.l_vec.empty()) {
        return unexpected_error(ErrorCode::EmptyInput, "commit_norm_arg_witness_only:empty_vectors");
    }
    if (!inputs.generators.empty() && inputs.generators.size() != inputs.n_vec.size() + inputs.l_vec.size()) {
        return unexpected_error(ErrorCode::SizeMismatch, "commit_norm_arg_witness_only:generator_size");
    }

    const std::vector<PointBytes>* generators = &inputs.generators;
    std::vector<PointBytes> generated_generators;
    if (generators->empty()) {
        Result<std::vector<PointBytes>> generated = create_generators(inputs.n_vec.size() + inputs.l_vec.size());
        if (!generated.has_value()) {
            return unexpected_error(generated.error(), "commit_norm_arg_witness_only:create_generators");
        }
        generated_generators = std::move(*generated);
        generators = &generated_generators;
    }

    std::span<const unsigned char> generator_bytes = byte_span(*generators);
    std::span<const unsigned char> n_vec = byte_span(inputs.n_vec);
    std::span<const unsigned char> l_vec = byte_span(inputs.l_vec);
    purify_bppp_backend_resources* resources = cached_bppp_backend_resources(*generators);
    PointBytes commitment{};
    const int ok = resources != nullptr
        ? purify_bppp_commit_witness_only_with_resources(resources, n_vec.data(), inputs.n_vec.size(),
                                                         l_vec.data(), inputs.l_vec.size(), commitment.data())
        : purify_bppp_commit_witness_only(generator_bytes.data(), generators->size(), n_vec.data(),
                                          inputs.n_vec.size(), l_vec.data(), inputs.l_vec.size(),
                                          commitment.data());
    if (!require_ok(ok)) {
        return unexpected_error(ErrorCode::BackendRejectedInput, "commit_norm_arg_witness_only:backend");
    }
    return commitment;
}

Result<PointBytes> offset_commitment(const PointBytes& commitment, const FieldElement& scalar) {
    PointBytes out{};
    ScalarBytes scalar32 = scalar_bytes(scalar);
    if (!require_ok(purify_bppp_offset_commitment(commitment.data(), scalar32.data(), out.data()))) {
        return unexpected_error(ErrorCode::BackendRejectedInput, "offset_commitment:backend");
    }
    return out;
}

Result<PointBytes> point_scale(const PointBytes& point, const FieldElement& scalar) {
    PointBytes out{};
    ScalarBytes scalar32 = scalar_bytes(scalar);
    if (!require_ok(purify_point_scale(point.data(), scalar32.data(), out.data()))) {
        return unexpected_error(ErrorCode::BackendRejectedInput, "point_scale:backend");
    }
    return out;
}

Result<PointBytes> point_add(const PointBytes& lhs, const PointBytes& rhs) {
    PointBytes out{};
    if (!require_ok(purify_point_add(lhs.data(), rhs.data(), out.data()))) {
        return unexpected_error(ErrorCode::BackendRejectedInput, "point_add:backend");
    }
    return out;
}

Result<PointBytes> point_from_scalar_base(const FieldElement& scalar) {
    ScalarBytes blind{};
    return pedersen_commit_char(blind, scalar_bytes(scalar), base_generator());
}

Bytes bind_public_commitments(std::span<const PointBytes> public_commitments,
                              std::span<const unsigned char> statement_binding) {
    Bytes out = bytes_from_ascii(kCircuitNormArgPublicCommitmentTag);
    append_u64_le(out, static_cast<std::uint64_t>(public_commitments.size()));
    for (const PointBytes& point : public_commitments) {
        out.insert(out.end(), point.begin(), point.end());
    }
    append_u64_le(out, static_cast<std::uint64_t>(statement_binding.size()));
    out.insert(out.end(), statement_binding.begin(), statement_binding.end());
    return out;
}

Status validate_public_commitments(std::span<const PointBytes> public_commitments,
                                   std::span<const FieldElement> commitments) {
    if (public_commitments.size() != commitments.size()) {
        return unexpected_error(ErrorCode::SizeMismatch, "validate_public_commitments:size");
    }
    for (std::size_t i = 0; i < commitments.size(); ++i) {
        Result<PointBytes> expected = point_from_scalar_base(commitments[i]);
        if (!expected.has_value()) {
            return unexpected_error(expected.error(), "validate_public_commitments:point_from_scalar_base");
        }
        if (*expected != public_commitments[i]) {
            return unexpected_error(ErrorCode::BindingMismatch, "validate_public_commitments:mismatch");
        }
    }
    return {};
}

Result<PointBytes> add_scaled_points(const PointBytes& base_commitment,
                                     std::span<const PointBytes> points,
                                     std::span<const FieldElement> scalars) {
    if (points.size() != scalars.size()) {
        return unexpected_error(ErrorCode::SizeMismatch, "add_scaled_points:size_mismatch");
    }

    PointBytes out = base_commitment;
    for (std::size_t i = 0; i < points.size(); ++i) {
        if (scalars[i].is_zero()) {
            continue;
        }
        Result<PointBytes> scaled = point_scale(points[i], scalars[i]);
        if (!scaled.has_value()) {
            return unexpected_error(scaled.error(), "add_scaled_points:scale");
        }
        Result<PointBytes> combined = point_add(out, *scaled);
        if (!combined.has_value()) {
            return unexpected_error(combined.error(), "add_scaled_points:add");
        }
        out = *combined;
    }
    return out;
}

Result<PointBytes> anchor_zk_a_commitment(const PointBytes& a_witness_commitment,
                                          const CircuitNormArgPublicData& public_data,
                                          std::span<const PointBytes> public_commitments) {
    if (public_commitments.size() != public_data.public_commitment_coeffs.size()) {
        return unexpected_error(ErrorCode::SizeMismatch, "anchor_zk_a_commitment:public_commitment_size");
    }

    Result<PointBytes> anchored = offset_commitment(a_witness_commitment, public_data.target);
    if (!anchored.has_value()) {
        return unexpected_error(anchored.error(), "anchor_zk_a_commitment:target");
    }
    if (public_commitments.empty()) {
        return anchored;
    }

    std::vector<FieldElement> negated_coeffs;
    negated_coeffs.reserve(public_data.public_commitment_coeffs.size());
    for (const FieldElement& coeff : public_data.public_commitment_coeffs) {
        negated_coeffs.push_back(coeff.negate());
    }
    return add_scaled_points(*anchored, public_commitments, negated_coeffs);
}

Result<PointBytes> commit_explicit_norm_arg(const NormArgInputs& inputs, const FieldElement& value) {
    Result<PointBytes> witness_commitment = commit_norm_arg_witness_only(inputs);
    if (!witness_commitment.has_value()) {
        return unexpected_error(witness_commitment.error(), "commit_explicit_norm_arg:witness_commitment");
    }
    return offset_commitment(*witness_commitment, value);
}

Result<PointBytes> combine_zk_commitments(const PointBytes& a_commitment,
                                          const PointBytes& s_commitment,
                                          const FieldElement& challenge,
                                          const FieldElement& t2) {
    Result<PointBytes> scaled_s = point_scale(s_commitment, challenge);
    if (!scaled_s.has_value()) {
        return unexpected_error(scaled_s.error(), "combine_zk_commitments:scale_s");
    }
    Result<PointBytes> combined = point_add(a_commitment, *scaled_s);
    if (!combined.has_value()) {
        return unexpected_error(combined.error(), "combine_zk_commitments:add");
    }
    return offset_commitment(*combined, challenge * challenge * t2);
}

template <typename Inputs>
Result<NormArgProof> prove_norm_arg_impl(Inputs&& inputs) {
    if (inputs.n_vec.empty() || inputs.l_vec.empty() || inputs.c_vec.empty()) {
        return unexpected_error(ErrorCode::EmptyInput, "prove_norm_arg:empty_vectors");
    }
    if (inputs.l_vec.size() != inputs.c_vec.size()) {
        return unexpected_error(ErrorCode::SizeMismatch, "prove_norm_arg:l_c_size_mismatch");
    }

    const std::vector<PointBytes>* generators = &inputs.generators;
    std::vector<PointBytes> generated_generators;
    if (generators->empty()) {
        Result<std::vector<PointBytes>> generated = create_generators(inputs.n_vec.size() + inputs.l_vec.size());
        if (!generated.has_value()) {
            return unexpected_error(generated.error(), "prove_norm_arg:create_generators");
        }
        generated_generators = std::move(*generated);
        generators = &generated_generators;
    }
    std::span<const unsigned char> generator_bytes = byte_span(*generators);
    std::span<const unsigned char> n_vec = byte_span(inputs.n_vec);
    std::span<const unsigned char> l_vec = byte_span(inputs.l_vec);
    std::span<const unsigned char> c_vec = byte_span(inputs.c_vec);
    purify_bppp_backend_resources* resources = cached_bppp_backend_resources(*generators);
    std::size_t proof_len = purify_bppp_required_proof_size(inputs.n_vec.size(), inputs.c_vec.size());
    PointBytes commitment{};
    Bytes proof(proof_len);

    if (proof_len == 0) {
        return unexpected_error(ErrorCode::InvalidDimensions, "prove_norm_arg:proof_len_zero");
    }
    const int ok = resources != nullptr
        ? purify_bppp_prove_norm_arg_with_resources(resources, inputs.rho.data(), n_vec.data(), inputs.n_vec.size(),
                                                    l_vec.data(), inputs.l_vec.size(), c_vec.data(),
                                                    inputs.c_vec.size(), commitment.data(), proof.data(), &proof_len)
        : purify_bppp_prove_norm_arg(inputs.rho.data(), generator_bytes.data(), generators->size(), n_vec.data(),
                                     inputs.n_vec.size(), l_vec.data(), inputs.l_vec.size(), c_vec.data(),
                                     inputs.c_vec.size(), commitment.data(), proof.data(), &proof_len);
    if (!require_ok(ok)) {
        return unexpected_error(ErrorCode::BackendRejectedInput, "prove_norm_arg:backend");
    }
    proof.resize(proof_len);

    std::vector<PointBytes> proof_generators;
    if (!generated_generators.empty()) {
        proof_generators = std::move(generated_generators);
    } else if constexpr (!std::is_const_v<std::remove_reference_t<Inputs>> && std::is_rvalue_reference_v<Inputs&&>) {
        proof_generators = std::move(inputs.generators);
    } else {
        proof_generators = inputs.generators;
    }

    std::vector<ScalarBytes> proof_c_vec;
    if constexpr (!std::is_const_v<std::remove_reference_t<Inputs>> && std::is_rvalue_reference_v<Inputs&&>) {
        proof_c_vec = std::move(inputs.c_vec);
    } else {
        proof_c_vec = inputs.c_vec;
    }

    return NormArgProof{inputs.rho, std::move(proof_generators), std::move(proof_c_vec), inputs.n_vec.size(), commitment, std::move(proof)};
}

Result<FieldElement> derive_zk_challenge(std::span<const unsigned char> binding_digest,
                                         const PointBytes& a_commitment,
                                         const PointBytes& s_commitment,
                                         const FieldElement& t2) {
    Bytes seed(binding_digest.begin(), binding_digest.end());
    seed.insert(seed.end(), a_commitment.begin(), a_commitment.end());
    seed.insert(seed.end(), s_commitment.begin(), s_commitment.end());
    ScalarBytes t2_bytes = scalar_bytes(t2);
    seed.insert(seed.end(), t2_bytes.begin(), t2_bytes.end());
    return derive_nonzero_scalar(seed, kCircuitZkChallengeTag, 0);
}

}  // namespace

GeneratorBytes base_generator() {
    GeneratorBytes out{};
    bool ok = require_ok(purify_bppp_base_generator(out.data()));
    assert(ok && "base_generator() requires a functioning backend");
    (void)ok;
    return out;
}

GeneratorBytes value_generator_h() {
    GeneratorBytes out{};
    bool ok = require_ok(purify_bppp_value_generator_h(out.data()));
    assert(ok && "value_generator_h() requires a functioning backend");
    (void)ok;
    return out;
}

Result<std::vector<PointBytes>> create_generators(std::size_t count) {
    std::vector<PointBytes> out(count);
    if (count == 0) {
        return out;
    }
    std::span<unsigned char> serialized = writable_byte_span(out);
    std::size_t serialized_len = serialized.size();
    if (!require_ok(purify_bppp_create_generators(count, serialized.data(), &serialized_len))) {
        return unexpected_error(ErrorCode::BackendRejectedInput, "create_generators:backend");
    }
    if (serialized_len != serialized.size()) {
        return unexpected_error(ErrorCode::UnexpectedSize, "create_generators:serialized_len");
    }
    return out;
}

Result<PointBytes> commit_norm_arg(const NormArgInputs& inputs) {
    if (inputs.n_vec.empty() || inputs.l_vec.empty() || inputs.c_vec.empty()) {
        return unexpected_error(ErrorCode::EmptyInput, "commit_norm_arg:empty_vectors");
    }
    if (inputs.l_vec.size() != inputs.c_vec.size()) {
        return unexpected_error(ErrorCode::SizeMismatch, "commit_norm_arg:l_c_size_mismatch");
    }

    const std::vector<PointBytes>* generators = &inputs.generators;
    std::vector<PointBytes> generated_generators;
    if (generators->empty()) {
        Result<std::vector<PointBytes>> generated = create_generators(inputs.n_vec.size() + inputs.l_vec.size());
        if (!generated.has_value()) {
            return unexpected_error(generated.error(), "commit_norm_arg:create_generators");
        }
        generated_generators = std::move(*generated);
        generators = &generated_generators;
    }

    std::span<const unsigned char> generator_bytes = byte_span(*generators);
    std::span<const unsigned char> n_vec = byte_span(inputs.n_vec);
    std::span<const unsigned char> l_vec = byte_span(inputs.l_vec);
    std::span<const unsigned char> c_vec = byte_span(inputs.c_vec);
    purify_bppp_backend_resources* resources = cached_bppp_backend_resources(*generators);
    PointBytes commitment{};
    const int ok = resources != nullptr
        ? purify_bppp_commit_norm_arg_with_resources(resources, inputs.rho.data(), n_vec.data(), inputs.n_vec.size(),
                                                     l_vec.data(), inputs.l_vec.size(), c_vec.data(),
                                                     inputs.c_vec.size(), commitment.data())
        : purify_bppp_commit_norm_arg(inputs.rho.data(), generator_bytes.data(), generators->size(), n_vec.data(),
                                      inputs.n_vec.size(), l_vec.data(), inputs.l_vec.size(), c_vec.data(),
                                      inputs.c_vec.size(), commitment.data());
    if (!require_ok(ok)) {
        return unexpected_error(ErrorCode::BackendRejectedInput, "commit_norm_arg:backend");
    }
    return commitment;
}

Result<PointBytes> pedersen_commit_char(const ScalarBytes& blind, const ScalarBytes& value,
                                        const GeneratorBytes& value_gen, const GeneratorBytes& blind_gen) {
    PointBytes commitment{};
    if (!require_ok(purify_pedersen_commit_char(blind.data(), value.data(), value_gen.data(), blind_gen.data(), commitment.data()))) {
        return unexpected_error(ErrorCode::BackendRejectedInput, "pedersen_commit_char:backend");
    }
    return commitment;
}

Result<NormArgProof> prove_norm_arg(const NormArgInputs& inputs) {
    return prove_norm_arg_impl(inputs);
}

Result<NormArgProof> prove_norm_arg(NormArgInputs&& inputs) {
    return prove_norm_arg_impl(std::move(inputs));
}

Result<NormArgProof> prove_norm_arg_to_commitment(const NormArgInputs& inputs, const PointBytes& commitment) {
    if (inputs.n_vec.empty() || inputs.l_vec.empty() || inputs.c_vec.empty()) {
        return unexpected_error(ErrorCode::EmptyInput, "prove_norm_arg_to_commitment:empty_vectors");
    }
    if (inputs.l_vec.size() != inputs.c_vec.size()) {
        return unexpected_error(ErrorCode::SizeMismatch, "prove_norm_arg_to_commitment:l_c_size_mismatch");
    }

    const std::vector<PointBytes>* generators = &inputs.generators;
    std::vector<PointBytes> generated_generators;
    if (generators->empty()) {
        Result<std::vector<PointBytes>> generated = create_generators(inputs.n_vec.size() + inputs.l_vec.size());
        if (!generated.has_value()) {
            return unexpected_error(generated.error(), "prove_norm_arg_to_commitment:create_generators");
        }
        generated_generators = std::move(*generated);
        generators = &generated_generators;
    }

    std::span<const unsigned char> generator_bytes = byte_span(*generators);
    std::span<const unsigned char> n_vec = byte_span(inputs.n_vec);
    std::span<const unsigned char> l_vec = byte_span(inputs.l_vec);
    std::span<const unsigned char> c_vec = byte_span(inputs.c_vec);
    purify_bppp_backend_resources* resources = cached_bppp_backend_resources(*generators);
    std::size_t proof_len = purify_bppp_required_proof_size(inputs.n_vec.size(), inputs.c_vec.size());
    Bytes proof(proof_len);
    if (proof_len == 0) {
        return unexpected_error(ErrorCode::InvalidDimensions, "prove_norm_arg_to_commitment:proof_len_zero");
    }
    const int ok = resources != nullptr
        ? purify_bppp_prove_norm_arg_to_commitment_with_resources(resources, inputs.rho.data(), n_vec.data(),
                                                                  inputs.n_vec.size(), l_vec.data(),
                                                                  inputs.l_vec.size(), c_vec.data(),
                                                                  inputs.c_vec.size(), commitment.data(),
                                                                  proof.data(), &proof_len)
        : purify_bppp_prove_norm_arg_to_commitment(inputs.rho.data(), generator_bytes.data(), generators->size(),
                                                   n_vec.data(), inputs.n_vec.size(), l_vec.data(),
                                                   inputs.l_vec.size(), c_vec.data(), inputs.c_vec.size(),
                                                   commitment.data(), proof.data(), &proof_len);
    if (!require_ok(ok)) {
        return unexpected_error(ErrorCode::BackendRejectedInput, "prove_norm_arg_to_commitment:backend");
    }
    proof.resize(proof_len);

    std::vector<PointBytes> proof_generators;
    if (!generated_generators.empty()) {
        proof_generators = std::move(generated_generators);
    } else {
        proof_generators = inputs.generators;
    }
    return NormArgProof{inputs.rho, std::move(proof_generators), inputs.c_vec, inputs.n_vec.size(), commitment, std::move(proof)};
}

bool verify_norm_arg(const NormArgProof& proof) {
    if (proof.n_vec_len == 0 || proof.c_vec.empty()) {
        return false;
    }

    std::span<const unsigned char> generator_bytes = byte_span(proof.generators);
    std::span<const unsigned char> c_vec = byte_span(proof.c_vec);
    purify_bppp_backend_resources* resources = cached_bppp_backend_resources(proof.generators);
    const int ok = resources != nullptr
        ? purify_bppp_verify_norm_arg_with_resources(resources, proof.rho.data(), c_vec.data(),
                                                     proof.c_vec.size(), proof.n_vec_len, proof.commitment.data(),
                                                     proof.proof.data(), proof.proof.size())
        : purify_bppp_verify_norm_arg(proof.rho.data(), generator_bytes.data(), proof.generators.size(),
                                      c_vec.data(), proof.c_vec.size(), proof.n_vec_len, proof.commitment.data(),
                                      proof.proof.data(), proof.proof.size());
    return ok != 0;
}

Result<PointBytes> commit_experimental_circuit_witness(
    const NativeBulletproofCircuit& circuit,
    const BulletproofAssignmentData& assignment,
    std::span<const unsigned char> statement_binding) {
    Result<CircuitNormArgReduction> reduction = reduce_experimental_circuit_to_norm_arg(circuit, assignment, statement_binding);
    if (!reduction.has_value()) {
        return unexpected_error(reduction.error(), "commit_experimental_circuit_witness:reduce");
    }
    return commit_norm_arg_witness_only(build_norm_arg_inputs(*reduction));
}

Result<ExperimentalCircuitNormArgProof> prove_experimental_circuit_norm_arg_to_commitment(
    const NativeBulletproofCircuit& circuit,
    const BulletproofAssignmentData& assignment,
    const PointBytes& witness_commitment,
    std::span<const unsigned char> statement_binding) {
    if (!circuit.has_valid_shape()) {
        return unexpected_error(ErrorCode::InvalidDimensions, "prove_experimental_circuit_norm_arg_to_commitment:circuit_shape");
    }
    if (!is_power_of_two(circuit.n_gates)) {
        return unexpected_error(ErrorCode::InvalidDimensions, "prove_experimental_circuit_norm_arg_to_commitment:n_gates_power_of_two");
    }
    if (assignment.left.size() != circuit.n_gates
        || assignment.right.size() != circuit.n_gates
        || assignment.output.size() != circuit.n_gates
        || assignment.commitments.size() != circuit.n_commitments) {
        return unexpected_error(ErrorCode::SizeMismatch, "prove_experimental_circuit_norm_arg_to_commitment:assignment_shape");
    }
    if (!circuit.evaluate(assignment)) {
        return unexpected_error(ErrorCode::EquationMismatch, "prove_experimental_circuit_norm_arg_to_commitment:assignment_invalid");
    }

    Result<CircuitNormArgReduction> reduction = reduce_experimental_circuit_to_norm_arg(circuit, assignment, statement_binding);
    if (!reduction.has_value()) {
        return unexpected_error(reduction.error(), "prove_experimental_circuit_norm_arg_to_commitment:reduce");
    }

    NormArgInputs inputs = build_norm_arg_inputs(*reduction);
    Result<PointBytes> computed_witness_commitment = commit_norm_arg_witness_only(inputs);
    if (!computed_witness_commitment.has_value()) {
        return unexpected_error(computed_witness_commitment.error(),
                                "prove_experimental_circuit_norm_arg_to_commitment:commit_witness");
    }
    if (*computed_witness_commitment != witness_commitment) {
        return unexpected_error(ErrorCode::BackendRejectedInput,
                                "prove_experimental_circuit_norm_arg_to_commitment:witness_commitment_mismatch");
    }

    Result<PointBytes> anchored_commitment = offset_commitment(witness_commitment, reduction->public_data->target);
    if (!anchored_commitment.has_value()) {
        return unexpected_error(anchored_commitment.error(),
                                "prove_experimental_circuit_norm_arg_to_commitment:anchor");
    }

    Result<NormArgProof> proof = prove_norm_arg_to_commitment(inputs, *anchored_commitment);
    if (!proof.has_value()) {
        return unexpected_error(proof.error(), "prove_experimental_circuit_norm_arg_to_commitment:prove");
    }
    return ExperimentalCircuitNormArgProof{witness_commitment, std::move(proof->proof)};
}

Result<ExperimentalCircuitNormArgProof> prove_experimental_circuit_norm_arg(
    const NativeBulletproofCircuit& circuit,
    const BulletproofAssignmentData& assignment,
    std::span<const unsigned char> statement_binding) {
    Result<PointBytes> witness_commitment = commit_experimental_circuit_witness(circuit, assignment, statement_binding);
    if (!witness_commitment.has_value()) {
        return unexpected_error(witness_commitment.error(), "prove_experimental_circuit_norm_arg:commit_witness");
    }
    return prove_experimental_circuit_norm_arg_to_commitment(circuit, assignment, *witness_commitment, statement_binding);
}

Result<bool> verify_experimental_circuit_norm_arg(
    const NativeBulletproofCircuit& circuit,
    const ExperimentalCircuitNormArgProof& proof,
    std::span<const unsigned char> statement_binding) {
    if (!circuit.has_valid_shape()) {
        return unexpected_error(ErrorCode::InvalidDimensions, "verify_experimental_circuit_norm_arg:circuit_shape");
    }
    if (!is_power_of_two(circuit.n_gates)) {
        return unexpected_error(ErrorCode::InvalidDimensions, "verify_experimental_circuit_norm_arg:n_gates_power_of_two");
    }
    if (proof.proof.empty()) {
        return unexpected_error(ErrorCode::EmptyInput, "verify_experimental_circuit_norm_arg:proof_empty");
    }

    Result<CircuitNormArgPublicDataPtr> public_data = build_circuit_norm_arg_public_data(circuit, statement_binding);
    if (!public_data.has_value()) {
        return unexpected_error(public_data.error(), "verify_experimental_circuit_norm_arg:public_data");
    }
    Result<PointBytes> anchored_commitment = offset_commitment(proof.witness_commitment, (*public_data)->target);
    if (!anchored_commitment.has_value()) {
        return unexpected_error(anchored_commitment.error(), "verify_experimental_circuit_norm_arg:anchor");
    }

    NormArgProof bundle;
    bundle.rho = (*public_data)->rho_bytes;
    bundle.generators = (*public_data)->generators;
    bundle.c_vec = (*public_data)->c_vec_bytes;
    bundle.n_vec_len = 4 * circuit.n_gates;
    bundle.commitment = *anchored_commitment;
    bundle.proof = proof.proof;
    return verify_norm_arg(bundle);
}

Result<ExperimentalCircuitZkNormArgProof> prove_experimental_circuit_zk_norm_arg_impl(
    const NativeBulletproofCircuit& circuit,
    const BulletproofAssignmentData& assignment,
    const ScalarBytes& nonce,
    std::span<const PointBytes> public_commitments,
    std::span<const unsigned char> statement_binding,
    bool externalize_commitments) {
    if (!circuit.has_valid_shape()) {
        return unexpected_error(ErrorCode::InvalidDimensions, "prove_experimental_circuit_zk_norm_arg_impl:circuit_shape");
    }
    if (!is_power_of_two(circuit.n_gates)) {
        return unexpected_error(ErrorCode::InvalidDimensions, "prove_experimental_circuit_zk_norm_arg_impl:n_gates_power_of_two");
    }
    if (assignment.left.size() != circuit.n_gates
        || assignment.right.size() != circuit.n_gates
        || assignment.output.size() != circuit.n_gates
        || assignment.commitments.size() != circuit.n_commitments) {
        return unexpected_error(ErrorCode::SizeMismatch, "prove_experimental_circuit_zk_norm_arg_impl:assignment_shape");
    }
    if (!circuit.evaluate(assignment)) {
        return unexpected_error(ErrorCode::EquationMismatch, "prove_experimental_circuit_zk_norm_arg_impl:assignment_invalid");
    }

    Bytes bound_statement_binding = externalize_commitments
        ? bind_public_commitments(public_commitments, statement_binding)
        : Bytes(statement_binding.begin(), statement_binding.end());
    if (externalize_commitments) {
        Status public_commitment_status = validate_public_commitments(public_commitments, assignment.commitments);
        if (!public_commitment_status.has_value()) {
            return unexpected_error(public_commitment_status.error(),
                                    "prove_experimental_circuit_zk_norm_arg_impl:validate_public_commitments");
        }
    }

    Result<CircuitNormArgReduction> base_reduction =
        reduce_experimental_circuit_to_norm_arg(circuit, assignment, bound_statement_binding, externalize_commitments);
    if (!base_reduction.has_value()) {
        return unexpected_error(base_reduction.error(), "prove_experimental_circuit_zk_norm_arg_impl:reduce");
    }

    Bytes binding_digest = experimental_circuit_binding_digest(circuit, bound_statement_binding);
    Bytes seed = binding_digest;
    seed.insert(seed.end(), nonce.begin(), nonce.end());
    const std::size_t used_l = circuit.n_gates + (externalize_commitments ? 0 : circuit.n_commitments);
    std::optional<Error> masked_failure;

    for (std::uint64_t attempt = 0; attempt < 32; ++attempt) {
        CircuitNormArgReduction hidden = *base_reduction;
        for (std::size_t i = used_l; i < hidden.l_vec.size(); ++i) {
            Result<FieldElement> blind = derive_scalar(seed, kCircuitZkBlindTag, i - used_l, attempt);
            if (!blind.has_value()) {
                return unexpected_error(blind.error(), "prove_experimental_circuit_zk_norm_arg_impl:blind");
            }
            hidden.l_vec[i] = *blind;
        }

        std::vector<FieldElement> mask_n(hidden.n_vec.size(), FieldElement::zero());
        for (std::size_t i = 0; i < mask_n.size(); ++i) {
            Result<FieldElement> value = derive_scalar(seed, kCircuitZkMaskNTag, i, attempt);
            if (!value.has_value()) {
                return unexpected_error(value.error(), "prove_experimental_circuit_zk_norm_arg_impl:mask_n");
            }
            mask_n[i] = *value;
        }

        std::vector<FieldElement> mask_l(hidden.l_vec.size(), FieldElement::zero());
        for (std::size_t i = 0; i < mask_l.size(); ++i) {
            Result<FieldElement> value = derive_scalar(seed, kCircuitZkMaskLTag, i, attempt);
            if (!value.has_value()) {
                return unexpected_error(value.error(), "prove_experimental_circuit_zk_norm_arg_impl:mask_l");
            }
            mask_l[i] = *value;
        }

        const FieldElement t2 = weighted_bppp_inner_product(mask_n, mask_n, hidden.public_data->rho);
        if (t2.is_zero()) {
            continue;
        }
        FieldElement t1 = FieldElement::from_int(2) * weighted_bppp_inner_product(hidden.n_vec, mask_n, hidden.public_data->rho);
        for (std::size_t i = 0; i < mask_l.size(); ++i) {
            t1 = t1 + (mask_l[i] * hidden.public_data->c_vec[i]);
        }

        NormArgInputs hidden_inputs = build_norm_arg_inputs(hidden);
        NormArgInputs mask_inputs;
        mask_inputs.rho = hidden.public_data->rho_bytes;
        mask_inputs.generators = hidden.public_data->generators;
        mask_inputs.n_vec = scalar_bytes(mask_n);
        mask_inputs.l_vec = scalar_bytes(mask_l);
        mask_inputs.c_vec = hidden.public_data->c_vec_bytes;

        Result<PointBytes> a_witness_commitment = commit_norm_arg_witness_only(hidden_inputs);
        if (!a_witness_commitment.has_value()) {
            if (!masked_failure.has_value()) {
                masked_failure = unexpected_error(a_witness_commitment.error(),
                                                  "prove_experimental_circuit_zk_norm_arg_impl:a_witness_commitment")
                                     .error();
            }
            continue;
        }
        Result<PointBytes> a_commitment =
            anchor_zk_a_commitment(*a_witness_commitment, *hidden.public_data, public_commitments);
        if (!a_commitment.has_value()) {
            if (!masked_failure.has_value()) {
                masked_failure = unexpected_error(a_commitment.error(),
                                                  "prove_experimental_circuit_zk_norm_arg_impl:a_commitment")
                                     .error();
            }
            continue;
        }
        Result<PointBytes> s_commitment = commit_explicit_norm_arg(mask_inputs, t1);
        if (!s_commitment.has_value()) {
            if (!masked_failure.has_value()) {
                masked_failure = unexpected_error(s_commitment.error(),
                                                  "prove_experimental_circuit_zk_norm_arg_impl:s_commitment")
                                     .error();
            }
            continue;
        }
        Result<FieldElement> challenge = derive_zk_challenge(binding_digest, *a_commitment, *s_commitment, t2);
        if (!challenge.has_value()) {
            return unexpected_error(challenge.error(), "prove_experimental_circuit_zk_norm_arg_impl:challenge");
        }

        CircuitNormArgReduction masked = hidden;
        for (std::size_t i = 0; i < masked.n_vec.size(); ++i) {
            masked.n_vec[i] = masked.n_vec[i] + (*challenge * mask_n[i]);
        }
        for (std::size_t i = 0; i < masked.l_vec.size(); ++i) {
            masked.l_vec[i] = masked.l_vec[i] + (*challenge * mask_l[i]);
        }
        NormArgInputs masked_inputs = build_norm_arg_inputs(masked);

        Result<PointBytes> combined_commitment = combine_zk_commitments(*a_commitment, *s_commitment, *challenge, t2);
        if (!combined_commitment.has_value()) {
            if (!masked_failure.has_value()) {
                masked_failure = unexpected_error(combined_commitment.error(),
                                                  "prove_experimental_circuit_zk_norm_arg_impl:combined_commitment")
                                     .error();
            }
            continue;
        }
        Result<PointBytes> direct_commitment = commit_norm_arg(masked_inputs);
        if (!direct_commitment.has_value()) {
            if (!masked_failure.has_value()) {
                masked_failure = unexpected_error(direct_commitment.error(),
                                                  "prove_experimental_circuit_zk_norm_arg_impl:direct_commitment")
                                     .error();
            }
            continue;
        }
        if (*combined_commitment != *direct_commitment) {
            return unexpected_error(ErrorCode::InternalMismatch,
                                    "prove_experimental_circuit_zk_norm_arg_impl:commitment_mismatch");
        }

        Result<NormArgProof> proof = prove_norm_arg_to_commitment(masked_inputs, *combined_commitment);
        if (!proof.has_value()) {
            if (!masked_failure.has_value()) {
                masked_failure = unexpected_error(proof.error(),
                                                  "prove_experimental_circuit_zk_norm_arg_impl:prove_norm_arg_to_commitment")
                                     .error();
            }
            continue;
        }
        return ExperimentalCircuitZkNormArgProof{*a_witness_commitment, *s_commitment, scalar_bytes(t2),
                                                 std::move(proof->proof)};
    }

    if (masked_failure.has_value()) {
        return unexpected_error(*masked_failure, "prove_experimental_circuit_zk_norm_arg_impl:masking_attempts");
    }
    return unexpected_error(ErrorCode::BackendRejectedInput, "prove_experimental_circuit_zk_norm_arg_impl:masking_attempts");
}

Result<bool> verify_experimental_circuit_zk_norm_arg_impl(
    const NativeBulletproofCircuit& circuit,
    const ExperimentalCircuitZkNormArgProof& proof,
    std::span<const PointBytes> public_commitments,
    std::span<const unsigned char> statement_binding,
    bool externalize_commitments) {
    if (!circuit.has_valid_shape()) {
        return unexpected_error(ErrorCode::InvalidDimensions, "verify_experimental_circuit_zk_norm_arg_impl:circuit_shape");
    }
    if (!is_power_of_two(circuit.n_gates)) {
        return unexpected_error(ErrorCode::InvalidDimensions, "verify_experimental_circuit_zk_norm_arg_impl:n_gates_power_of_two");
    }
    if (proof.proof.empty()) {
        return unexpected_error(ErrorCode::EmptyInput, "verify_experimental_circuit_zk_norm_arg_impl:proof_empty");
    }

    Bytes bound_statement_binding = externalize_commitments
        ? bind_public_commitments(public_commitments, statement_binding)
        : Bytes(statement_binding.begin(), statement_binding.end());
    Result<CircuitNormArgPublicDataPtr> public_data =
        build_circuit_norm_arg_public_data(circuit, bound_statement_binding, externalize_commitments);
    if (!public_data.has_value()) {
        return unexpected_error(public_data.error(), "verify_experimental_circuit_zk_norm_arg_impl:public_data");
    }
    Result<FieldElement> t2 = FieldElement::try_from_bytes32(proof.t2);
    if (!t2.has_value()) {
        return unexpected_error(t2.error(), "verify_experimental_circuit_zk_norm_arg_impl:t2");
    }
    Result<PointBytes> a_commitment =
        anchor_zk_a_commitment(proof.a_commitment, *(*public_data), public_commitments);
    if (!a_commitment.has_value()) {
        return unexpected_error(a_commitment.error(), "verify_experimental_circuit_zk_norm_arg_impl:a_commitment");
    }
    Bytes binding_digest = experimental_circuit_binding_digest(circuit, bound_statement_binding);
    Result<FieldElement> challenge = derive_zk_challenge(binding_digest, *a_commitment, proof.s_commitment, *t2);
    if (!challenge.has_value()) {
        return unexpected_error(challenge.error(), "verify_experimental_circuit_zk_norm_arg_impl:challenge");
    }
    Result<PointBytes> commitment = combine_zk_commitments(*a_commitment, proof.s_commitment, *challenge, *t2);
    if (!commitment.has_value()) {
        return unexpected_error(commitment.error(), "verify_experimental_circuit_zk_norm_arg_impl:commitment");
    }

    NormArgProof bundle;
    bundle.rho = (*public_data)->rho_bytes;
    bundle.generators = (*public_data)->generators;
    bundle.c_vec = (*public_data)->c_vec_bytes;
    bundle.n_vec_len = 4 * circuit.n_gates;
    bundle.commitment = *commitment;
    bundle.proof = proof.proof;
    return verify_norm_arg(bundle);
}

Result<ExperimentalCircuitZkNormArgProof> prove_experimental_circuit_zk_norm_arg(
    const NativeBulletproofCircuit& circuit,
    const BulletproofAssignmentData& assignment,
    const ScalarBytes& nonce,
    std::span<const unsigned char> statement_binding) {
    Result<ExperimentalCircuitZkNormArgProof> proof =
        prove_experimental_circuit_zk_norm_arg_impl(circuit, assignment, nonce, {}, statement_binding, false);
    if (!proof.has_value()) {
        return unexpected_error(proof.error(), "prove_experimental_circuit_zk_norm_arg");
    }
    return proof;
}

Result<bool> verify_experimental_circuit_zk_norm_arg(
    const NativeBulletproofCircuit& circuit,
    const ExperimentalCircuitZkNormArgProof& proof,
    std::span<const unsigned char> statement_binding) {
    Result<bool> ok = verify_experimental_circuit_zk_norm_arg_impl(circuit, proof, {}, statement_binding, false);
    if (!ok.has_value()) {
        return unexpected_error(ok.error(), "verify_experimental_circuit_zk_norm_arg");
    }
    return ok;
}

Result<ExperimentalCircuitZkNormArgProof> prove_experimental_circuit_zk_norm_arg_with_public_commitments(
    const NativeBulletproofCircuit& circuit,
    const BulletproofAssignmentData& assignment,
    const ScalarBytes& nonce,
    std::span<const PointBytes> public_commitments,
    std::span<const unsigned char> statement_binding) {
    Result<ExperimentalCircuitZkNormArgProof> proof =
        prove_experimental_circuit_zk_norm_arg_impl(circuit, assignment, nonce,
                                                    public_commitments, statement_binding, true);
    if (!proof.has_value()) {
        return unexpected_error(proof.error(),
                                "prove_experimental_circuit_zk_norm_arg_with_public_commitments");
    }
    return proof;
}

Result<bool> verify_experimental_circuit_zk_norm_arg_with_public_commitments(
    const NativeBulletproofCircuit& circuit,
    const ExperimentalCircuitZkNormArgProof& proof,
    std::span<const PointBytes> public_commitments,
    std::span<const unsigned char> statement_binding) {
    Result<bool> ok = verify_experimental_circuit_zk_norm_arg_impl(circuit, proof,
                                                                   public_commitments, statement_binding, true);
    if (!ok.has_value()) {
        return unexpected_error(ok.error(),
                                "verify_experimental_circuit_zk_norm_arg_with_public_commitments");
    }
    return ok;
}

Result<CommittedPurifyWitness> commit_output_witness(const Bytes& message, const UInt512& secret,
                                                     const ScalarBytes& blind,
                                                     const GeneratorBytes& value_gen,
                                                     const GeneratorBytes& blind_gen) {
    Result<BulletproofWitnessData> witness = prove_assignment_data(message, secret);
    if (!witness.has_value()) {
        return unexpected_error(witness.error(), "commit_output_witness:prove_assignment_data");
    }
    Result<PointBytes> commitment = pedersen_commit_char(blind, scalar_bytes(witness->output), value_gen, blind_gen);
    if (!commitment.has_value()) {
        return unexpected_error(commitment.error(), "commit_output_witness:pedersen_commit_char");
    }
    return CommittedPurifyWitness{witness->public_key, witness->output, std::move(witness->assignment), *commitment};
}

}  // namespace purify::bppp
