// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file purify_bppp.cpp
 * @brief C++ convenience wrappers over the low-level BPPP C bridge.
 */

#include "purify_bppp.hpp"

#include <algorithm>
#include <span>
#include <tuple>
#include <type_traits>
#include <vector>

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
    std::size_t proof_len = purify_bppp_required_proof_size(inputs.n_vec.size(), inputs.c_vec.size());
    PointBytes commitment{};
    Bytes proof(proof_len);

    if (proof_len == 0) {
        return unexpected_error(ErrorCode::InvalidDimensions, "prove_norm_arg:proof_len_zero");
    }
    if (!require_ok(purify_bppp_prove_norm_arg(inputs.rho.data(), generator_bytes.data(), generators->size(),
                                               n_vec.data(), inputs.n_vec.size(), l_vec.data(), inputs.l_vec.size(),
                                               c_vec.data(), inputs.c_vec.size(), commitment.data(), proof.data(), &proof_len))) {
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

bool verify_norm_arg(const NormArgProof& proof) {
    if (proof.n_vec_len == 0 || proof.c_vec.empty()) {
        return false;
    }

    std::span<const unsigned char> generator_bytes = byte_span(proof.generators);
    std::span<const unsigned char> c_vec = byte_span(proof.c_vec);
    return purify_bppp_verify_norm_arg(proof.rho.data(), generator_bytes.data(), proof.generators.size(),
                                       c_vec.data(), proof.c_vec.size(), proof.n_vec_len,
                                       proof.commitment.data(), proof.proof.data(), proof.proof.size()) != 0;
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
