// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file purify_bppp.cpp
 * @brief C++ convenience wrappers over the low-level BPPP C bridge.
 */

#include "purify_bppp.hpp"

#include <algorithm>
#include <vector>

#include "purify_bppp_bridge.h"

namespace purify::bppp {
namespace {

/** @brief Flattens compressed point encodings into the contiguous layout expected by the C bridge. */
std::vector<unsigned char> flatten_points(const std::vector<PointBytes>& points) {
    std::vector<unsigned char> out;
    out.reserve(points.size() * PointBytes{}.size());
    for (const PointBytes& point : points) {
        out.insert(out.end(), point.begin(), point.end());
    }
    return out;
}

/** @brief Flattens scalar encodings into the contiguous layout expected by the C bridge. */
std::vector<unsigned char> flatten_scalars(const std::vector<ScalarBytes>& scalars) {
    std::vector<unsigned char> out;
    out.reserve(scalars.size() * ScalarBytes{}.size());
    for (const ScalarBytes& scalar : scalars) {
        out.insert(out.end(), scalar.begin(), scalar.end());
    }
    return out;
}

/** @brief Returns true when a bridge call signals success. */
bool require_ok(int ok) {
    return ok != 0;
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
    std::size_t serialized_len = count * PointBytes{}.size();
    if (count == 0) {
        return out;
    }
    std::vector<unsigned char> serialized(serialized_len);
    if (!require_ok(purify_bppp_create_generators(count, serialized.data(), &serialized_len))) {
        return unexpected_error(ErrorCode::BackendRejectedInput, "create_generators:backend");
    }
    if (serialized_len != serialized.size()) {
        return unexpected_error(ErrorCode::UnexpectedSize, "create_generators:serialized_len");
    }
    for (std::size_t i = 0; i < count; ++i) {
        std::copy_n(serialized.data() + i * PointBytes{}.size(), PointBytes{}.size(), out[i].data());
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
    if (inputs.n_vec.empty() || inputs.l_vec.empty() || inputs.c_vec.empty()) {
        return unexpected_error(ErrorCode::EmptyInput, "prove_norm_arg:empty_vectors");
    }
    if (inputs.l_vec.size() != inputs.c_vec.size()) {
        return unexpected_error(ErrorCode::SizeMismatch, "prove_norm_arg:l_c_size_mismatch");
    }

    std::vector<PointBytes> generators = inputs.generators;
    if (generators.empty()) {
        Result<std::vector<PointBytes>> generated = create_generators(inputs.n_vec.size() + inputs.l_vec.size());
        if (!generated.has_value()) {
            return unexpected_error(generated.error(), "prove_norm_arg:create_generators");
        }
        generators = std::move(*generated);
    }
    std::vector<unsigned char> generator_bytes = flatten_points(generators);
    std::vector<unsigned char> n_vec = flatten_scalars(inputs.n_vec);
    std::vector<unsigned char> l_vec = flatten_scalars(inputs.l_vec);
    std::vector<unsigned char> c_vec = flatten_scalars(inputs.c_vec);
    std::size_t proof_len = purify_bppp_required_proof_size(inputs.n_vec.size(), inputs.c_vec.size());
    PointBytes commitment{};
    Bytes proof(proof_len);

    if (proof_len == 0) {
        return unexpected_error(ErrorCode::InvalidDimensions, "prove_norm_arg:proof_len_zero");
    }
    if (!require_ok(purify_bppp_prove_norm_arg(inputs.rho.data(), generator_bytes.data(), generators.size(),
                                               n_vec.data(), inputs.n_vec.size(), l_vec.data(), inputs.l_vec.size(),
                                               c_vec.data(), inputs.c_vec.size(), commitment.data(), proof.data(), &proof_len))) {
        return unexpected_error(ErrorCode::BackendRejectedInput, "prove_norm_arg:backend");
    }
    proof.resize(proof_len);

    return NormArgProof{inputs.rho, std::move(generators), inputs.c_vec, inputs.n_vec.size(), commitment, std::move(proof)};
}

bool verify_norm_arg(const NormArgProof& proof) {
    if (proof.n_vec_len == 0 || proof.c_vec.empty()) {
        return false;
    }

    std::vector<unsigned char> generator_bytes = flatten_points(proof.generators);
    std::vector<unsigned char> c_vec = flatten_scalars(proof.c_vec);
    return purify_bppp_verify_norm_arg(proof.rho.data(), generator_bytes.data(), proof.generators.size(),
                                       c_vec.data(), proof.c_vec.size(), proof.n_vec_len,
                                       proof.commitment.data(), proof.proof.data(), proof.proof.size()) != 0;
}

}  // namespace purify::bppp
