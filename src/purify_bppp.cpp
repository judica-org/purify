// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file purify_bppp.cpp
 * @brief C++ convenience wrappers over the low-level BPPP C bridge.
 */

#include "purify_bppp.hpp"

#include <algorithm>
#include <stdexcept>
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

/** @brief Throws when a bridge call signals failure. */
void require_ok(int ok, const char* message) {
    if (ok == 0) {
        throw std::runtime_error(message);
    }
}

}  // namespace

GeneratorBytes base_generator() {
    GeneratorBytes out{};
    require_ok(purify_bppp_base_generator(out.data()), "Unable to serialize base generator");
    return out;
}

GeneratorBytes value_generator_h() {
    GeneratorBytes out{};
    require_ok(purify_bppp_value_generator_h(out.data()), "Unable to serialize alternate generator");
    return out;
}

std::vector<PointBytes> create_generators(std::size_t count) {
    std::vector<PointBytes> out(count);
    std::size_t serialized_len = count * PointBytes{}.size();
    if (count == 0) {
        return out;
    }
    std::vector<unsigned char> serialized(serialized_len);
    require_ok(purify_bppp_create_generators(count, serialized.data(), &serialized_len), "Unable to create BPPP generators");
    if (serialized_len != serialized.size()) {
        throw std::runtime_error("Unexpected BPPP generator serialization length");
    }
    for (std::size_t i = 0; i < count; ++i) {
        std::copy_n(serialized.data() + i * PointBytes{}.size(), PointBytes{}.size(), out[i].data());
    }
    return out;
}

PointBytes pedersen_commit_char(const ScalarBytes& blind, const ScalarBytes& value,
                                const GeneratorBytes& value_gen, const GeneratorBytes& blind_gen) {
    PointBytes commitment{};
    require_ok(purify_pedersen_commit_char(blind.data(), value.data(), value_gen.data(), blind_gen.data(), commitment.data()),
               "Unable to compute Pedersen commitment");
    return commitment;
}

NormArgProof prove_norm_arg(const NormArgInputs& inputs) {
    if (inputs.n_vec.empty() || inputs.l_vec.empty() || inputs.c_vec.empty()) {
        throw std::runtime_error("BPPP vectors must be non-empty");
    }
    if (inputs.l_vec.size() != inputs.c_vec.size()) {
        throw std::runtime_error("BPPP l_vec and c_vec must have the same length");
    }

    std::vector<PointBytes> generators = inputs.generators.empty()
        ? create_generators(inputs.n_vec.size() + inputs.l_vec.size())
        : inputs.generators;
    std::vector<unsigned char> generator_bytes = flatten_points(generators);
    std::vector<unsigned char> n_vec = flatten_scalars(inputs.n_vec);
    std::vector<unsigned char> l_vec = flatten_scalars(inputs.l_vec);
    std::vector<unsigned char> c_vec = flatten_scalars(inputs.c_vec);
    std::size_t proof_len = purify_bppp_required_proof_size(inputs.n_vec.size(), inputs.c_vec.size());
    PointBytes commitment{};
    Bytes proof(proof_len);

    if (proof_len == 0) {
        throw std::runtime_error("Invalid BPPP proof dimensions");
    }
    require_ok(purify_bppp_prove_norm_arg(inputs.rho.data(), generator_bytes.data(), generators.size(),
                                          n_vec.data(), inputs.n_vec.size(), l_vec.data(), inputs.l_vec.size(),
                                          c_vec.data(), inputs.c_vec.size(), commitment.data(), proof.data(), &proof_len),
               "Unable to produce BPPP norm argument");
    proof.resize(proof_len);

    return {inputs.rho, std::move(generators), inputs.c_vec, inputs.n_vec.size(), commitment, std::move(proof)};
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
