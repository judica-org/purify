// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include <array>
#include <cstddef>
#include <utility>
#include <vector>

extern "C" {
#include "third_party/secp256k1-zkp/include/secp256k1.h"
#include "third_party/secp256k1-zkp/include/secp256k1_bppp.h"
#include "third_party/secp256k1-zkp/include/secp256k1_generator.h"
}

#include "purify.hpp"

namespace purify::bppp {

using ScalarBytes = std::array<unsigned char, 32>;
using PointBytes = std::array<unsigned char, 33>;
using GeneratorBytes = std::array<unsigned char, 33>;

GeneratorBytes base_generator();
GeneratorBytes value_generator_h();
std::vector<PointBytes> create_generators(std::size_t count);

PointBytes pedersen_commit_char(const ScalarBytes& blind, const ScalarBytes& value,
                                const GeneratorBytes& value_gen = value_generator_h(),
                                const GeneratorBytes& blind_gen = base_generator());

inline ScalarBytes scalar_bytes(const FieldElement& value) {
    return value.to_bytes_be();
}

inline std::vector<ScalarBytes> scalar_bytes(const std::vector<FieldElement>& values) {
    std::vector<ScalarBytes> out;
    out.reserve(values.size());
    for (const FieldElement& value : values) {
        out.push_back(scalar_bytes(value));
    }
    return out;
}

struct NormArgInputs {
    ScalarBytes rho{};
    std::vector<PointBytes> generators;
    std::vector<ScalarBytes> n_vec;
    std::vector<ScalarBytes> l_vec;
    std::vector<ScalarBytes> c_vec;
};

struct NormArgProof {
    ScalarBytes rho{};
    std::vector<PointBytes> generators;
    std::vector<ScalarBytes> c_vec;
    std::size_t n_vec_len = 0;
    PointBytes commitment{};
    Bytes proof;
};

NormArgProof prove_norm_arg(const NormArgInputs& inputs);
bool verify_norm_arg(const NormArgProof& proof);

struct CommittedPurifyWitness {
    UInt512 public_key;
    FieldElement output;
    BulletproofAssignmentData assignment;
    PointBytes commitment;
};

inline CommittedPurifyWitness commit_output_witness(const Bytes& message, const UInt512& secret,
                                                    const ScalarBytes& blind,
                                                    const GeneratorBytes& value_gen = value_generator_h(),
                                                    const GeneratorBytes& blind_gen = base_generator()) {
    BulletproofWitnessData witness = prove_assignment_data(message, secret);
    return {witness.public_key, witness.output, std::move(witness.assignment),
            pedersen_commit_char(blind, scalar_bytes(witness.output), value_gen, blind_gen)};
}

}  // namespace purify::bppp
