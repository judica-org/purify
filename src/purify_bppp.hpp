// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file purify_bppp.hpp
 * @brief C++ wrappers for the BPPP functionality used by Purify.
 */

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

/** @brief Big-endian 32-byte scalar encoding. */
using ScalarBytes = std::array<unsigned char, 32>;
/** @brief Compressed 33-byte curve-point encoding. */
using PointBytes = std::array<unsigned char, 33>;
/** @brief Serialized generator encoding used by the BPPP bridge. */
using GeneratorBytes = std::array<unsigned char, 33>;

/** @brief Returns the serialized secp256k1 base generator used as the blind generator. */
GeneratorBytes base_generator();
/** @brief Returns the serialized alternate generator used for committed values. */
GeneratorBytes value_generator_h();
/**
 * @brief Expands the BPPP generator list.
 * @param count Number of generators requested.
 * @return Serialized generator points.
 */
std::vector<PointBytes> create_generators(std::size_t count);

/**
 * @brief Computes a Pedersen commitment to an arbitrary 32-byte scalar value.
 * @param blind Blinding factor.
 * @param value Committed scalar value.
 * @param value_gen Generator used for the value term.
 * @param blind_gen Generator used for the blind term.
 * @return Serialized compressed commitment point.
 */
PointBytes pedersen_commit_char(const ScalarBytes& blind, const ScalarBytes& value,
                                const GeneratorBytes& value_gen = value_generator_h(),
                                const GeneratorBytes& blind_gen = base_generator());

/**
 * @brief Serializes a Purify field element into the scalar encoding expected by the BPPP bridge.
 * @param value Field element to serialize.
 * @return Big-endian scalar bytes.
 */
inline ScalarBytes scalar_bytes(const FieldElement& value) {
    return value.to_bytes_be();
}

/**
 * @brief Serializes a vector of Purify field elements into BPPP scalar encodings.
 * @param values Field elements to serialize.
 * @return Serialized scalar vector.
 */
inline std::vector<ScalarBytes> scalar_bytes(const std::vector<FieldElement>& values) {
    std::vector<ScalarBytes> out;
    out.reserve(values.size());
    for (const FieldElement& value : values) {
        out.push_back(scalar_bytes(value));
    }
    return out;
}

/** @brief Inputs required to produce a standalone BPPP norm argument. */
struct NormArgInputs {
    ScalarBytes rho{};
    std::vector<PointBytes> generators;
    std::vector<ScalarBytes> n_vec;
    std::vector<ScalarBytes> l_vec;
    std::vector<ScalarBytes> c_vec;
};

/** @brief Standalone BPPP norm-argument proof bundle with all verifier-side inputs. */
struct NormArgProof {
    ScalarBytes rho{};
    std::vector<PointBytes> generators;
    std::vector<ScalarBytes> c_vec;
    std::size_t n_vec_len = 0;
    PointBytes commitment{};
    Bytes proof;
};

/**
 * @brief Produces a standalone BPPP norm argument.
 * @param inputs Prover inputs and optional generators.
 * @return Proof bundle containing all verifier-side inputs.
 */
NormArgProof prove_norm_arg(const NormArgInputs& inputs);
/**
 * @brief Verifies a standalone BPPP norm argument.
 * @param proof Proof bundle returned by prove_norm_arg.
 * @return True when the proof verifies.
 */
bool verify_norm_arg(const NormArgProof& proof);

/** @brief Purify witness bundle together with a Pedersen commitment to the output. */
struct CommittedPurifyWitness {
    UInt512 public_key;
    FieldElement output;
    BulletproofAssignmentData assignment;
    PointBytes commitment;
};

/**
 * @brief Evaluates Purify, derives its witness, and commits to the output.
 * @param message Message to evaluate.
 * @param secret Packed secret scalar pair.
 * @param blind Blinding factor for the output commitment.
 * @param value_gen Generator used for the value term.
 * @param blind_gen Generator used for the blind term.
 * @return Witness bundle extended with the serialized output commitment.
 */
inline CommittedPurifyWitness commit_output_witness(const Bytes& message, const UInt512& secret,
                                                    const ScalarBytes& blind,
                                                    const GeneratorBytes& value_gen = value_generator_h(),
                                                    const GeneratorBytes& blind_gen = base_generator()) {
    BulletproofWitnessData witness = prove_assignment_data(message, secret);
    return {witness.public_key, witness.output, std::move(witness.assignment),
            pedersen_commit_char(blind, scalar_bytes(witness.output), value_gen, blind_gen)};
}

}  // namespace purify::bppp
