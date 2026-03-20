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
#include <memory>
#include <span>
#include <utility>
#include <vector>

#include "purify/api.hpp"

struct purify_bppp_backend_resources;

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
 * @return Serialized generator points, or a BPPP input/backend error.
 */
Result<std::vector<PointBytes>> create_generators(std::size_t count);

/**
 * @brief Computes a Pedersen commitment to an arbitrary 32-byte scalar value.
 * @param blind Blinding factor.
 * @param value Committed scalar value.
 * @param value_gen Generator used for the value term.
 * @param blind_gen Generator used for the blind term.
 * @return Serialized compressed commitment point, or a backend rejection error.
 */
Result<PointBytes> pedersen_commit_char(const ScalarBytes& blind, const ScalarBytes& value,
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

/** @brief Computes the public BPPP commitment for a standalone norm-argument input bundle. */
Result<PointBytes> commit_norm_arg(const NormArgInputs& inputs);

/** @brief Standalone BPPP norm-argument proof bundle with all verifier-side inputs. */
struct NormArgProof {
    ScalarBytes rho{};
    std::vector<PointBytes> generators;
    std::vector<ScalarBytes> c_vec;
    std::size_t n_vec_len = 0;
    PointBytes commitment{};
    Bytes proof;
};

/** @brief Caller-owned cache for reusable experimental circuit reduction and BPPP backend data. */
class ExperimentalCircuitCache {
public:
    ExperimentalCircuitCache();
    ExperimentalCircuitCache(const ExperimentalCircuitCache&) = delete;
    ExperimentalCircuitCache& operator=(const ExperimentalCircuitCache&) = delete;
    ExperimentalCircuitCache(ExperimentalCircuitCache&& other) noexcept;
    ExperimentalCircuitCache& operator=(ExperimentalCircuitCache&& other) noexcept;
    ~ExperimentalCircuitCache();

    void clear();
    [[nodiscard]] std::size_t size() const noexcept;
    /** @brief Looks up opaque cached reduction data by digest key. */
    [[nodiscard]] std::shared_ptr<const void> find_public_data(const std::array<unsigned char, 32>& key) const;
    /** @brief Stores opaque cached reduction data by digest key. */
    void insert_public_data(std::array<unsigned char, 32> key, std::shared_ptr<const void> value);
    /** @brief Returns cached backend resources for this generator set, creating them on first use. */
    [[nodiscard]] purify_bppp_backend_resources* get_or_create_backend_resources(std::span<const PointBytes> generators);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

/**
 * @brief Produces a standalone BPPP norm argument.
 * @param inputs Prover inputs and optional generators.
 * @return Proof bundle containing all verifier-side inputs, or a BPPP input/backend error.
 */
Result<NormArgProof> prove_norm_arg(const NormArgInputs& inputs);
/** @brief Produces a standalone BPPP norm argument, moving large inputs into the returned proof when possible. */
Result<NormArgProof> prove_norm_arg(NormArgInputs&& inputs);
/** @brief Produces a standalone BPPP norm argument anchored to a caller-supplied public commitment. */
Result<NormArgProof> prove_norm_arg_to_commitment(const NormArgInputs& inputs, const PointBytes& commitment);
/**
 * @brief Verifies a standalone BPPP norm argument.
 * @param proof Proof bundle returned by prove_norm_arg.
 * @return True when the proof verifies.
 */
bool verify_norm_arg(const NormArgProof& proof);

/** @brief Experimental transparent circuit proof backed by the standalone BPPP norm argument. */
struct ExperimentalCircuitNormArgProof {
    PointBytes witness_commitment{};
    Bytes proof;
};

/** @brief Experimental masked circuit proof that hides the reduced witness before the final BPPP argument. */
struct ExperimentalCircuitZkNormArgProof {
    /** @brief Witness-only outer A commitment; verifiers re-anchor it to the public statement. */
    PointBytes a_commitment{};
    PointBytes s_commitment{};
    ScalarBytes t2{};
    Bytes proof;
};

/**
 * @brief Commits to the reduced witness coordinates used by the experimental circuit-to-BPPP reduction.
 * @param circuit Native circuit to reduce.
 * @param assignment Witness assignment to commit.
 * @param statement_binding Optional statement bytes folded into the public reduction challenges.
 * @return Commitment to the reduced hidden witness coordinates.
 */
Result<PointBytes> commit_experimental_circuit_witness(
    const NativeBulletproofCircuit& circuit,
    const BulletproofAssignmentData& assignment,
    std::span<const unsigned char> statement_binding = {},
    ExperimentalCircuitCache* cache = nullptr);

/**
 * @brief Produces an anchored transparent circuit proof using the experimental circuit-to-BPPP reduction.
 * @param circuit Native circuit to reduce.
 * @param assignment Witness assignment to prove.
 * @param statement_binding Optional statement bytes folded into the public reduction challenges.
 * @return Proof carrying the reduced witness commitment and BPPP proof bytes.
 */
Result<ExperimentalCircuitNormArgProof> prove_experimental_circuit_norm_arg(
    const NativeBulletproofCircuit& circuit,
    const BulletproofAssignmentData& assignment,
    std::span<const unsigned char> statement_binding = {},
    ExperimentalCircuitCache* cache = nullptr);

/**
 * @brief Produces an anchored transparent circuit proof against a caller-supplied reduced witness commitment.
 * @param circuit Native circuit to reduce.
 * @param assignment Witness assignment to prove.
 * @param witness_commitment Public reduced witness commitment expected by the verifier.
 * @param statement_binding Optional statement bytes folded into the public reduction challenges.
 * @return Proof carrying the supplied reduced witness commitment and BPPP proof bytes.
 */
Result<ExperimentalCircuitNormArgProof> prove_experimental_circuit_norm_arg_to_commitment(
    const NativeBulletproofCircuit& circuit,
    const BulletproofAssignmentData& assignment,
    const PointBytes& witness_commitment,
    std::span<const unsigned char> statement_binding = {},
    ExperimentalCircuitCache* cache = nullptr);

/**
 * @brief Verifies an experimental transparent circuit proof produced by `prove_experimental_circuit_norm_arg`.
 * @param circuit Native circuit to reduce.
 * @param proof Reduced witness commitment plus proof bytes.
 * @param statement_binding Optional statement bytes folded into the public reduction challenges.
 * @return True when the proof verifies against the public circuit statement.
 */
Result<bool> verify_experimental_circuit_norm_arg(
    const NativeBulletproofCircuit& circuit,
    const ExperimentalCircuitNormArgProof& proof,
    std::span<const unsigned char> statement_binding = {},
    ExperimentalCircuitCache* cache = nullptr);

/**
 * @brief Produces an experimental masked circuit proof over the reduced BPPP relation.
 *
 * This wrapper is intended to mimic the outer masking strategy of Bulletproof-style protocols:
 * it commits to the reduced witness, commits to a random mask, derives a challenge, and only
 * proves the challenge-combined witness with the inner BPPP norm argument. The inner BPPP
 * implementation remains variable-time and should still be treated as experimental for secret data.
 *
 * @param circuit Native circuit to reduce.
 * @param assignment Witness assignment to prove.
 * @param nonce Deterministic prover randomness used to derive the outer masking vectors.
 * @param statement_binding Optional statement bytes folded into the public reduction challenges.
 * @return Masked proof bundle, or a reduction/backend error.
 */
Result<ExperimentalCircuitZkNormArgProof> prove_experimental_circuit_zk_norm_arg(
    const NativeBulletproofCircuit& circuit,
    const BulletproofAssignmentData& assignment,
    const ScalarBytes& nonce,
    std::span<const unsigned char> statement_binding = {},
    ExperimentalCircuitCache* cache = nullptr);

/**
 * @brief Verifies an experimental masked circuit proof produced by `prove_experimental_circuit_zk_norm_arg`.
 * @param circuit Native circuit to reduce.
 * @param proof Outer commitments plus the inner masked BPPP proof.
 * @param statement_binding Optional statement bytes folded into the public reduction challenges.
 * @return True when the masked proof verifies against the public circuit statement.
 */
Result<bool> verify_experimental_circuit_zk_norm_arg(
    const NativeBulletproofCircuit& circuit,
    const ExperimentalCircuitZkNormArgProof& proof,
    std::span<const unsigned char> statement_binding = {},
    ExperimentalCircuitCache* cache = nullptr);

/**
 * @brief Produces an experimental masked circuit proof bound to explicit public commitment points.
 *
 * This variant removes the circuit commitment scalars from the hidden reduced witness and instead
 * binds them through caller-supplied compressed secp256k1 points. Each point must equal the exact
 * public commitment `assignment.commitments[i] * G` for the matching circuit commitment wire.
 */
Result<ExperimentalCircuitZkNormArgProof> prove_experimental_circuit_zk_norm_arg_with_public_commitments(
    const NativeBulletproofCircuit& circuit,
    const BulletproofAssignmentData& assignment,
    const ScalarBytes& nonce,
    std::span<const PointBytes> public_commitments,
    std::span<const unsigned char> statement_binding = {},
    ExperimentalCircuitCache* cache = nullptr);

/**
 * @brief Verifies an experimental masked circuit proof against explicit public commitment points.
 *
 * The verifier reconstructs the anchored outer commitment from `proof.a_commitment`, the folded
 * circuit target, and the supplied public commitment points before checking the inner BPPP proof.
 */
Result<bool> verify_experimental_circuit_zk_norm_arg_with_public_commitments(
    const NativeBulletproofCircuit& circuit,
    const ExperimentalCircuitZkNormArgProof& proof,
    std::span<const PointBytes> public_commitments,
    std::span<const unsigned char> statement_binding = {},
    ExperimentalCircuitCache* cache = nullptr);

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
 * @param secret Owned Purify secret key.
 * @param blind Blinding factor for the output commitment.
 * @param value_gen Generator used for the value term.
 * @param blind_gen Generator used for the blind term.
 * @return Witness bundle extended with the serialized output commitment.
 */
Result<CommittedPurifyWitness> commit_output_witness(const Bytes& message, const SecretKey& secret,
                                                     const ScalarBytes& blind,
                                                     const GeneratorBytes& value_gen = value_generator_h(),
                                                     const GeneratorBytes& blind_gen = base_generator());

}  // namespace purify::bppp
