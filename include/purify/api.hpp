// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file api.hpp
 * @brief High-level Purify key generation, evaluation, witness generation, and circuit helpers.
 */

#pragma once

#include "purify/bulletproof.hpp"

namespace purify {

/** @brief Derived Purify keypair in packed integer form. */
struct GeneratedKey {
    UInt512 secret;
    UInt512 public_key;
};

/** @brief Complete witness bundle for evaluating and proving a Purify instance. */
struct BulletproofWitnessData {
    UInt512 public_key;
    FieldElement output;
    BulletproofAssignmentData assignment;
};

/** @brief Returns the size of the packed Purify secret-key space. */
inline UInt512 key_space_size() {
    static const UInt512 value = multiply(half_n1(), half_n2());
    return value;
}

/**
 * @brief Derives the packed public key corresponding to a packed secret.
 * @param secret Packed secret scalar pair.
 * @return Derived keypair bundle.
 */
inline GeneratedKey derive_key(const UInt512& secret) {
    auto unpacked = unpack_secret(secret);
    AffinePoint p1 = curve1().affine(curve1().mul(generator1(), unpacked.first));
    AffinePoint p2 = curve2().affine(curve2().mul(generator2(), unpacked.second));
    return {secret, pack_public(p1.x.to_uint256(), p2.x.to_uint256())};
}

/**
 * @brief Evaluates the Purify PRF for a packed secret and message.
 * @param secret Packed secret scalar pair.
 * @param message Message bytes to evaluate.
 * @return Purify output as a field element, or `ErrorCode::HashToCurveExhausted`.
 */
inline Result<FieldElement> eval(const UInt512& secret, const Bytes& message) {
    auto unpacked = unpack_secret(secret);
    Result<JacobianPoint> m1 = hash_to_curve(bytes_from_ascii("Eval/1/") + message, curve1());
    if (!m1.has_value()) {
        return unexpected_error(m1.error(), "eval:hash_to_curve_m1");
    }
    Result<JacobianPoint> m2 = hash_to_curve(bytes_from_ascii("Eval/2/") + message, curve2());
    if (!m2.has_value()) {
        return unexpected_error(m2.error(), "eval:hash_to_curve_m2");
    }
    AffinePoint q1 = curve1().affine(curve1().mul(*m1, unpacked.first));
    AffinePoint q2 = curve2().affine(curve2().mul(*m2, unpacked.second));
    return combine(q1.x, q2.x);
}

/**
 * @brief Builds the legacy serialized verifier description for a message and public key.
 * @param message Message bytes baked into the verifier.
 * @param pubkey Packed public key.
 * @return Serialized verifier program, or `ErrorCode::HashToCurveExhausted`.
 */
inline Result<std::string> verifier(const Bytes& message, const UInt512& pubkey) {
    Result<JacobianPoint> m1 = hash_to_curve(bytes_from_ascii("Eval/1/") + message, curve1());
    if (!m1.has_value()) {
        return unexpected_error(m1.error(), "verifier:hash_to_curve_m1");
    }
    Result<JacobianPoint> m2 = hash_to_curve(bytes_from_ascii("Eval/2/") + message, curve2());
    if (!m2.has_value()) {
        return unexpected_error(m2.error(), "verifier:hash_to_curve_m2");
    }
    Transcript transcript;
    CircuitMainResult result = circuit_main(transcript, *m1, *m2);
    BulletproofTranscript bp;
    bp.from_transcript(transcript, result.n_bits);
    bp.add_pubkey_and_out(pubkey, result.p1x, result.p2x, result.out);
    return bp.to_string();
}

/**
 * @brief Builds the native verifier circuit for a message and public key.
 * @param message Message bytes baked into the circuit.
 * @param pubkey Packed public key.
 * @return Native circuit object ready for evaluation or proving, or `ErrorCode::HashToCurveExhausted`.
 */
inline Result<NativeBulletproofCircuit> verifier_circuit(const Bytes& message, const UInt512& pubkey) {
    Result<JacobianPoint> m1 = hash_to_curve(bytes_from_ascii("Eval/1/") + message, curve1());
    if (!m1.has_value()) {
        return unexpected_error(m1.error(), "verifier_circuit:hash_to_curve_m1");
    }
    Result<JacobianPoint> m2 = hash_to_curve(bytes_from_ascii("Eval/2/") + message, curve2());
    if (!m2.has_value()) {
        return unexpected_error(m2.error(), "verifier_circuit:hash_to_curve_m2");
    }
    Transcript transcript;
    CircuitMainResult result = circuit_main(transcript, *m1, *m2);
    BulletproofTranscript bp;
    bp.from_transcript(transcript, result.n_bits);
    bp.add_pubkey_and_out(pubkey, result.p1x, result.p2x, result.out);
    return bp.native_circuit();
}

/**
 * @brief Computes the native Purify witness for a message and secret.
 * @param message Message bytes to evaluate.
 * @param secret Packed secret scalar pair.
 * @return Witness bundle containing public key, output, and assignment columns, or `ErrorCode::HashToCurveExhausted`.
 */
inline Result<BulletproofWitnessData> prove_assignment_data(const Bytes& message, const UInt512& secret) {
    auto unpacked = unpack_secret(secret);
    Result<JacobianPoint> m1 = hash_to_curve(bytes_from_ascii("Eval/1/") + message, curve1());
    if (!m1.has_value()) {
        return unexpected_error(m1.error(), "prove_assignment_data:hash_to_curve_m1");
    }
    Result<JacobianPoint> m2 = hash_to_curve(bytes_from_ascii("Eval/2/") + message, curve2());
    if (!m2.has_value()) {
        return unexpected_error(m2.error(), "prove_assignment_data:hash_to_curve_m2");
    }
    AffinePoint p1 = curve1().affine(curve1().mul(generator1(), unpacked.first));
    AffinePoint p2 = curve2().affine(curve2().mul(generator2(), unpacked.second));
    AffinePoint q1 = curve1().affine(curve1().mul(*m1, unpacked.first));
    AffinePoint q2 = curve2().affine(curve2().mul(*m2, unpacked.second));
    FieldElement native_out = combine(q1.x, q2.x);

    Transcript transcript;
    CircuitMainResult result = circuit_main(transcript, *m1, *m2, unpacked.first, unpacked.second);
    assert(transcript.evaluate(result.p1x) == std::optional<FieldElement>(p1.x) && "prove_assignment_data() p1x mismatch");
    assert(transcript.evaluate(result.p2x) == std::optional<FieldElement>(p2.x) && "prove_assignment_data() p2x mismatch");
    assert(transcript.evaluate(result.out) == std::optional<FieldElement>(native_out) && "prove_assignment_data() output mismatch");

    UInt512 pubkey = pack_public(p1.x.to_uint256(), p2.x.to_uint256());
    BulletproofTranscript bp;
    bp.from_transcript(transcript, result.n_bits);
    bp.add_pubkey_and_out(pubkey, result.p1x, result.p2x, result.out);
    assert(bp.evaluate(transcript.varmap(), native_out) && "prove_assignment_data() transcript self-check failed");

    auto vars = transcript.varmap();
    auto it = vars.find("V0");
    if (it == vars.end()) {
        vars.insert({"V0", native_out});
    } else {
        vars["V0"] = native_out;
    }
    Result<BulletproofAssignmentData> assignment = bp.assignment_data(vars);
    assert(assignment.has_value() && "prove_assignment_data() should materialize a complete assignment");
    if (!assignment.has_value()) {
        return unexpected_error(ErrorCode::InternalMismatch, "prove_assignment_data:assignment_data");
    }
    return BulletproofWitnessData{pubkey, native_out, std::move(*assignment)};
}

/**
 * @brief Evaluates the generated verifier circuit against an explicit witness.
 * @param message Message baked into the verifier circuit.
 * @param witness Witness bundle to validate.
 * @return True when the witness satisfies the circuit, or `ErrorCode::HashToCurveExhausted`.
 */
inline Result<bool> evaluate_verifier_circuit(const Bytes& message, const BulletproofWitnessData& witness) {
    Result<NativeBulletproofCircuit> circuit = verifier_circuit(message, witness.public_key);
    if (!circuit.has_value()) {
        return unexpected_error(circuit.error(), "evaluate_verifier_circuit:verifier_circuit");
    }
    return circuit->evaluate(witness.assignment);
}

/**
 * @brief Evaluates the generated verifier circuit using a witness derived from a secret.
 * @param message Message baked into the verifier circuit.
 * @param secret Packed secret scalar pair.
 * @return True when the derived witness satisfies the circuit, or `ErrorCode::HashToCurveExhausted`.
 */
inline Result<bool> evaluate_verifier_circuit(const Bytes& message, const UInt512& secret) {
    Result<BulletproofWitnessData> witness = prove_assignment_data(message, secret);
    if (!witness.has_value()) {
        return unexpected_error(witness.error(), "evaluate_verifier_circuit:prove_assignment_data");
    }
    return evaluate_verifier_circuit(message, *witness);
}

/**
 * @brief Serializes the witness assignment produced for a message and secret.
 * @param message Message bytes to evaluate.
 * @param secret Packed secret scalar pair.
 * @return Serialized witness blob compatible with the legacy assignment format, or `ErrorCode::HashToCurveExhausted`.
 */
inline Result<Bytes> prove_assignment(const Bytes& message, const UInt512& secret) {
    Result<BulletproofWitnessData> witness = prove_assignment_data(message, secret);
    if (!witness.has_value()) {
        return unexpected_error(witness.error(), "prove_assignment:prove_assignment_data");
    }
    Result<Bytes> serialized = witness->assignment.serialize();
    assert(serialized.has_value() && "prove_assignment() should serialize a well-formed assignment");
    if (!serialized.has_value()) {
        return unexpected_error(ErrorCode::InternalMismatch, "prove_assignment:serialize_assignment");
    }
    return serialized;
}

}  // namespace purify
