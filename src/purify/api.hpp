// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include "purify/bulletproof.hpp"

namespace purify {

struct GeneratedKey {
    UInt512 secret;
    UInt512 public_key;
};

struct BulletproofWitnessData {
    UInt512 public_key;
    FieldElement output;
    BulletproofAssignmentData assignment;
};

inline UInt512 key_space_size() {
    static const UInt512 value = multiply(half_n1(), half_n2());
    return value;
}

inline GeneratedKey derive_key(const UInt512& secret) {
    auto unpacked = unpack_secret(secret);
    AffinePoint p1 = curve1().affine(curve1().mul(generator1(), unpacked.first));
    AffinePoint p2 = curve2().affine(curve2().mul(generator2(), unpacked.second));
    return {secret, pack_public(p1.x.to_uint256(), p2.x.to_uint256())};
}

inline FieldElement eval(const UInt512& secret, const Bytes& message) {
    auto unpacked = unpack_secret(secret);
    JacobianPoint m1 = hash_to_curve(bytes_from_ascii("Eval/1/") + message, curve1());
    JacobianPoint m2 = hash_to_curve(bytes_from_ascii("Eval/2/") + message, curve2());
    AffinePoint q1 = curve1().affine(curve1().mul(m1, unpacked.first));
    AffinePoint q2 = curve2().affine(curve2().mul(m2, unpacked.second));
    return combine(q1.x, q2.x);
}

inline std::string verifier(const Bytes& message, const UInt512& pubkey) {
    JacobianPoint m1 = hash_to_curve(bytes_from_ascii("Eval/1/") + message, curve1());
    JacobianPoint m2 = hash_to_curve(bytes_from_ascii("Eval/2/") + message, curve2());
    Transcript transcript;
    CircuitMainResult result = circuit_main(transcript, m1, m2);
    BulletproofTranscript bp;
    bp.from_transcript(transcript, result.n_bits);
    bp.add_pubkey_and_out(pubkey, result.p1x, result.p2x, result.out);
    return bp.to_string();
}

inline NativeBulletproofCircuit verifier_circuit(const Bytes& message, const UInt512& pubkey) {
    JacobianPoint m1 = hash_to_curve(bytes_from_ascii("Eval/1/") + message, curve1());
    JacobianPoint m2 = hash_to_curve(bytes_from_ascii("Eval/2/") + message, curve2());
    Transcript transcript;
    CircuitMainResult result = circuit_main(transcript, m1, m2);
    BulletproofTranscript bp;
    bp.from_transcript(transcript, result.n_bits);
    bp.add_pubkey_and_out(pubkey, result.p1x, result.p2x, result.out);
    return bp.native_circuit();
}

inline BulletproofWitnessData prove_assignment_data(const Bytes& message, const UInt512& secret) {
    auto unpacked = unpack_secret(secret);
    JacobianPoint m1 = hash_to_curve(bytes_from_ascii("Eval/1/") + message, curve1());
    JacobianPoint m2 = hash_to_curve(bytes_from_ascii("Eval/2/") + message, curve2());
    AffinePoint p1 = curve1().affine(curve1().mul(generator1(), unpacked.first));
    AffinePoint p2 = curve2().affine(curve2().mul(generator2(), unpacked.second));
    AffinePoint q1 = curve1().affine(curve1().mul(m1, unpacked.first));
    AffinePoint q2 = curve2().affine(curve2().mul(m2, unpacked.second));
    FieldElement native_out = combine(q1.x, q2.x);

    Transcript transcript;
    CircuitMainResult result = circuit_main(transcript, m1, m2, unpacked.first, unpacked.second);
    if (transcript.evaluate(result.p1x) != std::optional<FieldElement>(p1.x)) {
        throw std::runtime_error("P1x mismatch");
    }
    if (transcript.evaluate(result.p2x) != std::optional<FieldElement>(p2.x)) {
        throw std::runtime_error("P2x mismatch");
    }
    if (transcript.evaluate(result.out) != std::optional<FieldElement>(native_out)) {
        throw std::runtime_error("Output mismatch");
    }

    UInt512 pubkey = pack_public(p1.x.to_uint256(), p2.x.to_uint256());
    BulletproofTranscript bp;
    bp.from_transcript(transcript, result.n_bits);
    bp.add_pubkey_and_out(pubkey, result.p1x, result.p2x, result.out);
    if (!bp.evaluate(transcript.varmap(), native_out)) {
        throw std::runtime_error("Bulletproof transcript check failed");
    }

    auto vars = transcript.varmap();
    auto it = vars.find("V0");
    if (it == vars.end()) {
        vars.insert({"V0", native_out});
    } else {
        vars["V0"] = native_out;
    }
    return {pubkey, native_out, bp.assignment_data(vars)};
}

inline bool evaluate_verifier_circuit(const Bytes& message, const BulletproofWitnessData& witness) {
    return verifier_circuit(message, witness.public_key).evaluate(witness.assignment);
}

inline bool evaluate_verifier_circuit(const Bytes& message, const UInt512& secret) {
    return evaluate_verifier_circuit(message, prove_assignment_data(message, secret));
}

inline Bytes prove_assignment(const Bytes& message, const UInt512& secret) {
    return prove_assignment_data(message, secret).assignment.serialize();
}

}  // namespace purify
