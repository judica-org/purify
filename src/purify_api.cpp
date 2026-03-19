// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file purify_api.cpp
 * @brief High-level Purify API implementations, including key generation and proof helpers.
 */

#include "purify/api.hpp"

#include <algorithm>
#include <cassert>
#include <cerrno>
#include <cstdlib>
#include <fstream>

#if defined(_WIN32)
#include <bcrypt.h>
#elif defined(__linux__)
#include <sys/random.h>
#include <unistd.h>
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <unistd.h>
#else
#include <unistd.h>
#endif

namespace purify {
namespace {

const UInt256& secp256k1_order() {
    static const UInt256 value =
        UInt256::from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    return value;
}

const UInt256& secp256k1_order_minus_one() {
    static const UInt256 value = [] {
        UInt256 out = secp256k1_order();
        out.sub_assign(UInt256::one());
        return out;
    }();
    return value;
}

Bytes tagged_message(std::string_view prefix, const Bytes& message) {
    Bytes out;
    out.reserve(prefix.size() + message.size());
    out.insert(out.end(), prefix.begin(), prefix.end());
    out.insert(out.end(), message.begin(), message.end());
    return out;
}

void add_expr_slack(NativeBulletproofCircuit::PackedSlackPlan& slack, const Expr& expr) {
    for (const auto& term : expr.linear()) {
        switch (term.first.kind) {
        case SymbolKind::Left:
            if (term.first.index < slack.wl.size()) {
                ++slack.wl[term.first.index];
            }
            break;
        case SymbolKind::Right:
            if (term.first.index < slack.wr.size()) {
                ++slack.wr[term.first.index];
            }
            break;
        case SymbolKind::Output:
            if (term.first.index < slack.wo.size()) {
                ++slack.wo[term.first.index];
            }
            break;
        case SymbolKind::Commitment:
            if (term.first.index < slack.wv.size()) {
                ++slack.wv[term.first.index];
            }
            break;
        case SymbolKind::Witness:
            assert(false && "verifier_circuit_template should not pack raw witness symbols");
            break;
        }
    }
}

NativeBulletproofCircuit::PackedSlackPlan build_template_slack(std::size_t n_gates, std::size_t n_commitments,
                                                               const Expr& p1x, const Expr& p2x, const Expr& out) {
    NativeBulletproofCircuit::PackedSlackPlan slack;
    slack.constraint_slack = 3;
    slack.wl.assign(n_gates, 0);
    slack.wr.assign(n_gates, 0);
    slack.wo.assign(n_gates, 0);
    slack.wv.assign(n_commitments, 0);
    add_expr_slack(slack, p1x.split().second);
    add_expr_slack(slack, p2x.split().second);
    add_expr_slack(slack, out);
    if (!slack.wv.empty()) {
        ++slack.wv[0];
    }
    return slack;
}

}  // namespace

Status fill_secure_random(std::span<unsigned char> bytes) noexcept {
#if defined(_WIN32)
    unsigned char* out = bytes.data();
    std::size_t size = bytes.size();
    while (size != 0) {
        ULONG chunk = static_cast<ULONG>(std::min<std::size_t>(size, static_cast<std::size_t>(0xFFFFFFFFu)));
        NTSTATUS status = BCryptGenRandom(nullptr, out, chunk, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (status < 0) {
            return unexpected_error(ErrorCode::EntropyUnavailable, "fill_secure_random:bcrypt");
        }
        out += chunk;
        size -= chunk;
    }
    return {};
#elif defined(__linux__)
    unsigned char* out = bytes.data();
    std::size_t size = bytes.size();
    while (size != 0) {
        ssize_t written = getrandom(out, size, 0);
        if (written > 0) {
            out += static_cast<std::size_t>(written);
            size -= static_cast<std::size_t>(written);
            continue;
        }
        if (written < 0 && errno == EINTR) {
            continue;
        }
        return unexpected_error(ErrorCode::EntropyUnavailable, "fill_secure_random:getrandom");
    }
    return {};
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
    arc4random_buf(bytes.data(), bytes.size());
    return {};
#else
    std::ifstream file("/dev/urandom", std::ios::binary);
    if (!file) {
        return unexpected_error(ErrorCode::EntropyUnavailable, "fill_secure_random:open_urandom");
    }
    file.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!file) {
        return unexpected_error(ErrorCode::EntropyUnavailable, "fill_secure_random:read_urandom");
    }
    return {};
#endif
}

Result<UInt512> random_below(const UInt512& range) {
    return random_below(range, fill_secure_random);
}

Result<GeneratedKey> generate_key() {
    Result<UInt512> secret = random_below(key_space_size());
    if (!secret.has_value()) {
        return unexpected_error(secret.error(), "generate_key:random_below");
    }
    return derive_key(*secret);
}

Result<GeneratedKey> generate_key(KeySeed seed) {
    Bytes seed_bytes(seed.begin(), seed.end());
    std::optional<UInt512> secret = hash_to_int<8>(seed_bytes, key_space_size(), bytes_from_ascii("Purify/KeyGen"));
    if (!secret.has_value()) {
        return unexpected_error(ErrorCode::InternalMismatch, "generate_key:hash_to_int_seed");
    }
    return derive_key(*secret);
}

Result<GeneratedKey> derive_key(const UInt512& secret) {
    Result<std::pair<UInt256, UInt256>> unpacked = unpack_secret(secret);
    if (!unpacked.has_value()) {
        return unexpected_error(unpacked.error(), "derive_key:unpack_secret");
    }
    Result<AffinePoint> p1 = curve1().mul_secret_affine(generator1(), unpacked->first);
    if (!p1.has_value()) {
        return unexpected_error(p1.error(), "derive_key:mul_secret_affine_p1");
    }
    Result<AffinePoint> p2 = curve2().mul_secret_affine(generator2(), unpacked->second);
    if (!p2.has_value()) {
        return unexpected_error(p2.error(), "derive_key:mul_secret_affine_p2");
    }
    return GeneratedKey{secret, pack_public(p1->x.to_uint256(), p2->x.to_uint256())};
}

Result<Bip340Key> derive_bip340_key(const UInt512& secret) {
    Status status = validate_secret_key(secret);
    if (!status.has_value()) {
        return unexpected_error(status.error(), "derive_bip340_key:validate_secret_key");
    }

    std::array<unsigned char, 64> packed_secret = secret.to_bytes_be();
    Bytes ikm(packed_secret.begin(), packed_secret.end());
    std::optional<UInt256> scalar =
        hash_to_int<4>(ikm, secp256k1_order_minus_one(), bytes_from_ascii("Purify/BIP340/KeyGen"));
    if (!scalar.has_value()) {
        return unexpected_error(ErrorCode::InternalMismatch, "derive_bip340_key:hash_to_int");
    }
    scalar->add_small(1);

    Bip340Key out{};
    out.seckey = scalar->to_bytes_be();
    if (purify_bip340_key_from_seckey(out.seckey.data(), out.xonly_pubkey.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput, "derive_bip340_key:bip340_bridge");
    }
    return out;
}

Result<FieldElement> eval(const UInt512& secret, const Bytes& message) {
    Result<std::pair<UInt256, UInt256>> unpacked = unpack_secret(secret);
    if (!unpacked.has_value()) {
        return unexpected_error(unpacked.error(), "eval:unpack_secret");
    }
    Result<JacobianPoint> m1 = hash_to_curve(tagged_message("Eval/1/", message), curve1());
    if (!m1.has_value()) {
        return unexpected_error(m1.error(), "eval:hash_to_curve_m1");
    }
    Result<JacobianPoint> m2 = hash_to_curve(tagged_message("Eval/2/", message), curve2());
    if (!m2.has_value()) {
        return unexpected_error(m2.error(), "eval:hash_to_curve_m2");
    }
    Result<AffinePoint> q1 = curve1().mul_secret_affine(*m1, unpacked->first);
    if (!q1.has_value()) {
        return unexpected_error(q1.error(), "eval:mul_secret_affine_q1");
    }
    Result<AffinePoint> q2 = curve2().mul_secret_affine(*m2, unpacked->second);
    if (!q2.has_value()) {
        return unexpected_error(q2.error(), "eval:mul_secret_affine_q2");
    }
    return combine(q1->x, q2->x);
}

Result<std::string> verifier(const Bytes& message, const UInt512& pubkey) {
    Result<JacobianPoint> m1 = hash_to_curve(tagged_message("Eval/1/", message), curve1());
    if (!m1.has_value()) {
        return unexpected_error(m1.error(), "verifier:hash_to_curve_m1");
    }
    Result<JacobianPoint> m2 = hash_to_curve(tagged_message("Eval/2/", message), curve2());
    if (!m2.has_value()) {
        return unexpected_error(m2.error(), "verifier:hash_to_curve_m2");
    }
    Transcript transcript;
    Result<CircuitMainResult> result = circuit_main(transcript, *m1, *m2);
    if (!result.has_value()) {
        return unexpected_error(result.error(), "verifier:circuit_main");
    }
    BulletproofTranscript bp;
    Status transcript_status = bp.from_transcript(transcript, result->n_bits);
    if (!transcript_status.has_value()) {
        return unexpected_error(transcript_status.error(), "verifier:from_transcript");
    }
    Status pubkey_status = bp.add_pubkey_and_out(pubkey, result->p1x, result->p2x, result->out);
    if (!pubkey_status.has_value()) {
        return unexpected_error(pubkey_status.error(), "verifier:add_pubkey_and_out");
    }
    return bp.to_string();
}

Result<NativeBulletproofCircuit> verifier_circuit(const Bytes& message, const UInt512& pubkey) {
    Result<NativeBulletproofCircuitTemplate> template_circuit = verifier_circuit_template(message);
    if (!template_circuit.has_value()) {
        return unexpected_error(template_circuit.error(), "verifier_circuit:verifier_circuit_template");
    }
    return template_circuit->instantiate(pubkey);
}

Result<NativeBulletproofCircuitTemplate> verifier_circuit_template(const Bytes& message) {
    Result<JacobianPoint> m1 = hash_to_curve(tagged_message("Eval/1/", message), curve1());
    if (!m1.has_value()) {
        return unexpected_error(m1.error(), "verifier_circuit_template:hash_to_curve_m1");
    }
    Result<JacobianPoint> m2 = hash_to_curve(tagged_message("Eval/2/", message), curve2());
    if (!m2.has_value()) {
        return unexpected_error(m2.error(), "verifier_circuit_template:hash_to_curve_m2");
    }
    Transcript transcript;
    Result<CircuitMainResult> result = circuit_main(transcript, *m1, *m2);
    if (!result.has_value()) {
        return unexpected_error(result.error(), "verifier_circuit_template:circuit_main");
    }
    BulletproofTranscript bp;
    Status transcript_status = bp.from_transcript(transcript, result->n_bits);
    if (!transcript_status.has_value()) {
        return unexpected_error(transcript_status.error(), "verifier_circuit_template:from_transcript");
    }
    Expr p1x = result->p1x;
    Expr p2x = result->p2x;
    Expr out = result->out;
    bp.replace_expr_v_with_bp_var(p1x);
    bp.replace_expr_v_with_bp_var(p2x);
    bp.replace_expr_v_with_bp_var(out);

    NativeBulletproofCircuitTemplate template_circuit;
    NativeBulletproofCircuit base_circuit = bp.native_circuit();
    Result<NativeBulletproofCircuit::PackedWithSlack> packed =
        base_circuit.pack_with_slack(build_template_slack(base_circuit.n_gates, base_circuit.n_commitments, p1x, p2x, out));
    if (!packed.has_value()) {
        return unexpected_error(packed.error(), "verifier_circuit_template:pack_with_slack");
    }
    template_circuit.base_packed_ = std::move(*packed);
    template_circuit.p1x_ = std::move(p1x);
    template_circuit.p2x_ = std::move(p2x);
    template_circuit.out_ = std::move(out);
    return template_circuit;
}

Result<BulletproofWitnessData> prove_assignment_data(const Bytes& message, const UInt512& secret) {
    Result<std::pair<UInt256, UInt256>> unpacked = unpack_secret(secret);
    if (!unpacked.has_value()) {
        return unexpected_error(unpacked.error(), "prove_assignment_data:unpack_secret");
    }
    Result<JacobianPoint> m1 = hash_to_curve(tagged_message("Eval/1/", message), curve1());
    if (!m1.has_value()) {
        return unexpected_error(m1.error(), "prove_assignment_data:hash_to_curve_m1");
    }
    Result<JacobianPoint> m2 = hash_to_curve(tagged_message("Eval/2/", message), curve2());
    if (!m2.has_value()) {
        return unexpected_error(m2.error(), "prove_assignment_data:hash_to_curve_m2");
    }
    Result<AffinePoint> p1 = curve1().mul_secret_affine(generator1(), unpacked->first);
    if (!p1.has_value()) {
        return unexpected_error(p1.error(), "prove_assignment_data:mul_secret_affine_p1");
    }
    Result<AffinePoint> p2 = curve2().mul_secret_affine(generator2(), unpacked->second);
    if (!p2.has_value()) {
        return unexpected_error(p2.error(), "prove_assignment_data:mul_secret_affine_p2");
    }
    Result<AffinePoint> q1 = curve1().mul_secret_affine(*m1, unpacked->first);
    if (!q1.has_value()) {
        return unexpected_error(q1.error(), "prove_assignment_data:mul_secret_affine_q1");
    }
    Result<AffinePoint> q2 = curve2().mul_secret_affine(*m2, unpacked->second);
    if (!q2.has_value()) {
        return unexpected_error(q2.error(), "prove_assignment_data:mul_secret_affine_q2");
    }
    FieldElement native_out = combine(q1->x, q2->x);

    Transcript transcript;
    Result<CircuitMainResult> result = circuit_main(transcript, *m1, *m2, unpacked->first, unpacked->second);
    if (!result.has_value()) {
        return unexpected_error(result.error(), "prove_assignment_data:circuit_main");
    }
    if (transcript.evaluate(result->p1x) != std::optional<FieldElement>(p1->x)) {
        return unexpected_error(ErrorCode::InternalMismatch, "prove_assignment_data:p1x_mismatch");
    }
    if (transcript.evaluate(result->p2x) != std::optional<FieldElement>(p2->x)) {
        return unexpected_error(ErrorCode::InternalMismatch, "prove_assignment_data:p2x_mismatch");
    }
    if (transcript.evaluate(result->out) != std::optional<FieldElement>(native_out)) {
        return unexpected_error(ErrorCode::InternalMismatch, "prove_assignment_data:output_mismatch");
    }

    UInt512 pubkey = pack_public(p1->x.to_uint256(), p2->x.to_uint256());
    BulletproofTranscript bp;
    Status transcript_status = bp.from_transcript(transcript, result->n_bits);
    if (!transcript_status.has_value()) {
        return unexpected_error(transcript_status.error(), "prove_assignment_data:from_transcript");
    }
    Status pubkey_status = bp.add_pubkey_and_out(pubkey, result->p1x, result->p2x, result->out);
    if (!pubkey_status.has_value()) {
        return unexpected_error(pubkey_status.error(), "prove_assignment_data:add_pubkey_and_out");
    }
    if (!bp.evaluate(transcript.varmap(), native_out)) {
        return unexpected_error(ErrorCode::TranscriptCheckFailed, "prove_assignment_data:transcript_check");
    }

    Result<BulletproofAssignmentData> assignment = bp.assignment_data(transcript.varmap(), native_out);
    assert(assignment.has_value() && "prove_assignment_data() should materialize a complete assignment");
    if (!assignment.has_value()) {
        return unexpected_error(ErrorCode::InternalMismatch, "prove_assignment_data:assignment_data");
    }
    return BulletproofWitnessData{pubkey, native_out, std::move(*assignment)};
}

Result<bool> evaluate_verifier_circuit(const Bytes& message, const BulletproofWitnessData& witness) {
    Result<NativeBulletproofCircuit> circuit = verifier_circuit(message, witness.public_key);
    if (!circuit.has_value()) {
        return unexpected_error(circuit.error(), "evaluate_verifier_circuit:verifier_circuit");
    }
    return circuit->evaluate(witness.assignment);
}

Result<bool> evaluate_verifier_circuit(const Bytes& message, const UInt512& secret) {
    Result<BulletproofWitnessData> witness = prove_assignment_data(message, secret);
    if (!witness.has_value()) {
        return unexpected_error(witness.error(), "evaluate_verifier_circuit:prove_assignment_data");
    }
    return evaluate_verifier_circuit(message, *witness);
}

Result<Bytes> prove_assignment(const Bytes& message, const UInt512& secret) {
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
