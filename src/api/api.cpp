// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file api.cpp
 * @brief High-level Purify API implementations, including key generation and proof helpers.
 */

#include "purify/api.hpp"

#include <algorithm>
#include <cassert>

#include "purify.h"
#include "error_bridge.hpp"

namespace purify {
namespace {

Status status_from_core(purify_error_code code, const char* context) {
    if (code == PURIFY_ERROR_OK) {
        return {};
    }
    return unexpected_error(core_api_detail::from_core_error_code(code), context);
}

void clear_core_generated_key(purify_generated_key& generated) noexcept {
    detail::secure_clear_bytes(generated.secret_key, sizeof(generated.secret_key));
    std::fill(std::begin(generated.public_key), std::end(generated.public_key), 0);
}

void clear_core_bip340_key(purify_bip340_key& key) noexcept {
    detail::secure_clear_bytes(key.secret_key, sizeof(key.secret_key));
    std::fill(std::begin(key.xonly_public_key), std::end(key.xonly_public_key), 0);
}

Result<GeneratedKey> generated_key_from_core(const purify_generated_key& generated) {
    const UInt512 packed_secret = UInt512::from_bytes_be(generated.secret_key, sizeof(generated.secret_key));
    PURIFY_ASSIGN_OR_RETURN(auto owned_secret, SecretKey::from_packed(packed_secret),
                            "generated_key_from_core:from_packed");
    const UInt512 public_key = UInt512::from_bytes_be(generated.public_key, sizeof(generated.public_key));
    return GeneratedKey{std::move(owned_secret), public_key};
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
    return status_from_core(purify_fill_secure_random(bytes.data(), bytes.size()),
                            "fill_secure_random:purify_fill_secure_random");
}

Result<UInt512> random_below(const UInt512& range) {
    return random_below(range, fill_secure_random);
}

Result<GeneratedKey> generate_key() {
    purify_generated_key generated{};
    const purify_error_code code = purify_generate_key(&generated);
    if (code != PURIFY_ERROR_OK) {
        clear_core_generated_key(generated);
        return unexpected_error(core_api_detail::from_core_error_code(code), "generate_key:purify_generate_key");
    }
    Result<GeneratedKey> out = generated_key_from_core(generated);
    clear_core_generated_key(generated);
    if (!out.has_value()) {
        return unexpected_error(out.error(), "generate_key:generated_key_from_core");
    }
    return out;
}

Result<GeneratedKey> generate_key(KeySeed seed) {
    purify_generated_key generated{};
    const purify_error_code code = purify_generate_key_from_seed(&generated, seed.data(), seed.size());
    if (code != PURIFY_ERROR_OK) {
        clear_core_generated_key(generated);
        return unexpected_error(core_api_detail::from_core_error_code(code), "generate_key:purify_generate_key_from_seed");
    }
    Result<GeneratedKey> out = generated_key_from_core(generated);
    clear_core_generated_key(generated);
    if (!out.has_value()) {
        return unexpected_error(out.error(), "generate_key:generated_key_from_core");
    }
    return out;
}

Result<GeneratedKey> derive_key(const SecretKey& secret) {
    PURIFY_ASSIGN_OR_RETURN(auto owned_secret, secret.clone(), "derive_key:clone");
    return derive_key(std::move(owned_secret));
}

Result<GeneratedKey> derive_key(SecretKey&& secret) {
    std::array<unsigned char, PURIFY_SECRET_KEY_BYTES> secret_bytes = secret.packed().to_bytes_be();
    std::array<unsigned char, PURIFY_PUBLIC_KEY_BYTES> public_key_bytes{};
    const purify_error_code code = purify_derive_public_key(public_key_bytes.data(), secret_bytes.data());
    detail::secure_clear_bytes(secret_bytes.data(), secret_bytes.size());
    if (code != PURIFY_ERROR_OK) {
        std::fill(public_key_bytes.begin(), public_key_bytes.end(), 0);
        return unexpected_error(core_api_detail::from_core_error_code(code), "derive_key:purify_derive_public_key");
    }
    const UInt512 public_key = UInt512::from_bytes_be(public_key_bytes.data(), public_key_bytes.size());
    std::fill(public_key_bytes.begin(), public_key_bytes.end(), 0);
    return GeneratedKey{std::move(secret), public_key};
}

Result<Bip340Key> derive_bip340_key(const SecretKey& secret) {
    std::array<unsigned char, PURIFY_SECRET_KEY_BYTES> secret_bytes = secret.packed().to_bytes_be();
    purify_bip340_key key{};
    const purify_error_code code = purify_derive_bip340_key(&key, secret_bytes.data());
    detail::secure_clear_bytes(secret_bytes.data(), secret_bytes.size());
    if (code != PURIFY_ERROR_OK) {
        clear_core_bip340_key(key);
        return unexpected_error(core_api_detail::from_core_error_code(code), "derive_bip340_key:purify_derive_bip340_key");
    }
    Bip340Key out{};
    std::copy(std::begin(key.secret_key), std::end(key.secret_key), out.seckey.begin());
    std::copy(std::begin(key.xonly_public_key), std::end(key.xonly_public_key), out.xonly_pubkey.begin());
    clear_core_bip340_key(key);
    return out;
}

Result<FieldElement> eval(const SecretKey& secret, const Bytes& message) {
    std::array<unsigned char, PURIFY_SECRET_KEY_BYTES> secret_bytes = secret.packed().to_bytes_be();
    std::array<unsigned char, PURIFY_FIELD_ELEMENT_BYTES> output_bytes{};
    const purify_error_code code =
        purify_eval(output_bytes.data(), secret_bytes.data(), message.data(), message.size());
    detail::secure_clear_bytes(secret_bytes.data(), secret_bytes.size());
    if (code != PURIFY_ERROR_OK) {
        std::fill(output_bytes.begin(), output_bytes.end(), 0);
        return unexpected_error(core_api_detail::from_core_error_code(code), "eval:purify_eval");
    }
    return FieldElement::try_from_bytes32(output_bytes);
}

Result<std::string> verifier(const Bytes& message, const UInt512& pubkey) {
    PURIFY_ASSIGN_OR_RETURN(const auto& m1, hash_to_curve(tagged_message("Eval/1/", message), curve1()),
                            "verifier:hash_to_curve_m1");
    PURIFY_ASSIGN_OR_RETURN(const auto& m2, hash_to_curve(tagged_message("Eval/2/", message), curve2()),
                            "verifier:hash_to_curve_m2");
    Transcript transcript;
    PURIFY_ASSIGN_OR_RETURN(const auto& result, circuit_main(transcript, m1, m2), "verifier:circuit_main");
    BulletproofTranscript bp;
    PURIFY_RETURN_IF_ERROR(bp.from_transcript(transcript, result.n_bits), "verifier:from_transcript");
    PURIFY_RETURN_IF_ERROR(bp.add_pubkey_and_out(pubkey, result.p1x, result.p2x, result.out),
                           "verifier:add_pubkey_and_out");
    return bp.to_string();
}

Result<NativeBulletproofCircuit> verifier_circuit(const Bytes& message, const UInt512& pubkey) {
    PURIFY_ASSIGN_OR_RETURN(const auto& template_circuit, verifier_circuit_template(message),
                            "verifier_circuit:verifier_circuit_template");
    return template_circuit.instantiate(pubkey);
}

Result<NativeBulletproofCircuitTemplate> verifier_circuit_template(const Bytes& message) {
    PURIFY_ASSIGN_OR_RETURN(const auto& m1, hash_to_curve(tagged_message("Eval/1/", message), curve1()),
                            "verifier_circuit_template:hash_to_curve_m1");
    PURIFY_ASSIGN_OR_RETURN(const auto& m2, hash_to_curve(tagged_message("Eval/2/", message), curve2()),
                            "verifier_circuit_template:hash_to_curve_m2");
    Transcript transcript;
    PURIFY_ASSIGN_OR_RETURN(const auto& result, circuit_main(transcript, m1, m2),
                            "verifier_circuit_template:circuit_main");
    BulletproofTranscript bp;
    PURIFY_RETURN_IF_ERROR(bp.from_transcript(transcript, result.n_bits), "verifier_circuit_template:from_transcript");
    Expr p1x = result.p1x;
    Expr p2x = result.p2x;
    Expr out = result.out;
    bp.replace_expr_v_with_bp_var(p1x);
    bp.replace_expr_v_with_bp_var(p2x);
    bp.replace_expr_v_with_bp_var(out);

    NativeBulletproofCircuit base_circuit = bp.native_circuit();
    PURIFY_ASSIGN_OR_RETURN(
        auto packed,
        base_circuit.pack_with_slack(build_template_slack(base_circuit.n_gates, base_circuit.n_commitments, p1x, p2x, out)),
        "verifier_circuit_template:pack_with_slack");
    return NativeBulletproofCircuitTemplate::from_parts(std::move(packed), std::move(p1x), std::move(p2x),
                                                        std::move(out));
}

Result<BulletproofWitnessData> prove_assignment_data(const Bytes& message, const SecretKey& secret) {
    PURIFY_ASSIGN_OR_RETURN(const auto& unpacked, unpack_secret(secret.packed()), "prove_assignment_data:unpack_secret");
    PURIFY_ASSIGN_OR_RETURN(const auto& m1, hash_to_curve(tagged_message("Eval/1/", message), curve1()),
                            "prove_assignment_data:hash_to_curve_m1");
    PURIFY_ASSIGN_OR_RETURN(const auto& m2, hash_to_curve(tagged_message("Eval/2/", message), curve2()),
                            "prove_assignment_data:hash_to_curve_m2");
    PURIFY_ASSIGN_OR_RETURN(const auto& p1, curve1().mul_secret_affine(generator1(), unpacked.first),
                            "prove_assignment_data:mul_secret_affine_p1");
    PURIFY_ASSIGN_OR_RETURN(const auto& p2, curve2().mul_secret_affine(generator2(), unpacked.second),
                            "prove_assignment_data:mul_secret_affine_p2");
    PURIFY_ASSIGN_OR_RETURN(const auto& q1, curve1().mul_secret_affine(m1, unpacked.first),
                            "prove_assignment_data:mul_secret_affine_q1");
    PURIFY_ASSIGN_OR_RETURN(const auto& q2, curve2().mul_secret_affine(m2, unpacked.second),
                            "prove_assignment_data:mul_secret_affine_q2");
    FieldElement native_out = combine(q1.x, q2.x);

    Transcript transcript;
    PURIFY_ASSIGN_OR_RETURN(const auto& result, circuit_main(transcript, m1, m2, unpacked.first, unpacked.second),
                            "prove_assignment_data:circuit_main");
    if (transcript.evaluate(result.p1x) != std::optional<FieldElement>(p1.x)) {
        return unexpected_error(ErrorCode::InternalMismatch, "prove_assignment_data:p1x_mismatch");
    }
    if (transcript.evaluate(result.p2x) != std::optional<FieldElement>(p2.x)) {
        return unexpected_error(ErrorCode::InternalMismatch, "prove_assignment_data:p2x_mismatch");
    }
    if (transcript.evaluate(result.out) != std::optional<FieldElement>(native_out)) {
        return unexpected_error(ErrorCode::InternalMismatch, "prove_assignment_data:output_mismatch");
    }

    UInt512 pubkey = pack_public(p1.x.to_uint256(), p2.x.to_uint256());
    BulletproofTranscript bp;
    PURIFY_RETURN_IF_ERROR(bp.from_transcript(transcript, result.n_bits), "prove_assignment_data:from_transcript");
    PURIFY_RETURN_IF_ERROR(bp.add_pubkey_and_out(pubkey, result.p1x, result.p2x, result.out),
                           "prove_assignment_data:add_pubkey_and_out");
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
    PURIFY_ASSIGN_OR_RETURN(const auto& circuit, verifier_circuit(message, witness.public_key),
                            "evaluate_verifier_circuit:verifier_circuit");
    return circuit.evaluate(witness.assignment);
}

Result<bool> evaluate_verifier_circuit(const Bytes& message, const SecretKey& secret) {
    PURIFY_ASSIGN_OR_RETURN(const auto& witness, prove_assignment_data(message, secret),
                            "evaluate_verifier_circuit:prove_assignment_data");
    return evaluate_verifier_circuit(message, witness);
}

Result<Bytes> prove_assignment(const Bytes& message, const SecretKey& secret) {
    PURIFY_ASSIGN_OR_RETURN(const auto& witness, prove_assignment_data(message, secret), "prove_assignment:prove_assignment_data");
    Result<Bytes> serialized = witness.assignment.serialize();
    assert(serialized.has_value() && "prove_assignment() should serialize a well-formed assignment");
    if (!serialized.has_value()) {
        return unexpected_error(ErrorCode::InternalMismatch, "prove_assignment:serialize_assignment");
    }
    return serialized;
}

}  // namespace purify
