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
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
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

Result<UInt512> derive_public_key_from_secret(const UInt512& secret) {
    PURIFY_ASSIGN_OR_RETURN(const auto& unpacked, unpack_secret(secret), "derive_public_key_from_secret:unpack_secret");
    PURIFY_ASSIGN_OR_RETURN(const auto& p1, curve1().mul_secret_affine(generator1(), unpacked.first),
                            "derive_public_key_from_secret:mul_secret_affine_p1");
    PURIFY_ASSIGN_OR_RETURN(const auto& p2, curve2().mul_secret_affine(generator2(), unpacked.second),
                            "derive_public_key_from_secret:mul_secret_affine_p2");
    return pack_public(p1.x.to_uint256(), p2.x.to_uint256());
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
    PURIFY_ASSIGN_OR_RETURN(const auto& secret, random_below(key_space_size()), "generate_key:random_below");
    PURIFY_ASSIGN_OR_RETURN(auto owned_secret, SecretKey::from_packed(secret), "generate_key:from_packed_secret");
    return derive_key(std::move(owned_secret));
}

Result<GeneratedKey> generate_key(KeySeed seed) {
    Bytes seed_bytes(seed.begin(), seed.end());
    std::optional<UInt512> secret = hash_to_int<8>(seed_bytes, key_space_size(), bytes_from_ascii("Purify/KeyGen"));
    if (!secret.has_value()) {
        return unexpected_error(ErrorCode::InternalMismatch, "generate_key:hash_to_int_seed");
    }
    PURIFY_ASSIGN_OR_RETURN(auto owned_secret, SecretKey::from_packed(*secret), "generate_key:from_packed_seed_secret");
    return derive_key(std::move(owned_secret));
}

Result<GeneratedKey> derive_key(const SecretKey& secret) {
    PURIFY_ASSIGN_OR_RETURN(auto owned_secret, secret.clone(), "derive_key:clone");
    return derive_key(std::move(owned_secret));
}

Result<GeneratedKey> derive_key(SecretKey&& secret) {
    PURIFY_ASSIGN_OR_RETURN(const auto& public_key, derive_public_key_from_secret(secret.packed()),
                            "derive_key:derive_public_key_from_secret");
    return GeneratedKey{std::move(secret), public_key};
}

Result<Bip340Key> derive_bip340_key(const SecretKey& secret) {
    static const TaggedHash kBip340KeyGenTag("Purify/BIP340/KeyGen");
    std::array<unsigned char, 64> packed_secret = secret.packed().to_bytes_be();
    Bytes ikm(packed_secret.begin(), packed_secret.end());
#if PURIFY_USE_LEGACY_FIELD_HASHES
    std::optional<UInt256> scalar =
        hash_to_int<4>(ikm, secp256k1_order_minus_one(), bytes_from_ascii("Purify/BIP340/KeyGen"));
#else
    std::optional<UInt256> scalar = tagged_hash_to_int<4>(
        std::span<const unsigned char>(ikm.data(), ikm.size()), secp256k1_order_minus_one(), kBip340KeyGenTag);
#endif
    detail::secure_clear_bytes(ikm.data(), ikm.size());
    detail::secure_clear_bytes(packed_secret.data(), packed_secret.size());
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

Result<FieldElement> eval(const SecretKey& secret, const Bytes& message) {
    PURIFY_ASSIGN_OR_RETURN(const auto& unpacked, unpack_secret(secret.packed()), "eval:unpack_secret");
    PURIFY_ASSIGN_OR_RETURN(const auto& m1, hash_to_curve(tagged_message("Eval/1/", message), curve1()),
                            "eval:hash_to_curve_m1");
    PURIFY_ASSIGN_OR_RETURN(const auto& m2, hash_to_curve(tagged_message("Eval/2/", message), curve2()),
                            "eval:hash_to_curve_m2");
    PURIFY_ASSIGN_OR_RETURN(const auto& q1, curve1().mul_secret_affine(m1, unpacked.first), "eval:mul_secret_affine_q1");
    PURIFY_ASSIGN_OR_RETURN(const auto& q2, curve2().mul_secret_affine(m2, unpacked.second), "eval:mul_secret_affine_q2");
    return combine(q1.x, q2.x);
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

Result<NativeBulletproofCircuit> verifier_circuit(const Bytes& message, const UInt512& pubkey,
                                                  bool no_padding) {
    PURIFY_ASSIGN_OR_RETURN(const auto& template_circuit, verifier_circuit_template(message, no_padding),
                            "verifier_circuit:verifier_circuit_template");
    return template_circuit.instantiate(pubkey);
}

Result<NativeBulletproofCircuitTemplate> verifier_circuit_template(const Bytes& message, bool no_padding) {
    PURIFY_ASSIGN_OR_RETURN(const auto& m1, hash_to_curve(tagged_message("Eval/1/", message), curve1()),
                            "verifier_circuit_template:hash_to_curve_m1");
    PURIFY_ASSIGN_OR_RETURN(const auto& m2, hash_to_curve(tagged_message("Eval/2/", message), curve2()),
                            "verifier_circuit_template:hash_to_curve_m2");
    Transcript transcript;
    PURIFY_ASSIGN_OR_RETURN(const auto& result, circuit_main(transcript, m1, m2),
                            "verifier_circuit_template:circuit_main");
    BulletproofTranscript bp;
    PURIFY_RETURN_IF_ERROR(bp.from_transcript(transcript, result.n_bits, no_padding),
                           "verifier_circuit_template:from_transcript");
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

Result<BulletproofWitnessData> prove_assignment_data(const Bytes& message, const SecretKey& secret,
                                                     bool no_padding) {
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
    PURIFY_RETURN_IF_ERROR(bp.from_transcript(transcript, result.n_bits, no_padding),
                           "prove_assignment_data:from_transcript");
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

Result<bool> evaluate_verifier_circuit(const Bytes& message, const BulletproofWitnessData& witness,
                                       bool no_padding) {
    PURIFY_ASSIGN_OR_RETURN(const auto& circuit, verifier_circuit(message, witness.public_key, no_padding),
                            "evaluate_verifier_circuit:verifier_circuit");
    return circuit.evaluate(witness.assignment);
}

Result<bool> evaluate_verifier_circuit(const Bytes& message, const SecretKey& secret, bool no_padding) {
    PURIFY_ASSIGN_OR_RETURN(const auto& witness, prove_assignment_data(message, secret, no_padding),
                            "evaluate_verifier_circuit:prove_assignment_data");
    return evaluate_verifier_circuit(message, witness, no_padding);
}

Result<Bytes> prove_assignment(const Bytes& message, const SecretKey& secret, bool no_padding) {
    PURIFY_ASSIGN_OR_RETURN(const auto& witness, prove_assignment_data(message, secret, no_padding),
                            "prove_assignment:prove_assignment_data");
    Result<Bytes> serialized = witness.assignment.serialize();
    assert(serialized.has_value() && "prove_assignment() should serialize a well-formed assignment");
    if (!serialized.has_value()) {
        return unexpected_error(ErrorCode::InternalMismatch, "prove_assignment:serialize_assignment");
    }
    return serialized;
}

}  // namespace purify
