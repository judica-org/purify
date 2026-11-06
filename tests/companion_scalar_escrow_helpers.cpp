// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <algorithm>
#include <array>
#include <chrono>
#include <iostream>
#include <optional>
#include <utility>
#include <vector>

#include "purify.hpp"
#include "purify/bppp.hpp"
#include "purify/puresign/accountable.hpp"
#include "companion_scalar_escrow_helpers.hpp"

namespace purify_test::scalar_escrow {

using purify::Bytes;
using purify::Expr;
using purify::FieldElement;
using purify::Result;
using purify::UInt256;
using purify::UInt512;
using PointPair = std::pair<purify::JacobianPoint, purify::JacobianPoint>;

// A local honest-witness experiment. No production codec, decryption service,
// malicious-prover soundness, chosen-ciphertext or MPC claim is made here.
Result<PointPair> decode_points(const UInt512& encoded) {
    PURIFY_ASSIGN_OR_RETURN(const auto& coords, purify::unpack_public(encoded), "scalar_escrow:unpack");
    PURIFY_ASSIGN_OR_RETURN(const auto& x1, FieldElement::try_from_uint256(coords.first), "scalar_escrow:x1");
    PURIFY_ASSIGN_OR_RETURN(const auto& x2, FieldElement::try_from_uint256(coords.second), "scalar_escrow:x2");
    const auto first = purify::curve1().lift_x(x1);
    const auto second = purify::curve2().lift_x(x2);
    if (!first || !second || first->infinity || second->infinity ||
        !purify::curve1().mul(*first, purify::order_n1()).infinity ||
        !purify::curve2().mul(*second, purify::order_n2()).infinity) {
        return purify::unexpected_error(purify::ErrorCode::BackendRejectedInput, "scalar_escrow:points");
    }
    return PointPair{*first, *second};
}

Result<purify::GeneratedKey> key_from_pair(UInt256 first, UInt256 second) {
    if (first.is_zero() || second.is_zero() || purify::half_n1() < first || purify::half_n2() < second) {
        return purify::unexpected_error(purify::ErrorCode::RangeViolation, "scalar_escrow:canonical_pair");
    }
    first.sub_assign(UInt256::one());
    second.sub_assign(UInt256::one());
    auto packed = purify::multiply(purify::half_n1(), second);
    packed.add_assign(purify::widen<8>(first));
    PURIFY_ASSIGN_OR_RETURN(auto secret, purify::SecretKey::from_packed(packed), "scalar_escrow:secret");
    return purify::derive_key(std::move(secret));
}

Result<purify::GeneratedKey> recipient_from_scalar(const FieldElement& scalar) {
    if (scalar.is_zero()) {
        return purify::unexpected_error(purify::ErrorCode::RangeViolation, "scalar_escrow:zero_coalition");
    }
    const auto value = scalar.to_uint256();
    const auto magnitude = purify::prime_p().shifted_right(1) < value ? scalar.negate().to_uint256() : value;
    auto first = magnitude;
    auto second = magnitude;
    if (purify::half_n1() < first) { first = purify::order_n1(); first.sub_assign(magnitude); }
    if (purify::half_n2() < second) { second = purify::order_n2(); second.sub_assign(magnitude); }
    return key_from_pair(first, second);
}

Result<FieldElement> shared_pad(const purify::SecretKey& secret, const UInt512& peer) {
    PURIFY_ASSIGN_OR_RETURN(const auto& scalars, purify::unpack_secret(secret.packed()), "scalar_escrow:secret");
    PURIFY_ASSIGN_OR_RETURN(const auto& points, decode_points(peer), "scalar_escrow:peer");
    PURIFY_ASSIGN_OR_RETURN(const auto& first,
        purify::curve1().mul_secret_affine(points.first, scalars.first), "scalar_escrow:shared_first");
    PURIFY_ASSIGN_OR_RETURN(const auto& second,
        purify::curve2().mul_secret_affine(points.second, scalars.second), "scalar_escrow:shared_second");
    return purify::combine(first.x, second.x);
}

Result<Ciphertext> encrypt(const UInt512& recipient, const Opening& opening) {
    PURIFY_ASSIGN_OR_RETURN(const auto& scalars, purify::unpack_secret(opening.payload.packed()), "scalar_escrow:payload");
    const std::array<UInt256, 2> payload{scalars.first, scalars.second};
    Ciphertext out;
    for (std::size_t i = 0; i < 2; ++i) {
        PURIFY_ASSIGN_OR_RETURN(const auto& pad, shared_pad(opening.ephemeral[i]->secret, recipient), "scalar_escrow:pad");
        out.ephemeral[i] = opening.ephemeral[i]->public_key;
        out.masked[i] = FieldElement::from_uint256(payload[i]) + pad;
    }
    return out;
}

Expr exceeds_bound(purify::Transcript& transcript, const std::vector<Expr>& bits, const UInt256& bound) {
    Expr equal_prefix(1);
    Expr exceeds(0);
    for (std::size_t i = bits.size(); i != 0; --i) {
        const Expr first_one = transcript.mul(equal_prefix, bits[i - 1]);
        if (bound.bit(i - 1)) equal_prefix = first_one;
        else {
            exceeds = exceeds + first_one;
            equal_prefix = equal_prefix - first_one;
        }
    }
    return exceeds;
}

std::vector<Expr> ordinary_bits(purify::Transcript& transcript, const std::optional<UInt256>& value) {
    std::vector<Expr> bits;
    bits.reserve(255);
    for (std::size_t i = 0; i < 255; ++i) {
        const auto bit = value ? std::optional<FieldElement>(FieldElement::from_u64(value->bit(i))) : std::nullopt;
        bits.push_back(transcript.boolean(transcript.secret(bit)));
    }
    return bits;
}

std::vector<Expr> signed_window_bits(purify::Transcript& transcript, const std::vector<Expr>& ordinary) {
    auto bits = ordinary;
    for (std::size_t i = 3; i < bits.size(); i += 3) {
        bits[i] = Expr(1) - ordinary[i];
        for (std::size_t offset : {1U, 2U}) {
            bits[i - offset] = Expr(1) - ordinary[i] - ordinary[i - offset]
                + 2 * transcript.mul(ordinary[i], ordinary[i - offset]);
        }
    }
    return bits;
}

Expr canonical_payload(purify::Transcript& transcript, const std::vector<Expr>& bits, UInt256 limit) {
    limit.sub_assign(UInt256::one());
    transcript.equal(exceeds_bound(transcript, bits, limit), Expr(0));
    Expr value(1);
    FieldElement power = FieldElement::one();
    for (const auto& bit : bits) {
        value = value + power * bit;
        power = power + power;
    }
    return value;
}

Result<purify::CircuitMainResult> escrow_relation(purify::Transcript& transcript, const UInt512& recipient,
                                                const Ciphertext& ciphertext, const Opening* opening) {
    PURIFY_ASSIGN_OR_RETURN(const auto& receiver, decode_points(recipient), "scalar_escrow:recipient");
    std::array<std::pair<UInt256, UInt256>, 2> ephemeral_coords;
    for (std::size_t i = 0; i < 2; ++i) {
        PURIFY_RETURN_IF_ERROR(decode_points(ciphertext.ephemeral[i]), "scalar_escrow:ephemeral");
        PURIFY_ASSIGN_OR_RETURN(ephemeral_coords[i], purify::unpack_public(ciphertext.ephemeral[i]), "scalar_escrow:coords");
    }
    std::array<std::optional<UInt256>, 2> payload_values;
    if (opening) {
        PURIFY_ASSIGN_OR_RETURN(const auto& pair, purify::unpack_secret(opening->payload.packed()), "scalar_escrow:payload");
        payload_values = {pair.first, pair.second};
        for (auto& value : payload_values) value->sub_assign(UInt256::one());
    }
    // Keep every Boolean gate first, before recoding, comparison or EC work.
    std::array<std::vector<Expr>, 2> payload_bits{
        ordinary_bits(transcript, payload_values[0]), ordinary_bits(transcript, payload_values[1])};
    // Only payloads need canonical half-order representatives. These signed
    // Boolean windows still encode nonzero scalars below each curve order;
    // x-only shared points are invariant under choosing the opposite sign.
    std::array<std::array<std::vector<Expr>, 2>, 2> ephemeral_bits;
    for (std::size_t i = 0; i < 2; ++i) {
        std::array<std::vector<int>, 2> values{std::vector<int>(255, -1), std::vector<int>(255, -1)};
        if (opening) {
            PURIFY_ASSIGN_OR_RETURN(const auto& pair, purify::unpack_secret(opening->ephemeral[i]->secret.packed()),
                                    "scalar_escrow:ephemeral_secret");
            PURIFY_ASSIGN_OR_RETURN(values[0], purify::key_to_bits(pair.first, purify::half_n1()), "scalar_escrow:r1_bits");
            PURIFY_ASSIGN_OR_RETURN(values[1], purify::key_to_bits(pair.second, purify::half_n2()), "scalar_escrow:r2_bits");
        }
        for (std::size_t component = 0; component < 2; ++component) {
            auto& bits = ephemeral_bits[i][component];
            bits.reserve(255);
            for (int bit : values[component]) {
                bits.push_back(transcript.boolean(transcript.secret(bit < 0 ? std::nullopt :
                    std::optional<FieldElement>(FieldElement::from_int(bit)))));
            }
        }
    }
    const std::array<Expr, 2> plaintext{
        canonical_payload(transcript, payload_bits[0], purify::half_n1()),
        canonical_payload(transcript, payload_bits[1], purify::half_n2())};
    const auto first_bits = signed_window_bits(transcript, payload_bits[0]);
    const auto second_bits = signed_window_bits(transcript, payload_bits[1]);
    const Expr first_key = purify::circuit_ec_multiply_x(purify::curve1(), transcript, purify::generator1(), first_bits);
    const Expr second_key = purify::circuit_ec_multiply_x(purify::curve2(), transcript, purify::generator2(), second_bits);
    for (std::size_t i = 0; i < 2; ++i) {
        const auto& bits = ephemeral_bits[i];
        const Expr a1 = purify::circuit_ec_multiply_x(purify::curve1(), transcript, purify::generator1(), bits[0]);
        const Expr a2 = purify::circuit_ec_multiply_x(purify::curve2(), transcript, purify::generator2(), bits[1]);
        transcript.equal(a1, Expr(FieldElement::from_uint256(ephemeral_coords[i].first)));
        transcript.equal(a2, Expr(FieldElement::from_uint256(ephemeral_coords[i].second)));
        const Expr s1 = purify::circuit_ec_multiply_x(purify::curve1(), transcript, receiver.first, bits[0]);
        const Expr s2 = purify::circuit_ec_multiply_x(purify::curve2(), transcript, receiver.second, bits[1]);
        transcript.equal(plaintext[i] + purify::circuit_combine(transcript, s1, s2), Expr(ciphertext.masked[i]));
    }
    // The sole public commitment is fixed to G. All encrypted values are
    // constrained by native equations; none is an independently blinded output.
    return purify::CircuitMainResult{Expr(1), first_key, second_key, 6 * 255};
}

Result<purify::NativeBulletproofCircuit> public_circuit(const UInt512& recipient, const UInt512& payload,
                                                      const Ciphertext& ciphertext) {
    PURIFY_RETURN_IF_ERROR(decode_points(payload), "scalar_escrow:old_root");
    purify::Transcript transcript;
    PURIFY_ASSIGN_OR_RETURN(const auto& relation, escrow_relation(transcript, recipient, ciphertext, nullptr), "scalar_escrow:relation");
    purify::BulletproofTranscript bp;
    PURIFY_RETURN_IF_ERROR(bp.from_transcript(transcript, relation.n_bits), "scalar_escrow:lower");
    PURIFY_RETURN_IF_ERROR(bp.add_pubkey_and_out(payload, relation.p1x, relation.p2x, relation.out), "scalar_escrow:bind");
    return bp.native_circuit();
}

Result<purify::BulletproofAssignmentData> assignment(const UInt512& recipient, const UInt512& payload,
                                                   const Ciphertext& ciphertext, const Opening& opening) {
    purify::Transcript transcript;
    PURIFY_ASSIGN_OR_RETURN(const auto& relation, escrow_relation(transcript, recipient, ciphertext, &opening), "scalar_escrow:witness");
    purify::BulletproofTranscript bp;
    PURIFY_RETURN_IF_ERROR(bp.from_transcript(transcript, relation.n_bits), "scalar_escrow:lower");
    PURIFY_RETURN_IF_ERROR(bp.add_pubkey_and_out(payload, relation.p1x, relation.p2x, relation.out), "scalar_escrow:bind");
    return bp.assignment_data(transcript.varmap(), FieldElement::one());
}

Bytes ciphertext_bytes(const Ciphertext& ciphertext) {
    Bytes out;
    out.reserve(192);
    for (std::size_t i = 0; i < 2; ++i) {
        const auto ephemeral = ciphertext.ephemeral[i].to_bytes_be();
        const auto masked = ciphertext.masked[i].to_bytes_be();
        out.insert(out.end(), ephemeral.begin(), ephemeral.end());
        out.insert(out.end(), masked.begin(), masked.end());
    }
    return out;
}

Bytes binding(const UInt512& recipient, const UInt512& payload, const Ciphertext& ciphertext, const Bytes& context) {
    const auto recipient_bytes = recipient.to_bytes_be();
    const auto payload_bytes = payload.to_bytes_be();
    const auto encrypted = ciphertext_bytes(ciphertext);
    const auto hash = purify::TaggedHash("Purify/CompanionScalarEscrow/HonestV1").digest_many<4>(
        {recipient_bytes, payload_bytes, encrypted, context});
    return Bytes(hash.begin(), hash.end());
}

Result<purify::bppp::PointBytes> secp_point(const FieldElement& scalar, purify_secp_context* secp) {
    const purify::bppp::ScalarBytes zero{};
    const auto generator = purify::bppp::base_generator(secp);
    return purify::bppp::pedersen_commit_char(zero, scalar.to_bytes_be(), secp, generator, generator);
}

Result<bool> verify(const UInt512& recipient, const UInt512& payload, const Ciphertext& ciphertext,
                    const Bytes& context, const purify::bppp::ExperimentalCircuitZkNormArgProof& proof,
                    purify_secp_context* secp) {
    PURIFY_ASSIGN_OR_RETURN(const auto& circuit, public_circuit(recipient, payload, ciphertext), "scalar_escrow:public");
    PURIFY_ASSIGN_OR_RETURN(const auto& generator, secp_point(FieldElement::one(), secp), "scalar_escrow:fixed_output");
    const std::array<purify::bppp::PointBytes, 1> output{generator};
    return purify::bppp::verify_experimental_circuit_zk_norm_arg_with_public_commitments(
        circuit, proof, output, secp, binding(recipient, payload, ciphertext, context));
}

Result<purify::GeneratedKey> decrypt_checked(const purify::SecretKey& recipient_secret, const UInt512& recipient,
                                            const UInt512& payload, const Ciphertext& ciphertext, const Bytes& context,
                                            const purify::bppp::ExperimentalCircuitZkNormArgProof& proof,
                                            purify_secp_context* secp) {
    PURIFY_ASSIGN_OR_RETURN(const auto& accepted, verify(recipient, payload, ciphertext, context, proof, secp), "scalar_escrow:verify");
    if (!accepted) return purify::unexpected_error(purify::ErrorCode::BindingMismatch, "scalar_escrow:invalid_proof");
    return decrypt_payload(recipient_secret, recipient, payload, ciphertext);
}

Result<purify::GeneratedKey> decrypt_payload(const purify::SecretKey& recipient_secret, const UInt512& recipient,
                                            const UInt512& payload, const Ciphertext& ciphertext) {
    PURIFY_ASSIGN_OR_RETURN(const auto& receiver, purify::derive_key(recipient_secret), "scalar_escrow:recipient_secret");
    if (receiver.public_key != recipient) {
        return purify::unexpected_error(purify::ErrorCode::BindingMismatch, "scalar_escrow:wrong_recipient");
    }
    std::array<UInt256, 2> plaintext;
    for (std::size_t i = 0; i < 2; ++i) {
        PURIFY_ASSIGN_OR_RETURN(const auto& pad, shared_pad(recipient_secret, ciphertext.ephemeral[i]), "scalar_escrow:decrypt_pad");
        plaintext[i] = (ciphertext.masked[i] - pad).to_uint256();
    }
    PURIFY_ASSIGN_OR_RETURN(auto root, key_from_pair(plaintext[0], plaintext[1]), "scalar_escrow:canonical_plaintext");
    if (root.public_key != payload) {
        return purify::unexpected_error(purify::ErrorCode::BindingMismatch, "scalar_escrow:wrong_plaintext");
    }
    return root;
}

} // namespace purify_test::scalar_escrow
