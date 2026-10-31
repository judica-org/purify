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
#include "canonical_recovery_root_helpers.hpp"

namespace purify_test::canonical_root {

using purify::Bytes;
using purify::Expr;
using purify::FieldElement;
using purify::Result;
using purify::UInt256;
using purify::UInt512;
using PointPair = std::pair<purify::JacobianPoint, purify::JacobianPoint>;
using PointBytes = purify::bppp::PointBytes;

// Public toy witnesses only. These helpers are not a production setup or
// distributed protocol, and the experimental proof backend remains unreviewed.
UInt256 half_secp_order() { return purify::prime_p().shifted_right(1); }

UInt256 magnitude(const FieldElement& scalar) {
    const auto value = scalar.to_uint256();
    return half_secp_order() < value ? scalar.negate().to_uint256() : value;
}

Result<PointBytes> secp_point(const FieldElement& value, purify_secp_context* context) {
    const purify::bppp::ScalarBytes zero{};
    const auto generator = purify::bppp::base_generator(context);
    return purify::bppp::pedersen_commit_char(zero, value.to_bytes_be(), context, generator, generator);
}

Result<PointPair> decode_root(const UInt512& encoded) {
    PURIFY_ASSIGN_OR_RETURN(const auto& coords, purify::unpack_public(encoded), "root_setup:unpack");
    PURIFY_ASSIGN_OR_RETURN(const auto& x1, FieldElement::try_from_uint256(coords.first), "root_setup:x1");
    PURIFY_ASSIGN_OR_RETURN(const auto& x2, FieldElement::try_from_uint256(coords.second), "root_setup:x2");
    const auto p1 = purify::curve1().lift_x(x1);
    const auto p2 = purify::curve2().lift_x(x2);
    if (!p1 || !p2 || p1->infinity || p2->infinity ||
        !purify::curve1().mul(*p1, purify::order_n1()).infinity ||
        !purify::curve2().mul(*p2, purify::order_n2()).infinity) {
        return purify::unexpected_error(purify::ErrorCode::BackendRejectedInput, "root_setup:points");
    }
    return PointPair{*p1, *p2};
}

Result<purify::GeneratedKey> root_from_scalar(const FieldElement& scalar) {
    if (scalar.is_zero()) {
        return purify::unexpected_error(purify::ErrorCode::RangeViolation, "root_setup:zero");
    }
    auto first = magnitude(scalar);
    auto second = first;
    if (purify::half_n2() < second) {
        second = purify::order_n2();
        second.sub_assign(first);
    }
    // first <= half(secp order) < half_n1; second is normalized for x-only D2.
    first.sub_assign(UInt256::one());
    second.sub_assign(UInt256::one());
    auto packed = purify::multiply(purify::half_n1(), second);
    packed.add_assign(purify::widen<8>(first));
    PURIFY_ASSIGN_OR_RETURN(auto secret, purify::SecretKey::from_packed(packed), "root_setup:secret");
    return purify::derive_key(std::move(secret));
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

// Boolean inputs make equal_prefix and exceeds Boolean. Only the first
// differing bit contributes, so this comparison is over integers, not F_n.
Expr exceeds_bound(purify::Transcript& transcript, const std::vector<Expr>& bits, const UInt256& bound) {
    Expr equal_prefix(1);
    Expr exceeds(0);
    for (std::size_t i = bits.size(); i != 0; --i) {
        const Expr same_and_one = transcript.mul(equal_prefix, bits[i - 1]);
        if (bound.bit(i - 1)) {
            equal_prefix = same_and_one;
        } else {
            exceeds = exceeds + same_and_one;
            equal_prefix = equal_prefix - same_and_one;
        }
    }
    return exceeds;
}

// The curve gadget consumes signed-window digits derived from (a - 1),
// not ordinary scalar bits. Match the independent C key_to_bits codec.
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

Result<purify::CircuitMainResult> setup_relation(purify::Transcript& transcript,
                                                const std::optional<FieldElement>& scalar) {
    if (scalar && scalar->is_zero()) {
        return purify::unexpected_error(purify::ErrorCode::RangeViolation, "root_setup:zero_witness");
    }
    std::optional<UInt256> value;
    std::optional<FieldElement> sign_value;
    if (scalar) {
        value = magnitude(*scalar);
        value->sub_assign(UInt256::one());
        sign_value = FieldElement::from_u64(half_secp_order() < scalar->to_uint256());
    }
    const auto bits = ordinary_bits(transcript, value);
    const Expr sign = transcript.boolean(transcript.secret(sign_value));
    auto bound = half_secp_order();
    bound.sub_assign(UInt256::one());
    transcript.equal(exceeds_bound(transcript, bits, bound), Expr(0));
    Expr a(1);
    FieldElement power = FieldElement::one();
    for (const auto& bit : bits) {
        a = a + power * bit;
        power = power + power;
    }
    const auto recoded = signed_window_bits(transcript, bits);
    const Expr first = purify::circuit_ec_multiply_x(purify::curve1(), transcript, purify::generator1(), recoded);
    const Expr second = purify::circuit_ec_multiply_x(purify::curve2(), transcript, purify::generator2(), recoded);
    return purify::CircuitMainResult{transcript.mul(Expr(1) - 2 * sign, a), first, second, bits.size() + 1};
}

Result<purify::NativeBulletproofCircuit> public_setup_circuit(const UInt512& root) {
    PURIFY_RETURN_IF_ERROR(decode_root(root), "root_setup:root");
    purify::Transcript transcript;
    PURIFY_ASSIGN_OR_RETURN(const auto& relation, setup_relation(transcript), "root_setup:relation");
    purify::BulletproofTranscript bp;
    PURIFY_RETURN_IF_ERROR(bp.from_transcript(transcript, relation.n_bits), "root_setup:lower");
    PURIFY_RETURN_IF_ERROR(bp.add_pubkey_and_out(root, relation.p1x, relation.p2x, relation.out), "root_setup:bind");
    return bp.native_circuit();
}

Result<purify::BulletproofAssignmentData> setup_assignment(const UInt512& root, const FieldElement& scalar) {
    purify::Transcript transcript;
    PURIFY_ASSIGN_OR_RETURN(const auto& relation, setup_relation(transcript, scalar), "root_setup:witness");
    purify::BulletproofTranscript bp;
    PURIFY_RETURN_IF_ERROR(bp.from_transcript(transcript, relation.n_bits), "root_setup:lower");
    PURIFY_RETURN_IF_ERROR(bp.add_pubkey_and_out(root, relation.p1x, relation.p2x, relation.out), "root_setup:bind");
    return bp.assignment_data(transcript.varmap(), scalar);
}

Bytes binding(const PointBytes& key, const UInt512& root, const Bytes& context) {
    const auto encoded = root.to_bytes_be();
    const auto hash = purify::TaggedHash("Purify/RecoveryRoot/HonestSetupV1").digest_many<3>({key, encoded, context});
    return Bytes(hash.begin(), hash.end());
}

Result<bool> verify_setup(const PointBytes& key, const UInt512& root, const Bytes& context,
                          const purify::bppp::ExperimentalCircuitZkNormArgProof& proof,
                          purify_secp_context* secp) {
    if (key[0] != 0x02 || purify_bip340_validate_xonly_pubkey(secp, key.data() + 1) == 0) {
        return purify::unexpected_error(purify::ErrorCode::RangeViolation, "root_setup:even_key");
    }
    PURIFY_ASSIGN_OR_RETURN(const auto& circuit, public_setup_circuit(root), "root_setup:public_circuit");
    const std::array<PointBytes, 1> outputs{key};
    return purify::bppp::verify_experimental_circuit_zk_norm_arg_with_public_commitments(
        circuit, proof, outputs, secp, binding(key, root, context));
}

Result<purify::GeneratedKey> recover_root(const FieldElement& scalar, const PointBytes& key,
                                         const UInt512& expected_root, purify_secp_context* secp) {
    PURIFY_ASSIGN_OR_RETURN(const auto& point, secp_point(scalar, secp), "root_setup:recovered_point");
    if (key[0] != 0x02 || point != key) {
        return purify::unexpected_error(purify::ErrorCode::BindingMismatch, "root_setup:exact_key");
    }
    PURIFY_ASSIGN_OR_RETURN(auto root, root_from_scalar(scalar), "root_setup:recover");
    if (root.public_key != expected_root) {
        return purify::unexpected_error(purify::ErrorCode::BindingMismatch, "root_setup:exact_root");
    }
    return root;
}

Result<FieldElement> leaf_output(const purify::SecretKey& secret, const UInt512& peer) {
    PURIFY_ASSIGN_OR_RETURN(const auto& scalars, purify::unpack_secret(secret.packed()), "root_setup:leaf_secret");
    PURIFY_ASSIGN_OR_RETURN(const auto& points, decode_root(peer), "root_setup:leaf_peer");
    PURIFY_ASSIGN_OR_RETURN(const auto& first,
        purify::curve1().mul_secret_affine(points.first, scalars.first), "root_setup:leaf_first");
    PURIFY_ASSIGN_OR_RETURN(const auto& second,
        purify::curve2().mul_secret_affine(points.second, scalars.second), "root_setup:leaf_second");
    return purify::combine(first.x, second.x);
}

} // namespace purify_test::canonical_root
