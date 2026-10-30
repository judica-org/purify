// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "purify/puresign/accountable.hpp"
#include "purify_test_helpers.hpp"

namespace {

using purify_test::TestContext;
using purify_test::expect_error;
using purify_test::expect_ok;
using purify::accountable::ConflictContext;
using purify::accountable::ScalarSignature;
using purify::accountable::nonce_evaluation_input;
using purify::accountable::reconstruct_nonce;
using purify::accountable::signature_challenge;

auto bytes32(std::string_view hex) {
    return purify::UInt256::from_hex(hex).to_bytes_be();
}

} // namespace

void run_accountable_signature_tests(TestContext& ctx) {
    auto secp = purify::make_secp_context();
    ctx.expect(secp != nullptr, "accountable signature context creates");
    if (!secp) return;

    // Independently reproduced with reference_accountable_vectors.py, including
    // an odd-Y raw nonce: normalizing it would change both expected responses.
    const auto slot = purify::bytes_from_ascii("domain=7;epoch=13;slot=2");
    ConflictContext context{
        bytes32("f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"),
        bytes32("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
        slot,
    };
    const auto body_a = purify::bytes_from_ascii("accept:root-a");
    const auto body_b = purify::bytes_from_ascii("accept:root-b");
    auto input = nonce_evaluation_input(context, secp.get());
    auto challenge_a = signature_challenge(context, body_a, secp.get());
    auto challenge_b = signature_challenge(context, body_b, secp.get());
    expect_ok(ctx, input, "slot has a deterministic nonce input");
    expect_ok(ctx, challenge_a, "first statement has a challenge");
    expect_ok(ctx, challenge_b, "second statement has a challenge");
    if (!input || !challenge_a || !challenge_b) return;
    ctx.expect(*input == bytes32("258bae0387bd127d74086f64296e65369efb5f5a3f13536f999355d0ab59b6fb"),
               "nonce input matches independent tagged-hash vector");
    ctx.expect(challenge_a->to_bytes_be()
                   == bytes32("80457868aaf037437aad6d868692b67cee17b9159fc0c06364b151527aa16305"),
               "first challenge matches independent tagged-hash vector");
    ctx.expect(challenge_b->to_bytes_be()
                   == bytes32("f7c579404420e83db97c4a47974c66420644fd1bbb7e689c00c0b8a0ce241458"),
               "second challenge matches independent tagged-hash vector");

    const auto encoded_a = bytes32("80d0693a00d0a5ca7008489393b823780f984e5a2ff9a0ee6e41956a9fade7d4");
    const auto encoded_b = bytes32("e7506bc0cc62b8b92c74ded6c5e532c89d713d85d3e9f95c829d6cc8c9ffba8c");
    auto signature_a = ScalarSignature::deserialize(encoded_a);
    auto signature_b = ScalarSignature::deserialize(encoded_b);
    expect_ok(ctx, signature_a, "first scalar trace entry decodes");
    expect_ok(ctx, signature_b, "second scalar trace entry decodes");
    if (!signature_a || !signature_b) return;
    ctx.expect(signature_a->serialize() == encoded_a, "scalar trace roundtrips exactly 32 bytes");
    auto nonce_a = reconstruct_nonce(context, body_a, *signature_a, secp.get());
    auto nonce_b = reconstruct_nonce(context, body_b, *signature_b, secp.get());
    expect_ok(ctx, nonce_a, "first scalar reconstructs the full nonce");
    expect_ok(ctx, nonce_b, "second scalar reconstructs the full nonce");
    if (!nonce_a || !nonce_b) return;
    std::array<unsigned char, 33> expected_nonce{};
    expected_nonce[0] = 0x03;
    const auto nonce_x = bytes32("fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556");
    std::copy(nonce_x.begin(), nonce_x.end(), expected_nonce.begin() + 1);
    ctx.expect(*nonce_a == expected_nonce && *nonce_b == expected_nonce,
               "both scalar responses preserve the identical odd-Y raw nonce");

    const auto scalar_a = purify::FieldElement::from_bytes32(encoded_a);
    const auto scalar_b = purify::FieldElement::from_bytes32(encoded_b);
    const auto recovered = (scalar_a - scalar_b) * (*challenge_a - *challenge_b).inverse();
    ctx.expect(recovered == purify::FieldElement::from_u64(3),
               "independent same-slot response vectors cancel their nonce");

    // Reconstruction alone makes no validity claim; the nonce proof must check
    // the reconstructed point, which changes with an unauthenticated statement.
    auto changed_nonce = reconstruct_nonce(context, body_b, *signature_a, secp.get());
    expect_ok(ctx, changed_nonce, "a changed statement still has an algebraic reconstruction");
    if (changed_nonce) ctx.expect(*changed_nonce != *nonce_a, "changed body reconstructs a different point");

    auto changed = context;
    changed.host_commitment[0] ^= 1;
    auto changed_input = nonce_evaluation_input(changed, secp.get());
    auto changed_challenge = signature_challenge(changed, body_a, secp.get());
    expect_ok(ctx, changed_input, "alternate registered hosts have a nonce input");
    expect_ok(ctx, changed_challenge, "alternate registered hosts have a challenge");
    if (changed_input) ctx.expect(*changed_input != *input, "host commitment binds the nonce input");
    if (changed_challenge) ctx.expect(*changed_challenge != *challenge_a, "host commitment binds the challenge");

    const auto short_slot = purify::bytes_from_ascii("a");
    const auto long_slot = purify::bytes_from_ascii("ab");
    const auto short_body = purify::bytes_from_ascii("c");
    const auto long_body = purify::bytes_from_ascii("bc");
    changed.slot = short_slot;
    auto short_slot_challenge = signature_challenge(changed, long_body, secp.get());
    changed.slot = long_slot;
    auto long_slot_challenge = signature_challenge(changed, short_body, secp.get());
    expect_ok(ctx, short_slot_challenge, "short-slot context challenges");
    expect_ok(ctx, long_slot_challenge, "long-slot context challenges");
    if (short_slot_challenge && long_slot_challenge) {
        ctx.expect(*short_slot_challenge != *long_slot_challenge,
                   "length prefixes distinguish equal concatenations of slot and body");
    }

    changed = context;
    changed.slot = {};
    expect_error(ctx, signature_challenge(changed, body_a, secp.get()), purify::ErrorCode::EmptyInput,
                 "empty conflict slots reject");
    changed = context;
    changed.signing_key.fill(0xff);
    expect_error(ctx, signature_challenge(changed, body_a, secp.get()), purify::ErrorCode::RangeViolation,
                 "invalid signing-key coordinates reject");
    expect_error(ctx, signature_challenge(context, body_a, nullptr), purify::ErrorCode::MissingValue,
                 "missing secp context rejects");
    expect_error(ctx, ScalarSignature::deserialize(std::span(encoded_a).first(31)),
                 purify::ErrorCode::InvalidFixedSize, "truncated scalar rejects");
    purify::Bytes trailing(encoded_a.begin(), encoded_a.end());
    trailing.push_back(0);
    expect_error(ctx, ScalarSignature::deserialize(trailing), purify::ErrorCode::InvalidFixedSize,
                 "trailing scalar bytes reject");
    expect_error(ctx, ScalarSignature::deserialize(purify::prime_p().to_bytes_be()),
                 purify::ErrorCode::RangeViolation, "group-order scalar rejects instead of reducing");

    std::array<unsigned char, 32> zero{};
    auto zero_signature = ScalarSignature::deserialize(zero);
    expect_ok(ctx, zero_signature, "zero is a canonical response scalar");
    if (zero_signature) {
        expect_ok(ctx, reconstruct_nonce(context, body_a, *zero_signature, secp.get()),
                  "zero response reconstructs minus e times Q");
    }
    const auto infinity_response = (*challenge_a * purify::FieldElement::from_u64(3)).to_bytes_be();
    auto infinity_signature = ScalarSignature::deserialize(infinity_response);
    expect_ok(ctx, infinity_signature, "infinity case has a canonical response encoding");
    if (infinity_signature) {
        expect_error(ctx, reconstruct_nonce(context, body_a, *infinity_signature, secp.get()),
                     purify::ErrorCode::RangeViolation, "a reconstructed nonce at infinity rejects");
    }
}
