// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "purify/puresign/accountable_responses.hpp"
#include "purify_test_helpers.hpp"

namespace {

using purify_test::TestContext;
using purify_test::expect_error;
using purify_test::expect_ok;
using purify::FieldElement;
using purify::accountable::ConflictContext;
using purify::accountable::PartialResponse;
using purify::accountable::ScalarSignature;
using purify::accountable::SigningRoster;
using purify::accountable::aggregate_responses;
using purify::accountable::recover_same_slot_key;
using purify::accountable::reconstruct_nonce;
using purify::accountable::signature_challenge;
using purify::accountable::verify_partial_response;

// Test-only centralized algebra using public toy scalars. Restore the original
// point sign after the existing BIP340 helper canonicalizes its scalar copy.
purify::Result<std::array<unsigned char, 33>> public_point(
    FieldElement scalar, purify_secp_context* secp_context) {
    const auto original = scalar.to_bytes_be();
    auto normalized = original;
    std::array<unsigned char, 32> x{};
    if (purify_bip340_key_from_seckey(secp_context, normalized.data(), x.data()) == 0) {
        return purify::unexpected_error(purify::ErrorCode::RangeViolation, "response_test:point");
    }
    std::array<unsigned char, 33> out{};
    out[0] = normalized == original ? 0x02 : 0x03;
    std::copy(x.begin(), x.end(), out.begin() + 1);
    return out;
}

purify::Result<std::vector<PartialResponse>> toy_partials(
    const SigningRoster& roster, std::span<const FieldElement> secrets,
    std::span<const FieldElement> nonces, const FieldElement& challenge,
    purify_secp_context* secp_context) {
    std::vector<PartialResponse> out;
    out.reserve(secrets.size());
    for (std::size_t i = 0; i < secrets.size(); ++i) {
        const auto value = nonces[i] + challenge * roster.members()[i].coefficient * secrets[i];
        PURIFY_ASSIGN_OR_RETURN(auto response, ScalarSignature::deserialize(value.to_bytes_be()),
                                "response_test:scalar");
        PURIFY_ASSIGN_OR_RETURN(auto nonce, public_point(nonces[i], secp_context), "response_test:nonce");
        out.push_back({nonce, response});
    }
    return out;
}

} // namespace

void run_accountable_response_tests(TestContext& ctx) {
    auto secp = purify::make_secp_context();
    ctx.expect(secp != nullptr, "response context creates");
    if (!secp) return;
    const std::array secrets{FieldElement::from_u64(3), FieldElement::from_u64(6), FieldElement::from_u64(8)};
    const std::array nonces{FieldElement::from_u64(6), FieldElement::from_u64(7), FieldElement::from_u64(8)};
    std::array<std::array<unsigned char, 33>, 3> keys{};
    for (std::size_t i = 0; i < keys.size(); ++i) {
        auto point = public_point(secrets[i], secp.get());
        expect_ok(ctx, point, "toy signing point derives");
        if (!point) return;
        keys[i] = *point;
    }
    const auto slot = purify::bytes_from_ascii("responses/domain=4/epoch=8/slot=3");
    const auto other_slot = purify::bytes_from_ascii("responses/domain=4/epoch=8/slot=4");
    const auto body = purify::bytes_from_ascii("decision:root-a");
    const auto other_body = purify::bytes_from_ascii("decision:root-b");
    for (std::size_t count = 1; count <= keys.size(); ++count) {
        auto roster = SigningRoster::aggregate(std::span(keys).first(count), secp.get());
        expect_ok(ctx, roster, "response roster aggregates");
        if (!roster) return;
        ConflictContext context{roster->signing_key(), {}, slot};
        context.host_commitment[0] = 0x42;
        auto challenge = signature_challenge(context, body, secp.get());
        expect_ok(ctx, challenge, "response challenge derives");
        if (!challenge) return;
        auto partials = toy_partials(*roster, std::span(secrets).first(count),
                                     std::span(nonces).first(count), *challenge, secp.get());
        expect_ok(ctx, partials, "toy response fixtures construct");
        if (!partials) return;
        ctx.expect(partials->front().nonce[0] == 0x03, "first raw nonce retains odd Y");
        if (count == 3) ctx.expect(roster->aggregate_was_negated(), "three-member fixture uses aggregate sign");
        for (std::size_t i = 0; i < count; ++i) {
            expect_ok(ctx, verify_partial_response(*roster, i, context, body, (*partials)[i], secp.get()),
                      "each member response satisfies its ordered equation");
        }
        auto aggregate = aggregate_responses(*roster, context, body, *partials, secp.get());
        expect_ok(ctx, aggregate, "N=1,2,3 responses aggregate");
        if (!aggregate) return;
        auto reconstructed = reconstruct_nonce(context, body, *aggregate, secp.get());
        auto nonce_sum = FieldElement::from_u64(0);
        for (std::size_t i = 0; i < count; ++i) nonce_sum = nonce_sum + nonces[i];
        auto expected_nonce = public_point(nonce_sum, secp.get());
        expect_ok(ctx, reconstructed, "aggregate response reconstructs a nonce");
        expect_ok(ctx, expected_nonce, "sum of toy nonces derives a point");
        if (reconstructed && expected_nonce) {
            ctx.expect(*reconstructed == *expected_nonce, "aggregate response retains the exact raw nonce sum");
        }
        ctx.expect(aggregate->serialize().size() == 32, "final response contains no nonce point");

        auto other_challenge = signature_challenge(context, other_body, secp.get());
        expect_ok(ctx, other_challenge, "conflicting toy body derives another challenge");
        if (!other_challenge) return;
        auto other_partials = toy_partials(*roster, std::span(secrets).first(count),
                                           std::span(nonces).first(count), *other_challenge, secp.get());
        expect_ok(ctx, other_partials, "same-slot toy responses construct for the second body");
        if (!other_partials) return;
        auto other_aggregate = aggregate_responses(*roster, context, other_body, *other_partials, secp.get());
        expect_ok(ctx, other_aggregate, "second-body responses aggregate under the same roster");
        if (!other_aggregate) return;
        auto recovered = recover_same_slot_key(context, body, *aggregate, other_body, *other_aggregate, secp.get());
        expect_ok(ctx, recovered, "two toy aggregates expose their exact same-slot key");
        auto normalized_key = FieldElement::from_u64(0);
        for (std::size_t i = 0; i < count; ++i) {
            normalized_key = normalized_key + roster->members()[i].coefficient * secrets[i];
        }
        if (recovered) {
            ctx.expect(*recovered == normalized_key.to_bytes_be(),
                       "public aggregation and recovery match the exact parity-adjusted aggregate scalar");
        }

        auto changed = partials->front();
        changed.nonce[0] ^= 1;
        expect_error(ctx, verify_partial_response(*roster, 0, context, body, changed, secp.get()),
                     purify::ErrorCode::EquationMismatch, "negating a raw partial nonce rejects");
        changed.nonce.fill(0);
        expect_error(ctx, verify_partial_response(*roster, 0, context, body, changed, secp.get()),
                     purify::ErrorCode::RangeViolation, "identity encoding is not a partial nonce");
        changed = partials->front();
        const auto plus_one = FieldElement::from_bytes32(changed.response.serialize()) + FieldElement::from_u64(1);
        auto changed_scalar = ScalarSignature::deserialize(plus_one.to_bytes_be());
        expect_ok(ctx, changed_scalar, "changed scalar remains canonical");
        if (!changed_scalar) return;
        changed.response = *changed_scalar;
        expect_error(ctx, verify_partial_response(*roster, 0, context, body, changed, secp.get()),
                     purify::ErrorCode::EquationMismatch, "changed response rejects");
        auto altered = *partials;
        altered[0] = changed;
        expect_error(ctx, aggregate_responses(*roster, context, body, altered, secp.get()),
                     purify::ErrorCode::EquationMismatch, "aggregate checks each response before returning a scalar");

        expect_error(ctx, verify_partial_response(*roster, 0, context, other_body, partials->front(), secp.get()),
                     purify::ErrorCode::EquationMismatch, "another message invalidates a partial equation");
        auto other_context = context;
        other_context.host_commitment[0] ^= 1;
        expect_error(ctx, verify_partial_response(*roster, 0, other_context, body, partials->front(), secp.get()),
                     purify::ErrorCode::EquationMismatch, "another host commitment invalidates a partial equation");
        other_context = context;
        other_context.slot = other_slot;
        expect_error(ctx, verify_partial_response(*roster, 0, other_context, body, partials->front(), secp.get()),
                     purify::ErrorCode::EquationMismatch, "another slot invalidates a partial equation");
        other_context = context;
        other_context.signing_key[0] ^= 1;
        expect_error(ctx, aggregate_responses(*roster, other_context, body, *partials, secp.get()),
                     purify::ErrorCode::BindingMismatch, "context cannot substitute another aggregate key");
        expect_error(ctx, verify_partial_response(*roster, count, context, body, partials->front(), secp.get()),
                     purify::ErrorCode::IndexOutOfRange, "out-of-range member index rejects");
        expect_error(ctx, aggregate_responses(*roster, context, body, std::span(*partials).first(count - 1), secp.get()),
                     purify::ErrorCode::SizeMismatch, "missing responses reject");
        altered = *partials;
        altered.push_back(partials->front());
        expect_error(ctx, aggregate_responses(*roster, context, body, altered, secp.get()),
                     purify::ErrorCode::SizeMismatch, "extra responses reject");
        if (count > 1) {
            expect_error(ctx, verify_partial_response(*roster, 1, context, body, partials->front(), secp.get()),
                         purify::ErrorCode::EquationMismatch, "member index binds the response equation");
            altered = *partials;
            std::swap(altered[0], altered[1]);
            expect_error(ctx, aggregate_responses(*roster, context, body, altered, secp.get()),
                         purify::ErrorCode::EquationMismatch, "reordered member responses reject");
        }

        // A zero response is valid algebra when its nonzero raw nonce is -e*b_i*x_i.
        auto zero_nonces = nonces;
        zero_nonces[0] = (*challenge * roster->members()[0].coefficient * secrets[0]).negate();
        auto zero_partials = toy_partials(*roster, std::span(secrets).first(count),
                                          std::span(zero_nonces).first(count), *challenge, secp.get());
        expect_ok(ctx, zero_partials, "zero response fixtures construct");
        if (!zero_partials) return;
        ctx.expect(zero_partials->front().response.serialize() == std::array<unsigned char, 32>{},
                   "zero-response fixture is exactly zero");
        expect_ok(ctx, verify_partial_response(*roster, 0, context, body, zero_partials->front(), secp.get()),
                  "canonical zero response with a valid equation accepts");
        expect_ok(ctx, aggregate_responses(*roster, context, body, *zero_partials, secp.get()),
                  "zero member response contributes normally to aggregation");

        if (count > 1) {
            auto cancelling = nonces;
            cancelling[1] = cancelling[0].negate();
            auto cancelled = toy_partials(*roster, std::span(secrets).first(count),
                                          std::span(cancelling).first(count), *challenge, secp.get());
            expect_ok(ctx, cancelled, "cancelling nonce fixtures construct");
            if (!cancelled) return;
            if (count == 2) {
                expect_error(ctx, aggregate_responses(*roster, context, body, *cancelled, secp.get()),
                             purify::ErrorCode::RangeViolation, "final identity nonce rejects");
            } else {
                expect_ok(ctx, aggregate_responses(*roster, context, body, *cancelled, secp.get()),
                          "intermediate nonce cancellation permits a nonidentity final nonce");
            }
        }
        expect_error(ctx, aggregate_responses(*roster, context, body, *partials, nullptr),
                     purify::ErrorCode::MissingValue, "aggregation without a secp context rejects");

        auto moved = std::move(*roster);
        expect_error(ctx, aggregate_responses(*roster, context, body, {}, secp.get()),
                     purify::ErrorCode::EmptyInput, "moved-from empty roster cannot authorize an empty aggregate");
        expect_ok(ctx, aggregate_responses(moved, context, body, *partials, secp.get()),
                  "moved roster retains valid aggregation behavior");
    }
}
