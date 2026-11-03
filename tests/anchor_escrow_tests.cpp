// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <algorithm>
#include <array>
#include <chrono>
#include <iostream>
#include <span>
#include <utility>

#include "purify.hpp"
#include "purify/puresign/anchor_escrow.hpp"
#include "../src/puresign/anchor_escrow_internal.hpp"
#include "purify_test_helpers.hpp"

namespace {

using purify_test::TestContext;
using purify_test::expect_error;
using purify_test::expect_ok;
using purify::FieldElement;
using purify::Result;
using purify::accountable::AnchorEscrowContextDigest;
using purify::accountable::CoalitionCoreDigest;
using purify::accountable::RecoveryBoundSigningRoster;
using purify::accountable::SigningRoster;

void test_anchor_punishment_derivation(TestContext& ctx) {
    auto secp = purify::make_secp_context();
    ctx.expect(secp != nullptr,
               "anchor punishment secp context creates");
    if (!secp) return;
    std::array<unsigned char, 32> invalid_punishment_xonly{};
    invalid_punishment_xonly.fill(0xff);
    expect_error(
        ctx,
        purify::accountable::AnchorPunishmentPublicKey::create(
            invalid_punishment_xonly, secp.get()),
        purify::ErrorCode::BackendRejectedInput,
        "noncanonical punishment public key rejects");
    expect_error(
        ctx,
        purify::accountable::AnchorPunishmentPublicKey::create(
            invalid_punishment_xonly, nullptr),
        purify::ErrorCode::MissingValue,
        "punishment public-key parsing requires a secp context");
    auto minimum_secret = purify::SecretKey::from_packed(
        purify::UInt512::zero());
    expect_ok(ctx, minimum_secret,
              "minimum canonical anchor secret parses");
    if (!minimum_secret) return;
    auto anchor = purify::derive_key(std::move(*minimum_secret));
    expect_ok(ctx, anchor,
              "minimum canonical anchor recovery key derives");
    if (!anchor) return;
#if PURIFY_USE_LEGACY_FIELD_HASHES
    expect_error(
        ctx,
        purify::accountable::derive_anchor_punishment_key(
            *anchor, secp.get()),
        purify::ErrorCode::UnsupportedSymbol,
        "anchor v3 derivation rejects the legacy field-hash suite");
    return;
#else
    expect_error(
        ctx,
        purify::accountable::derive_anchor_punishment_key(*anchor,
                                                          nullptr),
        purify::ErrorCode::MissingValue,
        "punishment-key derivation requires a secp context");
    auto punishment =
        purify::accountable::derive_anchor_punishment_key(*anchor,
                                                          secp.get());
    expect_ok(ctx, punishment,
              "fixed-domain anchor punishment key derives");
    if (!punishment) return;
    const auto punishment_key = punishment->public_key();
    auto raw_punishment = purify::eval(
        anchor->secret,
        purify::bytes_from_ascii(
            "Purify/Accountable/AnchorPunishmentKey/v1"));
    expect_ok(ctx, raw_punishment,
              "pinned punishment evaluation input derives");
    if (!raw_punishment) return;
    auto canonical_punishment = raw_punishment->to_bytes_be();
    std::array<unsigned char, 32> canonical_punishment_xonly{};
    constexpr auto kMinimumRaw =
        "74e11ba824a807f9b33bf4f7bf1c9a4d"
        "5ebc612adf2fa1a81e3500a6582b19c5";
    constexpr auto kMinimumXonly =
        "3ea23ca101b865e6edc3b299bc92592c"
        "69f1f8d506b05b284bf8a6f0c651dca2";
    ctx.expect(
        raw_punishment->to_hex() == kMinimumRaw &&
            purify_bip340_key_from_seckey(
                secp.get(), canonical_punishment.data(),
                canonical_punishment_xonly.data()) != 0 &&
            canonical_punishment == punishment->bip340_key().seckey &&
            canonical_punishment_xonly == punishment_key.xonly() &&
            purify::UInt256::from_bytes_be(
                punishment_key.xonly().data(),
                punishment_key.xonly().size()).to_hex() ==
                kMinimumXonly,
        "minimum anchor matches the even fixed-domain key vector");

    auto parsed_punishment =
        purify::accountable::AnchorPunishmentPublicKey::create(
            punishment_key.xonly(), secp.get());
    expect_ok(ctx, parsed_punishment,
              "derived punishment public key reparses");
    if (!parsed_punishment) return;
    ctx.expect(*parsed_punishment == punishment_key,
               "punishment public key has one canonical x-only form");

    std::array<unsigned char, 32> seed{};
    seed.fill(0x48);
    auto other_anchor = purify::generate_key(seed);
    expect_ok(ctx, other_anchor,
              "distinct punishment derivation anchor generates");
    if (!other_anchor) return;
    auto other_punishment =
        purify::accountable::derive_anchor_punishment_key(
            *other_anchor, secp.get());
    expect_ok(ctx, other_punishment,
              "distinct fixed-domain punishment key derives");
    if (!other_punishment) return;
    ctx.expect(other_punishment->public_key() != punishment_key,
               "fixed-domain punishment derivation depends on the anchor");

    auto anchor_secret_copy = anchor->secret.clone();
    expect_ok(ctx, anchor_secret_copy,
              "punishment mismatch fixture clones its secret");
    if (!anchor_secret_copy) return;
    purify::GeneratedKey mismatched_anchor{
        std::move(*anchor_secret_copy), other_anchor->public_key};
    expect_error(
        ctx,
        purify::accountable::derive_anchor_punishment_key(
            mismatched_anchor, secp.get()),
        purify::ErrorCode::BindingMismatch,
        "punishment derivation rejects a mismatched anchor keypair");

    auto odd_secret = purify::SecretKey::from_packed(
        purify::UInt512::from_u64(8));
    expect_ok(ctx, odd_secret,
              "odd fixed-domain vector secret parses");
    if (!odd_secret) return;
    auto odd_anchor = purify::derive_key(std::move(*odd_secret));
    expect_ok(ctx, odd_anchor,
              "odd fixed-domain vector anchor derives");
    if (!odd_anchor) return;
    auto odd_punishment =
        purify::accountable::derive_anchor_punishment_key(
            *odd_anchor, secp.get());
    expect_ok(ctx, odd_punishment,
              "odd fixed-domain punishment key derives");
    if (!odd_punishment) return;
    auto odd_raw = purify::eval(
        odd_anchor->secret,
        purify::bytes_from_ascii(
            "Purify/Accountable/AnchorPunishmentKey/v1"));
    expect_ok(ctx, odd_raw,
              "odd fixed-domain raw evaluation derives");
    if (!odd_raw) return;
    constexpr auto kOddRaw =
        "3e271baaafdb9ac9fea6ef734e3579b2"
        "eb8a855bbbedfcfee9cabcc8058797f9";
    constexpr auto kOddNormalized =
        "c1d8e455502465360159108cb1ca864b"
        "cf24578af35aa33cd607a1c4caaea948";
    constexpr auto kOddXonly =
        "966bb6ac89e212303f3bbeb495fdf212"
        "828eb31ced01d7650acac9e1378d4824";
    ctx.expect(
        odd_raw->to_hex() == kOddRaw &&
            purify::UInt256::from_bytes_be(
                odd_punishment->bip340_key().seckey.data(),
                odd_punishment->bip340_key().seckey.size()).to_hex() ==
                kOddNormalized &&
            purify::UInt256::from_bytes_be(
                odd_punishment->public_key().xonly().data(),
                odd_punishment->public_key().xonly().size()).to_hex() ==
                kOddXonly &&
            odd_raw->to_bytes_be() !=
                odd_punishment->bip340_key().seckey,
        "odd raw output normalizes to the frozen even-Y key vector");
#endif
}

void test_anchor_v3_hash_suite_mode(TestContext& ctx) {
#if PURIFY_USE_LEGACY_FIELD_HASHES
    auto secp = purify::make_secp_context();
    ctx.expect(secp != nullptr,
               "anchor v3 suite-mode secp context creates");
    if (!secp) return;
    auto anchor_secret = purify::SecretKey::from_packed(
        purify::UInt512::from_u64(8));
    expect_ok(ctx, anchor_secret,
              "anchor v3 suite-mode secret parses");
    if (!anchor_secret) return;
    auto anchor = purify::derive_key(std::move(*anchor_secret));
    expect_ok(ctx, anchor,
              "anchor v3 suite-mode key derives");
    if (!anchor) return;
    expect_error(
        ctx,
        purify::accountable::anchor_escrow_circuit_shape_for_testing(
            anchor->public_key, anchor->public_key, {}),
        purify::ErrorCode::UnsupportedSymbol,
        "anchor v3 circuit construction rejects legacy field hashes");
    auto accumulator =
        purify::accountable::AnchorEscrowAccumulator::create(secp.get());
    expect_ok(ctx, accumulator,
              "legacy builds retain non-accepting anchor basis syntax");
#else
    (void)ctx;
#endif
}

} // namespace

void run_anchor_escrow_tests(TestContext& ctx) {
    test_anchor_punishment_derivation(ctx);
    test_anchor_v3_hash_suite_mode(ctx);
}
