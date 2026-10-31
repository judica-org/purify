// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "../src/bridge/bppp_bridge.h"
#include "../src/puresign/slash_adaptor_internal.hpp"
#include "purify/puresign/slash_adaptor.hpp"
#include "purify/secp_bridge.h"
#include "purify_test_helpers.hpp"

#include <algorithm>
#include <optional>
#include <utility>

namespace {

using purify::ErrorCode;
using purify::Result;
using purify::puresign::Bip340Signature;
using purify::puresign::CoalitionScalar;
using purify::puresign::EvenCoalitionKey;
using purify::puresign::SecpPoint;
using purify::puresign::SlashAdaptorReceipt;
using purify::puresign::SlashMessageDigest;
using purify_test::expect_error;
using purify_test::expect_ok;
using purify_test::TestContext;

unsigned char hex_nibble(char value) {
  if (value >= '0' && value <= '9') {
    return static_cast<unsigned char>(value - '0');
  }
  return static_cast<unsigned char>(value - 'a' + 10);
}

template <std::size_t N>
std::array<unsigned char, N> fixed_hex(std::string_view hex) {
  std::array<unsigned char, N> out{};
  if (hex.size() != 2 * N)
    return out;
  for (std::size_t i = 0; i < N; ++i) {
    out[i] = static_cast<unsigned char>((hex_nibble(hex[2 * i]) << 4) |
                                        hex_nibble(hex[2 * i + 1]));
  }
  return out;
}

CoalitionScalar scalar_from_u64(std::uint64_t value) {
  CoalitionScalar out{};
  for (std::size_t i = 0; i < sizeof(value); ++i) {
    out[out.size() - 1 - i] =
        static_cast<unsigned char>((value >> (8 * i)) & 0xffU);
  }
  return out;
}

CoalitionScalar negate_scalar(const CoalitionScalar &value) {
  purify_scalar scalar{};
  int overflow = 0;
  purify_scalar_set_b32(&scalar, value.data(), &overflow);
  purify_scalar_negate(&scalar, &scalar);
  CoalitionScalar out{};
  purify_scalar_get_b32(out.data(), &scalar);
  return out;
}

CoalitionScalar increment_scalar(const CoalitionScalar &value) {
  purify_scalar scalar{};
  purify_scalar one{};
  int overflow = 0;
  purify_scalar_set_b32(&scalar, value.data(), &overflow);
  purify_scalar_set_int(&one, 1);
  purify_scalar_add(&scalar, &scalar, &one);
  CoalitionScalar out{};
  purify_scalar_get_b32(out.data(), &scalar);
  return out;
}

Result<purify::Bip340Key> bip340_key(std::uint64_t value,
                                     purify_secp_context *secp_context) {
  purify::Bip340Key out;
  out.seckey = scalar_from_u64(value);
  if (purify_bip340_key_from_seckey(secp_context, out.seckey.data(),
                                    out.xonly_pubkey.data()) == 0) {
    return purify::unexpected_error(ErrorCode::BackendRejectedInput,
                                    "slash_adaptor_test:key");
  }
  return out;
}

struct CoalitionFixture {
  EvenCoalitionKey key;
  CoalitionScalar scalar{};
};

Result<CoalitionFixture> coalition_fixture(std::uint64_t value,
                                           purify_secp_context *secp_context) {
  CoalitionScalar scalar = scalar_from_u64(value);
  std::array<unsigned char, 32> xonly{};
  if (purify_bip340_key_from_seckey(secp_context, scalar.data(),
                                    xonly.data()) == 0) {
    return purify::unexpected_error(ErrorCode::BackendRejectedInput,
                                    "slash_adaptor_test:coalition");
  }
  SecpPoint point{};
  point[0] = 0x02;
  std::copy(xonly.begin(), xonly.end(), point.begin() + 1);
  PURIFY_ASSIGN_OR_RETURN(auto key,
                          EvenCoalitionKey::parse(point, secp_context),
                          "slash_adaptor_test:coalition_parse");
  return CoalitionFixture{std::move(key), scalar};
}

SlashMessageDigest message_digest(std::string_view text) {
  SlashMessageDigest out{};
  purify_sha256(out.data(),
                reinterpret_cast<const unsigned char *>(text.data()),
                text.size());
  return out;
}

Result<SecpPoint> unadapted_nonce(const SlashAdaptorReceipt &receipt,
                                  const EvenCoalitionKey &coalition,
                                  purify_secp_context *secp_context) {
  SecpPoint negative_coalition = coalition.point();
  negative_coalition[0] = 0x03;
  SecpPoint out{};
  if (purify_point_add(secp_context, receipt.adapted_nonce.data(),
                       negative_coalition.data(), out.data()) == 0) {
    return purify::unexpected_error(ErrorCode::BackendRejectedInput,
                                    "slash_adaptor_test:unadapt");
  }
  return out;
}

bool verified(TestContext &ctx, const Result<bool> &result,
              std::string_view message) {
  expect_ok(ctx, result, message);
  if (!result)
    return false;
  ctx.expect(*result, message);
  return *result;
}

struct ParityReceipts {
  SlashAdaptorReceipt even;
  SlashAdaptorReceipt odd;
};

Result<ParityReceipts> find_both_parities(const purify::Bip340Key &anchor,
                                          const EvenCoalitionKey &coalition,
                                          const SlashMessageDigest &message,
                                          purify_secp_context *secp_context) {
  std::optional<SlashAdaptorReceipt> even;
  std::optional<SlashAdaptorReceipt> odd;
  for (std::uint64_t nonce = 1; nonce <= 512 && (!even || !odd); ++nonce) {
    auto receipt =
        purify::puresign::detail::create_slash_adaptor_receipt_with_nonce(
            anchor, coalition, message, scalar_from_u64(nonce), secp_context);
    if (!receipt) {
      if (receipt.error().code == ErrorCode::EquationMismatch)
        continue;
      return purify::unexpected_error(receipt.error(),
                                      "slash_adaptor_test:parity_receipt");
    }
    if (receipt->adapted_nonce[0] == 0x02) {
      even = *receipt;
    } else {
      odd = *receipt;
    }
  }
  if (!even || !odd) {
    return purify::unexpected_error(ErrorCode::InternalMismatch,
                                    "slash_adaptor_test:both_parities");
  }
  return ParityReceipts{*even, *odd};
}

void test_roundtrip_and_parities(TestContext &ctx,
                                 const purify::Bip340Key &anchor,
                                 const CoalitionFixture &coalition,
                                 const SlashMessageDigest &message,
                                 const ParityReceipts &receipts,
                                 purify_secp_context *secp_context) {
  ctx.expect(receipts.even.adapted_nonce[0] == 0x02,
             "fixed vectors cover an even adapted nonce");
  ctx.expect(receipts.odd.adapted_nonce[0] == 0x03,
             "fixed vectors cover an odd adapted nonce");

  for (const SlashAdaptorReceipt *receipt : {&receipts.even, &receipts.odd}) {
    verified(ctx,
             purify::puresign::verify_slash_adaptor_receipt(
                 *receipt, anchor.xonly_pubkey, coalition.key, message,
                 secp_context),
             "adaptor equation verifies for either parity");
    const auto bytes = receipt->serialize();
    ctx.expect(bytes.size() == SlashAdaptorReceipt::kSerializedSize,
               "adaptor receipt is exactly 65 bytes");
    auto parsed = SlashAdaptorReceipt::deserialize(bytes, secp_context);
    expect_ok(ctx, parsed, "adaptor receipt parses");
    if (parsed) {
      ctx.expect(parsed->adapted_nonce == receipt->adapted_nonce &&
                     parsed->pre_response == receipt->pre_response,
                 "adaptor receipt roundtrips exactly");
    }

    auto signature =
        purify::puresign::detail::complete_slash_adaptor_receipt_with_scalar(
            *receipt, anchor.xonly_pubkey, coalition.key, message,
            coalition.scalar, secp_context);
    expect_ok(ctx, signature, "exposed coalition scalar completes receipt");
    if (!signature)
      continue;
    ctx.expect(purify_bip340_verify(secp_context, signature->data(),
                                    message.data(), message.size(),
                                    anchor.xonly_pubkey.data()) != 0,
               "completed receipt is an ordinary BIP340 signature");
    ctx.expect(std::equal(signature->begin(), signature->begin() + 32,
                          receipt->adapted_nonce.begin() + 1),
               "completed signature retains the exact receipt nonce");
    auto extracted = purify::puresign::extract_slash_adaptor_secret(
        *receipt, *signature, anchor.xonly_pubkey, coalition.key, message,
        secp_context);
    expect_ok(ctx, extracted, "completed receipt extracts coalition scalar");
    if (extracted) {
      ctx.expect(*extracted == coalition.scalar,
                 "extraction returns the exact even-point scalar");
    }
  }
}

void test_statement_binding(TestContext &ctx, const purify::Bip340Key &anchor,
                            const purify::Bip340Key &other_anchor,
                            const CoalitionFixture &coalition,
                            const CoalitionFixture &other_coalition,
                            const SlashMessageDigest &message,
                            const ParityReceipts &receipts,
                            purify_secp_context *secp_context) {
  std::array<unsigned char, 32> invalid_anchor{};
  invalid_anchor.fill(0xff);
  expect_error(
      ctx,
      purify::puresign::verify_slash_adaptor_receipt(
          receipts.even, invalid_anchor, coalition.key, message, secp_context),
      ErrorCode::BackendRejectedInput,
      "receipt rejects a malformed anchor key");

  auto wrong_anchor = purify::puresign::verify_slash_adaptor_receipt(
      receipts.even, other_anchor.xonly_pubkey, coalition.key, message,
      secp_context);
  expect_ok(ctx, wrong_anchor, "wrong anchor is a well-formed statement");
  if (wrong_anchor) {
    ctx.expect(!*wrong_anchor, "receipt rejects a different anchor");
  }

  auto wrong_coalition = purify::puresign::verify_slash_adaptor_receipt(
      receipts.even, anchor.xonly_pubkey, other_coalition.key, message,
      secp_context);
  expect_ok(ctx, wrong_coalition, "wrong coalition is a well-formed statement");
  if (wrong_coalition) {
    ctx.expect(!*wrong_coalition, "receipt rejects a different coalition");
  }

  auto other_message = message;
  other_message.back() ^= 1;
  auto wrong_message = purify::puresign::verify_slash_adaptor_receipt(
      receipts.even, anchor.xonly_pubkey, coalition.key, other_message,
      secp_context);
  expect_ok(ctx, wrong_message, "wrong digest is a well-formed statement");
  if (wrong_message) {
    ctx.expect(!*wrong_message, "receipt rejects a different message digest");
  }

  auto wrong_nonce = receipts.even;
  wrong_nonce.adapted_nonce = receipts.odd.adapted_nonce;
  auto wrong_nonce_ok = purify::puresign::verify_slash_adaptor_receipt(
      wrong_nonce, anchor.xonly_pubkey, coalition.key, message, secp_context);
  expect_ok(ctx, wrong_nonce_ok,
            "altered adapted nonce remains syntactically valid");
  if (wrong_nonce_ok) {
    ctx.expect(!*wrong_nonce_ok, "receipt binds the adapted nonce");
  }

  auto wrong_response = receipts.even;
  wrong_response.pre_response = increment_scalar(wrong_response.pre_response);
  auto wrong_response_ok = purify::puresign::verify_slash_adaptor_receipt(
      wrong_response, anchor.xonly_pubkey, coalition.key, message,
      secp_context);
  expect_ok(ctx, wrong_response_ok,
            "altered pre-response remains syntactically valid");
  if (wrong_response_ok) {
    ctx.expect(!*wrong_response_ok, "receipt binds the pre-response");
  }

  auto zero_unadapted_nonce = receipts.even;
  zero_unadapted_nonce.adapted_nonce = coalition.key.point();
  expect_error(ctx,
               purify::puresign::verify_slash_adaptor_receipt(
                   zero_unadapted_nonce, anchor.xonly_pubkey, coalition.key,
                   message, secp_context),
               ErrorCode::RangeViolation,
               "verifier rejects A equal to Q and a zero hidden nonce");
}

void test_encoding_rejections(TestContext &ctx,
                              const CoalitionFixture &coalition,
                              const ParityReceipts &receipts,
                              purify_secp_context *secp_context) {
  auto bytes = receipts.even.serialize();
  expect_error(
      ctx,
      SlashAdaptorReceipt::deserialize(
          std::span<const unsigned char>(bytes).first(64), secp_context),
      ErrorCode::InvalidFixedSize, "receipt rejects truncation");

  auto invalid_point = bytes;
  invalid_point[0] = 0;
  expect_error(ctx,
               SlashAdaptorReceipt::deserialize(invalid_point, secp_context),
               ErrorCode::BackendRejectedInput,
               "receipt rejects an invalid adapted point");

  auto noncanonical_response = bytes;
  std::fill(noncanonical_response.begin() + 33, noncanonical_response.end(),
            0xff);
  expect_error(
      ctx,
      SlashAdaptorReceipt::deserialize(noncanonical_response, secp_context),
      ErrorCode::RangeViolation,
      "receipt rejects a non-canonical pre-response");

  auto odd_coalition = coalition.key.point();
  odd_coalition[0] = 0x03;
  expect_error(ctx, EvenCoalitionKey::parse(odd_coalition, secp_context),
               ErrorCode::RangeViolation,
               "coalition key rejects the opposite point sign");
}

void test_completion_rejections(TestContext &ctx,
                                const purify::Bip340Key &anchor,
                                const CoalitionFixture &coalition,
                                const SlashMessageDigest &message,
                                const ParityReceipts &receipts,
                                purify_secp_context *secp_context) {
  const auto wrong_scalar = negate_scalar(coalition.scalar);
  expect_error(
      ctx,
      purify::puresign::detail::complete_slash_adaptor_receipt_with_scalar(
          receipts.even, anchor.xonly_pubkey, coalition.key, message,
          wrong_scalar, secp_context),
      ErrorCode::BindingMismatch,
      "completion rejects the negative coalition representative");
  expect_error(
      ctx,
      purify::puresign::detail::complete_slash_adaptor_receipt_with_scalar(
          receipts.even, anchor.xonly_pubkey, coalition.key, message,
          CoalitionScalar{}, secp_context),
      ErrorCode::RangeViolation, "completion rejects a zero coalition scalar");
  const auto curve_order = fixed_hex<32>(
      "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
  expect_error(
      ctx,
      purify::puresign::detail::complete_slash_adaptor_receipt_with_scalar(
          receipts.even, anchor.xonly_pubkey, coalition.key, message,
          curve_order, secp_context),
      ErrorCode::RangeViolation,
      "completion rejects the non-canonical curve order");

  auto altered = receipts.even;
  altered.pre_response = increment_scalar(altered.pre_response);
  expect_error(
      ctx,
      purify::puresign::detail::complete_slash_adaptor_receipt_with_scalar(
          altered, anchor.xonly_pubkey, coalition.key, message,
          coalition.scalar, secp_context),
      ErrorCode::EquationMismatch,
      "completion rejects an invalid adaptor equation");

  auto even_signature =
      purify::puresign::detail::complete_slash_adaptor_receipt_with_scalar(
          receipts.even, anchor.xonly_pubkey, coalition.key, message,
          coalition.scalar, secp_context);
  auto odd_signature =
      purify::puresign::detail::complete_slash_adaptor_receipt_with_scalar(
          receipts.odd, anchor.xonly_pubkey, coalition.key, message,
          coalition.scalar, secp_context);
  expect_ok(ctx, even_signature, "even receipt completes for extraction tests");
  expect_ok(ctx, odd_signature, "odd receipt completes for extraction tests");
  if (!even_signature || !odd_signature)
    return;

  expect_error(ctx,
               purify::puresign::extract_slash_adaptor_secret(
                   receipts.even, *odd_signature, anchor.xonly_pubkey,
                   coalition.key, message, secp_context),
               ErrorCode::BindingMismatch,
               "extraction rejects a valid signature with another nonce");

  Bip340Signature invalid_signature = *even_signature;
  invalid_signature.back() ^= 1;
  expect_error(ctx,
               purify::puresign::extract_slash_adaptor_secret(
                   receipts.even, invalid_signature, anchor.xonly_pubkey,
                   coalition.key, message, secp_context),
               ErrorCode::EquationMismatch,
               "extraction rejects an invalid final signature");
}

void test_nonce_and_key_rejections(TestContext &ctx,
                                   const purify::Bip340Key &anchor,
                                   const purify::Bip340Key &other_anchor,
                                   const CoalitionFixture &coalition,
                                   const SlashMessageDigest &message,
                                   purify_secp_context *secp_context) {
  expect_error(
      ctx,
      purify::puresign::detail::create_slash_adaptor_receipt_with_nonce(
          anchor, coalition.key, message, CoalitionScalar{}, secp_context),
      ErrorCode::RangeViolation, "fixed constructor rejects a zero nonce");
  CoalitionScalar noncanonical{};
  noncanonical.fill(0xff);
  expect_error(
      ctx,
      purify::puresign::detail::create_slash_adaptor_receipt_with_nonce(
          anchor, coalition.key, message, noncanonical, secp_context),
      ErrorCode::RangeViolation,
      "fixed constructor rejects a non-canonical nonce");

  const auto infinity_nonce = negate_scalar(coalition.scalar);
  expect_error(
      ctx,
      purify::puresign::detail::create_slash_adaptor_receipt_with_nonce(
          anchor, coalition.key, message, infinity_nonce, secp_context),
      ErrorCode::EquationMismatch, "fixed constructor rejects A at infinity");

  auto mismatched_anchor = bip340_key(17, secp_context);
  expect_ok(ctx, mismatched_anchor, "mismatched anchor fixture derives");
  if (mismatched_anchor) {
    mismatched_anchor->xonly_pubkey = other_anchor.xonly_pubkey;
    expect_error(
        ctx,
        purify::puresign::detail::create_slash_adaptor_receipt_with_nonce(
            *mismatched_anchor, coalition.key, message, scalar_from_u64(1),
            secp_context),
        ErrorCode::BindingMismatch,
        "constructor rejects a mismatched anchor keypair");
  }

  auto noncanonical_anchor = bip340_key(23, secp_context);
  expect_ok(ctx, noncanonical_anchor, "non-canonical anchor fixture derives");
  if (noncanonical_anchor) {
    noncanonical_anchor->seckey = negate_scalar(noncanonical_anchor->seckey);
    expect_error(
        ctx,
        purify::puresign::detail::create_slash_adaptor_receipt_with_nonce(
            *noncanonical_anchor, coalition.key, message, scalar_from_u64(1),
            secp_context),
        ErrorCode::BindingMismatch,
        "constructor rejects a non-canonical anchor secret");
  }
}

void test_hedged_nonce_binding(TestContext &ctx,
                               const purify::Bip340Key &anchor,
                               const purify::Bip340Key &other_anchor,
                               const CoalitionFixture &coalition,
                               const CoalitionFixture &other_coalition,
                               const SlashMessageDigest &message,
                               purify_secp_context *secp_context) {
  CoalitionScalar auxiliary_randomness{};
  for (std::size_t i = 0; i < auxiliary_randomness.size(); ++i) {
    auxiliary_randomness[i] = static_cast<unsigned char>(i);
  }
  auto first = purify::puresign::detail::
      create_slash_adaptor_receipt_with_aux_randomness(
          anchor, coalition.key, message, auxiliary_randomness, secp_context);
  auto repeated = purify::puresign::detail::
      create_slash_adaptor_receipt_with_aux_randomness(
          anchor, coalition.key, message, auxiliary_randomness, secp_context);
  expect_ok(ctx, first, "hedged deterministic receipt derives");
  expect_ok(ctx, repeated, "hedged receipt repeats deterministically");
  if (!first || !repeated)
    return;
  ctx.expect(first->serialize() == repeated->serialize(),
             "same auxiliary randomness and statement reproduce one nonce");
  // Fixed vector inputs are canonical anchor scalar n-11, coalition scalar 7,
  // SHA256("exact slash transaction digest"), and auxiliary bytes 00..1f.
  // Completion is independently checked by the vendored BIP340 verifier.
  const auto expected_odd_receipt = fixed_hex<65>(
      "0309dfb80cbe463184d9c4c2f957a9758acbe5630eee6b1ce297f1c51c"
      "05130720e894cadc3a1d4f4b8acd4f2f2999c02dbd73fcfe2c796783c69"
      "25d93122ca09f");
  ctx.expect(first->serialize() == expected_odd_receipt,
             "hedged odd-parity receipt matches its fixed vector");
  auto odd_signature =
      purify::puresign::detail::complete_slash_adaptor_receipt_with_scalar(
          *first, anchor.xonly_pubkey, coalition.key, message, coalition.scalar,
          secp_context);
  expect_ok(ctx, odd_signature, "hedged odd vector completes");
  if (odd_signature) {
    const auto expected_signature = fixed_hex<64>(
        "09dfb80cbe463184d9c4c2f957a9758acbe5630eee6b1ce297f1c51c05"
        "130720e894cadc3a1d4f4b8acd4f2f2999c02dbd73fcfe2c796783c6925"
        "d93122ca098");
    ctx.expect(*odd_signature == expected_signature,
               "hedged odd completion matches its BIP340 vector");
  }

  auto even_auxiliary = auxiliary_randomness;
  even_auxiliary.back() = 0;
  auto even = purify::puresign::detail::
      create_slash_adaptor_receipt_with_aux_randomness(
          anchor, coalition.key, message, even_auxiliary, secp_context);
  expect_ok(ctx, even, "hedged even vector derives");
  if (even) {
    const auto expected_even_receipt = fixed_hex<65>(
        "02d57ce7d9ff42f0acb7191c40f5742558a00e19f72f1e3b6da02dfe24"
        "ac0b9c648854c16c2de74187d99bb028ec0260c930a81cf514fc58e1689"
        "6842ffa1e191e");
    ctx.expect(even->serialize() == expected_even_receipt,
               "hedged even-parity receipt matches its fixed vector");
    auto even_signature =
        purify::puresign::detail::complete_slash_adaptor_receipt_with_scalar(
            *even, anchor.xonly_pubkey, coalition.key, message,
            coalition.scalar, secp_context);
    expect_ok(ctx, even_signature, "hedged even vector completes");
    if (even_signature) {
      const auto expected_signature = fixed_hex<64>(
          "d57ce7d9ff42f0acb7191c40f5742558a00e19f72f1e3b6da02dfe24ac"
          "0b9c648854c16c2de74187d99bb028ec0260c930a81cf514fc58e168968"
          "42ffa1e1925");
      ctx.expect(*even_signature == expected_signature,
                 "hedged even completion matches its BIP340 vector");
    }
  }

  auto other_message = message;
  other_message.front() ^= 1;
  auto message_bound = purify::puresign::detail::
      create_slash_adaptor_receipt_with_aux_randomness(
          anchor, coalition.key, other_message, auxiliary_randomness,
          secp_context);
  auto coalition_bound = purify::puresign::detail::
      create_slash_adaptor_receipt_with_aux_randomness(
          anchor, other_coalition.key, message, auxiliary_randomness,
          secp_context);
  auto anchor_bound = purify::puresign::detail::
      create_slash_adaptor_receipt_with_aux_randomness(
          other_anchor, coalition.key, message, auxiliary_randomness,
          secp_context);
  expect_ok(ctx, message_bound, "hedged nonce binds another message");
  expect_ok(ctx, coalition_bound, "hedged nonce binds another coalition");
  expect_ok(ctx, anchor_bound, "hedged nonce binds another anchor");
  if (!message_bound || !coalition_bound || !anchor_bound)
    return;
  auto first_nonce = unadapted_nonce(*first, coalition.key, secp_context);
  auto message_nonce =
      unadapted_nonce(*message_bound, coalition.key, secp_context);
  auto coalition_nonce =
      unadapted_nonce(*coalition_bound, other_coalition.key, secp_context);
  auto anchor_nonce =
      unadapted_nonce(*anchor_bound, coalition.key, secp_context);
  expect_ok(ctx, first_nonce, "first hedged nonce reconstructs");
  expect_ok(ctx, message_nonce, "message-bound hedged nonce reconstructs");
  expect_ok(ctx, coalition_nonce, "coalition-bound hedged nonce reconstructs");
  expect_ok(ctx, anchor_nonce, "anchor-bound hedged nonce reconstructs");
  if (!first_nonce || !message_nonce || !coalition_nonce || !anchor_nonce) {
    return;
  }
  ctx.expect(*message_nonce != *first_nonce,
             "repeated auxiliary randomness cannot reuse across messages");
  ctx.expect(*coalition_nonce != *first_nonce,
             "repeated auxiliary randomness cannot reuse across coalitions");
  ctx.expect(*anchor_nonce != *first_nonce,
             "repeated auxiliary randomness cannot reuse across anchors");
}

void test_missing_context_rejections(TestContext &ctx,
                                     const purify::Bip340Key &anchor,
                                     const CoalitionFixture &coalition,
                                     const SlashMessageDigest &message,
                                     const SlashAdaptorReceipt &receipt,
                                     purify_secp_context *secp_context) {
  expect_error(ctx, EvenCoalitionKey::parse(coalition.key.point(), nullptr),
               ErrorCode::MissingValue,
               "coalition parsing rejects a missing context");
  const auto bytes = receipt.serialize();
  expect_error(ctx, SlashAdaptorReceipt::deserialize(bytes, nullptr),
               ErrorCode::MissingValue,
               "receipt parsing rejects a missing context");
  expect_error(ctx,
               purify::puresign::create_slash_adaptor_receipt(
                   anchor, coalition.key, message, nullptr),
               ErrorCode::MissingValue,
               "receipt creation rejects a missing context");
  expect_error(
      ctx,
      purify::puresign::verify_slash_adaptor_receipt(
          receipt, anchor.xonly_pubkey, coalition.key, message, nullptr),
      ErrorCode::MissingValue,
      "receipt verification rejects a missing context");
  expect_error(
      ctx,
      purify::puresign::detail::complete_slash_adaptor_receipt_with_scalar(
          receipt, anchor.xonly_pubkey, coalition.key, message,
          coalition.scalar, nullptr),
      ErrorCode::MissingValue, "receipt completion rejects a missing context");
  auto signature =
      purify::puresign::detail::complete_slash_adaptor_receipt_with_scalar(
          receipt, anchor.xonly_pubkey, coalition.key, message,
          coalition.scalar, secp_context);
  expect_ok(ctx, signature, "signature fixture completes for context test");
  if (signature) {
    expect_error(ctx,
                 purify::puresign::extract_slash_adaptor_secret(
                     receipt, *signature, anchor.xonly_pubkey, coalition.key,
                     message, nullptr),
                 ErrorCode::MissingValue,
                 "secret extraction rejects a missing context");
  }
}

} // namespace

void run_slash_adaptor_tests(TestContext &ctx) {
  auto secp = purify::make_secp_context();
  ctx.expect(secp != nullptr, "slash adaptor context creates");
  if (!secp)
    return;

  auto anchor = bip340_key(11, secp.get());
  auto other_anchor = bip340_key(13, secp.get());
  auto coalition = coalition_fixture(7, secp.get());
  auto other_coalition = coalition_fixture(19, secp.get());
  expect_ok(ctx, anchor, "anchor key fixture derives");
  expect_ok(ctx, other_anchor, "other anchor key fixture derives");
  expect_ok(ctx, coalition, "coalition key fixture derives");
  expect_ok(ctx, other_coalition, "other coalition fixture derives");
  if (!anchor || !other_anchor || !coalition || !other_coalition)
    return;

  const auto message = message_digest("exact slash transaction digest");
  auto receipts =
      find_both_parities(*anchor, coalition->key, message, secp.get());
  expect_ok(ctx, receipts, "deterministic vectors find both nonce parities");
  if (!receipts)
    return;

  test_roundtrip_and_parities(ctx, *anchor, *coalition, message, *receipts,
                              secp.get());
  test_statement_binding(ctx, *anchor, *other_anchor, *coalition,
                         *other_coalition, message, *receipts, secp.get());
  test_encoding_rejections(ctx, *coalition, *receipts, secp.get());
  test_completion_rejections(ctx, *anchor, *coalition, message, *receipts,
                             secp.get());
  test_nonce_and_key_rejections(ctx, *anchor, *other_anchor, *coalition,
                                message, secp.get());
  test_hedged_nonce_binding(ctx, *anchor, *other_anchor, *coalition,
                            *other_coalition, message, secp.get());
  test_missing_context_rejections(ctx, *anchor, *coalition, message,
                                  receipts->even, secp.get());

  auto random_receipt = purify::puresign::create_slash_adaptor_receipt(
      *anchor, coalition->key, message, secp.get());
  expect_ok(ctx, random_receipt,
            "production constructor samples a valid receipt");
  if (random_receipt) {
    verified(ctx,
             purify::puresign::verify_slash_adaptor_receipt(
                 *random_receipt, anchor->xonly_pubkey, coalition->key, message,
                 secp.get()),
             "random production receipt verifies");
  }
}
