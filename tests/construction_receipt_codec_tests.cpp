// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <algorithm>
#include <array>
#include <cstdint>
#include <utility>
#include <vector>

#include "test_harness.hpp"

namespace {

using purify_test::TestContext;
using purify_test::expect_error;
using purify_test::expect_ok;
using purify::Bytes;
using purify::FieldElement;
using purify::Result;
using purify::UInt512;
using purify::accountable::AnchorReference;
using purify::accountable::ConstructionReceiptEntry;
using purify::accountable::ConstructionReceiptPayload;
using purify::accountable::ResolvedConstructionReceiptEntry;

struct ReceiptFixture {
    purify::accountable::CoalitionSetupReference setup_reference{};
    UInt512 recovery_root{};
    std::vector<ConstructionReceiptEntry> entries;
    std::vector<ResolvedConstructionReceiptEntry> resolved;
};

Result<UInt512> public_root(unsigned char marker) {
    std::array<unsigned char, 32> seed{};
    seed.fill(marker);
    seed[0] ^= 0xa5U;
    PURIFY_ASSIGN_OR_RETURN(auto generated,
                            purify::generate_key(seed),
                            "construction_receipt_codec_test:key");
    return generated.public_key;
}

AnchorReference reference(unsigned char marker) {
    AnchorReference out{};
    out.fill(marker);
    return out;
}

Result<ReceiptFixture> make_fixture() {
    ReceiptFixture fixture;
    fixture.setup_reference.fill(0x31);
    PURIFY_ASSIGN_OR_RETURN(fixture.recovery_root,
                            public_root(1),
                            "construction_receipt_codec_test:root");

    fixture.entries.resize(2);
    fixture.entries[0].anchor_reference = reference(0x41);
    PURIFY_ASSIGN_OR_RETURN(
        fixture.entries[0].ciphertext.ephemeral_keys[0],
        public_root(2),
        "construction_receipt_codec_test:ephemeral_0_0");
    PURIFY_ASSIGN_OR_RETURN(
        fixture.entries[0].ciphertext.ephemeral_keys[1],
        public_root(3),
        "construction_receipt_codec_test:ephemeral_0_1");
    fixture.entries[0].ciphertext.masked_scalars = {
        FieldElement::from_u64(11), FieldElement::from_u64(12)};

    fixture.entries[1].anchor_reference = reference(0x42);
    PURIFY_ASSIGN_OR_RETURN(
        fixture.entries[1].ciphertext.ephemeral_keys[0],
        public_root(4),
        "construction_receipt_codec_test:ephemeral_1_0");
    PURIFY_ASSIGN_OR_RETURN(
        fixture.entries[1].ciphertext.ephemeral_keys[1],
        public_root(5),
        "construction_receipt_codec_test:ephemeral_1_1");
    fixture.entries[1].ciphertext.masked_scalars = {
        FieldElement::from_u64(21), FieldElement::from_u64(22)};

    fixture.resolved.resize(2);
    for (std::size_t i = 0; i < fixture.resolved.size(); ++i) {
        fixture.resolved[i].anchor_reference =
            fixture.entries[i].anchor_reference;
        PURIFY_ASSIGN_OR_RETURN(
            fixture.resolved[i].anchor_root,
            public_root(static_cast<unsigned char>(6 + i)),
            "construction_receipt_codec_test:anchor_root");
        fixture.resolved[i].context_digest.fill(
            static_cast<unsigned char>(0x51 + i));
    }
    return fixture;
}

Result<ConstructionReceiptPayload> make_payload(
    const ReceiptFixture& fixture) {
    return ConstructionReceiptPayload::create(fixture.setup_reference,
                                               fixture.recovery_root,
                                               fixture.entries);
}

void test_canonical_layout_and_round_trip(TestContext& ctx) {
    auto fixture = make_fixture();
    expect_ok(ctx, fixture, "receipt codec fixture constructs");
    if (!fixture) return;
    auto payload = make_payload(*fixture);
    expect_ok(ctx, payload, "canonical payload constructs");
    if (!payload) return;

    constexpr std::size_t kExpectedSize = 1 + 32 + 64 + 4 +
                                          2 * (32 + 192);
    static_assert(ConstructionReceiptPayload::kFixedHeaderSize == 101);
    static_assert(ConstructionReceiptPayload::kEntrySize == 224);
    const Bytes encoded = payload->serialize();
    ctx.expect(payload->serialized_size() == kExpectedSize,
               "reported size accounts for every fixed field");
    ctx.expect(encoded.size() == kExpectedSize,
               "wire size is exactly 101 + 224*N bytes");
    ctx.expect(encoded[0] ==
                   ConstructionReceiptPayload::kSerializationVersion,
               "wire starts with the construction receipt version");
    ctx.expect(std::equal(fixture->setup_reference.begin(),
                          fixture->setup_reference.end(),
                          encoded.begin() + 1),
               "wire carries the exact setup reference");
    const auto recovery_root_bytes = fixture->recovery_root.to_bytes_be();
    ctx.expect(std::equal(recovery_root_bytes.begin(),
                          recovery_root_bytes.end(),
                          encoded.begin() + 33),
               "wire carries the exact 64-byte recovery root");
    ctx.expect(encoded[97] == 0 && encoded[98] == 0 &&
                   encoded[99] == 0 && encoded[100] == 2,
               "wire count is canonical big endian");

    constexpr std::size_t kFirstEntryOffset =
        ConstructionReceiptPayload::kFixedHeaderSize;
    constexpr std::size_t kFirstCiphertextOffset =
        kFirstEntryOffset + 32;
    ctx.expect(std::equal(fixture->entries[0].anchor_reference.begin(),
                          fixture->entries[0].anchor_reference.end(),
                          encoded.begin() + kFirstEntryOffset),
               "wire carries the first ordered anchor reference");
    const auto first_ephemeral =
        fixture->entries[0].ciphertext.ephemeral_keys[0].to_bytes_be();
    ctx.expect(std::equal(first_ephemeral.begin(),
                          first_ephemeral.end(),
                          encoded.begin() + kFirstCiphertextOffset),
               "ciphertext starts with its first 64-byte ephemeral key");
    const auto first_masked =
        fixture->entries[0].ciphertext.masked_scalars[0].to_bytes_be();
    ctx.expect(std::equal(first_masked.begin(),
                          first_masked.end(),
                          encoded.begin() + kFirstCiphertextOffset + 64),
               "ciphertext interleaves its first 32-byte masked scalar");
    const auto second_ephemeral =
        fixture->entries[0].ciphertext.ephemeral_keys[1].to_bytes_be();
    ctx.expect(std::equal(second_ephemeral.begin(),
                          second_ephemeral.end(),
                          encoded.begin() + kFirstCiphertextOffset + 96),
               "ciphertext carries its second ephemeral key in order");

    auto decoded = ConstructionReceiptPayload::deserialize(encoded);
    expect_ok(ctx, decoded, "canonical wire payload decodes");
    if (!decoded) return;
    ctx.expect(decoded->serialize() == encoded,
               "decoding and encoding preserve canonical bytes");
    ctx.expect(decoded->coalition_setup_reference() ==
                   fixture->setup_reference,
               "round trip preserves the setup reference");
    ctx.expect(decoded->recovery_root() == fixture->recovery_root,
               "round trip preserves the recovery root");
    ctx.expect(decoded->entries().size() == fixture->entries.size(),
               "round trip preserves the entry count");
}

void test_construction_invariants(TestContext& ctx) {
    auto fixture = make_fixture();
    expect_ok(ctx, fixture, "invariant fixture constructs");
    if (!fixture) return;

    expect_error(ctx,
                 ConstructionReceiptPayload::create(
                     fixture->setup_reference,
                     fixture->recovery_root,
                     {}),
                 purify::ErrorCode::EmptyInput,
                 "empty entry collections are rejected");

    auto duplicate_references = fixture->entries;
    duplicate_references[1].anchor_reference =
        duplicate_references[0].anchor_reference;
    expect_error(ctx,
                 ConstructionReceiptPayload::create(
                     fixture->setup_reference,
                     fixture->recovery_root,
                     std::move(duplicate_references)),
                 purify::ErrorCode::BindingMismatch,
                 "duplicate anchor references are rejected");

    auto duplicate_ephemerals = fixture->entries;
    duplicate_ephemerals[0].ciphertext.ephemeral_keys[1] =
        duplicate_ephemerals[0].ciphertext.ephemeral_keys[0];
    expect_error(ctx,
                 ConstructionReceiptPayload::create(
                     fixture->setup_reference,
                     fixture->recovery_root,
                     std::move(duplicate_ephemerals)),
                 purify::ErrorCode::BindingMismatch,
                 "duplicate ciphertext ephemerals are rejected");

    expect_error(ctx,
                 ConstructionReceiptPayload::create(
                     fixture->setup_reference,
                     purify::packed_public_key_space_size(),
                     fixture->entries),
                 purify::ErrorCode::RangeViolation,
                 "out-of-range recovery roots are rejected");
}

void test_noncanonical_and_framing_rejection(TestContext& ctx) {
    auto fixture = make_fixture();
    expect_ok(ctx, fixture, "framing fixture constructs");
    if (!fixture) return;
    auto payload = make_payload(*fixture);
    expect_ok(ctx, payload, "framing payload constructs");
    if (!payload) return;
    const Bytes encoded = payload->serialize();

    auto truncated_byte = encoded;
    truncated_byte.pop_back();
    ctx.expect(!ConstructionReceiptPayload::deserialize(truncated_byte),
               "one-byte truncation is rejected");

    auto truncated_entry = encoded;
    truncated_entry.erase(
        truncated_entry.end() - ConstructionReceiptPayload::kEntrySize,
        truncated_entry.end());
    ctx.expect(!ConstructionReceiptPayload::deserialize(truncated_entry),
               "whole-entry truncation is rejected by the count");

    auto trailing = encoded;
    trailing.push_back(0);
    ctx.expect(!ConstructionReceiptPayload::deserialize(trailing),
               "trailing bytes are rejected");

    auto wrong_version = encoded;
    wrong_version[0] ^= 1U;
    expect_error(ctx,
                 ConstructionReceiptPayload::deserialize(wrong_version),
                 purify::ErrorCode::UnsupportedSymbol,
                 "unknown payload versions are rejected");

    auto zero_count = encoded;
    std::fill(zero_count.begin() + 97, zero_count.begin() + 101, 0);
    expect_error(ctx,
                 ConstructionReceiptPayload::deserialize(zero_count),
                 purify::ErrorCode::EmptyInput,
                 "zero entry count is rejected");

    auto smaller_count = encoded;
    smaller_count[100] = 1;
    ctx.expect(!ConstructionReceiptPayload::deserialize(smaller_count),
               "a count smaller than the carried entries is rejected");

    auto larger_count = encoded;
    larger_count[100] = 3;
    ctx.expect(!ConstructionReceiptPayload::deserialize(larger_count),
               "a count larger than the carried entries is rejected");

    constexpr std::size_t kFirstEntry =
        ConstructionReceiptPayload::kFixedHeaderSize;
    constexpr std::size_t kFirstCiphertext = kFirstEntry + 32;
    auto invalid_recovery_root = encoded;
    const auto invalid_root =
        purify::packed_public_key_space_size().to_bytes_be();
    std::copy(invalid_root.begin(), invalid_root.end(),
              invalid_recovery_root.begin() + 33);
    ctx.expect(!ConstructionReceiptPayload::deserialize(
                   invalid_recovery_root),
               "noncanonical recovery roots are rejected");

    auto invalid_ephemeral = encoded;
    std::copy(invalid_root.begin(), invalid_root.end(),
              invalid_ephemeral.begin() + kFirstCiphertext);
    ctx.expect(!ConstructionReceiptPayload::deserialize(invalid_ephemeral),
               "noncanonical ephemeral keys are rejected");

    auto invalid_scalar = encoded;
    const auto modulus = purify::prime_p().to_bytes_be();
    std::copy(modulus.begin(), modulus.end(),
              invalid_scalar.begin() + kFirstCiphertext + 64);
    ctx.expect(!ConstructionReceiptPayload::deserialize(invalid_scalar),
               "noncanonical masked scalars are rejected");

    auto duplicate_ephemeral = encoded;
    std::copy_n(duplicate_ephemeral.begin() + kFirstCiphertext,
                64,
                duplicate_ephemeral.begin() + kFirstCiphertext + 96);
    expect_error(ctx,
                 ConstructionReceiptPayload::deserialize(
                     duplicate_ephemeral),
                 purify::ErrorCode::BindingMismatch,
                 "duplicate ephemeral keys are rejected on decode");

    auto duplicate_reference = encoded;
    std::copy_n(duplicate_reference.begin() + kFirstEntry,
                32,
                duplicate_reference.begin() +
                    kFirstEntry + ConstructionReceiptPayload::kEntrySize);
    expect_error(ctx,
                 ConstructionReceiptPayload::deserialize(
                     duplicate_reference),
                 purify::ErrorCode::BindingMismatch,
                 "duplicate anchor references are rejected on decode");
}

void test_statement_digest_binds_all_inputs(TestContext& ctx) {
    auto fixture = make_fixture();
    expect_ok(ctx, fixture, "statement fixture constructs");
    if (!fixture) return;
    auto payload = make_payload(*fixture);
    expect_ok(ctx, payload, "statement payload constructs");
    if (!payload) return;
    auto digest = purify::accountable::construction_receipt_statement_digest(
        *payload, fixture->resolved);
    expect_ok(ctx, digest, "statement digest constructs");
    if (!digest) return;
    ctx.expect(
        purify::UInt256::from_bytes_be(digest->data(), digest->size())
                .to_hex() ==
            "4f0477952c606d317e80c180f20a7c603afea54800c54b7b"
            "ef120a38d13ed862",
        "statement digest matches the canonical tagged-hash vector");
    auto repeated =
        purify::accountable::construction_receipt_statement_digest(
            *payload, fixture->resolved);
    expect_ok(ctx, repeated, "statement digest repeats");
    if (!repeated) return;
    ctx.expect(*repeated == *digest,
               "identical statements have identical digests");

    auto missing_resolved = fixture->resolved;
    missing_resolved.pop_back();
    expect_error(
        ctx,
        purify::accountable::construction_receipt_statement_digest(
            *payload, missing_resolved),
        purify::ErrorCode::InvalidFixedSize,
        "resolved input count must equal the payload count");

    auto wrong_resolution = fixture->resolved;
    std::swap(wrong_resolution[0], wrong_resolution[1]);
    expect_error(
        ctx,
        purify::accountable::construction_receipt_statement_digest(
            *payload, wrong_resolution),
        purify::ErrorCode::BindingMismatch,
        "resolved roots cannot be reordered under payload references");

    auto changed_setup = *fixture;
    changed_setup.setup_reference[0] ^= 1U;
    auto changed_setup_payload = make_payload(changed_setup);
    expect_ok(ctx, changed_setup_payload, "changed setup payload constructs");
    if (!changed_setup_payload) return;
    auto changed_setup_digest =
        purify::accountable::construction_receipt_statement_digest(
            *changed_setup_payload, changed_setup.resolved);
    expect_ok(ctx, changed_setup_digest, "changed setup digest constructs");
    if (!changed_setup_digest) return;
    ctx.expect(*changed_setup_digest != *digest,
               "statement digest binds the setup reference");

    auto changed_root = public_root(8);
    expect_ok(ctx, changed_root, "changed recovery root constructs");
    if (!changed_root) return;
    auto changed_recovery = *fixture;
    changed_recovery.recovery_root = *changed_root;
    auto changed_recovery_payload = make_payload(changed_recovery);
    expect_ok(ctx, changed_recovery_payload,
              "changed recovery payload constructs");
    if (!changed_recovery_payload) return;
    auto changed_recovery_digest =
        purify::accountable::construction_receipt_statement_digest(
            *changed_recovery_payload, changed_recovery.resolved);
    expect_ok(ctx, changed_recovery_digest,
              "changed recovery digest constructs");
    if (!changed_recovery_digest) return;
    ctx.expect(*changed_recovery_digest != *digest,
               "statement digest binds the recovery root");

    auto changed_reference = *fixture;
    changed_reference.entries[0].anchor_reference[0] ^= 1U;
    changed_reference.resolved[0].anchor_reference =
        changed_reference.entries[0].anchor_reference;
    auto changed_reference_payload = make_payload(changed_reference);
    expect_ok(ctx, changed_reference_payload,
              "changed reference payload constructs");
    if (!changed_reference_payload) return;
    auto changed_reference_digest =
        purify::accountable::construction_receipt_statement_digest(
            *changed_reference_payload, changed_reference.resolved);
    expect_ok(ctx, changed_reference_digest,
              "changed reference digest constructs");
    if (!changed_reference_digest) return;
    ctx.expect(*changed_reference_digest != *digest,
               "statement digest binds every anchor reference");

    auto changed_ciphertext = *fixture;
    changed_ciphertext.entries[0].ciphertext.masked_scalars[0] =
        changed_ciphertext.entries[0].ciphertext.masked_scalars[0] +
        FieldElement::one();
    auto changed_ciphertext_payload = make_payload(changed_ciphertext);
    expect_ok(ctx, changed_ciphertext_payload,
              "changed ciphertext payload constructs");
    if (!changed_ciphertext_payload) return;
    auto changed_ciphertext_digest =
        purify::accountable::construction_receipt_statement_digest(
            *changed_ciphertext_payload, changed_ciphertext.resolved);
    expect_ok(ctx, changed_ciphertext_digest,
              "changed ciphertext digest constructs");
    if (!changed_ciphertext_digest) return;
    ctx.expect(*changed_ciphertext_digest != *digest,
               "statement digest binds every ciphertext byte");

    auto reordered = *fixture;
    std::swap(reordered.entries[0], reordered.entries[1]);
    std::swap(reordered.resolved[0], reordered.resolved[1]);
    auto reordered_payload = make_payload(reordered);
    expect_ok(ctx, reordered_payload, "reordered payload constructs");
    if (!reordered_payload) return;
    auto reordered_digest =
        purify::accountable::construction_receipt_statement_digest(
            *reordered_payload, reordered.resolved);
    expect_ok(ctx, reordered_digest, "reordered digest constructs");
    if (!reordered_digest) return;
    ctx.expect(*reordered_digest != *digest,
               "statement digest binds entry order");

    auto changed_anchor = *fixture;
    changed_anchor.resolved[0].anchor_root = *changed_root;
    auto changed_anchor_digest =
        purify::accountable::construction_receipt_statement_digest(
            *payload, changed_anchor.resolved);
    expect_ok(ctx, changed_anchor_digest, "changed anchor digest constructs");
    if (!changed_anchor_digest) return;
    ctx.expect(*changed_anchor_digest != *digest,
               "statement digest binds each exact anchor root");

    auto changed_context = fixture->resolved;
    changed_context[0].context_digest[0] ^= 1U;
    auto changed_context_digest =
        purify::accountable::construction_receipt_statement_digest(
            *payload, changed_context);
    expect_ok(ctx, changed_context_digest,
              "changed context digest constructs");
    if (!changed_context_digest) return;
    ctx.expect(*changed_context_digest != *digest,
               "statement digest binds each exact context digest");
}

}  // namespace

void run_construction_receipt_codec_tests(TestContext& ctx) {
    test_canonical_layout_and_round_trip(ctx);
    test_construction_invariants(ctx);
    test_noncanonical_and_framing_rejection(ctx);
    test_statement_digest_binds_all_inputs(ctx);
}
