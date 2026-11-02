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
using purify::accountable::AnchorPunishmentPublicKey;
using purify::accountable::ConstructionReceiptEntry;
using purify::accountable::ConstructionReceiptEnvelope;
using purify::accountable::ConstructionReceiptPayload;
using purify::accountable::ResolvedConstructionReceiptEntry;
using purify::accountable::ResolvedConstructionSetupDigest;
using purify::accountable::ResolvedConstructionSetupDigestBytes;

struct ReceiptFixture {
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

Result<AnchorPunishmentPublicKey> punishment_key(unsigned char marker) {
    auto secp = purify::make_secp_context();
    if (!secp) {
        return purify::unexpected_error(
            purify::ErrorCode::BackendRejectedInput,
            "construction_receipt_codec_test:secp");
    }
    std::array<unsigned char, 32> scalar{};
    scalar.back() = marker;
    std::array<unsigned char, 32> xonly{};
    if (purify_bip340_key_from_seckey(
            secp.get(), scalar.data(), xonly.data()) == 0) {
        return purify::unexpected_error(
            purify::ErrorCode::BackendRejectedInput,
            "construction_receipt_codec_test:punishment_key");
    }
    return AnchorPunishmentPublicKey::create(xonly, secp.get());
}

Result<ResolvedConstructionSetupDigest> resolved_setup(
    unsigned char marker) {
    ResolvedConstructionSetupDigestBytes digest{};
    digest.fill(marker);
    return ResolvedConstructionSetupDigest::create(digest);
}

Result<ReceiptFixture> make_fixture() {
    ReceiptFixture fixture;
    PURIFY_ASSIGN_OR_RETURN(fixture.recovery_root,
                            public_root(1),
                            "construction_receipt_codec_test:root");

    fixture.entries.resize(2);
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
    fixture.entries[0].circuit_precommitment =
        FieldElement::from_u64(31).to_bytes_be();

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
    fixture.entries[1].circuit_precommitment =
        FieldElement::from_u64(32).to_bytes_be();

    fixture.resolved.reserve(2);
    for (std::size_t i = 0; i < 2; ++i) {
        PURIFY_ASSIGN_OR_RETURN(
            auto root,
            public_root(static_cast<unsigned char>(6 + i)),
            "construction_receipt_codec_test:anchor_root");
        PURIFY_ASSIGN_OR_RETURN(
            auto punishment,
            punishment_key(static_cast<unsigned char>(9 + i)),
            "construction_receipt_codec_test:punishment_key");
        purify::accountable::AnchorEscrowContextDigest context{};
        context.fill(static_cast<unsigned char>(0x51 + i));
        fixture.resolved.emplace_back(
            reference(static_cast<unsigned char>(0x41 + i)), root,
            std::move(punishment), context);
    }
    return fixture;
}

Result<ConstructionReceiptPayload> make_payload(
    const ReceiptFixture& fixture) {
    return ConstructionReceiptPayload::create(fixture.recovery_root,
                                               fixture.entries);
}

void test_canonical_layout_and_round_trip(TestContext& ctx) {
    auto fixture = make_fixture();
    expect_ok(ctx, fixture, "receipt codec fixture constructs");
    if (!fixture) return;
    auto payload = make_payload(*fixture);
    expect_ok(ctx, payload, "canonical payload constructs");
    if (!payload) return;

    constexpr std::size_t kExpectedSize = 1 + 64 + 4 + 2 * 224;
    static_assert(ConstructionReceiptPayload::kFixedHeaderSize == 69);
    static_assert(ConstructionReceiptPayload::kEntrySize == 224);
    const Bytes encoded = payload->serialize();
    ctx.expect(payload->serialized_size() == kExpectedSize,
               "reported size accounts for every fixed field");
    ctx.expect(encoded.size() == kExpectedSize,
               "wire size is exactly 69 + 224*N bytes");
    ctx.expect(encoded[0] ==
                       ConstructionReceiptPayload::kSerializationVersion &&
                   encoded[0] == 2,
               "wire starts with construction receipt version 2");
    const auto recovery_root_bytes = fixture->recovery_root.to_bytes_be();
    ctx.expect(std::equal(recovery_root_bytes.begin(),
                          recovery_root_bytes.end(),
                          encoded.begin() + 1),
               "wire carries the exact 64-byte recovery root");
    ctx.expect(encoded[65] == 0 && encoded[66] == 0 &&
                   encoded[67] == 0 && encoded[68] == 2,
               "wire count is canonical big endian");

    constexpr std::size_t kFirstCiphertextOffset =
        ConstructionReceiptPayload::kFixedHeaderSize;
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
    constexpr std::size_t kFirstPrecommitmentOffset =
        kFirstCiphertextOffset +
        purify::accountable::AnchorEscrowCiphertext::kSerializedSize;
    ctx.expect(
        std::equal(
            fixture->entries[0].circuit_precommitment.begin(),
            fixture->entries[0].circuit_precommitment.end(),
            encoded.begin() + kFirstPrecommitmentOffset),
        "entry appends its exact 32-byte circuit precommitment");
    constexpr std::size_t kSecondEntryOffset =
        kFirstCiphertextOffset + ConstructionReceiptPayload::kEntrySize;
    const auto second_entry_ephemeral =
        fixture->entries[1].ciphertext.ephemeral_keys[0].to_bytes_be();
    ctx.expect(
        std::equal(second_entry_ephemeral.begin(),
                   second_entry_ephemeral.end(),
                   encoded.begin() + kSecondEntryOffset) &&
            std::equal(
                fixture->entries[1].circuit_precommitment.begin(),
                fixture->entries[1].circuit_precommitment.end(),
                encoded.begin() + kSecondEntryOffset +
                    purify::accountable::AnchorEscrowCiphertext::
                        kSerializedSize),
        "entry stride is exactly 224 bytes");

    auto decoded = ConstructionReceiptPayload::deserialize(encoded);
    expect_ok(ctx, decoded, "canonical wire payload decodes");
    if (!decoded) return;
    ctx.expect(decoded->serialize() == encoded,
               "decoding and encoding preserve canonical bytes");
    ctx.expect(decoded->recovery_root() == fixture->recovery_root,
               "round trip preserves the recovery root");
    ctx.expect(decoded->entries().size() == fixture->entries.size(),
               "round trip preserves the entry count");
    ctx.expect(
        decoded->entries()[0].circuit_precommitment ==
                fixture->entries[0].circuit_precommitment &&
            decoded->entries()[1].circuit_precommitment ==
                fixture->entries[1].circuit_precommitment,
        "round trip preserves every circuit precommitment");
}

void test_construction_invariants(TestContext& ctx) {
    auto fixture = make_fixture();
    expect_ok(ctx, fixture, "invariant fixture constructs");
    if (!fixture) return;

    expect_error(ctx,
                 ConstructionReceiptPayload::create(
                     fixture->recovery_root,
                     {}),
                 purify::ErrorCode::EmptyInput,
                 "empty entry collections are rejected");

    auto duplicate_ephemerals = fixture->entries;
    duplicate_ephemerals[0].ciphertext.ephemeral_keys[1] =
        duplicate_ephemerals[0].ciphertext.ephemeral_keys[0];
    expect_error(ctx,
                 ConstructionReceiptPayload::create(
                     fixture->recovery_root,
                     std::move(duplicate_ephemerals)),
                 purify::ErrorCode::BindingMismatch,
                 "duplicate ciphertext ephemerals are rejected");

    expect_error(ctx,
                 ConstructionReceiptPayload::create(
                     purify::packed_public_key_space_size(),
                     fixture->entries),
                 purify::ErrorCode::RangeViolation,
                 "out-of-range recovery roots are rejected");

    auto zero_precommitment = fixture->entries;
    zero_precommitment[0].circuit_precommitment = {};
    expect_error(
        ctx,
        ConstructionReceiptPayload::create(
            fixture->recovery_root, std::move(zero_precommitment)),
        purify::ErrorCode::RangeViolation,
        "zero circuit precommitments are rejected on create");

    auto noncanonical_precommitment = fixture->entries;
    noncanonical_precommitment[0].circuit_precommitment =
        purify::prime_p().to_bytes_be();
    expect_error(
        ctx,
        ConstructionReceiptPayload::create(
            fixture->recovery_root,
            std::move(noncanonical_precommitment)),
        purify::ErrorCode::RangeViolation,
        "noncanonical circuit precommitments are rejected on create");
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

    auto truncated_precommitment = encoded;
    truncated_precommitment.erase(
        truncated_precommitment.end() - 32,
        truncated_precommitment.end());
    ctx.expect(
        !ConstructionReceiptPayload::deserialize(
            truncated_precommitment),
        "truncated circuit precommitment is rejected by framing");

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
    std::fill(zero_count.begin() + 65, zero_count.begin() + 69, 0);
    expect_error(ctx,
                 ConstructionReceiptPayload::deserialize(zero_count),
                 purify::ErrorCode::EmptyInput,
                 "zero entry count is rejected");

    auto smaller_count = encoded;
    smaller_count[68] = 1;
    ctx.expect(!ConstructionReceiptPayload::deserialize(smaller_count),
               "a count smaller than the carried entries is rejected");

    auto larger_count = encoded;
    larger_count[68] = 3;
    ctx.expect(!ConstructionReceiptPayload::deserialize(larger_count),
               "a count larger than the carried entries is rejected");

    constexpr std::size_t kFirstCiphertext =
        ConstructionReceiptPayload::kFixedHeaderSize;
    auto invalid_recovery_root = encoded;
    const auto invalid_root =
        purify::packed_public_key_space_size().to_bytes_be();
    std::copy(invalid_root.begin(), invalid_root.end(),
              invalid_recovery_root.begin() + 1);
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

    constexpr std::size_t kFirstPrecommitment =
        kFirstCiphertext +
        purify::accountable::AnchorEscrowCiphertext::kSerializedSize;
    auto zero_precommitment = encoded;
    std::fill_n(zero_precommitment.begin() + kFirstPrecommitment,
                32, 0);
    expect_error(
        ctx,
        ConstructionReceiptPayload::deserialize(zero_precommitment),
        purify::ErrorCode::RangeViolation,
        "zero circuit precommitments are rejected on decode");

    auto noncanonical_precommitment = encoded;
    std::copy(
        modulus.begin(), modulus.end(),
        noncanonical_precommitment.begin() + kFirstPrecommitment);
    expect_error(
        ctx,
        ConstructionReceiptPayload::deserialize(
            noncanonical_precommitment),
        purify::ErrorCode::RangeViolation,
        "noncanonical circuit precommitments are rejected on decode");

}

void test_parent_envelope_layout_and_syntax(TestContext& ctx) {
    auto fixture = make_fixture();
    expect_ok(ctx, fixture, "envelope fixture constructs");
    if (!fixture) return;
    auto payload = make_payload(*fixture);
    expect_ok(ctx, payload, "envelope payload constructs");
    if (!payload) return;
    static_assert(ConstructionReceiptEnvelope::kParentProofSize == 12'466);
    Bytes parent_proof(
        ConstructionReceiptEnvelope::kParentProofSize, 0xa5);
    auto envelope = ConstructionReceiptEnvelope::create(
        *payload, parent_proof);
    expect_ok(ctx, envelope, "canonical parent envelope constructs");
    if (!envelope) return;
    const Bytes encoded = envelope->serialize();
    const std::size_t expected_size =
        69 + 224 * fixture->entries.size() + parent_proof.size();
    ctx.expect(envelope->serialized_size() == expected_size &&
                   encoded.size() == expected_size,
               "envelope is exactly 69 + 224*N + 12,466 bytes");
    const Bytes payload_bytes = payload->serialize();
    ctx.expect(std::equal(payload_bytes.begin(), payload_bytes.end(),
                          encoded.begin()),
               "envelope starts with the canonical public payload");
    auto decoded = ConstructionReceiptEnvelope::deserialize(encoded);
    expect_ok(ctx, decoded, "canonical parent envelope decodes");
    if (!decoded) return;
    ctx.expect(decoded->serialize() == encoded &&
                   decoded->parent_proof() == parent_proof,
               "parent envelope round-trips exactly");

    auto truncated = encoded;
    truncated.pop_back();
    expect_error(ctx,
                 ConstructionReceiptEnvelope::deserialize(truncated),
                 purify::ErrorCode::InvalidFixedSize,
                 "a truncated fixed-size parent proof is rejected");

    auto trailing = encoded;
    trailing.push_back(0);
    expect_error(ctx,
                 ConstructionReceiptEnvelope::deserialize(trailing),
                 purify::ErrorCode::InvalidFixedSize,
                 "trailing parent-proof bytes are rejected");

    auto short_proof = parent_proof;
    short_proof.pop_back();
    expect_error(ctx,
                 ConstructionReceiptEnvelope::create(
                     *payload, std::move(short_proof)),
                 purify::ErrorCode::InvalidFixedSize,
                 "a short parent proof is rejected before publication");

    auto long_proof = parent_proof;
    long_proof.push_back(0);
    expect_error(ctx,
                 ConstructionReceiptEnvelope::create(
                     *payload, std::move(long_proof)),
                 purify::ErrorCode::InvalidFixedSize,
                 "a long parent proof is rejected before publication");

    Bytes legacy = payload_bytes;
    legacy.insert(legacy.end(), 545, 0);
    legacy.insert(legacy.end(), 1019, 0xa5);
    expect_error(ctx,
                 ConstructionReceiptEnvelope::deserialize(legacy),
                 purify::ErrorCode::InvalidFixedSize,
                 "the legacy root-plus-variable-proof envelope is rejected");
}

void test_statement_digest_binds_all_inputs(TestContext& ctx) {
    auto fixture = make_fixture();
    expect_ok(ctx, fixture, "statement fixture constructs");
    if (!fixture) return;
    auto payload = make_payload(*fixture);
    expect_ok(ctx, payload, "statement payload constructs");
    if (!payload) return;
    auto setup = resolved_setup(0x31);
    expect_ok(ctx, setup, "resolved setup digest constructs");
    if (!setup) return;
    auto digest = purify::accountable::construction_receipt_statement_digest(
        *payload, *setup, fixture->resolved);
    expect_ok(ctx, digest, "statement digest constructs");
    if (!digest) return;
#if !PURIFY_USE_LEGACY_FIELD_HASHES
    ctx.expect(
        purify::UInt256::from_bytes_be(digest->data(), digest->size())
                .to_hex() ==
            "e888642f3a2f97f87f030c98b8b11e92"
            "020f95d5ac361692f05c7b1f85fc55d2",
        "statement digest matches the canonical V3 tagged-hash vector");
#endif
    auto repeated =
        purify::accountable::construction_receipt_statement_digest(
            *payload, *setup, fixture->resolved);
    expect_ok(ctx, repeated, "statement digest repeats");
    if (!repeated) return;
    ctx.expect(*repeated == *digest,
               "identical statements have identical digests");

    auto changed_setup = resolved_setup(0x32);
    expect_ok(ctx, changed_setup,
              "changed resolved setup digest constructs");
    if (!changed_setup) return;
    auto changed_setup_statement =
        purify::accountable::construction_receipt_statement_digest(
            *payload, *changed_setup, fixture->resolved);
    expect_ok(ctx, changed_setup_statement,
              "changed setup statement digest constructs");
    if (!changed_setup_statement) return;
    ctx.expect(*changed_setup_statement != *digest,
               "statement binds the exact resolved setup record");

    expect_error(
        ctx,
        ResolvedConstructionSetupDigest::create(
            ResolvedConstructionSetupDigestBytes{}),
        purify::ErrorCode::RangeViolation,
        "zero cannot stand in for an unresolved setup record");

    auto missing_resolved = fixture->resolved;
    missing_resolved.pop_back();
    expect_error(
        ctx,
        purify::accountable::construction_receipt_statement_digest(
            *payload, *setup, missing_resolved),
        purify::ErrorCode::InvalidFixedSize,
        "resolved input count must equal the payload count");

    auto reordered_resolution = fixture->resolved;
    std::swap(reordered_resolution[0], reordered_resolution[1]);
    auto reordered_resolution_digest =
        purify::accountable::construction_receipt_statement_digest(
            *payload, *setup, reordered_resolution);
    expect_ok(ctx, reordered_resolution_digest,
              "reordered resolved inputs construct a distinct statement");
    if (!reordered_resolution_digest) return;
    ctx.expect(*reordered_resolution_digest != *digest,
               "statement digest binds resolved input order");

    auto duplicate_resolution = fixture->resolved;
    duplicate_resolution[1].anchor_reference =
        duplicate_resolution[0].anchor_reference;
    expect_error(
        ctx,
        purify::accountable::construction_receipt_statement_digest(
            *payload, *setup, duplicate_resolution),
        purify::ErrorCode::BindingMismatch,
        "one receipt cannot resolve the same anchor twice");

    auto duplicate_root = fixture->resolved;
    duplicate_root[1].anchor_root = duplicate_root[0].anchor_root;
    expect_error(
        ctx,
        purify::accountable::construction_receipt_statement_digest(
            *payload, *setup, duplicate_root),
        purify::ErrorCode::BindingMismatch,
        "distinct references cannot resolve the same anchor root");

    auto duplicate_punishment = fixture->resolved;
    duplicate_punishment[1].punishment_key =
        duplicate_punishment[0].punishment_key;
    expect_error(
        ctx,
        purify::accountable::construction_receipt_statement_digest(
            *payload, *setup, duplicate_punishment),
        purify::ErrorCode::BindingMismatch,
        "distinct anchors cannot resolve the same punishment key");

    auto changed_punishment = fixture->resolved;
    auto replacement_punishment = punishment_key(0x2a);
    expect_ok(ctx, replacement_punishment,
              "replacement punishment key constructs");
    if (!replacement_punishment) return;
    changed_punishment[0].punishment_key = *replacement_punishment;
    auto changed_punishment_digest =
        purify::accountable::construction_receipt_statement_digest(
            *payload, *setup, changed_punishment);
    expect_ok(ctx, changed_punishment_digest,
              "changed punishment statement constructs");
    if (!changed_punishment_digest) return;
    ctx.expect(*changed_punishment_digest != *digest,
               "statement digest binds every punishment key");

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
            *changed_recovery_payload, *setup,
            changed_recovery.resolved);
    expect_ok(ctx, changed_recovery_digest,
              "changed recovery digest constructs");
    if (!changed_recovery_digest) return;
    ctx.expect(*changed_recovery_digest != *digest,
               "statement digest binds the recovery root");

    auto changed_reference = *fixture;
    changed_reference.resolved[0].anchor_reference[0] ^= 1U;
    auto changed_reference_payload = make_payload(changed_reference);
    expect_ok(ctx, changed_reference_payload,
              "changed reference payload constructs");
    if (!changed_reference_payload) return;
    auto changed_reference_digest =
        purify::accountable::construction_receipt_statement_digest(
            *changed_reference_payload, *setup,
            changed_reference.resolved);
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
            *changed_ciphertext_payload, *setup,
            changed_ciphertext.resolved);
    expect_ok(ctx, changed_ciphertext_digest,
              "changed ciphertext digest constructs");
    if (!changed_ciphertext_digest) return;
    ctx.expect(*changed_ciphertext_digest != *digest,
               "statement digest binds every ciphertext byte");

    auto changed_precommitment = *fixture;
    changed_precommitment.entries[0].circuit_precommitment =
        FieldElement::from_u64(33).to_bytes_be();
    auto changed_precommitment_payload =
        make_payload(changed_precommitment);
    expect_ok(ctx, changed_precommitment_payload,
              "changed circuit precommitment payload constructs");
    if (!changed_precommitment_payload) return;
    auto changed_precommitment_digest =
        purify::accountable::construction_receipt_statement_digest(
            *changed_precommitment_payload, *setup,
            changed_precommitment.resolved);
    expect_ok(ctx, changed_precommitment_digest,
              "changed circuit precommitment digest constructs");
    if (!changed_precommitment_digest) return;
    ctx.expect(*changed_precommitment_digest != *digest,
               "statement digest binds every circuit precommitment");

    auto reordered = *fixture;
    std::swap(reordered.entries[0], reordered.entries[1]);
    std::swap(reordered.resolved[0], reordered.resolved[1]);
    auto reordered_payload = make_payload(reordered);
    expect_ok(ctx, reordered_payload, "reordered payload constructs");
    if (!reordered_payload) return;
    auto reordered_digest =
        purify::accountable::construction_receipt_statement_digest(
            *reordered_payload, *setup, reordered.resolved);
    expect_ok(ctx, reordered_digest, "reordered digest constructs");
    if (!reordered_digest) return;
    ctx.expect(*reordered_digest != *digest,
               "statement digest binds entry order");

    auto changed_anchor = *fixture;
    changed_anchor.resolved[0].anchor_root = *changed_root;
    auto changed_anchor_digest =
        purify::accountable::construction_receipt_statement_digest(
            *payload, *setup, changed_anchor.resolved);
    expect_ok(ctx, changed_anchor_digest, "changed anchor digest constructs");
    if (!changed_anchor_digest) return;
    ctx.expect(*changed_anchor_digest != *digest,
               "statement digest binds each exact anchor root");

    auto changed_context = fixture->resolved;
    changed_context[0].context_digest[0] ^= 1U;
    auto changed_context_digest =
        purify::accountable::construction_receipt_statement_digest(
            *payload, *setup, changed_context);
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
    test_parent_envelope_layout_and_syntax(ctx);
    test_statement_digest_binds_all_inputs(ctx);
}
