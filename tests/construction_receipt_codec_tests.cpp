// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <algorithm>
#include <array>
#include <cstdint>
#include <string_view>
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
using purify::accountable::ConstructionReceiptAnchorEntry;
using purify::accountable::ConstructionReceiptEnvelope;
using purify::accountable::ConstructionReceiptPayload;
using purify::accountable::ConstructionReceiptSetupEntry;
using purify::accountable::RecoveryRootShare;
using purify::accountable::ResolvedConstructionReceiptEntry;
using purify::accountable::ResolvedConstructionSetupDigest;
using purify::accountable::ResolvedConstructionSetupDigestBytes;

struct ReceiptFixture {
    UInt512 recovery_root{};
    std::vector<ConstructionReceiptSetupEntry> setup_entries;
    std::vector<ConstructionReceiptAnchorEntry> anchor_entries;
    std::vector<ResolvedConstructionReceiptEntry> resolved;
};

Result<RecoveryRootShare> recovery_share(std::uint64_t scalar) {
    const auto magnitude = FieldElement::from_u64(scalar).to_uint256();
    const auto first = purify::curve1().affine(
        purify::curve1().mul(purify::generator1(), magnitude));
    const auto second = purify::curve2().affine(
        purify::curve2().mul(purify::generator2(), magnitude));
    Bytes encoded;
    encoded.reserve(RecoveryRootShare::kSerializedSize);
    for (const auto& point : {first, second}) {
        encoded.push_back(
            static_cast<unsigned char>(point.y.is_odd() ? 0x03 : 0x02));
        const auto x = point.x.to_bytes_be();
        encoded.insert(encoded.end(), x.begin(), x.end());
    }
    return RecoveryRootShare::deserialize(encoded);
}

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
    std::vector<RecoveryRootShare> shares;
    for (std::uint64_t scalar : {3, 5}) {
        PURIFY_ASSIGN_OR_RETURN(
            auto share, recovery_share(scalar),
            "construction_receipt_codec_test:share");
        shares.push_back(share);
        fixture.setup_entries.emplace_back(
            std::move(share),
            FieldElement::from_u64(20 + scalar).to_bytes_be());
    }
    PURIFY_ASSIGN_OR_RETURN(
        const auto aggregate,
        purify::accountable::aggregate_recovery_root_shares(shares),
        "construction_receipt_codec_test:aggregate");
    fixture.recovery_root = aggregate.recovery_root();

    fixture.anchor_entries.resize(2);
    PURIFY_ASSIGN_OR_RETURN(
        fixture.anchor_entries[0].ciphertext.ephemeral_key,
        public_root(2),
        "construction_receipt_codec_test:ephemeral_0");
    fixture.anchor_entries[0].ciphertext.masked_scalar =
        FieldElement::from_u64(11);
    fixture.anchor_entries[0].circuit_precommitment =
        FieldElement::from_u64(31).to_bytes_be();

    PURIFY_ASSIGN_OR_RETURN(
        fixture.anchor_entries[1].ciphertext.ephemeral_key,
        public_root(4),
        "construction_receipt_codec_test:ephemeral_1");
    fixture.anchor_entries[1].ciphertext.masked_scalar =
        FieldElement::from_u64(21);
    fixture.anchor_entries[1].circuit_precommitment =
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
    return ConstructionReceiptPayload::create(
        fixture.recovery_root, fixture.setup_entries,
        fixture.anchor_entries);
}

void test_canonical_layout_and_round_trip(TestContext& ctx) {
    auto fixture = make_fixture();
    expect_ok(ctx, fixture, "receipt codec fixture constructs");
    if (!fixture) return;
    auto payload = make_payload(*fixture);
    expect_ok(ctx, payload, "canonical payload constructs");
    if (!payload) return;

    constexpr std::size_t kExpectedSize = 73 + 2 * 98 + 2 * 128;
    static_assert(ConstructionReceiptPayload::kFixedHeaderSize == 73);
    static_assert(ConstructionReceiptPayload::kSetupEntrySize == 98);
    static_assert(ConstructionReceiptPayload::kAnchorEntrySize == 128);
    const Bytes encoded = payload->serialize();
    ctx.expect(payload->serialized_size() == kExpectedSize,
               "reported size accounts for every fixed field");
    ctx.expect(encoded.size() == kExpectedSize,
               "wire size is exactly 73 + 98*N + 128*A bytes");
    ctx.expect(encoded[0] ==
                       ConstructionReceiptPayload::kSerializationVersion &&
                   encoded[0] == 4,
               "wire starts with construction receipt version 4");
    const auto recovery_root_bytes = fixture->recovery_root.to_bytes_be();
    ctx.expect(std::equal(recovery_root_bytes.begin(),
                          recovery_root_bytes.end(),
                          encoded.begin() + 1),
               "wire carries the exact 64-byte recovery root");
    ctx.expect(encoded[65] == 0 && encoded[66] == 0 &&
                   encoded[67] == 0 && encoded[68] == 2,
               "wire setup count is canonical big endian");
    ctx.expect(encoded[69] == 0 && encoded[70] == 0 &&
                   encoded[71] == 0 && encoded[72] == 2,
               "wire anchor count is canonical big endian");

    constexpr std::size_t kFirstSetupOffset =
        ConstructionReceiptPayload::kFixedHeaderSize;
    const auto first_share = fixture->setup_entries[0].share.serialize();
    ctx.expect(std::equal(first_share.begin(), first_share.end(),
                          encoded.begin() + kFirstSetupOffset),
               "setup entry starts with its exact signed share");
    ctx.expect(
        std::equal(
            fixture->setup_entries[0].circuit_precommitment.begin(),
            fixture->setup_entries[0].circuit_precommitment.end(),
            encoded.begin() + kFirstSetupOffset +
                RecoveryRootShare::kSerializedSize),
        "setup entry appends its exact precommitment");

    constexpr std::size_t kFirstCiphertextOffset =
        ConstructionReceiptPayload::kFixedHeaderSize +
        2 * ConstructionReceiptPayload::kSetupEntrySize;
    const auto first_ephemeral =
        fixture->anchor_entries[0].ciphertext.ephemeral_key.to_bytes_be();
    ctx.expect(std::equal(first_ephemeral.begin(),
                          first_ephemeral.end(),
                          encoded.begin() + kFirstCiphertextOffset),
               "ciphertext starts with its first 64-byte ephemeral key");
    const auto first_masked =
        fixture->anchor_entries[0].ciphertext.masked_scalar.to_bytes_be();
    ctx.expect(std::equal(first_masked.begin(),
                          first_masked.end(),
                          encoded.begin() + kFirstCiphertextOffset + 64),
               "ciphertext appends its 32-byte masked scalar");
    constexpr std::size_t kFirstPrecommitmentOffset =
        kFirstCiphertextOffset +
        purify::accountable::AnchorEscrowCiphertext::kSerializedSize;
    ctx.expect(
        std::equal(
            fixture->anchor_entries[0].circuit_precommitment.begin(),
            fixture->anchor_entries[0].circuit_precommitment.end(),
            encoded.begin() + kFirstPrecommitmentOffset),
        "entry appends its exact 32-byte circuit precommitment");
    constexpr std::size_t kSecondEntryOffset =
        kFirstCiphertextOffset +
        ConstructionReceiptPayload::kAnchorEntrySize;
    const auto second_entry_ephemeral =
        fixture->anchor_entries[1].ciphertext.ephemeral_key.to_bytes_be();
    ctx.expect(
        std::equal(second_entry_ephemeral.begin(),
                   second_entry_ephemeral.end(),
                   encoded.begin() + kSecondEntryOffset) &&
            std::equal(
                fixture->anchor_entries[1].circuit_precommitment.begin(),
                fixture->anchor_entries[1].circuit_precommitment.end(),
                encoded.begin() + kSecondEntryOffset +
                    purify::accountable::AnchorEscrowCiphertext::
                        kSerializedSize),
        "entry stride is exactly 128 bytes");

    auto decoded = ConstructionReceiptPayload::deserialize(encoded);
    expect_ok(ctx, decoded, "canonical wire payload decodes");
    if (!decoded) return;
    ctx.expect(decoded->serialize() == encoded,
               "decoding and encoding preserve canonical bytes");
    ctx.expect(decoded->recovery_root() == fixture->recovery_root,
               "round trip preserves the recovery root");
    ctx.expect(
        decoded->setup_entries().size() == fixture->setup_entries.size() &&
            decoded->anchor_entries().size() ==
                fixture->anchor_entries.size(),
        "round trip preserves both typed entry counts");
    ctx.expect(
        decoded->setup_entries()[0].share.serialize() == first_share &&
            decoded->anchor_entries()[0].circuit_precommitment ==
                fixture->anchor_entries[0].circuit_precommitment &&
            decoded->anchor_entries()[1].circuit_precommitment ==
                fixture->anchor_entries[1].circuit_precommitment,
        "round trip preserves every circuit precommitment");
}

void test_construction_invariants(TestContext& ctx) {
    auto fixture = make_fixture();
    expect_ok(ctx, fixture, "invariant fixture constructs");
    if (!fixture) return;

    expect_error(ctx,
                 ConstructionReceiptPayload::create(
                     fixture->recovery_root,
                     {}, fixture->anchor_entries),
                 purify::ErrorCode::EmptyInput,
                 "empty setup entry collections are rejected");
    expect_error(ctx,
                 ConstructionReceiptPayload::create(
                     fixture->recovery_root,
                     fixture->setup_entries, {}),
                 purify::ErrorCode::EmptyInput,
                 "empty anchor entry collections are rejected");

    expect_error(ctx,
                 ConstructionReceiptPayload::create(
                     purify::packed_public_key_space_size(),
                     fixture->setup_entries,
                     fixture->anchor_entries),
                 purify::ErrorCode::RangeViolation,
                 "out-of-range recovery roots are rejected");

    auto zero_precommitment = fixture->anchor_entries;
    zero_precommitment[0].circuit_precommitment = {};
    expect_error(
        ctx,
        ConstructionReceiptPayload::create(
            fixture->recovery_root, fixture->setup_entries,
            std::move(zero_precommitment)),
        purify::ErrorCode::RangeViolation,
        "zero circuit precommitments are rejected on create");

    auto noncanonical_precommitment = fixture->setup_entries;
    noncanonical_precommitment[0].circuit_precommitment =
        purify::prime_p().to_bytes_be();
    expect_error(
        ctx,
        ConstructionReceiptPayload::create(
            fixture->recovery_root,
            std::move(noncanonical_precommitment),
            fixture->anchor_entries),
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
        truncated_entry.end() -
            ConstructionReceiptPayload::kAnchorEntrySize,
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

    auto zero_setup_count = encoded;
    std::fill(zero_setup_count.begin() + 65,
              zero_setup_count.begin() + 69, 0);
    expect_error(ctx,
                 ConstructionReceiptPayload::deserialize(zero_setup_count),
                 purify::ErrorCode::EmptyInput,
                 "zero setup count is rejected");

    auto zero_anchor_count = encoded;
    std::fill(zero_anchor_count.begin() + 69,
              zero_anchor_count.begin() + 73, 0);
    expect_error(ctx,
                 ConstructionReceiptPayload::deserialize(zero_anchor_count),
                 purify::ErrorCode::EmptyInput,
                 "zero anchor count is rejected");

    auto smaller_count = encoded;
    smaller_count[68] = 1;
    ctx.expect(!ConstructionReceiptPayload::deserialize(smaller_count),
               "a count smaller than the carried entries is rejected");

    auto larger_count = encoded;
    larger_count[68] = 3;
    ctx.expect(!ConstructionReceiptPayload::deserialize(larger_count),
               "a count larger than the carried entries is rejected");

    auto overflowing_total_count = encoded;
    std::fill(overflowing_total_count.begin() + 65,
              overflowing_total_count.begin() + 69, 0xff);
    std::fill(overflowing_total_count.begin() + 69,
              overflowing_total_count.begin() + 73, 0);
    overflowing_total_count[72] = 1;
    expect_error(
        ctx,
        ConstructionReceiptPayload::deserialize(
            overflowing_total_count),
        purify::ErrorCode::UnexpectedSize,
        "the combined typed entry count must fit u32");

    constexpr std::size_t kFirstSetup =
        ConstructionReceiptPayload::kFixedHeaderSize;
    constexpr std::size_t kFirstCiphertext =
        kFirstSetup + 2 * ConstructionReceiptPayload::kSetupEntrySize;
    auto invalid_recovery_root = encoded;
    const auto invalid_root =
        purify::packed_public_key_space_size().to_bytes_be();
    std::copy(invalid_root.begin(), invalid_root.end(),
              invalid_recovery_root.begin() + 1);
    ctx.expect(!ConstructionReceiptPayload::deserialize(
                   invalid_recovery_root),
               "noncanonical recovery roots are rejected");

    auto mismatched_share = encoded;
    mismatched_share[kFirstSetup] =
        static_cast<unsigned char>(mismatched_share[kFirstSetup] == 0x02
                                       ? 0x03
                                       : 0x02);
    expect_error(ctx,
                 ConstructionReceiptPayload::deserialize(mismatched_share),
                 purify::ErrorCode::BindingMismatch,
                 "full signed shares must aggregate to the header root");

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

    // Transport-only until mixed-profile qualification replaces this size.
    static_assert(ConstructionReceiptEnvelope::kParentProofSize == 15'076);
    Bytes parent_proof(
        ConstructionReceiptEnvelope::kParentProofSize, 0xa5);
    auto envelope = ConstructionReceiptEnvelope::create(
        *payload, parent_proof);
    expect_ok(ctx, envelope, "canonical parent envelope constructs");
    if (!envelope) return;
    const Bytes encoded = envelope->serialize();
    const std::size_t expected_size =
        73 + 98 * fixture->setup_entries.size() +
        128 * fixture->anchor_entries.size() + parent_proof.size();
    ctx.expect(envelope->serialized_size() == expected_size &&
                   encoded.size() == expected_size,
               "envelope uses the provisional 15,076-byte proof slot");
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
            "ce8734bae36717a69f9f5286ef5f0ff1"
            "9fdff2358e22ef3123cdcc31492ee231",
        "statement digest matches the canonical V5 tagged-hash vector");
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

    auto changed_recovery = *fixture;
    auto changed_share = recovery_share(7);
    expect_ok(ctx, changed_share, "changed setup share constructs");
    if (!changed_share) return;
    changed_recovery.setup_entries[0].share = *changed_share;
    std::vector<RecoveryRootShare> changed_shares;
    for (const auto& entry : changed_recovery.setup_entries) {
        changed_shares.push_back(entry.share);
    }
    auto changed_aggregate =
        purify::accountable::aggregate_recovery_root_shares(
            changed_shares);
    expect_ok(ctx, changed_aggregate,
              "changed setup aggregate constructs");
    if (!changed_aggregate) return;
    changed_recovery.recovery_root =
        changed_aggregate->recovery_root();
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
    changed_ciphertext.anchor_entries[0].ciphertext.masked_scalar =
        changed_ciphertext.anchor_entries[0].ciphertext.masked_scalar +
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
    changed_precommitment.anchor_entries[0].circuit_precommitment =
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

    auto reordered_setup = *fixture;
    std::swap(reordered_setup.setup_entries[0],
              reordered_setup.setup_entries[1]);
    auto reordered_setup_payload = make_payload(reordered_setup);
    expect_ok(ctx, reordered_setup_payload,
              "reordered setup payload constructs");
    if (!reordered_setup_payload) return;
    auto reordered_setup_digest =
        purify::accountable::construction_receipt_statement_digest(
            *reordered_setup_payload, *setup,
            reordered_setup.resolved);
    expect_ok(ctx, reordered_setup_digest,
              "reordered setup statement constructs");
    if (!reordered_setup_digest) return;
    ctx.expect(*reordered_setup_digest != *digest,
               "statement digest binds setup roster order");

    auto reordered = *fixture;
    std::swap(reordered.anchor_entries[0],
              reordered.anchor_entries[1]);
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
    auto changed_anchor_root = public_root(8);
    expect_ok(ctx, changed_anchor_root,
              "changed anchor root constructs");
    if (!changed_anchor_root) return;
    changed_anchor.resolved[0].anchor_root = *changed_anchor_root;
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

void test_construction_parent_profile_digest(TestContext& ctx) {
    auto secp = purify::make_secp_context();
    ctx.expect(secp != nullptr, "construction profile secp context creates");
    if (!secp) return;
    auto accumulator = purify::accountable::ConstructionReceiptAccumulator::
        create(secp.get());
    expect_ok(ctx, accumulator,
              "homogeneous construction accumulator creates");
    if (!accumulator) return;
    const auto& digest = accumulator->leaves().basis().digest();
    constexpr std::array<unsigned char, 32> kRecursiveProfileDigest{
        0x3e, 0x22, 0x80, 0x71, 0x8c, 0xf5, 0x97, 0x0d,
        0xaf, 0x53, 0xb8, 0xec, 0x3f, 0xf1, 0x1d, 0x59,
        0x2a, 0x71, 0x48, 0x35, 0x14, 0xba, 0x91, 0xa6,
        0xf1, 0xb3, 0x72, 0x08, 0xad, 0x9e, 0xb5, 0x94};
    ctx.expect(digest == kRecursiveProfileDigest,
               "native basis matches the recursive profile digest");

    std::array<unsigned char,
               purify::accountable::ConstructionReceiptAccumulator::
                   kRootClaimSerializedSize>
        empty_claim{};
    auto parsed = purify::bppp::accumulation::parse_root_claim(
        accumulator->leaves().basis(), empty_claim, secp.get());
    expect_ok(ctx, parsed,
              "canonical all-zero initial claim parses");
    if (!parsed) return;
    auto serialized = purify::bppp::accumulation::serialize_root_claim(
        accumulator->leaves().basis(), *parsed, secp.get());
    expect_ok(ctx, serialized,
              "canonical all-zero initial claim serializes");
    if (!serialized) return;
    ctx.expect(std::equal(serialized->begin(), serialized->end(),
                          empty_claim.begin()),
               "canonical initial claim is exactly 545 zero bytes");
}

#if defined(PURIFY_HAS_CONSTRUCTION_PARENT_VERIFIER)
void test_construction_parent_verifier_requires_artifact_path(
    TestContext& ctx) {
    expect_error(
        ctx,
        purify::accountable::ConstructionParentVerifier::load({}),
        purify::ErrorCode::RangeViolation,
        "construction parent verifier rejects an empty artifact path");

    const char embedded_nul[] = {'a', '\0', 'b'};
    expect_error(
        ctx,
        purify::accountable::ConstructionParentVerifier::load(
            std::string_view(embedded_nul, sizeof(embedded_nul))),
        purify::ErrorCode::RangeViolation,
        "construction parent verifier rejects an embedded NUL path");
}
#endif

}  // namespace

void run_construction_receipt_codec_tests(TestContext& ctx) {
    test_canonical_layout_and_round_trip(ctx);
    test_construction_invariants(ctx);
    test_noncanonical_and_framing_rejection(ctx);
    test_parent_envelope_layout_and_syntax(ctx);
    test_statement_digest_binds_all_inputs(ctx);
    test_construction_parent_profile_digest(ctx);
#if defined(PURIFY_HAS_CONSTRUCTION_PARENT_VERIFIER)
    test_construction_parent_verifier_requires_artifact_path(ctx);
#endif
}
