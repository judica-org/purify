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
#include "purify/puresign/construction_receipt_assembly.hpp"
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

std::array<unsigned char, 32> raw_generator_digest(
    std::span<const purify::bppp::PointBytes> generators) {
    std::array<unsigned char, 32> digest{};
    const auto bytes = std::as_bytes(generators);
    purify_sha256(
        digest.data(),
        reinterpret_cast<const unsigned char*>(bytes.data()),
        bytes.size());
    return digest;
}

Result<std::array<unsigned char, 33>> public_point(
    const FieldElement& scalar, purify_secp_context* secp_context) {
    const auto original = scalar.to_bytes_be();
    auto normalized = original;
    std::array<unsigned char, 32> xonly{};
    if (purify_bip340_key_from_seckey(
            secp_context, normalized.data(), xonly.data()) == 0) {
        return purify::unexpected_error(purify::ErrorCode::RangeViolation,
                                        "anchor_escrow_test:point");
    }
    std::array<unsigned char, 33> out{};
    out[0] = normalized == original ? 0x02 : 0x03;
    std::copy(xonly.begin(), xonly.end(), out.begin() + 1);
    return out;
}

struct BoundRosterFixture {
    RecoveryBoundSigningRoster roster;
    FieldElement signing_scalar;
    purify::accountable::RecoveryRootSetupProof setup_proof;
};

Result<BoundRosterFixture> make_roster(
    unsigned char digest_marker, unsigned char host_marker,
    purify_secp_context* secp_context) {
    auto member_secret = FieldElement::from_u64(3);
    PURIFY_ASSIGN_OR_RETURN(auto member_key,
                            public_point(member_secret, secp_context),
                            "anchor_escrow_test:member_key");
    if (member_key[0] == 0x03) {
        member_key[0] = 0x02;
        member_secret = member_secret.negate();
    }
    const std::array<std::array<unsigned char, 33>, 1> members{member_key};
    PURIFY_ASSIGN_OR_RETURN(
        auto raw, SigningRoster::aggregate(members, secp_context),
        "anchor_escrow_test:roster");
    const auto signing_scalar =
        raw.members().front().coefficient * member_secret;
    PURIFY_ASSIGN_OR_RETURN(
        const auto& recovery_root,
        purify::accountable::derive_recovery_root(signing_scalar),
        "anchor_escrow_test:recovery_root");
    CoalitionCoreDigest coalition_core_digest{};
    coalition_core_digest.fill(digest_marker);
    std::array<unsigned char, 32> host_seed{};
    host_seed.fill(host_marker);
    PURIFY_ASSIGN_OR_RETURN(
        const auto& host_key, purify::generate_key(host_seed),
        "anchor_escrow_test:host_key");
    PURIFY_ASSIGN_OR_RETURN(
        auto host,
        purify::puresign_plusplus::PublicKey::from_secret(
            host_key.secret, secp_context),
        "anchor_escrow_test:host");
    std::copy(member_key.begin() + 1, member_key.end(),
              host.bip340_pubkey.begin());
    const std::array hosts{host};
    PURIFY_ASSIGN_OR_RETURN(
        auto nonce_bound,
        purify::accountable::bind_nonce_hosts(
            std::move(raw), coalition_core_digest, hosts, secp_context),
        "anchor_escrow_test:nonce_bound");
    PURIFY_ASSIGN_OR_RETURN(
        auto setup_proof,
        purify::accountable::prove_recovery_root_setup(
            nonce_bound, recovery_root.public_key, signing_scalar,
            secp_context),
        "anchor_escrow_test:setup_proof");
    PURIFY_ASSIGN_OR_RETURN(
        auto bound,
        purify::accountable::verify_recovery_root_setup(
            std::move(nonce_bound), recovery_root.public_key, setup_proof,
            secp_context),
        "anchor_escrow_test:bound_roster");
    return BoundRosterFixture{
        std::move(bound), signing_scalar, std::move(setup_proof)};
}

void expect_rejected(TestContext& ctx, Result<bool> result,
                     const char* message) {
    ctx.expect(!result || !*result, message);
}

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

void test_anchor_escrow(TestContext& ctx) {
    auto secp = purify::make_secp_context();
    ctx.expect(secp != nullptr, "anchor escrow secp context creates");
    if (!secp) return;

    auto fixture = make_roster(0x51, 0xae, secp.get());
    expect_ok(ctx, fixture,
              "setup proof constructs a recovery-bound escrow roster");
    if (!fixture) return;
    auto anchor_secret = purify::SecretKey::from_packed(
        purify::UInt512::from_u64(8));
    expect_ok(ctx, anchor_secret,
              "odd-output anchor secret parses");
    if (!anchor_secret) return;
    auto anchor = purify::derive_key(std::move(*anchor_secret));
    expect_ok(ctx, anchor,
              "odd-output anchor recovery key derives");
    if (!anchor) return;
#if PURIFY_USE_LEGACY_FIELD_HASHES
    auto legacy_point = public_point(FieldElement::one(), secp.get());
    expect_ok(ctx, legacy_point,
              "legacy rejection punishment point derives");
    if (!legacy_point) return;
    std::array<unsigned char, 32> legacy_xonly{};
    std::copy(legacy_point->begin() + 1, legacy_point->end(),
              legacy_xonly.begin());
    auto legacy_punishment_key =
        purify::accountable::AnchorPunishmentPublicKey::create(
            legacy_xonly, secp.get());
    expect_ok(ctx, legacy_punishment_key,
              "legacy rejection punishment key parses");
    if (!legacy_punishment_key) return;
    const AnchorEscrowContextDigest legacy_context{};
    const purify::bppp::ScalarBytes legacy_auxiliary_randomness{};
    expect_error(
        ctx,
        purify::accountable::create_anchor_escrow(
            fixture->roster, *anchor, *legacy_punishment_key,
            legacy_context, secp.get()),
        purify::ErrorCode::UnsupportedSymbol,
        "anchor v3 creation rejects the legacy field-hash suite");
    expect_error(
        ctx,
        purify::accountable::create_anchor_escrow_with_aux_randomness(
            fixture->roster, *anchor, *legacy_punishment_key,
            legacy_context, legacy_auxiliary_randomness, secp.get()),
        purify::ErrorCode::UnsupportedSymbol,
        "deterministic anchor v3 creation rejects legacy field hashes");
    auto legacy_construction_accumulator = purify::accountable::
        ConstructionReceiptAccumulator::create(secp.get());
    expect_ok(ctx, legacy_construction_accumulator,
              "legacy builds retain non-accepting envelope basis syntax");
    return;
#endif
    auto punishment =
        purify::accountable::derive_anchor_punishment_key(*anchor,
                                                          secp.get());
    expect_ok(ctx, punishment,
              "anchor escrow punishment key derives");
    if (!punishment) return;
    const auto punishment_key = punishment->public_key();
    std::array<unsigned char, 32> seed{};
    const AnchorEscrowContextDigest context =
        purify::TaggedHash("Purify/Test/AnchorEscrowContext/v1")
            .digest(purify::bytes_from_ascii(
                "anchor=alice/bond=7/purpose=slash/domain=3"));

    purify::bppp::ScalarBytes auxiliary_randomness{};
    const auto started = std::chrono::steady_clock::now();
    auto record =
        purify::accountable::create_anchor_escrow_with_aux_randomness(
            fixture->roster, *anchor, punishment_key, context,
            auxiliary_randomness, secp.get());
    const auto proved = std::chrono::steady_clock::now();
    expect_ok(ctx, record,
              "deterministic test seam proves exact anchor encryption");
    if (!record) return;
    auto circuit_shape =
        purify::accountable::anchor_escrow_circuit_shape_for_testing(
            fixture->roster.recovery_root(), anchor->public_key,
            record->ciphertext());
    expect_ok(ctx, circuit_shape,
              "fixed-domain punishment circuit shape derives");
    if (!circuit_shape) return;
    ctx.expect(circuit_shape->unpadded_gates == 6938 &&
                   circuit_shape->padded_gates == 8192,
               "fixed-domain punishment relation stays in 8192 gates");
    ctx.expect(record->ciphertext().ephemeral_keys[0] !=
                   record->ciphertext().ephemeral_keys[1],
               "separate derivation tags give each pad a distinct key");
    auto accepted = purify::accountable::verify_anchor_escrow(
        fixture->roster, anchor->public_key, punishment_key, context,
        *record, secp.get());
    const auto verified = std::chrono::steady_clock::now();
    ctx.expect(accepted && *accepted,
               "exact recovery-bound escrow statement verifies");

    auto encoded = record->serialize(secp.get());
    expect_ok(ctx, encoded, "anchor escrow has a canonical encoding");
    if (!encoded) return;
    expect_error(ctx, record->serialize(nullptr),
                 purify::ErrorCode::MissingValue,
                 "anchor escrow serialization requires a secp context");
    expect_error(
        ctx,
        purify::accountable::AnchorEscrowRecord::deserialize(
            *encoded, nullptr),
        purify::ErrorCode::MissingValue,
        "anchor escrow parsing requires a secp context");
    ctx.expect(
        encoded->size() == 1329 &&
            encoded->size() ==
                purify::accountable::AnchorEscrowRecord::kSerializedSize &&
            encoded->front() == 3,
        "anchor escrow is one version byte plus 192 and 1136 bytes");
    auto parsed = purify::accountable::AnchorEscrowRecord::deserialize(
        *encoded, secp.get());
    expect_ok(ctx, parsed, "canonical anchor escrow reparses");
    if (!parsed) return;
    auto reencoded = parsed->serialize(secp.get());
    ctx.expect(reencoded && *reencoded == *encoded,
               "anchor escrow encoding round-trips exactly");

    auto construction_accumulator = purify::accountable::
        ConstructionReceiptAccumulator::create(secp.get());
    expect_ok(ctx, construction_accumulator,
              "construction receipt fixed accumulation bases create");
    if (!construction_accumulator) return;
    const auto* accumulator = &construction_accumulator->anchors();
    ctx.expect(
        accumulator->basis().n_vec_len() ==
                purify::accountable::AnchorEscrowAccumulator::
                    kNormVectorLength &&
            accumulator->basis().l_vec_len() ==
                purify::accountable::AnchorEscrowAccumulator::
                    kNormVectorLength,
        "anchor escrow accumulation fixes both norm dimensions");
    purify::bppp::ExperimentalCircuitCache parent_cache;
    auto prepared = accumulator->prepare(
        fixture->roster, anchor->public_key, punishment_key, context,
        *parsed, secp.get(), &parent_cache);
    expect_ok(ctx, prepared,
              "typed adapter prepares the exact anchor escrow statement");
    if (!prepared) return;
    ctx.expect(
        std::any_of(prepared->circuit_precommitment().begin(),
                    prepared->circuit_precommitment().end(),
                    [](unsigned char byte) { return byte != 0; }),
        "prepared anchor exposes its nonzero V4 precommitment");
    auto parent_constants = accumulator->derive_parent_constants(
        fixture->roster, anchor->public_key, punishment_key, context,
        parsed->ciphertext(), prepared->circuit_precommitment(),
        secp.get(), &parent_cache);
    expect_ok(ctx, parent_constants,
              "anchor parent constants derive from public payload data");
    if (!parent_constants) return;
    ctx.expect(
        parent_constants->raw_generator_digest ==
                raw_generator_digest(
                    accumulator->basis().norm_generators()) &&
            parent_constants->coefficient_commitment ==
                prepared->norm().coefficient_commitment(),
        "anchor parent constants match the prepared V4 proof family");
    auto changed_parent_context = context;
    changed_parent_context[0] ^= 1;
    auto changed_parent_constants = accumulator->derive_parent_constants(
        fixture->roster, anchor->public_key, punishment_key,
        changed_parent_context, parsed->ciphertext(),
        prepared->circuit_precommitment(), secp.get(), &parent_cache);
    expect_ok(ctx, changed_parent_constants,
              "changed anchor context still derives public constants");
    if (!changed_parent_constants) return;
    ctx.expect(
        changed_parent_constants->circuit_binding_digest !=
                parent_constants->circuit_binding_digest &&
            changed_parent_constants->raw_generator_digest ==
                parent_constants->raw_generator_digest &&
            changed_parent_constants->coefficient_commitment ==
                parent_constants->coefficient_commitment &&
            changed_parent_constants->anchored_offset ==
                parent_constants->anchored_offset,
        "only the parent binding digest follows a changed public context");
    expect_error(
        ctx,
        accumulator->derive_parent_constants(
            fixture->roster, anchor->public_key, punishment_key, context,
            parsed->ciphertext(), purify::bppp::ScalarBytes{},
            secp.get()),
        purify::ErrorCode::RangeViolation,
        "anchor parent constants reject a zero precommitment");
    auto duplicate_ciphertext = parsed->ciphertext();
    duplicate_ciphertext.ephemeral_keys[1] =
        duplicate_ciphertext.ephemeral_keys[0];
    expect_error(
        ctx,
        accumulator->derive_parent_constants(
            fixture->roster, anchor->public_key, punishment_key, context,
            duplicate_ciphertext, prepared->circuit_precommitment(),
            secp.get()),
        purify::ErrorCode::BindingMismatch,
        "anchor parent constants reject duplicate ephemeral keys");
    auto reduction =
        purify::bppp::accumulation::prove_algebraic_norm_reduction(
            accumulator->basis(), prepared->norm(), secp.get());
    expect_ok(ctx, reduction,
              "anchor escrow coefficient opening proves");
    if (!reduction) return;
    auto setup_prepared = construction_accumulator->setup().prepare(
        fixture->roster, fixture->roster.recovery_root(),
        fixture->setup_proof, secp.get());
    expect_ok(ctx, setup_prepared,
              "construction adapter prepares the exact setup proof");
    if (!setup_prepared) return;
    auto setup_reduction =
        purify::bppp::accumulation::prove_algebraic_norm_reduction(
            construction_accumulator->setup().basis(),
            *setup_prepared, secp.get());
    expect_ok(ctx, setup_reduction,
              "construction setup coefficient opening proves");
    if (!setup_reduction) return;
    auto promoted_setup =
        construction_accumulator->verify_setup_reduction(
            fixture->roster, fixture->roster.recovery_root(),
            fixture->setup_proof, *setup_reduction, secp.get());
    expect_ok(ctx, promoted_setup,
              "exact setup reduction promotes to the anchor basis");
    if (!promoted_setup) return;
    std::vector<purify::accountable::ConstructionReceiptEntry>
        receipt_entries{{parsed->ciphertext(),
                         prepared->circuit_precommitment()}};
    auto receipt_payload =
        purify::accountable::ConstructionReceiptPayload::create(
            fixture->roster.recovery_root(),
            std::move(receipt_entries));
    expect_ok(ctx, receipt_payload,
              "one-anchor construction payload creates");
    if (!receipt_payload) return;
    purify::accountable::AnchorReference anchor_reference{};
    anchor_reference.fill(0x71);
    purify::accountable::ResolvedConstructionReceiptEntry resolved(
        anchor_reference, anchor->public_key, punishment_key, context);
    purify::accountable::ResolvedConstructionSetupDigestBytes
        setup_digest_bytes;
    setup_digest_bytes.fill(0x72);
    auto setup_digest =
        purify::accountable::ResolvedConstructionSetupDigest::create(
            setup_digest_bytes);
    expect_ok(ctx, setup_digest,
              "resolved construction setup digest creates");
    if (!setup_digest) return;
    auto expected_statement =
        purify::accountable::construction_receipt_statement_digest(
            *receipt_payload, *setup_digest, {&resolved, 1});
    expect_ok(ctx, expected_statement,
              "typed assembly statement digest creates");
    if (!expected_statement) return;

    auto mismatched_circuit_precommitment =
        FieldElement::one().to_bytes_be();
    if (mismatched_circuit_precommitment ==
        prepared->circuit_precommitment()) {
        mismatched_circuit_precommitment =
            FieldElement::from_u64(2).to_bytes_be();
    }
    expect_error(
        ctx,
        construction_accumulator->verify_anchor_reduction(
            *promoted_setup, fixture->roster, anchor->public_key,
            punishment_key, context, *parsed,
            mismatched_circuit_precommitment, *reduction, secp.get()),
        purify::ErrorCode::BindingMismatch,
        "construction rejects a substituted circuit precommitment");
    auto mismatched_setup =
        construction_accumulator->verify_setup_reduction(
            fixture->roster, fixture->roster.recovery_root(),
            fixture->setup_proof, *setup_reduction, secp.get());
    expect_ok(ctx, mismatched_setup,
              "mismatch assembly setup promotes");
    if (!mismatched_setup) return;
    std::vector<purify::accountable::ConstructionReceiptEntry>
        mismatched_entries{{parsed->ciphertext(),
                            mismatched_circuit_precommitment}};
    auto mismatched_payload =
        purify::accountable::ConstructionReceiptPayload::create(
            fixture->roster.recovery_root(),
            std::move(mismatched_entries));
    expect_ok(ctx, mismatched_payload,
              "mismatched precommitment payload remains canonical");
    if (!mismatched_payload) return;
    auto mismatched_assembly =
        purify::accountable::ConstructionReceiptAssembly::create(
            std::move(*mismatched_setup),
            std::move(*mismatched_payload), *setup_digest, {resolved});
    expect_ok(ctx, mismatched_assembly,
              "mismatched precommitment assembly constructs");
    if (!mismatched_assembly) return;
    expect_error(
        ctx,
        mismatched_assembly->verify_anchor_reduction(
            0, *construction_accumulator, fixture->roster, *parsed,
            *reduction, secp.get()),
        purify::ErrorCode::BindingMismatch,
        "assembly passes its exact circuit precommitment to verification");

    auto assembly =
        purify::accountable::ConstructionReceiptAssembly::create(
            std::move(*promoted_setup), std::move(*receipt_payload),
            std::move(*setup_digest), {resolved});
    expect_ok(ctx, assembly,
              "typed construction assembly binds the exact manifest");
    if (!assembly) return;
    ctx.expect(assembly->statement_digest() == *expected_statement,
               "typed assembly owns the exact statement digest");
    expect_error(ctx, assembly->ordered_leaves(),
                 purify::ErrorCode::MissingValue,
                 "incomplete manifests cannot produce ordered leaves");
    expect_error(
        ctx,
        assembly->verify_anchor_reduction(
            1, *construction_accumulator, fixture->roster, *parsed,
            *reduction, secp.get()),
        purify::ErrorCode::IndexOutOfRange,
        "anchor leaves cannot be added beyond the manifest");

    auto changed_manifest_record_bytes = *encoded;
    std::array<unsigned char, 32> changed_manifest_mask{};
    std::copy_n(changed_manifest_record_bytes.begin() + 65,
                changed_manifest_mask.size(),
                changed_manifest_mask.begin());
    auto changed_manifest_scalar =
        FieldElement::try_from_bytes32(changed_manifest_mask);
    expect_ok(ctx, changed_manifest_scalar,
              "manifest substitution scalar is canonical");
    if (!changed_manifest_scalar) return;
    changed_manifest_mask =
        (*changed_manifest_scalar + FieldElement::one()).to_bytes_be();
    std::copy(changed_manifest_mask.begin(), changed_manifest_mask.end(),
              changed_manifest_record_bytes.begin() + 65);
    auto changed_manifest_record =
        purify::accountable::AnchorEscrowRecord::deserialize(
            changed_manifest_record_bytes, secp.get());
    expect_ok(ctx, changed_manifest_record,
              "manifest substitution record remains canonical");
    if (!changed_manifest_record) return;
    expect_error(
        ctx,
        assembly->verify_anchor_reduction(
            0, *construction_accumulator, fixture->roster,
            *changed_manifest_record, *reduction, secp.get()),
        purify::ErrorCode::BindingMismatch,
        "a leaf cannot substitute another payload ciphertext");

    auto pending = assembly->verify_anchor_reduction(
        0, *construction_accumulator, fixture->roster, *parsed,
        *reduction, secp.get());
    expect_ok(ctx, pending,
              "exact anchor reduction yields a pending obligation");
    if (!pending) return;
    expect_error(
        ctx,
        assembly->verify_anchor_reduction(
            0, *construction_accumulator, fixture->roster, *parsed,
            *reduction, secp.get()),
        purify::ErrorCode::BindingMismatch,
        "one manifest index cannot be proven twice");
    expect_ok(ctx, purify::bppp::accumulation::decide(
                       accumulator->basis(), *pending, secp.get()),
              "final MSM discharges the honest anchor escrow obligation");
    auto construction_leaves = assembly->ordered_leaves();
    expect_ok(ctx, construction_leaves,
              "complete manifest yields setup-first ordered leaves");
    if (!construction_leaves) return;
    ctx.expect(construction_leaves->size() == 2 &&
                   (*construction_leaves)[0].point() ==
                       assembly->setup().claim().point() &&
                   (*construction_leaves)[1].point() == pending->point(),
               "ordered leaves preserve setup and payload order");
    auto construction_step = purify::bppp::accumulation::prove_step(
        accumulator->basis(), *construction_leaves, secp.get());
    expect_ok(ctx, construction_step,
              "setup and anchor obligations fold into one root");
    if (!construction_step) return;
    auto construction_root = purify::bppp::accumulation::verify_step(
        accumulator->basis(), *construction_leaves,
        *construction_step, secp.get());
    expect_ok(ctx, construction_root,
              "combined construction root remains pending");
    if (!construction_root) return;
    auto encoded_construction_root =
        purify::bppp::accumulation::serialize_root_claim(
            accumulator->basis(), *construction_root, secp.get());
    expect_ok(ctx, encoded_construction_root,
              "combined construction root has a canonical encoding");
    if (!encoded_construction_root) return;
    ctx.expect(
        encoded_construction_root->size() ==
            purify::accountable::ConstructionReceiptAccumulator::
                kRootClaimSerializedSize &&
            encoded_construction_root->size() == 545,
        "combined construction root is exactly 545 bytes");
    auto parsed_construction_root =
        purify::bppp::accumulation::parse_root_claim(
            accumulator->basis(), *encoded_construction_root,
            secp.get());
    expect_ok(ctx, parsed_construction_root,
              "combined construction root reparses");
    if (!parsed_construction_root) return;
    expect_ok(ctx, purify::bppp::accumulation::decide(
                       accumulator->basis(),
                       *parsed_construction_root, secp.get()),
              "final MSM discharges setup and anchor together");

    const auto slot = purify::bytes_from_ascii(
        "anchor-escrow/domain=3/epoch=9/slot=4");
    purify::accountable::ConflictContext conflict{
        fixture->roster.signing_key(),
        fixture->roster.nonce_host_commitment(),
        fixture->roster.coalition_core_digest(), slot};
    const auto first_body = purify::bytes_from_ascii("decision/root-a");
    const auto second_body = purify::bytes_from_ascii("decision/root-b");
    auto first_challenge = purify::accountable::signature_challenge(
        conflict, first_body, secp.get());
    auto second_challenge = purify::accountable::signature_challenge(
        conflict, second_body, secp.get());
    expect_ok(ctx, first_challenge,
              "first conflicting response challenge derives");
    expect_ok(ctx, second_challenge,
              "second conflicting response challenge derives");
    if (!first_challenge || !second_challenge) return;
    const auto nonce = FieldElement::from_u64(17);
    auto first_response = purify::accountable::ScalarSignature::deserialize(
        (nonce + *first_challenge * fixture->signing_scalar).to_bytes_be());
    auto second_response = purify::accountable::ScalarSignature::deserialize(
        (nonce + *second_challenge * fixture->signing_scalar).to_bytes_be());
    expect_ok(ctx, first_response, "first conflicting response encodes");
    expect_ok(ctx, second_response, "second conflicting response encodes");
    if (!first_response || !second_response) return;
    auto extracted = purify::accountable::recover_same_slot_key(
        conflict, first_body, *first_response, second_body,
        *second_response, secp.get());
    expect_ok(ctx, extracted,
              "conflicting scalar responses expose the coalition scalar");
    if (!extracted) return;
    const auto extracted_scalar = FieldElement::from_bytes32(*extracted);
    ctx.expect(extracted_scalar == fixture->signing_scalar,
               "conflict extraction preserves the exact aggregate sign");
    auto recovered = purify::accountable::recover_escrowed_anchor(
        fixture->roster, extracted_scalar, anchor->public_key,
        punishment_key, context, *parsed, secp.get());
    expect_ok(ctx, recovered,
              "exposed coalition scalar verifies and decrypts the anchor");
    if (recovered) {
        ctx.expect(
            recovered->public_key() == punishment_key &&
                recovered->bip340_key().seckey ==
                    punishment->bip340_key().seckey,
            "decryption returns the exact registered punishment key");
    }
    expect_error(
        ctx,
        purify::accountable::recover_escrowed_anchor(
            fixture->roster, extracted_scalar.negate(),
            anchor->public_key, punishment_key, context, *parsed,
            secp.get()),
        purify::ErrorCode::BindingMismatch,
        "an exposed scalar for the opposite coalition point cannot decrypt");

    auto changed_context = context;
    changed_context[0] ^= 1;
    expect_rejected(
        ctx,
        purify::accountable::verify_anchor_escrow(
            fixture->roster, anchor->public_key, punishment_key,
            changed_context, *record, secp.get()),
        "escrow proof cannot move to another application context");
    expect_error(
        ctx,
        accumulator->prepare(
            fixture->roster, anchor->public_key, punishment_key,
            changed_context, *record, secp.get()),
        purify::ErrorCode::EquationMismatch,
        "public DLog binding rejects the changed escrow context");
    ctx.expect(
        !construction_accumulator->verify_anchor_reduction(
            assembly->setup(), fixture->roster, anchor->public_key,
            punishment_key, changed_context, *record,
            prepared->circuit_precommitment(),
            *reduction, secp.get()),
        "construction leaf authenticates the exact anchor statement");
    expect_error(
        ctx,
        purify::accountable::recover_escrowed_anchor(
            fixture->roster, fixture->signing_scalar,
            anchor->public_key, punishment_key, changed_context,
            *record, secp.get()),
        purify::ErrorCode::EquationMismatch,
        "recovery exposes no plaintext for an invalid context");

    seed.fill(0x48);
    auto other_anchor = purify::generate_key(seed);
    expect_ok(ctx, other_anchor, "substitution anchor fixture generates");
    if (!other_anchor) return;
    auto other_punishment =
        purify::accountable::derive_anchor_punishment_key(
            *other_anchor, secp.get());
    expect_ok(ctx, other_punishment,
              "substitution punishment key derives");
    if (!other_punishment) return;
    expect_rejected(
        ctx,
        purify::accountable::verify_anchor_escrow(
            fixture->roster, anchor->public_key,
            other_punishment->public_key(), context, *record,
            secp.get()),
        "public-mode proof cannot move to another punishment key");
    expect_error(
        ctx,
        purify::accountable::create_anchor_escrow(
            fixture->roster, *anchor, other_punishment->public_key(),
            context, secp.get()),
        purify::ErrorCode::BindingMismatch,
        "escrow creation rejects a mismatched punishment key");
    expect_rejected(
        ctx,
        purify::accountable::verify_anchor_escrow(
            fixture->roster, other_anchor->public_key, punishment_key,
            context, *record, secp.get()),
        "escrow proof cannot advertise another anchor root");
    auto anchor_secret_copy = anchor->secret.clone();
    expect_ok(ctx, anchor_secret_copy,
              "mismatched keypair fixture clones its secret");
    if (!anchor_secret_copy) return;
    purify::GeneratedKey mismatched_anchor{
        std::move(*anchor_secret_copy), other_anchor->public_key};
    expect_error(
        ctx,
        purify::accountable::create_anchor_escrow(
            fixture->roster, mismatched_anchor, punishment_key, context,
            secp.get()),
        purify::ErrorCode::BindingMismatch,
        "escrow creation rejects a mismatched anchor keypair");
    auto changed_record_bytes = *encoded;
    std::array<unsigned char, 32> changed_mask_bytes{};
    std::copy_n(changed_record_bytes.begin() + 65,
                changed_mask_bytes.size(), changed_mask_bytes.begin());
    auto changed_mask = FieldElement::try_from_bytes32(changed_mask_bytes);
    expect_ok(ctx, changed_mask, "ciphertext scalar reparses for tampering");
    if (!changed_mask) return;
    changed_mask_bytes = (*changed_mask + FieldElement::one()).to_bytes_be();
    std::copy(changed_mask_bytes.begin(), changed_mask_bytes.end(),
              changed_record_bytes.begin() + 65);
    auto changed_record =
        purify::accountable::AnchorEscrowRecord::deserialize(
            changed_record_bytes, secp.get());
    expect_ok(ctx, changed_record,
              "changed ciphertext remains canonically encoded");
    if (!changed_record) return;
    expect_rejected(
        ctx,
        purify::accountable::verify_anchor_escrow(
            fixture->roster, anchor->public_key, punishment_key, context,
            *changed_record, secp.get()),
        "escrow proof cannot move to another ciphertext");
    expect_error(
        ctx,
        accumulator->prepare(
            fixture->roster, anchor->public_key, punishment_key, context,
            *changed_record, secp.get()),
        purify::ErrorCode::EquationMismatch,
        "public DLog binding rejects the changed escrow ciphertext");

    auto changed_inner_bytes = *encoded;
    std::array<unsigned char, 32> terminal_n_bytes{};
    std::copy_n(changed_inner_bytes.end() - 64, terminal_n_bytes.size(),
                terminal_n_bytes.begin());
    auto terminal_n =
        FieldElement::try_from_bytes32(terminal_n_bytes);
    expect_ok(ctx, terminal_n,
              "anchor escrow terminal norm scalar is canonical");
    if (!terminal_n) return;
    terminal_n_bytes =
        (*terminal_n + FieldElement::one()).to_bytes_be();
    std::copy(terminal_n_bytes.begin(), terminal_n_bytes.end(),
              changed_inner_bytes.end() - 64);
    auto changed_inner_record =
        purify::accountable::AnchorEscrowRecord::deserialize(
            changed_inner_bytes, secp.get());
    expect_ok(ctx, changed_inner_record,
              "changed inner proof remains canonically encoded");
    if (!changed_inner_record) return;
    auto changed_inner_prepared = accumulator->prepare(
        fixture->roster, anchor->public_key, punishment_key, context,
        *changed_inner_record, secp.get());
    expect_ok(ctx, changed_inner_prepared,
              "parseable false inner proof remains pending");
    if (!changed_inner_prepared) return;
    ctx.expect(changed_inner_prepared->norm().prepared_binding() !=
                   prepared->norm().prepared_binding() &&
                   changed_inner_prepared->circuit_precommitment() ==
                       prepared->circuit_precommitment(),
               "typed adapter authenticates the exact inner proof");
    auto changed_inner_reduction =
        purify::bppp::accumulation::prove_algebraic_norm_reduction(
            accumulator->basis(), changed_inner_prepared->norm(),
            secp.get());
    expect_ok(ctx, changed_inner_reduction,
              "false inner proof has a public coefficient opening");
    if (!changed_inner_reduction) return;
    auto changed_inner_claim =
        purify::bppp::accumulation::verify_algebraic_norm_reduction(
            accumulator->basis(), changed_inner_prepared->norm(),
            *changed_inner_reduction, secp.get());
    expect_ok(ctx, changed_inner_claim,
              "short verifier keeps a false inner proof pending");
    if (!changed_inner_claim) return;
    ctx.expect(!purify::bppp::accumulation::decide(
                   accumulator->basis(), *changed_inner_claim, secp.get()),
               "final MSM rejects the changed inner proof");

    auto legacy_record = *encoded;
    legacy_record[0] = 2;
    legacy_record.erase(legacy_record.begin() + 291,
                        legacy_record.begin() + 355);
    expect_error(
        ctx,
        purify::accountable::AnchorEscrowRecord::deserialize(
            legacy_record, secp.get()),
        purify::ErrorCode::InvalidFixedSize,
        "legacy hidden-mode anchor record has no compatibility alias");

    auto other_fixture = make_roster(0x62, 0x9d, secp.get());
    expect_ok(ctx, other_fixture,
              "second setup statement constructs a bound roster");
    if (!other_fixture) return;
    ctx.expect(
        !construction_accumulator->verify_setup_reduction(
            fixture->roster, fixture->roster.recovery_root(),
            other_fixture->setup_proof, *setup_reduction, secp.get()),
        "construction promotion rejects another setup proof");
    expect_error(
        ctx,
        construction_accumulator->verify_anchor_reduction(
            assembly->setup(), other_fixture->roster,
            anchor->public_key, punishment_key, context, *parsed,
            prepared->circuit_precommitment(),
            *reduction,
            secp.get()),
        purify::ErrorCode::BindingMismatch,
        "one construction cannot mix setup and anchor rosters");
    expect_rejected(
        ctx,
        purify::accountable::verify_anchor_escrow(
            other_fixture->roster, anchor->public_key, punishment_key,
            context, *record, secp.get()),
        "escrow proof binds the exact coalition core and roster");
    auto other_nonce_hosts = make_roster(0x51, 0xaf, secp.get());
    expect_ok(ctx, other_nonce_hosts,
              "alternate nonce-host setup constructs a bound roster");
    if (!other_nonce_hosts) return;
    expect_rejected(
        ctx,
        purify::accountable::verify_anchor_escrow(
            other_nonce_hosts->roster, anchor->public_key,
            punishment_key, context, *record, secp.get()),
        "escrow proof binds the setup-registered nonce host commitment");

    auto repeated_record =
        purify::accountable::create_anchor_escrow_with_aux_randomness(
            fixture->roster, *anchor, punishment_key, context,
            auxiliary_randomness, secp.get());
    expect_ok(ctx, repeated_record,
              "identical auxiliary input recreates the escrow");
    if (!repeated_record) return;
    auto repeated_encoded = repeated_record->serialize(secp.get());
    expect_ok(ctx, repeated_encoded, "repeated anchor escrow serializes");
    if (!repeated_encoded) return;
    ctx.expect(*repeated_encoded == *encoded,
               "hedged derivation is deterministic for one exact statement");

    auto changed_auxiliary = auxiliary_randomness;
    changed_auxiliary.back() = 1;
    auto changed_aux_record =
        purify::accountable::create_anchor_escrow_with_aux_randomness(
            fixture->roster, *anchor, punishment_key, context,
            changed_auxiliary, secp.get());
    expect_ok(ctx, changed_aux_record,
              "changed auxiliary input creates another valid escrow");
    if (!changed_aux_record) return;
    auto changed_aux_encoded = changed_aux_record->serialize(secp.get());
    expect_ok(ctx, changed_aux_encoded,
              "changed-auxiliary anchor escrow serializes");
    if (!changed_aux_encoded) return;
    ctx.expect(*changed_aux_encoded != *encoded,
               "auxiliary randomness changes pads and proof randomness");
    accepted = purify::accountable::verify_anchor_escrow(
        fixture->roster, anchor->public_key, punishment_key, context,
        *changed_aux_record, secp.get());
    ctx.expect(accepted && *accepted,
               "changed-auxiliary escrow still verifies");

    auto changed_context_record =
        purify::accountable::create_anchor_escrow_with_aux_randomness(
            fixture->roster, *anchor, punishment_key, changed_context,
            auxiliary_randomness, secp.get());
    expect_ok(ctx, changed_context_record,
              "changed context creates a separately hedged escrow");
    if (!changed_context_record) return;
    auto changed_context_encoded =
        changed_context_record->serialize(secp.get());
    expect_ok(ctx, changed_context_encoded,
              "changed-context anchor escrow serializes");
    if (!changed_context_encoded) return;
    ctx.expect(*changed_context_encoded != *encoded,
               "repeated auxiliary input cannot reuse another context's pads");
    accepted = purify::accountable::verify_anchor_escrow(
        fixture->roster, anchor->public_key, punishment_key,
        changed_context, *changed_context_record, secp.get());
    ctx.expect(accepted && *accepted,
               "changed-context escrow verifies for its own statement");

    auto production_record = purify::accountable::create_anchor_escrow(
        fixture->roster, *anchor, punishment_key, context, secp.get());
    expect_ok(ctx, production_record,
              "production escrow samples operating-system auxiliary input");
    if (!production_record) return;
    accepted = purify::accountable::verify_anchor_escrow(
        fixture->roster, anchor->public_key, punishment_key, context,
        *production_record, secp.get());
    ctx.expect(accepted && *accepted,
               "production-randomized escrow verifies");

    auto maximum_packed = purify::key_space_size();
    maximum_packed.sub_assign(purify::UInt512::one());
    auto maximum_secret = purify::SecretKey::from_packed(maximum_packed);
    expect_ok(ctx, maximum_secret,
              "maximum canonical anchor secret parses");
    if (!maximum_secret) return;
    auto maximum_anchor = purify::derive_key(std::move(*maximum_secret));
    expect_ok(ctx, maximum_anchor,
              "maximum canonical anchor recovery key derives");
    if (!maximum_anchor) return;
    auto maximum_punishment =
        purify::accountable::derive_anchor_punishment_key(
            *maximum_anchor, secp.get());
    expect_ok(ctx, maximum_punishment,
              "maximum fixed-domain punishment key derives");
    if (!maximum_punishment) return;
    auto maximum_context = context;
    maximum_context.back() ^= 1;
    auto maximum_record =
        purify::accountable::create_anchor_escrow_with_aux_randomness(
            fixture->roster, *maximum_anchor,
            maximum_punishment->public_key(), maximum_context,
            auxiliary_randomness, secp.get());
    expect_ok(ctx, maximum_record,
              "maximum canonical anchor encrypts");
    if (!maximum_record) return;
    auto maximum_recovered = purify::accountable::recover_escrowed_anchor(
        fixture->roster, fixture->signing_scalar,
        maximum_anchor->public_key, maximum_punishment->public_key(),
        maximum_context, *maximum_record, secp.get());
    expect_ok(ctx, maximum_recovered,
              "maximum canonical anchor decrypts exactly");
    if (maximum_recovered) {
        ctx.expect(maximum_recovered->bip340_key().seckey ==
                       maximum_punishment->bip340_key().seckey,
                   "maximum punishment scalar survives escrow recovery");
    }

    auto malformed = *encoded;
    malformed.pop_back();
    expect_error(
        ctx,
        purify::accountable::AnchorEscrowRecord::deserialize(
            malformed, secp.get()),
        purify::ErrorCode::InvalidFixedSize,
        "truncated escrow record rejects");
    malformed = *encoded;
    malformed.push_back(0);
    expect_error(
        ctx,
        purify::accountable::AnchorEscrowRecord::deserialize(
            malformed, secp.get()),
        purify::ErrorCode::InvalidFixedSize,
        "oversized escrow record rejects");
    malformed = *encoded;
    malformed[0] = 2;
    expect_error(
        ctx,
        purify::accountable::AnchorEscrowRecord::deserialize(
            malformed, secp.get()),
        purify::ErrorCode::UnsupportedSymbol,
        "same-size anchor record version 2 has no compatibility alias");
    malformed = *encoded;
    std::fill_n(malformed.begin() + 1, 64, 0xff);
    ctx.expect(!purify::accountable::AnchorEscrowRecord::deserialize(
                   malformed, secp.get()),
               "noncanonical ephemeral key rejects");
    malformed = *encoded;
    std::fill_n(malformed.begin() + 65, 32, 0xff);
    expect_error(
        ctx,
        purify::accountable::AnchorEscrowRecord::deserialize(
            malformed, secp.get()),
        purify::ErrorCode::RangeViolation,
        "noncanonical masked scalar rejects");
    malformed = *encoded;
    std::copy_n(malformed.begin() + 1, 64,
                malformed.begin() + 97);
    expect_error(
        ctx,
        purify::accountable::AnchorEscrowRecord::deserialize(
            malformed, secp.get()),
        purify::ErrorCode::BindingMismatch,
        "identical ephemeral keys reject");
    malformed = *encoded;
    std::fill_n(malformed.begin() + 193, 33, 0);
    expect_error(
        ctx,
        purify::accountable::AnchorEscrowRecord::deserialize(
            malformed, secp.get()),
        purify::ErrorCode::BackendRejectedInput,
        "invalid escrow A commitment rejects");
    malformed = *encoded;
    std::fill_n(malformed.begin() + 226, 33, 0);
    expect_error(
        ctx,
        purify::accountable::AnchorEscrowRecord::deserialize(
            malformed, secp.get()),
        purify::ErrorCode::BackendRejectedInput,
        "invalid escrow S commitment rejects");
    malformed = *encoded;
    std::fill_n(malformed.begin() + 259, 32, 0xff);
    expect_error(
        ctx,
        purify::accountable::AnchorEscrowRecord::deserialize(
            malformed, secp.get()),
        purify::ErrorCode::RangeViolation,
        "noncanonical escrow t2 rejects");
    malformed = *encoded;
    std::fill_n(malformed.begin() + 291, 32, 0xff);
    expect_error(
        ctx,
        purify::accountable::AnchorEscrowRecord::deserialize(
            malformed, secp.get()),
        purify::ErrorCode::BackendRejectedInput,
        "invalid public-commitment DLog nonce rejects");
    malformed = *encoded;
    std::fill_n(malformed.begin() + 323, 32, 0xff);
    expect_error(
        ctx,
        purify::accountable::AnchorEscrowRecord::deserialize(
            malformed, secp.get()),
        purify::ErrorCode::RangeViolation,
        "noncanonical public-commitment DLog response rejects");
    malformed = *encoded;
    std::fill_n(malformed.begin() + 323, 32, 0);
    expect_error(
        ctx,
        purify::accountable::AnchorEscrowRecord::deserialize(
            malformed, secp.get()),
        purify::ErrorCode::RangeViolation,
        "zero public-commitment DLog response rejects");
    malformed = *encoded;
    std::copy(other_punishment->public_key().xonly().begin(),
              other_punishment->public_key().xonly().end(),
              malformed.begin() + 291);
    auto changed_dlog_nonce =
        purify::accountable::AnchorEscrowRecord::deserialize(
            malformed, secp.get());
    expect_ok(ctx, changed_dlog_nonce,
              "changed finite DLog nonce remains canonical");
    if (!changed_dlog_nonce) return;
    expect_rejected(
        ctx,
        purify::accountable::verify_anchor_escrow(
            fixture->roster, anchor->public_key, punishment_key, context,
            *changed_dlog_nonce, secp.get()),
        "public-mode transcript binds the exact DLog nonce");
    malformed = *encoded;
    std::array<unsigned char, 32> dlog_response_bytes{};
    std::copy_n(malformed.begin() + 323, dlog_response_bytes.size(),
                dlog_response_bytes.begin());
    auto dlog_response = FieldElement::try_from_bytes32(
        dlog_response_bytes);
    expect_ok(ctx, dlog_response,
              "public-commitment DLog response is canonical");
    if (!dlog_response) return;
    dlog_response_bytes =
        (*dlog_response + FieldElement::one()).to_bytes_be();
    std::copy(dlog_response_bytes.begin(), dlog_response_bytes.end(),
              malformed.begin() + 323);
    auto changed_dlog_response =
        purify::accountable::AnchorEscrowRecord::deserialize(
            malformed, secp.get());
    expect_ok(ctx, changed_dlog_response,
              "changed finite DLog response remains canonical");
    if (!changed_dlog_response) return;
    expect_rejected(
        ctx,
        purify::accountable::verify_anchor_escrow(
            fixture->roster, anchor->public_key, punishment_key, context,
            *changed_dlog_response, secp.get()),
        "public-mode transcript binds the exact DLog response");
    malformed = *encoded;
    malformed[355] = 4;
    expect_error(
        ctx,
        purify::accountable::AnchorEscrowRecord::deserialize(
            malformed, secp.get()),
        purify::ErrorCode::RangeViolation,
        "noncanonical escrow round parity rejects");
    malformed = *encoded;
    std::copy_n(malformed.begin() + 226, 33,
                malformed.begin() + 193);
    auto changed_raw_record =
        purify::accountable::AnchorEscrowRecord::deserialize(
            malformed, secp.get());
    expect_ok(ctx, changed_raw_record,
              "changed finite escrow raw commitment reparses");
    if (!changed_raw_record) return;
    expect_rejected(
        ctx,
        purify::accountable::verify_anchor_escrow(
            fixture->roster, anchor->public_key, punishment_key, context,
            *changed_raw_record, secp.get()),
        "V4 anchor precommitment binds the exact raw commitment");
    malformed = *encoded;
    malformed[355] ^= 1;
    auto opaque_inner =
        purify::accountable::AnchorEscrowRecord::deserialize(
            malformed, secp.get());
    expect_ok(ctx, opaque_inner,
              "fixed codec accepts structurally opaque inner proof bytes");
    if (!opaque_inner) return;
    expect_rejected(
        ctx,
        purify::accountable::verify_anchor_escrow(
            fixture->roster, anchor->public_key, punishment_key, context,
            *opaque_inner, secp.get()),
        "cryptographic verification rejects changed inner proof bytes");

    std::cout
        << "anchor_escrow wire_bytes=" << encoded->size()
        << " ciphertext_bytes="
        << purify::accountable::AnchorEscrowCiphertext::kSerializedSize
        << " proof_payload_bytes="
        << purify::accountable::AnchorEscrowRecord::kProofPayloadSize
        << " prove_ms="
        << std::chrono::duration<double, std::milli>(proved - started).count()
        << " verify_ms="
        << std::chrono::duration<double, std::milli>(verified - proved).count()
        << '\n';
}

} // namespace

void run_anchor_escrow_tests(TestContext& ctx) {
    test_anchor_punishment_derivation(ctx);
    test_anchor_v3_hash_suite_mode(ctx);
    test_anchor_escrow(ctx);
}
