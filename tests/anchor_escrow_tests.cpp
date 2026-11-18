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

void test_anchor_punishment_key(TestContext& ctx) {
    auto secp = purify::make_secp_context();
    ctx.expect(secp != nullptr,
               "anchor punishment secp context creates");
    if (!secp) return;
    std::array<unsigned char, 32> zero_secret{};
    expect_error(
        ctx,
        purify::accountable::AnchorPunishmentKey::from_secret(
            zero_secret, secp.get()),
        purify::ErrorCode::RangeViolation,
        "zero punishment secret rejects");
    auto raw_secret = FieldElement::from_u64(8).to_bytes_be();
    expect_error(
        ctx,
        purify::accountable::AnchorPunishmentKey::from_secret(
            raw_secret, nullptr),
        purify::ErrorCode::MissingValue,
        "punishment secret parsing requires a secp context");
    auto expected_secret = raw_secret;
    std::array<unsigned char, 32> expected_xonly{};
    ctx.expect(purify_bip340_key_from_seckey(
                   secp.get(), expected_secret.data(),
                   expected_xonly.data()) != 0,
               "punishment secret test vector normalizes");
    auto parsed_secret =
        purify::accountable::AnchorPunishmentKey::from_secret(
            raw_secret, secp.get());
    expect_ok(ctx, parsed_secret,
              "punishment secret parses to a typed key");
    if (!parsed_secret) return;
    ctx.expect(parsed_secret->bip340_key().seckey == expected_secret &&
                   parsed_secret->public_key().xonly() == expected_xonly,
               "typed punishment key uses the even-Y representative");

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
    auto parsed_public =
        purify::accountable::AnchorPunishmentPublicKey::create(
            parsed_secret->public_key().xonly(), secp.get());
    expect_ok(ctx, parsed_public,
              "typed punishment public key reparses");
    if (!parsed_public) return;
    ctx.expect(*parsed_public == parsed_secret->public_key(),
               "punishment public key has one canonical x-only form");

    auto odd_secret = FieldElement::from_u64(6).to_bytes_be();
    auto normalized_secret = odd_secret;
    std::array<unsigned char, 32> normalized_xonly{};
    ctx.expect(purify_bip340_key_from_seckey(
                   secp.get(), normalized_secret.data(),
                   normalized_xonly.data()) != 0,
               "odd-Y punishment fixture normalizes");
    auto normalized =
        purify::accountable::AnchorPunishmentKey::from_secret(
            odd_secret, secp.get());
    expect_ok(ctx, normalized,
              "odd-Y punishment secret constructs");
    if (!normalized) return;
    ctx.expect(normalized->bip340_key().seckey == normalized_secret &&
                   normalized->public_key().xonly() == normalized_xonly,
               "punishment factory stores only the even-Y representative");
}

void test_anchor_v4_hash_suite_mode(TestContext& ctx) {
#if PURIFY_USE_LEGACY_FIELD_HASHES
    auto secp = purify::make_secp_context();
    ctx.expect(secp != nullptr,
               "anchor v4 suite-mode secp context creates");
    if (!secp) return;
    auto anchor_secret = purify::SecretKey::from_packed(
        purify::UInt512::from_u64(8));
    expect_ok(ctx, anchor_secret,
               "anchor v4 suite-mode secret parses");
    if (!anchor_secret) return;
    auto anchor = purify::derive_key(std::move(*anchor_secret));
    expect_ok(ctx, anchor,
               "anchor v4 suite-mode key derives");
    if (!anchor) return;
    expect_error(
        ctx,
        purify::accountable::anchor_escrow_circuit_shape_for_testing(
            anchor->public_key, {}),
        purify::ErrorCode::UnsupportedSymbol,
        "anchor v4 circuit construction rejects legacy field hashes");
    auto accumulator =
        purify::accountable::ConstructionLeafAccumulator::create(secp.get());
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
              "anchor recovery root fixture derives");
    if (!anchor) return;
    auto punishment =
        purify::accountable::AnchorPunishmentKey::from_secret(
            FieldElement::from_u64(31).to_bytes_be(), secp.get());
    expect_ok(ctx, punishment,
              "anchor punishment key constructs independently");
    if (!punishment) return;
    const auto punishment_key = punishment->public_key();
    ctx.expect(
        punishment->bip340_key().seckey !=
            FieldElement::from_u64(8).to_bytes_be(),
        "anchor root and punishment key use distinct secret material");
#if PURIFY_USE_LEGACY_FIELD_HASHES
    const AnchorEscrowContextDigest legacy_context{};
    const purify::bppp::ScalarBytes legacy_auxiliary_randomness{};
    expect_error(
        ctx,
        purify::accountable::create_anchor_escrow(
            fixture->roster, anchor->public_key, *punishment,
            legacy_context, secp.get()),
        purify::ErrorCode::UnsupportedSymbol,
        "anchor v4 creation rejects the legacy field-hash suite");
    expect_error(
        ctx,
        purify::accountable::create_anchor_escrow_with_aux_randomness(
            fixture->roster, anchor->public_key, *punishment,
            legacy_context, legacy_auxiliary_randomness, secp.get()),
        purify::ErrorCode::UnsupportedSymbol,
        "deterministic anchor v4 creation rejects legacy field hashes");
    auto legacy_construction_accumulator = purify::accountable::
        ConstructionReceiptAccumulator::create(secp.get());
    expect_ok(ctx, legacy_construction_accumulator,
              "legacy builds retain non-accepting envelope basis syntax");
    return;
#endif
    std::array<unsigned char, 32> seed{};
    const AnchorEscrowContextDigest context =
        purify::TaggedHash("Purify/Test/AnchorEscrowContext/v1")
            .digest(purify::bytes_from_ascii(
                "anchor=alice/bond=7/purpose=slash/domain=3"));

    purify::bppp::ScalarBytes auxiliary_randomness{};
    expect_error(
        ctx,
        purify::accountable::create_anchor_escrow_with_aux_randomness(
            fixture->roster, fixture->roster.recovery_root(),
            *punishment, context, auxiliary_randomness, secp.get()),
        purify::ErrorCode::BindingMismatch,
        "anchor escrow rejects the coalition recovery root as an anchor");
    const auto started = std::chrono::steady_clock::now();
    auto record =
        purify::accountable::create_anchor_escrow_with_aux_randomness(
            fixture->roster, anchor->public_key, *punishment, context,
            auxiliary_randomness, secp.get());
    const auto proved = std::chrono::steady_clock::now();
    expect_ok(ctx, record,
              "deterministic test seam proves exact anchor encryption");
    if (!record) return;
    auto circuit_shape =
        purify::accountable::anchor_escrow_circuit_shape_for_testing(
            fixture->roster.recovery_root(), record->ciphertext());
    expect_ok(ctx, circuit_shape,
              "scalar-only punishment circuit shape derives");
    if (!circuit_shape) return;
    ctx.expect(circuit_shape->relation_multiplications == 2030 &&
                   circuit_shape->padded_gates == 8192,
               "scalar-only relation has 2030 multiplications in 8192 gates");
    auto accepted = purify::accountable::verify_anchor_escrow(
        fixture->roster, anchor->public_key, punishment_key, context,
        *record, secp.get());
    const auto verified = std::chrono::steady_clock::now();
    ctx.expect(accepted && *accepted,
               "exact recovery-bound escrow statement verifies");
    expect_error(
        ctx,
        purify::accountable::verify_anchor_escrow(
            fixture->roster, fixture->roster.recovery_root(),
            punishment_key, context, *record, secp.get()),
        purify::ErrorCode::BindingMismatch,
        "verification rejects a recovery-root alias for the anchor");

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
        encoded->size() == 1233 &&
            encoded->size() ==
                purify::accountable::AnchorEscrowRecord::kSerializedSize &&
            encoded->front() == 4,
        "anchor escrow is one version byte plus 96 and 1136 bytes");
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
    const auto* accumulator = &construction_accumulator->leaves();
    ctx.expect(
        accumulator->basis().n_vec_len() ==
                purify::accountable::ConstructionLeafAccumulator::
                    kNormVectorLength &&
            accumulator->basis().l_vec_len() ==
                purify::accountable::ConstructionLeafAccumulator::
                    kNormVectorLength,
        "anchor escrow accumulation fixes both norm dimensions");
    purify::bppp::ExperimentalCircuitCache parent_cache;
    auto prepared = accumulator->prepare(
        fixture->roster, anchor->public_key, punishment_key, context,
        *parsed, secp.get(), &parent_cache);
    expect_ok(ctx, prepared,
              "typed adapter prepares the exact anchor escrow statement");
    if (!prepared) return;
    expect_error(
        ctx,
        accumulator->prepare(
            fixture->roster, fixture->roster.recovery_root(),
            punishment_key, context, *parsed, secp.get()),
        purify::ErrorCode::BindingMismatch,
        "parent preparation rejects a recovery-root alias for the anchor");
    ctx.expect(
        std::any_of(prepared->circuit_precommitment().begin(),
                    prepared->circuit_precommitment().end(),
                    [](unsigned char byte) { return byte != 0; }),
        "prepared anchor exposes its nonzero V4 precommitment");
    auto parent_constants = accumulator->derive_parent_constants(
        fixture->roster, anchor->public_key, punishment_key, context,
        parsed->ciphertext(), prepared->circuit_precommitment(),
        secp.get());
    expect_ok(ctx, parent_constants,
              "anchor parent constants derive from public payload data");
    if (!parent_constants) return;
    expect_error(
        ctx,
        accumulator->derive_parent_constants(
            fixture->roster, fixture->roster.recovery_root(),
            punishment_key, context, parsed->ciphertext(),
            prepared->circuit_precommitment(), secp.get()),
        purify::ErrorCode::BindingMismatch,
        "parent constants reject a recovery-root alias for the anchor");
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
        prepared->circuit_precommitment(), secp.get());
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
    auto reduction =
        purify::bppp::accumulation::prove_algebraic_norm_reduction(
            accumulator->basis(), prepared->norm(), secp.get());
    expect_ok(ctx, reduction,
              "anchor escrow coefficient opening proves");
    if (!reduction) return;
    auto pending =
        purify::bppp::accumulation::verify_algebraic_norm_reduction(
            accumulator->basis(), prepared->norm(), *reduction,
            secp.get());
    expect_ok(ctx, pending,
              "exact anchor reduction yields a pending obligation");
    if (!pending) return;
    expect_ok(ctx, purify::bppp::accumulation::decide(
                       accumulator->basis(), *pending, secp.get()),
              "final MSM discharges the honest anchor escrow obligation");

    std::array<unsigned char,
               purify::accountable::ConstructionReceiptAccumulator::
                   kRootClaimSerializedSize>
        empty_root_bytes{};
    auto empty_root = purify::bppp::accumulation::parse_root_claim(
        accumulator->basis(), empty_root_bytes, secp.get());
    expect_ok(ctx, empty_root,
              "canonical empty construction root parses");
    if (!empty_root) return;
    auto encoded_empty_root =
        purify::bppp::accumulation::serialize_root_claim(
            accumulator->basis(), *empty_root, secp.get());
    ctx.expect(
        encoded_empty_root &&
            std::equal(encoded_empty_root->begin(),
                       encoded_empty_root->end(),
                       empty_root_bytes.begin(), empty_root_bytes.end()),
        "canonical empty construction root round-trips exactly");
    expect_ok(ctx, purify::bppp::accumulation::decide(
                       accumulator->basis(), *empty_root, secp.get()),
              "canonical empty construction root decides");

    const std::array first_claims{*empty_root, *pending};
    auto first_step = purify::bppp::accumulation::prove_algebraic_step(
        accumulator->basis(), first_claims, secp.get());
    expect_ok(ctx, first_step,
              "first construction step folds the empty root and one leaf");
    if (!first_step) return;
    auto first_root = purify::bppp::accumulation::verify_algebraic_step(
        accumulator->basis(), first_claims, *first_step, secp.get());
    expect_ok(ctx, first_root,
              "first construction step returns a pending root");
    if (!first_root) return;
    expect_ok(ctx, purify::bppp::accumulation::decide(
                       accumulator->basis(), *first_root, secp.get()),
              "first construction root reaches final decision");

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

    auto recipient = purify::accountable::recover_registered_root(
        fixture->roster, extracted_scalar, secp.get());
    expect_ok(ctx, recipient,
              "registered recovery recipient reconstructs");
    if (!recipient) return;
    auto punishment_scalar = FieldElement::try_from_bytes32(
        punishment->bip340_key().seckey);
    expect_ok(ctx, punishment_scalar,
              "normalized punishment scalar reparses");
    if (!punishment_scalar) return;
    auto odd_plaintext = parsed->ciphertext();
    odd_plaintext.masked_scalar =
        odd_plaintext.masked_scalar - *punishment_scalar -
        *punishment_scalar;
    expect_error(
        ctx,
        purify::accountable::recover_authenticated_anchor_ciphertext(
            *recipient, punishment_key, odd_plaintext, secp.get()),
        purify::ErrorCode::BindingMismatch,
        "recovery rejects the odd-Y representative before key matching");

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
        purify::accountable::AnchorPunishmentKey::from_secret(
            FieldElement::from_u64(9).to_bytes_be(), secp.get());
    expect_ok(ctx, other_punishment,
              "substitution punishment key constructs");
    if (!other_punishment) return;
    expect_rejected(
        ctx,
        purify::accountable::verify_anchor_escrow(
            fixture->roster, anchor->public_key,
            other_punishment->public_key(), context, *record,
            secp.get()),
        "public-mode proof cannot move to another punishment key");
    expect_rejected(
        ctx,
        purify::accountable::verify_anchor_escrow(
            fixture->roster, other_anchor->public_key, punishment_key,
            context, *record, secp.get()),
        "escrow proof cannot advertise another anchor root");
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

    auto other_fixture = make_roster(0x62, 0x9d, secp.get());
    expect_ok(ctx, other_fixture,
              "second setup statement constructs a bound roster");
    if (!other_fixture) return;
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
            fixture->roster, anchor->public_key, *punishment, context,
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
            fixture->roster, anchor->public_key, *punishment, context,
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
            fixture->roster, anchor->public_key, *punishment,
            changed_context,
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
        fixture->roster, anchor->public_key, *punishment, context,
        secp.get());
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
        purify::accountable::AnchorPunishmentKey::from_secret(
            FieldElement::one().negate().to_bytes_be(), secp.get());
    expect_ok(ctx, maximum_punishment,
              "high punishment scalar normalizes");
    if (!maximum_punishment) return;
    auto maximum_context = context;
    maximum_context.back() ^= 1;
    auto maximum_record =
        purify::accountable::create_anchor_escrow_with_aux_randomness(
            fixture->roster, maximum_anchor->public_key,
            *maximum_punishment, maximum_context,
            auxiliary_randomness, secp.get());
    expect_ok(ctx, maximum_record,
              "high punishment scalar encrypts");
    if (!maximum_record) return;
    auto maximum_recovered = purify::accountable::recover_escrowed_anchor(
        fixture->roster, fixture->signing_scalar,
        maximum_anchor->public_key, maximum_punishment->public_key(),
        maximum_context, *maximum_record, secp.get());
    expect_ok(ctx, maximum_recovered,
              "high punishment scalar decrypts exactly");
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
    malformed[0] = 3;
    expect_error(
        ctx,
        purify::accountable::AnchorEscrowRecord::deserialize(
            malformed, secp.get()),
        purify::ErrorCode::UnsupportedSymbol,
        "anchor record version 3 has no compatibility alias");
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
    std::fill_n(malformed.begin() + 97, 33, 0);
    expect_error(
        ctx,
        purify::accountable::AnchorEscrowRecord::deserialize(
            malformed, secp.get()),
        purify::ErrorCode::BackendRejectedInput,
        "invalid escrow A commitment rejects");
    malformed = *encoded;
    std::fill_n(malformed.begin() + 130, 33, 0);
    expect_error(
        ctx,
        purify::accountable::AnchorEscrowRecord::deserialize(
            malformed, secp.get()),
        purify::ErrorCode::BackendRejectedInput,
        "invalid escrow S commitment rejects");
    malformed = *encoded;
    std::fill_n(malformed.begin() + 163, 32, 0xff);
    expect_error(
        ctx,
        purify::accountable::AnchorEscrowRecord::deserialize(
            malformed, secp.get()),
        purify::ErrorCode::RangeViolation,
        "noncanonical escrow t2 rejects");
    malformed = *encoded;
    std::fill_n(malformed.begin() + 195, 32, 0xff);
    expect_error(
        ctx,
        purify::accountable::AnchorEscrowRecord::deserialize(
            malformed, secp.get()),
        purify::ErrorCode::BackendRejectedInput,
        "invalid public-commitment DLog nonce rejects");
    malformed = *encoded;
    std::fill_n(malformed.begin() + 227, 32, 0xff);
    expect_error(
        ctx,
        purify::accountable::AnchorEscrowRecord::deserialize(
            malformed, secp.get()),
        purify::ErrorCode::RangeViolation,
        "noncanonical public-commitment DLog response rejects");
    malformed = *encoded;
    std::fill_n(malformed.begin() + 227, 32, 0);
    expect_error(
        ctx,
        purify::accountable::AnchorEscrowRecord::deserialize(
            malformed, secp.get()),
        purify::ErrorCode::RangeViolation,
        "zero public-commitment DLog response rejects");
    malformed = *encoded;
    std::copy(other_punishment->public_key().xonly().begin(),
              other_punishment->public_key().xonly().end(),
              malformed.begin() + 195);
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
    std::copy_n(malformed.begin() + 227, dlog_response_bytes.size(),
                dlog_response_bytes.begin());
    auto dlog_response = FieldElement::try_from_bytes32(
        dlog_response_bytes);
    expect_ok(ctx, dlog_response,
              "public-commitment DLog response is canonical");
    if (!dlog_response) return;
    dlog_response_bytes =
        (*dlog_response + FieldElement::one()).to_bytes_be();
    std::copy(dlog_response_bytes.begin(), dlog_response_bytes.end(),
              malformed.begin() + 227);
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
    malformed[259] = 4;
    expect_error(
        ctx,
        purify::accountable::AnchorEscrowRecord::deserialize(
            malformed, secp.get()),
        purify::ErrorCode::RangeViolation,
        "noncanonical escrow round parity rejects");
    malformed = *encoded;
    std::copy_n(malformed.begin() + 130, 33,
                malformed.begin() + 97);
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
    malformed[259] ^= 1;
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
    test_anchor_punishment_key(ctx);
    test_anchor_v4_hash_suite_mode(ctx);
    test_anchor_escrow(ctx);
}
