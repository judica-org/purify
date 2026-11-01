// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <algorithm>
#include <array>
#include <chrono>
#include <iostream>
#include <utility>

#include "purify.hpp"
#include "purify/puresign/anchor_escrow.hpp"
#include "purify/puresign/anchor_escrow_accumulation.hpp"
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
        const auto& setup_proof,
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
    return BoundRosterFixture{std::move(bound), signing_scalar};
}

void expect_rejected(TestContext& ctx, Result<bool> result,
                     const char* message) {
    ctx.expect(!result || !*result, message);
}

void test_anchor_escrow(TestContext& ctx) {
    auto secp = purify::make_secp_context();
    ctx.expect(secp != nullptr, "anchor escrow secp context creates");
    if (!secp) return;

    auto fixture = make_roster(0x51, 0xae, secp.get());
    expect_ok(ctx, fixture,
              "setup proof constructs a recovery-bound escrow roster");
    if (!fixture) return;
    auto minimum_secret = purify::SecretKey::from_packed(
        purify::UInt512::zero());
    expect_ok(ctx, minimum_secret,
              "minimum canonical anchor secret parses");
    if (!minimum_secret) return;
    auto anchor = purify::derive_key(std::move(*minimum_secret));
    expect_ok(ctx, anchor,
              "minimum canonical anchor recovery key derives");
    if (!anchor) return;
    std::array<unsigned char, 32> seed{};
    const AnchorEscrowContextDigest context =
        purify::TaggedHash("Purify/Test/AnchorEscrowContext/v1")
            .digest(purify::bytes_from_ascii(
                "anchor=alice/bond=7/purpose=slash/domain=3"));

    purify::bppp::ScalarBytes auxiliary_randomness{};
    const auto started = std::chrono::steady_clock::now();
    auto record =
        purify::accountable::create_anchor_escrow_with_aux_randomness(
            fixture->roster, *anchor, context, auxiliary_randomness,
            secp.get());
    const auto proved = std::chrono::steady_clock::now();
    expect_ok(ctx, record,
              "deterministic test seam proves exact anchor encryption");
    if (!record) return;
    ctx.expect(record->ciphertext().ephemeral_keys[0] !=
                   record->ciphertext().ephemeral_keys[1],
               "separate derivation tags give each pad a distinct key");
    auto accepted = purify::accountable::verify_anchor_escrow(
        fixture->roster, anchor->public_key, context, *record,
        secp.get());
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
        encoded->size() == 1265 &&
            encoded->size() ==
                purify::accountable::AnchorEscrowRecord::kSerializedSize,
        "anchor escrow is one version byte plus 192 and 1072 bytes");
    auto parsed = purify::accountable::AnchorEscrowRecord::deserialize(
        *encoded, secp.get());
    expect_ok(ctx, parsed, "canonical anchor escrow reparses");
    if (!parsed) return;
    auto reencoded = parsed->serialize(secp.get());
    ctx.expect(reencoded && *reencoded == *encoded,
               "anchor escrow encoding round-trips exactly");

    auto accumulator =
        purify::accountable::AnchorEscrowAccumulator::create(secp.get());
    expect_ok(ctx, accumulator,
              "anchor escrow fixed accumulation basis creates");
    if (!accumulator) return;
    ctx.expect(
        accumulator->basis().n_vec_len() ==
                purify::accountable::AnchorEscrowAccumulator::
                    kNormVectorLength &&
            accumulator->basis().l_vec_len() ==
                purify::accountable::AnchorEscrowAccumulator::
                    kNormVectorLength,
        "anchor escrow accumulation fixes both norm dimensions");
    auto prepared = accumulator->prepare(
        fixture->roster, anchor->public_key, context, *parsed,
        secp.get());
    expect_ok(ctx, prepared,
              "typed adapter prepares the exact anchor escrow statement");
    if (!prepared) return;
    auto reduction = purify::bppp::accumulation::prove_norm_reduction(
        accumulator->basis(), *prepared, secp.get());
    expect_ok(ctx, reduction,
              "anchor escrow coefficient opening proves");
    if (!reduction) return;
    auto pending = purify::bppp::accumulation::verify_norm_reduction(
        accumulator->basis(), *prepared, *reduction, secp.get());
    expect_ok(ctx, pending,
              "anchor escrow reduction yields a pending obligation");
    if (!pending) return;
    expect_ok(ctx, purify::bppp::accumulation::decide(
                       accumulator->basis(), *pending, secp.get()),
              "final MSM discharges the honest anchor escrow obligation");

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
        fixture->roster, extracted_scalar, anchor->public_key, context,
        *parsed, secp.get());
    expect_ok(ctx, recovered,
              "exposed coalition scalar verifies and decrypts the anchor");
    if (recovered) {
        ctx.expect(recovered->public_key == anchor->public_key &&
                       recovered->secret == anchor->secret,
                   "decryption returns the exact registered anchor key");
    }
    expect_error(
        ctx,
        purify::accountable::recover_escrowed_anchor(
            fixture->roster, extracted_scalar.negate(),
            anchor->public_key, context, *parsed, secp.get()),
        purify::ErrorCode::BindingMismatch,
        "an exposed scalar for the opposite coalition point cannot decrypt");

    auto changed_context = context;
    changed_context[0] ^= 1;
    expect_rejected(
        ctx,
        purify::accountable::verify_anchor_escrow(
            fixture->roster, anchor->public_key, changed_context,
            *record, secp.get()),
        "escrow proof cannot move to another application context");
    auto changed_context_prepared = accumulator->prepare(
        fixture->roster, anchor->public_key, changed_context, *record,
        secp.get());
    expect_ok(ctx, changed_context_prepared,
              "changed context remains a pending public obligation");
    if (!changed_context_prepared) return;
    ctx.expect(changed_context_prepared->transcript_digest() !=
                   prepared->transcript_digest(),
               "typed adapter binds the exact escrow context");
    auto changed_context_claim =
        purify::bppp::accumulation::verify_norm_reduction(
            accumulator->basis(), *changed_context_prepared, *reduction,
            secp.get());
    ctx.expect(!changed_context_claim,
               "anchor reduction cannot move to another context");
    expect_error(
        ctx,
        purify::accountable::recover_escrowed_anchor(
            fixture->roster, fixture->signing_scalar,
            anchor->public_key, changed_context, *record, secp.get()),
        purify::ErrorCode::EquationMismatch,
        "recovery exposes no plaintext for an invalid context");

    seed.fill(0x48);
    auto other_anchor = purify::generate_key(seed);
    expect_ok(ctx, other_anchor, "substitution anchor fixture generates");
    if (!other_anchor) return;
    expect_rejected(
        ctx,
        purify::accountable::verify_anchor_escrow(
            fixture->roster, other_anchor->public_key, context,
            *record, secp.get()),
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
            fixture->roster, mismatched_anchor, context, secp.get()),
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
            fixture->roster, anchor->public_key, context,
            *changed_record, secp.get()),
        "escrow proof cannot move to another ciphertext");
    auto changed_ciphertext_prepared = accumulator->prepare(
        fixture->roster, anchor->public_key, context, *changed_record,
        secp.get());
    expect_ok(ctx, changed_ciphertext_prepared,
              "changed ciphertext remains a pending public obligation");
    if (!changed_ciphertext_prepared) return;
    ctx.expect(changed_ciphertext_prepared->transcript_digest() !=
                   prepared->transcript_digest(),
               "typed adapter binds the exact escrow ciphertext");
    auto changed_ciphertext_claim =
        purify::bppp::accumulation::verify_norm_reduction(
            accumulator->basis(), *changed_ciphertext_prepared, *reduction,
            secp.get());
    ctx.expect(!changed_ciphertext_claim,
               "anchor reduction cannot move to another ciphertext");

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
        fixture->roster, anchor->public_key, context,
        *changed_inner_record, secp.get());
    expect_ok(ctx, changed_inner_prepared,
              "parseable false inner proof remains pending");
    if (!changed_inner_prepared) return;
    ctx.expect(changed_inner_prepared->transcript_digest() !=
                   prepared->transcript_digest(),
               "typed adapter authenticates the exact inner proof");
    auto changed_inner_reduction =
        purify::bppp::accumulation::prove_norm_reduction(
            accumulator->basis(), *changed_inner_prepared, secp.get());
    expect_ok(ctx, changed_inner_reduction,
              "false inner proof has a public coefficient opening");
    if (!changed_inner_reduction) return;
    auto changed_inner_claim =
        purify::bppp::accumulation::verify_norm_reduction(
            accumulator->basis(), *changed_inner_prepared,
            *changed_inner_reduction, secp.get());
    expect_ok(ctx, changed_inner_claim,
              "short verifier keeps a false inner proof pending");
    if (!changed_inner_claim) return;
    ctx.expect(!purify::bppp::accumulation::decide(
                   accumulator->basis(), *changed_inner_claim, secp.get()),
               "final MSM rejects the changed inner proof");

    changed_record_bytes = *encoded;
    changed_record_bytes[291] ^= 1;
    changed_record = purify::accountable::AnchorEscrowRecord::deserialize(
        changed_record_bytes, secp.get());
    expect_ok(ctx, changed_record,
              "changed inner proof remains structurally canonical");
    if (!changed_record) return;
    expect_rejected(
        ctx,
        purify::accountable::verify_anchor_escrow(
            fixture->roster, anchor->public_key, context,
            *changed_record, secp.get()),
        "changed escrow proof rejects");

    auto other_fixture = make_roster(0x62, 0x9d, secp.get());
    expect_ok(ctx, other_fixture,
              "second setup statement constructs a bound roster");
    if (!other_fixture) return;
    expect_rejected(
        ctx,
        purify::accountable::verify_anchor_escrow(
            other_fixture->roster, anchor->public_key, context,
            *record, secp.get()),
        "escrow proof binds the exact coalition core and roster");
    auto other_nonce_hosts = make_roster(0x51, 0xaf, secp.get());
    expect_ok(ctx, other_nonce_hosts,
              "alternate nonce-host setup constructs a bound roster");
    if (!other_nonce_hosts) return;
    expect_rejected(
        ctx,
        purify::accountable::verify_anchor_escrow(
            other_nonce_hosts->roster, anchor->public_key, context,
            *record, secp.get()),
        "escrow proof binds the setup-registered nonce host commitment");

    auto repeated_record =
        purify::accountable::create_anchor_escrow_with_aux_randomness(
            fixture->roster, *anchor, context, auxiliary_randomness,
            secp.get());
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
            fixture->roster, *anchor, context, changed_auxiliary,
            secp.get());
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
        fixture->roster, anchor->public_key, context, *changed_aux_record,
        secp.get());
    ctx.expect(accepted && *accepted,
               "changed-auxiliary escrow still verifies");

    auto changed_context_record =
        purify::accountable::create_anchor_escrow_with_aux_randomness(
            fixture->roster, *anchor, changed_context,
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
        fixture->roster, anchor->public_key, changed_context,
        *changed_context_record, secp.get());
    ctx.expect(accepted && *accepted,
               "changed-context escrow verifies for its own statement");

    auto production_record = purify::accountable::create_anchor_escrow(
        fixture->roster, *anchor, context, secp.get());
    expect_ok(ctx, production_record,
              "production escrow samples operating-system auxiliary input");
    if (!production_record) return;
    accepted = purify::accountable::verify_anchor_escrow(
        fixture->roster, anchor->public_key, context, *production_record,
        secp.get());
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
    auto maximum_context = context;
    maximum_context.back() ^= 1;
    auto maximum_record =
        purify::accountable::create_anchor_escrow_with_aux_randomness(
            fixture->roster, *maximum_anchor, maximum_context,
            auxiliary_randomness, secp.get());
    expect_ok(ctx, maximum_record,
              "maximum canonical anchor encrypts");
    if (!maximum_record) return;
    auto maximum_recovered = purify::accountable::recover_escrowed_anchor(
        fixture->roster, fixture->signing_scalar,
        maximum_anchor->public_key, maximum_context, *maximum_record,
        secp.get());
    expect_ok(ctx, maximum_recovered,
              "maximum canonical anchor decrypts exactly");
    if (maximum_recovered) {
        ctx.expect(maximum_recovered->secret == maximum_anchor->secret,
                   "maximum plaintext survives the escrow circuit");
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
    malformed[0] ^= 1;
    expect_error(
        ctx,
        purify::accountable::AnchorEscrowRecord::deserialize(
            malformed, secp.get()),
        purify::ErrorCode::UnsupportedSymbol,
        "unknown escrow record version rejects");
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
        purify::ErrorCode::RangeViolation,
        "invalid escrow A commitment rejects");
    malformed = *encoded;
    std::fill_n(malformed.begin() + 226, 33, 0);
    expect_error(
        ctx,
        purify::accountable::AnchorEscrowRecord::deserialize(
            malformed, secp.get()),
        purify::ErrorCode::RangeViolation,
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
    malformed[291] ^= 1;
    auto opaque_inner =
        purify::accountable::AnchorEscrowRecord::deserialize(
            malformed, secp.get());
    expect_ok(ctx, opaque_inner,
              "fixed codec accepts structurally opaque inner proof bytes");
    if (!opaque_inner) return;
    expect_rejected(
        ctx,
        purify::accountable::verify_anchor_escrow(
            fixture->roster, anchor->public_key, context,
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
    test_anchor_escrow(ctx);
}
