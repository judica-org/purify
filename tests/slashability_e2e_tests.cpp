// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <algorithm>
#include <array>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <system_error>
#include <vector>

#include "canonical_recovery_root_helpers.hpp"
#include "companion_scalar_escrow_helpers.hpp"
#include "purify_test_helpers.hpp"
#include "slashability_e2e_fixture.hpp"

namespace {

using purify_test::TestContext;
using purify_test::expect_error;
using purify_test::expect_ok;
using purify_test::slashability::make_all_evil_coalition;
using purify_test::slashability::make_native_accumulation_reference;
using purify_test::slashability::expose_conflicting_coalition_key;
using purify_test::slashability::serialize_parent_prover_fixture;

#if defined(PURIFY_HAS_CONSTRUCTION_PARENT_VERIFIER)
#if !defined(PURIFY_TEST_CONSTRUCTION_PARENT_PROOF_PATH)
#error "receipt-cycle tests require the qualified parent proof path"
#endif
#if !defined(PURIFY_TEST_CONSTRUCTION_PARENT_NONDECIDING_PROOF_PATH)
#error "receipt-cycle tests require the nondeciding parent proof path"
#endif

std::optional<purify::Bytes> load_parent_proof(
    TestContext& ctx, const char* path) {
    constexpr std::size_t kProofSize =
        purify::accountable::ConstructionReceiptEnvelope::
            kParentProofSize;
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    ctx.expect(input.is_open(), "construction parent proof opens");
    if (!input.is_open()) return std::nullopt;
    const auto size = input.tellg();
    ctx.expect(size == static_cast<std::streamoff>(kProofSize),
               "construction parent proof has exact size");
    if (size != static_cast<std::streamoff>(kProofSize)) {
        return std::nullopt;
    }
    input.seekg(0, std::ios::beg);
    purify::Bytes proof(kProofSize);
    input.read(reinterpret_cast<char*>(proof.data()),
               static_cast<std::streamsize>(proof.size()));
    ctx.expect(input.good(),
               "construction parent proof reads completely");
    if (!input.good()) return std::nullopt;
    return proof;
}

std::optional<
    purify::accountable::ConstructionReceiptStatementDigest>
accept_construction_parent_if_requested(
    TestContext& ctx,
    const purify_test::slashability::
        NativeAccumulationReferenceFixture& construction,
    purify_secp_context* secp_context) {
    const char* artifact_path = std::getenv(
        "PURIFY_CONSTRUCTION_PARENT_VERIFIER_ARTIFACT");
    if (artifact_path == nullptr) return construction.statement;
    ctx.expect(artifact_path[0] != '\0',
               "construction parent artifact path is nonempty");
    if (artifact_path[0] == '\0') return std::nullopt;

    auto proof = load_parent_proof(
        ctx, PURIFY_TEST_CONSTRUCTION_PARENT_PROOF_PATH);
    if (!proof) return std::nullopt;
    auto envelope =
        purify::accountable::ConstructionReceiptEnvelope::create(
            construction.payload, *proof);
    expect_ok(ctx, envelope,
              "qualified construction parent envelope constructs");
    if (!envelope) return std::nullopt;
    auto verifier =
        purify::accountable::ConstructionParentVerifier::load(
            artifact_path);
    expect_ok(ctx, verifier,
              "qualified construction parent verifier loads");
    if (!verifier) return std::nullopt;
    auto accepted = verifier->verify(
        construction.setup, *envelope,
        construction.resolved_entries, construction.accumulator,
        secp_context);
    expect_ok(ctx, accepted,
              "two-anchor construction parent proof accepts");
    if (!accepted) return std::nullopt;
    ctx.expect(
        accepted->statement_digest() == construction.statement &&
            accepted->anchor_count() == construction.anchors.size(),
        "accepted construction binds the exact statement and count");

    auto corrupted_proof = *proof;
    corrupted_proof[corrupted_proof.size() / 2] ^= 1U;
    auto corrupted_envelope =
        purify::accountable::ConstructionReceiptEnvelope::create(
            construction.payload, std::move(corrupted_proof));
    expect_ok(ctx, corrupted_envelope,
              "corrupted parent envelope remains canonical transport");
    if (!corrupted_envelope) return std::nullopt;
    expect_error(
        ctx,
        verifier->verify(
            construction.setup, *corrupted_envelope,
            construction.resolved_entries, construction.accumulator,
            secp_context),
        purify::ErrorCode::BackendRejectedInput,
        "changed construction parent proof is rejected");

    auto changed_reference = construction.resolved_entries;
    changed_reference[0].anchor_reference[0] ^= 1U;
    expect_error(
        ctx,
        verifier->verify(
            construction.setup, *envelope, changed_reference,
            construction.accumulator, secp_context),
        purify::ErrorCode::BackendRejectedInput,
        "construction parent proof cannot rebind an anchor reference");

    std::vector<purify::accountable::ConstructionReceiptEntry>
        reordered_entries(
            construction.payload.entries().begin(),
            construction.payload.entries().end());
    std::swap(reordered_entries[0], reordered_entries[1]);
    auto reordered_payload =
        purify::accountable::ConstructionReceiptPayload::create(
            construction.payload.recovery_root(),
            std::move(reordered_entries));
    expect_ok(ctx, reordered_payload,
              "reordered construction payload constructs");
    if (!reordered_payload) return std::nullopt;
    auto reordered_envelope =
        purify::accountable::ConstructionReceiptEnvelope::create(
            std::move(*reordered_payload), *proof);
    expect_ok(ctx, reordered_envelope,
              "reordered construction parent envelope constructs");
    if (!reordered_envelope) return std::nullopt;
    auto reordered_resolved = construction.resolved_entries;
    std::swap(reordered_resolved[0], reordered_resolved[1]);
    expect_error(
        ctx,
        verifier->verify(
            construction.setup, *reordered_envelope,
            reordered_resolved, construction.accumulator,
            secp_context),
        purify::ErrorCode::BackendRejectedInput,
        "construction parent proof binds ordered anchors");

    auto nondeciding_proof = load_parent_proof(
        ctx,
        PURIFY_TEST_CONSTRUCTION_PARENT_NONDECIDING_PROOF_PATH);
    if (!nondeciding_proof) return std::nullopt;
    auto nondeciding_envelope =
        purify::accountable::ConstructionReceiptEnvelope::create(
            construction.payload, std::move(*nondeciding_proof));
    expect_ok(ctx, nondeciding_envelope,
              "nondeciding parent envelope remains canonical");
    if (!nondeciding_envelope) return std::nullopt;
    expect_error(
        ctx,
        verifier->verify(
            construction.setup, *nondeciding_envelope,
            construction.resolved_entries, construction.accumulator,
            secp_context),
        purify::ErrorCode::EquationMismatch,
        "recursive-valid nondeciding parent root is rejected");

    return accepted->statement_digest();
}
#endif

void write_parent_prover_fixture_if_requested(
    TestContext& ctx, const purify::Bytes& fixture,
    const char* environment_name) {
    const char* output_path = std::getenv(environment_name);
    if (output_path == nullptr) return;
    if (output_path[0] == '\0') {
        ctx.expect(false, "parent prover fixture output path is nonempty");
        return;
    }
    std::error_code filesystem_error;
    const bool exists =
        std::filesystem::exists(output_path, filesystem_error);
    if (filesystem_error || exists) {
        ctx.expect(false, "parent prover fixture output path is new");
        return;
    }
    std::ofstream output(
        output_path, std::ios::binary | std::ios::out);
    output.write(
        reinterpret_cast<const char*>(fixture.data()),
        static_cast<std::streamsize>(fixture.size()));
    output.flush();
    ctx.expect(output.good(), "parent prover fixture writes completely");
}

void test_hidden_second_generator_rejects(
    TestContext& ctx,
    const purify_test::slashability::CoalitionFixture& coalition,
    purify_secp_context* secp_context) {
    auto honest_root = purify::accountable::derive_recovery_root(
        coalition.signing_scalar);
    expect_ok(ctx, honest_root,
              "canonical coalition recovery root derives");
    if (!honest_root) return;
    auto scalars = purify::unpack_secret(honest_root->secret.packed());
    expect_ok(ctx, scalars,
              "canonical recovery root exposes both test scalars");
    if (!scalars) return;
    auto changed_second = scalars->second;
    if (changed_second < purify::half_n2()) {
        changed_second.add_assign(purify::UInt256::one());
    } else {
        changed_second.sub_assign(purify::UInt256::one());
    }
    auto rogue_root = purify_test::scalar_escrow::key_from_pair(
        scalars->first, changed_second);
    expect_ok(ctx, rogue_root,
              "rogue hidden-component recovery root constructs");
    if (!rogue_root) return;
    auto honest_public = purify::unpack_public(
        honest_root->public_key);
    auto rogue_public = purify::unpack_public(
        rogue_root->public_key);
    expect_ok(ctx, honest_public,
              "canonical root public components unpack");
    expect_ok(ctx, rogue_public,
              "rogue root public components unpack");
    if (!honest_public || !rogue_public) return;
    ctx.expect(
        honest_public->first == rogue_public->first &&
            honest_public->second != rogue_public->second,
        "rogue root preserves only the first generator component");

    auto rogue_circuit =
        purify_test::canonical_root::public_setup_circuit(
            rogue_root->public_key);
    auto rogue_assignment =
        purify_test::canonical_root::setup_assignment(
            rogue_root->public_key, coalition.signing_scalar);
    expect_ok(ctx, rogue_circuit,
              "rogue recovery-root relation constructs");
    expect_ok(ctx, rogue_assignment,
              "rogue recovery-root witness materializes");
    if (!rogue_circuit || !rogue_assignment) return;
    ctx.expect(
        !rogue_circuit->evaluate(*rogue_assignment),
        "hidden second component violates the setup circuit");

    expect_error(
        ctx,
        purify::accountable::prove_recovery_root_setup(
            coalition.registry_roster, rogue_root->public_key,
            coalition.signing_scalar, secp_context),
        purify::ErrorCode::BindingMismatch,
        "known aggregate key cannot prove a hidden root component");
    ctx.expect(
        !purify::accountable::verify_recovery_root_setup(
            coalition.registry_roster, rogue_root->public_key,
            coalition.setup_proof, secp_context),
        "honest setup proof cannot be rebound to a rogue component");
    auto recovered = purify::accountable::recover_registered_root(
        coalition.recovery_roster, coalition.signing_scalar,
        secp_context);
    expect_ok(ctx, recovered,
              "registered root recovers from the exposed scalar");
    if (recovered) {
        ctx.expect(recovered->secret == honest_root->secret &&
                       recovered->public_key == honest_root->public_key,
                   "recovery returns both canonical root components");
    }
}

void test_recovered_punishment_key_usability(
    TestContext& ctx,
    const purify::accountable::AnchorPunishmentKey& recovered,
    std::size_t index,
    purify_secp_context* secp_context) {
    std::array<unsigned char, 32> digest{};
    digest.fill(static_cast<unsigned char>(0x40 + index));
    auto nonce = purify::FieldElement::from_u64(101 + index)
                     .to_bytes_be();
    std::array<unsigned char, 32> nonce_public{};
    ctx.expect(
        purify_bip340_nonce_from_scalar(
            secp_context, nonce.data(), nonce_public.data()) != 0,
        "test punishment nonce canonicalizes");
    std::array<unsigned char, 64> signature{};
    ctx.expect(
        purify_bip340_sign_with_fixed_nonce(
            secp_context, signature.data(), digest.data(),
            digest.size(), recovered.bip340_key().seckey.data(),
            nonce.data()) != 0,
        "recovered punishment secret signs a test digest");
    ctx.expect(
        purify_bip340_verify(
            secp_context, signature.data(), digest.data(),
            digest.size(),
            recovered.public_key().xonly().data()) != 0,
        "advertised punishment key accepts the BIP340 signature");
}

} // namespace

void run_slashability_e2e_tests(TestContext& ctx) {
#if defined(PURIFY_TEST_REQUIRES_CONSTRUCTION_PARENT_ARTIFACT)
    const bool artifact_available =
        std::getenv(
            "PURIFY_CONSTRUCTION_PARENT_VERIFIER_ARTIFACT") != nullptr;
    ctx.expect(
        artifact_available,
        "qualified construction parent artifact is required");
    if (!artifact_available) return;
#endif
    auto secp = purify::make_secp_context();
    ctx.expect(secp != nullptr,
               "slashability end-to-end secp context creates");
    if (!secp) return;

    auto coalition = make_all_evil_coalition(secp.get());
    expect_ok(ctx, coalition,
              "three-member all-evil coalition setup verifies");
    if (!coalition) return;
    ctx.expect(coalition->member_secrets.size() == 3 &&
                   coalition->nonce_signers.size() == 3,
               "fixture controls every coalition signing secret");
    test_hidden_second_generator_rejects(
        ctx, *coalition, secp.get());

    auto construction = make_native_accumulation_reference(
        *coalition, 2, secp.get());
#if PURIFY_USE_LEGACY_FIELD_HASHES
    expect_error(
        ctx, construction, purify::ErrorCode::UnsupportedSymbol,
        "SHA construction rejects the legacy field-hash suite");
    return;
#endif
    expect_ok(ctx, construction,
              "two-anchor native accumulation reference decides");
    if (!construction) return;
    ctx.expect(
        construction->anchors.size() == 2 &&
            construction->resolved_entries.size() == 2 &&
            construction->payload.entries().size() == 2,
        "construction retains both ordered anchor statements");
    ctx.expect(
        construction->payload.serialized_size() ==
            purify::accountable::ConstructionReceiptPayload::
                kFixedHeaderSize +
                2 * purify::accountable::ConstructionReceiptPayload::
                        kEntrySize,
        "receipt payload carries two exact public anchor entries");
    ctx.expect(
        std::any_of(construction->statement.begin(),
                    construction->statement.end(),
                    [](unsigned char byte) { return byte != 0; }),
        "construction statement digest is nonzero");
    ctx.expect(
        construction->anchors[0].parent_constants
                .raw_generator_digest ==
            construction->anchors[1].parent_constants
                .raw_generator_digest &&
            construction->anchors[0].parent_constants
                .circuit_binding_digest !=
            construction->anchors[1].parent_constants
                .circuit_binding_digest,
        "parent inputs share a suite but bind each exact anchor");
    ctx.expect(
        std::all_of(
            construction->anchors.begin(),
            construction->anchors.end(),
            [](const auto& anchor) {
                return anchor.reduction_proof.size() == 1'022 &&
                       anchor.parent_step_proof.size() == 1'056;
            }),
        "construction retains canonical recursive witness proofs");
    auto prover_fixture = serialize_parent_prover_fixture(
        *construction, secp.get());
    expect_ok(ctx, prover_fixture,
              "construction prover fixture serializes canonically");
    if (!prover_fixture) return;
    ctx.expect(
        prover_fixture->size() == 8'314 &&
            std::equal(prover_fixture->begin(),
                       prover_fixture->begin() + 16,
                       std::array<unsigned char, 16>{
                           'P', 'u', 'r', 'i', 'f', 'y', '/', 'N',
                           'o', 'v', 'a', '/', 'W', 'i', 't', '1'}
                           .begin()),
        "construction prover fixture has the exact v1 frame");
    write_parent_prover_fixture_if_requested(
        ctx, *prover_fixture,
        "PURIFY_CONSTRUCTION_PARENT_PROVER_FIXTURE_OUT");

    auto accepted_statement = construction->statement;
#if defined(PURIFY_HAS_CONSTRUCTION_PARENT_VERIFIER)
    auto parent_statement = accept_construction_parent_if_requested(
        ctx, *construction, secp.get());
    if (!parent_statement) return;
    accepted_statement = *parent_statement;
#endif
    auto exposed = expose_conflicting_coalition_key(
        *coalition, accepted_statement, secp.get());
    expect_ok(ctx, exposed,
              "proof-attested conflicting responses expose a key");
    if (!exposed) return;
    ctx.expect(
        exposed->scalar() == coalition->signing_scalar &&
            exposed->signing_key() ==
                coalition->registry_roster.signing_key() &&
            exposed->host_commitment() ==
                coalition->registry_roster.nonce_host_commitment() &&
            exposed->coalition_core_digest() ==
                coalition->registry_roster.coalition_core_digest(),
        "exposure remains typed to the exact coalition identity");

    for (std::size_t i = 0;
         i < construction->anchors.size(); ++i) {
        const auto& anchor = construction->anchors[i];
        auto recovered = purify::accountable::recover_escrowed_anchor(
            construction->setup.roster(), exposed->scalar(),
            anchor.recovery_key.public_key,
            anchor.punishment_key.public_key(), anchor.context,
            anchor.record, secp.get());
        expect_ok(ctx, recovered,
                  "exposed coalition key decrypts an escrowed anchor");
        if (!recovered) return;
        ctx.expect(
            recovered->public_key() ==
                    anchor.punishment_key.public_key() &&
                recovered->bip340_key().seckey ==
                    anchor.punishment_key.bip340_key().seckey,
            "decryption returns the exact registered punishment key");
        test_recovered_punishment_key_usability(
            ctx, *recovered, i, secp.get());
        expect_error(
            ctx,
            purify::accountable::recover_escrowed_anchor(
                construction->setup.roster(),
                exposed->scalar().negate(),
                anchor.recovery_key.public_key,
                anchor.punishment_key.public_key(), anchor.context,
                anchor.record, secp.get()),
            purify::ErrorCode::BindingMismatch,
            "wrong exposed scalar cannot decrypt an anchor");
    }

    expect_error(
        ctx,
        purify::accountable::recover_escrowed_anchor(
            construction->setup.roster(), exposed->scalar(),
            construction->anchors[0].recovery_key.public_key,
            construction->anchors[0].punishment_key.public_key(),
            construction->anchors[0].context,
            construction->anchors[1].record, secp.get()),
        purify::ErrorCode::EquationMismatch,
        "one decided anchor cannot substitute another escrow proof");
}
