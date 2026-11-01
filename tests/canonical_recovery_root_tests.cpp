// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <algorithm>
#include <array>
#include <chrono>
#include <iostream>
#include <optional>
#include <span>
#include <utility>
#include <vector>

#include "purify.hpp"
#include "purify/bppp.hpp"
#include "purify/puresign/accountable.hpp"
#include "test_harness.hpp"
#include "canonical_recovery_root_helpers.hpp"

namespace {

using namespace purify_test::canonical_root;

using purify_test::TestContext;
using purify_test::expect_error;
using purify_test::expect_ok;
using purify::Bytes;
using purify::Expr;
using purify::FieldElement;
using purify::Result;
using purify::UInt256;
using purify::UInt512;
using PointPair = std::pair<purify::JacobianPoint, purify::JacobianPoint>;
using PointBytes = purify::bppp::PointBytes;

Result<std::vector<purify::puresign_plusplus::PublicKey>> nonce_hosts(
    std::span<const PointBytes> member_keys,
    purify_secp_context* secp_context) {
    std::vector<purify::puresign_plusplus::PublicKey> out;
    out.reserve(member_keys.size());
    for (std::size_t i = 0; i < member_keys.size(); ++i) {
        std::array<unsigned char, 32> seed{};
        seed[0] = 0x91;
        seed[1] = static_cast<unsigned char>(i);
        PURIFY_ASSIGN_OR_RETURN(
            const auto& generated, purify::generate_key(seed),
            "recovery_root_test:nonce_host_secret");
        PURIFY_ASSIGN_OR_RETURN(
            auto host,
            purify::puresign_plusplus::PublicKey::from_secret(
                generated.secret, secp_context),
            "recovery_root_test:nonce_host");
        std::copy(member_keys[i].begin() + 1, member_keys[i].end(),
                  host.bip340_pubkey.begin());
        out.push_back(std::move(host));
    }
    return out;
}

void test_bounds_and_recoding(TestContext& ctx) {
    auto bound = half_secp_order();
    bound.sub_assign(UInt256::one());
    auto below = bound;
    below.sub_assign(UInt256::one());
    auto above = bound;
    above.add_small(1);
    auto largest = UInt256::one().shifted_left(255);
    largest.sub_assign(UInt256::one());
    for (const auto& value : {UInt256::zero(), below, bound, above, largest}) {
        purify::Transcript transcript;
        const auto bits = ordinary_bits(transcript, value);
        const auto exceeds = transcript.evaluate(exceeds_bound(transcript, bits, bound));
        ctx.expect(exceeds && *exceeds == FieldElement::from_u64(bound < value),
                   "integer prefix comparator distinguishes both boundary sides");
        if (bound < value) continue; // No invalid setup witness or proof is generated.
        const auto recoded = signed_window_bits(transcript, bits);
        auto a = value;
        a.add_small(1);
        auto expected = purify::key_to_bits(a, half_secp_order());
        expect_ok(ctx, expected, "canonical magnitude has an independent C recoding");
        if (!expected) return;
        for (std::size_t i = 0; i < recoded.size(); ++i) {
            const auto actual = transcript.evaluate(recoded[i]);
            ctx.expect(actual && *actual == FieldElement::from_int((*expected)[i]),
                       "symbolic signed-window conversion matches the C codec");
        }
    }
}

void test_setup_and_recovery(TestContext& ctx) {
    auto secp = purify::make_secp_context();
    ctx.expect(secp != nullptr, "canonical-root secp context creates");
    if (!secp) return;
    bool saw_positive = false;
    bool saw_negative = false;
    for (const auto& a : {UInt256::one(), UInt256::from_u64(6), half_secp_order()}) {
        auto encoded = a.to_bytes_be();
        std::array<unsigned char, 32> xonly{};
        ctx.expect(purify_bip340_key_from_seckey(secp.get(), encoded.data(), xonly.data()) != 0,
                   "honest fixture normalizes to an even-Y coalition key");
        const auto q = FieldElement::from_bytes32(encoded);
        saw_positive |= q.to_uint256() == a;
        saw_negative |= q.to_uint256() != a;
        auto root = root_from_scalar(q);
        expect_ok(ctx, root, "canonical scalar derives a companion root");
        if (!root) return;
        auto circuit = public_setup_circuit(root->public_key);
        auto assignment = setup_assignment(root->public_key, q);
        expect_ok(ctx, circuit, "public setup relation constructs");
        expect_ok(ctx, assignment, "honest setup assignment constructs");
        if (!circuit || !assignment) return;
        ctx.expect(
            circuit->evaluate(*assignment),
            "small and maximum magnitudes satisfy the public relation");
        if (a == half_secp_order()) {
            auto scalars = purify::unpack_secret(root->secret.packed());
            expect_ok(ctx, scalars, "upper-bound root uses canonical companion secrets");
            if (scalars) ctx.expect(scalars->first == a && scalars->second < a,
                                   "upper-bound magnitude normalizes the second companion scalar");
        }
    }
    ctx.expect(saw_positive && saw_negative, "honest assignments exercise both private sign branches");
    ctx.expect(!root_from_scalar(FieldElement::zero()), "zero coalition scalar has no recovery root");

    std::array member_scalars{
        FieldElement::from_u64(3), FieldElement::from_u64(6)};
    std::array<PointBytes, 2> member_keys{};
    for (std::size_t i = 0; i < member_keys.size(); ++i) {
        auto member_key = secp_point(member_scalars[i], secp.get());
        expect_ok(ctx, member_key, "setup member key derives");
        if (!member_key) return;
        member_keys[i] = *member_key;
        if (member_keys[i][0] == 0x03) {
            member_keys[i][0] = 0x02;
            member_scalars[i] = member_scalars[i].negate();
        }
    }
    auto raw_roster = purify::accountable::SigningRoster::aggregate(
        member_keys, secp.get());
    expect_ok(ctx, raw_roster, "setup roster aggregates");
    if (!raw_roster) return;
    auto q = FieldElement::zero();
    for (std::size_t i = 0; i < member_scalars.size(); ++i) {
        q = q + raw_roster->members()[i].coefficient * member_scalars[i];
    }
    PointBytes key{};
    key[0] = 0x02;
    std::copy(raw_roster->signing_key().begin(), raw_roster->signing_key().end(),
              key.begin() + 1);
    auto root = root_from_scalar(q);
    expect_ok(ctx, root, "proof fixture has a canonical companion root");
    if (!root) return;
    const auto context = purify::bytes_from_ascii("public toy canonical-root setup/context");
    purify::accountable::CoalitionCoreDigest coalition_core_digest =
        purify::TaggedHash("Purify/Test/RecoveryRootRegistration/v1")
            .digest(context);
    auto hosts = nonce_hosts(member_keys, secp.get());
    expect_ok(ctx, hosts, "setup nonce hosts derive");
    if (!hosts) return;
    auto bound_roster = purify::accountable::bind_nonce_hosts(
        *raw_roster, coalition_core_digest, *hosts, secp.get());
    expect_ok(ctx, bound_roster,
              "setup roster binds its exact nonce hosts");
    if (!bound_roster) return;
    const auto start = std::chrono::steady_clock::now();
    auto proof = purify::accountable::prove_recovery_root_setup(
        *bound_roster, root->public_key, q, secp.get());
    const auto proved = std::chrono::steady_clock::now();
    expect_ok(ctx, proof, "production API proves the canonical-root setup relation");
    if (!proof) return;
    auto encoded_proof = proof->serialize(secp.get());
    expect_ok(ctx, encoded_proof,
              "recovery-root setup proof has a canonical encoding");
    if (!encoded_proof) return;
    expect_error(ctx, proof->serialize(nullptr),
                 purify::ErrorCode::MissingValue,
                 "setup proof serialization requires a secp context");
    expect_error(
        ctx,
        purify::accountable::RecoveryRootSetupProof::deserialize(
            *encoded_proof, nullptr),
        purify::ErrorCode::MissingValue,
        "setup proof parsing requires a secp context");
    ctx.expect(encoded_proof->size() == 1007 &&
                   encoded_proof->size() ==
                       purify::accountable::RecoveryRootSetupProof::kSerializedSize,
               "setup proof encoding accounts for its fixed V1 fields");
    auto parsed_proof = purify::accountable::RecoveryRootSetupProof::deserialize(
        *encoded_proof, secp.get());
    expect_ok(ctx, parsed_proof, "canonical setup proof reparses");
    if (!parsed_proof) return;
    auto reencoded_proof = parsed_proof->serialize(secp.get());
    ctx.expect(reencoded_proof && *reencoded_proof == *encoded_proof,
               "setup proof encoding round-trips exactly");
    auto construction_accumulator = purify::accountable::
        ConstructionReceiptAccumulator::create(secp.get());
    expect_ok(ctx, construction_accumulator,
              "construction receipt fixed accumulation bases create");
    if (!construction_accumulator) return;
    const auto* setup_accumulator = &construction_accumulator->setup();
    ctx.expect(
        setup_accumulator->basis().n_vec_len() ==
                purify::accountable::RecoveryRootSetupAccumulator::
                    kNormVectorLength &&
            setup_accumulator->basis().l_vec_len() ==
                purify::accountable::RecoveryRootSetupAccumulator::
                    kNormVectorLength,
        "recovery-root setup accumulation fixes both norm dimensions");
    auto setup_prepared = setup_accumulator->prepare(
        *bound_roster, root->public_key, *parsed_proof, secp.get());
    expect_ok(ctx, setup_prepared,
              "typed adapter prepares the exact setup statement");
    if (!setup_prepared) return;
    auto setup_reduction =
        purify::bppp::accumulation::prove_norm_reduction(
            setup_accumulator->basis(), *setup_prepared, secp.get());
    expect_ok(ctx, setup_reduction,
              "recovery-root setup coefficient opening proves");
    if (!setup_reduction) return;
    auto setup_pending =
        purify::bppp::accumulation::verify_norm_reduction(
            setup_accumulator->basis(), *setup_prepared,
            *setup_reduction, secp.get());
    expect_ok(ctx, setup_pending,
              "recovery-root setup reduction stays pending");
    if (!setup_pending) return;
    expect_ok(ctx, purify::bppp::accumulation::decide(
                       setup_accumulator->basis(), *setup_pending,
                       secp.get()),
              "final MSM discharges the honest setup obligation");
    auto promoted_setup =
        construction_accumulator->promote_setup_claim(*setup_pending);
    expect_ok(ctx, promoted_setup,
              "pending setup claim promotes to the construction basis");
    if (!promoted_setup) return;
    expect_ok(ctx, purify::bppp::accumulation::decide(
                       construction_accumulator->anchors().basis(),
                       *promoted_setup, secp.get()),
              "construction basis preserves the setup obligation");
    const std::span<const purify::bppp::accumulation::PendingClaim>
        promoted_claims(&*promoted_setup, 1);
    auto construction_step = purify::bppp::accumulation::prove_step(
        construction_accumulator->anchors().basis(), promoted_claims,
        secp.get());
    expect_ok(ctx, construction_step,
              "promoted setup claim folds into a construction root");
    if (!construction_step) return;
    auto construction_root = purify::bppp::accumulation::verify_step(
        construction_accumulator->anchors().basis(), promoted_claims,
        *construction_step, secp.get());
    expect_ok(ctx, construction_root,
              "construction root remains a pending obligation");
    if (!construction_root) return;
    auto encoded_construction_root =
        purify::bppp::accumulation::serialize_root_claim(
            construction_accumulator->anchors().basis(),
            *construction_root, secp.get());
    expect_ok(ctx, encoded_construction_root,
              "construction root has a canonical encoding");
    if (!encoded_construction_root) return;
    ctx.expect(
        encoded_construction_root->size() ==
            purify::accountable::ConstructionReceiptAccumulator::
                kRootClaimSerializedSize &&
            encoded_construction_root->size() == 545,
        "construction root encoding is exactly 545 bytes");
    auto parsed_construction_root =
        purify::bppp::accumulation::parse_root_claim(
            construction_accumulator->anchors().basis(),
            *encoded_construction_root, secp.get());
    expect_ok(ctx, parsed_construction_root,
              "construction root reparses against its fixed basis");
    if (!parsed_construction_root) return;
    expect_ok(ctx, purify::bppp::accumulation::decide(
                       construction_accumulator->anchors().basis(),
                       *parsed_construction_root, secp.get()),
              "final MSM discharges the parsed construction root");
    auto changed_encoding = *encoded_proof;
    changed_encoding[0] ^= 1;
    expect_error(ctx,
                 purify::accountable::RecoveryRootSetupProof::deserialize(
                     changed_encoding, secp.get()),
                 purify::ErrorCode::UnsupportedSymbol,
                 "unknown setup proof version rejects");
    changed_encoding = *encoded_proof;
    changed_encoding.pop_back();
    expect_error(ctx,
                 purify::accountable::RecoveryRootSetupProof::deserialize(
                     changed_encoding, secp.get()),
                 purify::ErrorCode::InvalidFixedSize,
                 "truncated setup proof rejects");
    changed_encoding = *encoded_proof;
    changed_encoding.push_back(0);
    expect_error(ctx,
                 purify::accountable::RecoveryRootSetupProof::deserialize(
                     changed_encoding, secp.get()),
                 purify::ErrorCode::InvalidFixedSize,
                 "oversized setup proof rejects");
    changed_encoding = *encoded_proof;
    std::fill_n(changed_encoding.begin() + 1, 33, 0);
    expect_error(ctx,
                 purify::accountable::RecoveryRootSetupProof::deserialize(
                     changed_encoding, secp.get()),
                 purify::ErrorCode::RangeViolation,
                 "invalid setup proof A commitment rejects");
    changed_encoding = *encoded_proof;
    std::fill_n(changed_encoding.begin() + 34, 33, 0);
    expect_error(ctx,
                 purify::accountable::RecoveryRootSetupProof::deserialize(
                     changed_encoding, secp.get()),
                 purify::ErrorCode::RangeViolation,
                 "invalid setup proof S commitment rejects");
    changed_encoding = *encoded_proof;
    std::fill_n(changed_encoding.begin() + 67, 32, 0xff);
    expect_error(ctx,
                 purify::accountable::RecoveryRootSetupProof::deserialize(
                     changed_encoding, secp.get()),
                 purify::ErrorCode::RangeViolation,
                 "non-canonical setup proof t2 rejects");
    changed_encoding = *encoded_proof;
    std::fill_n(changed_encoding.begin() + 99, 32, 0xff);
    expect_error(ctx,
                 purify::accountable::RecoveryRootSetupProof::deserialize(
                     changed_encoding, secp.get()),
                 purify::ErrorCode::RangeViolation,
                 "invalid DLog nonce encoding rejects");
    changed_encoding = *encoded_proof;
    std::fill_n(changed_encoding.begin() + 131, 32, 0);
    expect_error(ctx,
                 purify::accountable::RecoveryRootSetupProof::deserialize(
                     changed_encoding, secp.get()),
                 purify::ErrorCode::RangeViolation,
                 "zero setup proof DLog response rejects");
    changed_encoding = *encoded_proof;
    std::fill_n(changed_encoding.begin() + 131, 32, 0xff);
    expect_error(ctx,
                 purify::accountable::RecoveryRootSetupProof::deserialize(
                     changed_encoding, secp.get()),
                 purify::ErrorCode::RangeViolation,
                 "non-canonical setup proof DLog response rejects");
    auto verified = purify::accountable::verify_recovery_root_setup(
        *bound_roster, root->public_key, *parsed_proof, secp.get());
    const auto checked = std::chrono::steady_clock::now();
    expect_ok(ctx, verified,
              "setup verifier returns a knowledge-bound roster");
    if (!verified) return;
    expect_error(
        ctx,
        purify::accountable::prove_recovery_root_setup(
            *bound_roster, root->public_key, q.negate(), secp.get()),
        purify::ErrorCode::BindingMismatch,
        "prover rejects a scalar that opens the opposite full point");
    expect_error(
        ctx,
        purify::accountable::prove_recovery_root_setup(
            *bound_roster, root->public_key, FieldElement::zero(),
            secp.get()),
        purify::ErrorCode::RangeViolation,
        "prover rejects the zero aggregate scalar");
    expect_error(
        ctx,
        purify::accountable::prove_recovery_root_setup(
            *bound_roster, root->public_key, q, nullptr),
        purify::ErrorCode::MissingValue,
        "prover requires a secp context");
    auto changed_digest = coalition_core_digest;
    changed_digest[0] ^= 1;
    auto changed_core_roster = purify::accountable::bind_nonce_hosts(
        *raw_roster, changed_digest, *hosts, secp.get());
    expect_ok(ctx, changed_core_roster,
              "changed-core nonce hosts remain well formed");
    if (!changed_core_roster) return;
    ctx.expect(!purify::accountable::verify_recovery_root_setup(
                   *changed_core_roster, root->public_key, *proof,
                   secp.get()),
               "unchanged setup proof rejects changed coalition core");
    auto changed_hosts = *hosts;
    std::array<unsigned char, 32> changed_host_seed{};
    changed_host_seed.fill(0x92);
    auto changed_host_secret = purify::generate_key(changed_host_seed);
    expect_ok(ctx, changed_host_secret,
              "changed nonce-host secret derives");
    if (!changed_host_secret) return;
    auto changed_host = purify::puresign_plusplus::PublicKey::from_secret(
        changed_host_secret->secret, secp.get());
    expect_ok(ctx, changed_host, "changed nonce host derives");
    if (!changed_host) return;
    std::copy(member_keys[0].begin() + 1, member_keys[0].end(),
              changed_host->bip340_pubkey.begin());
    changed_hosts[0] = std::move(*changed_host);
    auto changed_host_roster = purify::accountable::bind_nonce_hosts(
        *raw_roster, coalition_core_digest, changed_hosts, secp.get());
    expect_ok(ctx, changed_host_roster,
              "changed nonce host remains well formed");
    if (!changed_host_roster) return;
    ctx.expect(!purify::accountable::verify_recovery_root_setup(
                   *changed_host_roster, root->public_key, *proof,
                   secp.get()),
               "unchanged setup proof rejects changed nonce hosts");
    auto other_root = root_from_scalar(FieldElement::from_u64(3));
    expect_ok(ctx, other_root, "substitution root fixture derives");
    if (!other_root) return;
    expect_error(
        ctx,
        purify::accountable::prove_recovery_root_setup(
            *bound_roster, other_root->public_key, q, secp.get()),
        purify::ErrorCode::BindingMismatch,
        "prover rejects a recovery root unrelated to its scalar");
    ctx.expect(!purify::accountable::verify_recovery_root_setup(
                   *bound_roster, other_root->public_key,
                   *proof, secp.get()),
               "unchanged setup proof rejects another recovery root");
    expect_error(
        ctx,
        setup_accumulator->prepare(
            *bound_roster, other_root->public_key, *parsed_proof,
            secp.get()),
        purify::ErrorCode::EquationMismatch,
        "typed adapter rejects a setup proof for another recovery root");
    auto changed_members = member_keys;
    auto changed_member = secp_point(
        FieldElement::from_u64(5), secp.get());
    expect_ok(ctx, changed_member, "changed member point derives");
    if (!changed_member) return;
    if ((*changed_member)[0] == 0x03) {
        (*changed_member)[0] = 0x02;
    }
    changed_members[0] = *changed_member;
    auto changed_roster = purify::accountable::SigningRoster::aggregate(
        changed_members, secp.get());
    expect_ok(ctx, changed_roster, "changed member roster remains valid");
    if (!changed_roster) return;
    auto changed_member_hosts = *hosts;
    std::copy(changed_members[0].begin() + 1, changed_members[0].end(),
              changed_member_hosts[0].bip340_pubkey.begin());
    auto changed_bound_roster = purify::accountable::bind_nonce_hosts(
        *changed_roster, coalition_core_digest, changed_member_hosts,
        secp.get());
    expect_ok(ctx, changed_bound_roster,
              "changed member binds its matching nonce host");
    if (!changed_bound_roster) return;
    ctx.expect(!purify::accountable::verify_recovery_root_setup(
                   *changed_bound_roster, root->public_key,
                   *proof, secp.get()),
               "unchanged setup proof rejects another coalition roster");
    ctx.expect(!purify::accountable::verify_recovery_root_setup(
                   *bound_roster,
                   purify::packed_public_key_space_size(), *proof,
                   secp.get()),
               "noncanonical recovery root rejects");

    const auto slot = purify::bytes_from_ascii("canonical-root/domain=1/epoch=2/slot=3");
    purify::accountable::ConflictContext conflict{
        bound_roster->signing_key(), bound_roster->nonce_host_commitment(),
        coalition_core_digest, slot};
    const auto first_body = purify::bytes_from_ascii("toy decision A");
    const auto second_body = purify::bytes_from_ascii("toy decision B");
    auto first_challenge = purify::accountable::signature_challenge(conflict, first_body, secp.get());
    auto second_challenge = purify::accountable::signature_challenge(conflict, second_body, secp.get());
    expect_ok(ctx, first_challenge, "first toy challenge derives");
    expect_ok(ctx, second_challenge, "second toy challenge derives");
    if (!first_challenge || !second_challenge) return;
    const auto r = FieldElement::from_u64(9);
    auto first = purify::accountable::ScalarSignature::deserialize((r + *first_challenge * q).to_bytes_be());
    auto second = purify::accountable::ScalarSignature::deserialize((r + *second_challenge * q).to_bytes_be());
    expect_ok(ctx, first, "first toy response encodes");
    expect_ok(ctx, second, "second toy response encodes");
    if (!first || !second) return;
    auto extracted = purify::accountable::recover_same_slot_key(conflict, first_body, *first, second_body, *second, secp.get());
    expect_ok(ctx, extracted, "existing accountable algebra extracts the exact coalition scalar");
    if (!extracted) return;
    auto recovered = purify::accountable::recover_registered_root(
        *verified, FieldElement::from_bytes32(*extracted), secp.get());
    expect_ok(ctx, recovered, "extracted scalar recovers the exact registered companion root");
    if (!recovered) return;
    ctx.expect(recovered->secret == root->secret, "recovery preserves both canonical companion scalars");
    ctx.expect(!purify::accountable::recover_registered_root(
                   *verified, q.negate(), secp.get()),
               "wrong scalar sign rejects before root recovery");
    for (unsigned char marker : {0x23, 0x45}) {
        std::array<unsigned char, 32> seed{};
        seed.fill(marker);
        auto owner = purify::generate_key(seed);
        expect_ok(ctx, owner, "independent leaf owner fixture generates");
        if (!owner) return;
        auto owned = leaf_output(owner->secret, root->public_key);
        auto unlocked = leaf_output(recovered->secret, owner->public_key);
        expect_ok(ctx, owned, "owner derives a punishment scalar");
        expect_ok(ctx, unlocked, "recovered root derives the same leaf scalar");
        if (!owned || !unlocked) return;
        auto owned_point = secp_point(*owned, secp.get());
        auto unlocked_point = secp_point(*unlocked, secp.get());
        expect_ok(ctx, owned_point, "owner punishment point is finite");
        expect_ok(ctx, unlocked_point, "recovered punishment point is finite");
        ctx.expect(*owned == *unlocked && owned_point && unlocked_point && *owned_point == *unlocked_point,
                   "extracted coalition scalar unlocks each exact leaf scalar and full point");
    }
    const auto proof_payload_bytes = encoded_proof->size() - 1;
    std::cout << "canonical_root_honest_setup"
              << " inner_proof_bytes="
              << purify::accountable::RecoveryRootSetupProof::kInnerProofSize
              << " proof_payload_bytes=" << proof_payload_bytes
              << " wire_proof_bytes=" << encoded_proof->size()
              << " root_bytes=64 total_wire_with_root_and_full_Q="
              << encoded_proof->size() + 64 + key.size()
              << " prove_ms=" << std::chrono::duration<double, std::milli>(proved - start).count()
              << " verify_ms=" << std::chrono::duration<double, std::milli>(checked - proved).count() << '\n';
}

} // namespace

void run_canonical_recovery_root_tests(TestContext& ctx) {
    test_bounds_and_recoding(ctx);
    test_setup_and_recovery(ctx);
}
