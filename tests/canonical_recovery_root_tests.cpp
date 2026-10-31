// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <algorithm>
#include <array>
#include <chrono>
#include <iostream>
#include <optional>
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
using purify_test::expect_ok;
using purify::Bytes;
using purify::Expr;
using purify::FieldElement;
using purify::Result;
using purify::UInt256;
using purify::UInt512;
using PointPair = std::pair<purify::JacobianPoint, purify::JacobianPoint>;
using PointBytes = purify::bppp::PointBytes;

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
        ctx.expect(circuit->evaluate(*assignment), "small and maximum magnitudes satisfy the public relation");
        if (a == half_secp_order()) {
            auto scalars = purify::unpack_secret(root->secret.packed());
            expect_ok(ctx, scalars, "upper-bound root uses canonical companion secrets");
            if (scalars) ctx.expect(scalars->first == a && scalars->second < a,
                                   "upper-bound magnitude normalizes the second companion scalar");
        }
    }
    ctx.expect(saw_positive && saw_negative, "honest assignments exercise both private sign branches");
    ctx.expect(!root_from_scalar(FieldElement::zero()), "zero coalition scalar has no recovery root");

    // q=-6 has an even-Y secp point and exercises the negative magnitude branch.
    const auto q = FieldElement::from_u64(6).negate();
    auto key = secp_point(q, secp.get());
    auto root = root_from_scalar(q);
    expect_ok(ctx, key, "proof fixture has a full coalition point");
    expect_ok(ctx, root, "proof fixture has a canonical companion root");
    if (!key || !root) return;
    auto circuit = public_setup_circuit(root->public_key);
    auto assignment = setup_assignment(root->public_key, q);
    expect_ok(ctx, circuit, "proof circuit builds from the public root");
    expect_ok(ctx, assignment, "proof witness builds from the toy scalar");
    if (!circuit || !assignment) return;
    const auto context = purify::bytes_from_ascii("public toy canonical-root setup/context");
    const std::array<PointBytes, 1> outputs{*key};
    purify::bppp::ScalarBytes nonce{};
    nonce.fill(0x81);
    const auto start = std::chrono::steady_clock::now();
    auto proof = purify::bppp::prove_experimental_circuit_zk_norm_arg_with_public_commitments(
        *circuit, *assignment, nonce, outputs, secp.get(), binding(*key, root->public_key, context));
    const auto proved = std::chrono::steady_clock::now();
    expect_ok(ctx, proof, "experimental backend proves the honest canonical-root relation");
    if (!proof) return;
    auto verified = verify_setup(*key, root->public_key, context, *proof, secp.get());
    const auto checked = std::chrono::steady_clock::now();
    expect_ok(ctx, verified, "setup verifier accepts well-formed public inputs");
    if (verified) ctx.expect(*verified, "honest canonical-root proof verifies");
    auto changed = context;
    changed.push_back(0);
    auto wrong_context = verify_setup(*key, root->public_key, changed, *proof, secp.get());
    ctx.expect(!wrong_context || !*wrong_context, "unchanged setup proof rejects changed context");
    auto other_root = root_from_scalar(FieldElement::from_u64(3));
    auto other_key = secp_point(FieldElement::from_u64(3), secp.get());
    expect_ok(ctx, other_root, "substitution root fixture derives");
    expect_ok(ctx, other_key, "substitution key fixture derives");
    if (!other_root || !other_key) return;
    auto wrong_root = verify_setup(*key, other_root->public_key, context, *proof, secp.get());
    auto wrong_key = verify_setup(*other_key, root->public_key, context, *proof, secp.get());
    auto odd_key = *key;
    odd_key[0] = 0x03;
    ctx.expect(!wrong_root || !*wrong_root, "unchanged setup proof rejects another root");
    ctx.expect(!wrong_key || !*wrong_key, "unchanged setup proof rejects another coalition key");
    ctx.expect(!verify_setup(odd_key, root->public_key, context, *proof, secp.get()), "odd coalition key rejects");
    ctx.expect(!public_setup_circuit(purify::packed_public_key_space_size()), "noncanonical root rejects");

    const auto slot = purify::bytes_from_ascii("canonical-root/domain=1/epoch=2/slot=3");
    purify::accountable::ConflictContext conflict{{}, {}, slot};
    std::copy(key->begin() + 1, key->end(), conflict.signing_key.begin());
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
    auto recovered = recover_root(FieldElement::from_bytes32(*extracted), *key, root->public_key, secp.get());
    expect_ok(ctx, recovered, "extracted scalar recovers the exact registered companion root");
    if (!recovered) return;
    ctx.expect(recovered->secret == root->secret, "recovery preserves both canonical companion scalars");
    ctx.expect(!recover_root(q.negate(), *key, root->public_key, secp.get()), "wrong scalar sign rejects before root recovery");
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
    const auto proof_bytes = proof->proof.size() + proof->a_commitment.size() + proof->s_commitment.size() + proof->t2.size();
    std::cout << "canonical_root_honest_setup gates=" << circuit->n_gates << " constraints=" << circuit->c.size()
              << " inner_proof_bytes=" << proof->proof.size() << " complete_proof_bytes=" << proof_bytes
              << " root_bytes=64 total_with_root_and_full_Q=" << proof_bytes + 64 + key->size()
              << " prove_ms=" << std::chrono::duration<double, std::milli>(proved - start).count()
              << " verify_ms=" << std::chrono::duration<double, std::milli>(checked - proved).count() << '\n';
}

} // namespace

void run_canonical_recovery_root_tests(TestContext& ctx) {
    test_bounds_and_recoding(ctx);
    test_setup_and_recovery(ctx);
}
