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
#include "companion_scalar_escrow_helpers.hpp"

namespace {

using namespace purify_test::scalar_escrow;

using purify_test::TestContext;
using purify_test::expect_ok;
using purify::Bytes;
using purify::Expr;
using purify::FieldElement;
using purify::Result;
using purify::UInt256;
using purify::UInt512;
using PointPair = std::pair<purify::JacobianPoint, purify::JacobianPoint>;

void test_companion_scalar_escrow(TestContext& ctx) {
    auto secp = purify::make_secp_context();
    ctx.expect(secp != nullptr, "scalar escrow secp context creates");
    if (!secp) return;
    // The old root is independent of, and chosen before, the new coalition.
    std::array<unsigned char, 32> seed{};
    seed.fill(0x31);
    auto old_root = purify::generate_key(seed);
    const auto q = FieldElement::from_u64(6).negate();
    auto coalition_point = secp_point(q, secp.get());
    auto recipient = recipient_from_scalar(q);
    seed.fill(0x51);
    auto first_ephemeral = purify::generate_key(seed);
    seed.fill(0x63);
    auto second_ephemeral = purify::generate_key(seed);
    expect_ok(ctx, old_root, "old root predates coalition encryption");
    expect_ok(ctx, coalition_point, "toy coalition has its full signing point");
    expect_ok(ctx, recipient, "known coalition scalar supplies the companion recipient");
    expect_ok(ctx, first_ephemeral, "first independent pad key generates");
    expect_ok(ctx, second_ephemeral, "second independent pad key generates");
    if (!old_root || !coalition_point || !recipient || !first_ephemeral || !second_ephemeral) return;
    Opening opening{old_root->secret, {&*first_ephemeral, &*second_ephemeral}};
    auto ciphertext = encrypt(recipient->public_key, opening);
    expect_ok(ctx, ciphertext, "both canonical old-root scalars encrypt");
    if (!ciphertext) return;
    auto circuit = public_circuit(recipient->public_key, old_root->public_key, *ciphertext);
    auto witness = assignment(recipient->public_key, old_root->public_key, *ciphertext, opening);
    expect_ok(ctx, circuit, "public escrow circuit binds root, recipient and ciphertext");
    expect_ok(ctx, witness, "honest encryption witness constructs");
    if (!circuit || !witness) return;
    ctx.expect(circuit->evaluate(*witness), "honest ciphertext satisfies every native equation");
    const auto context = purify::bytes_from_ascii("public toy preexisting-root/coalition/purpose");
    const auto generator = secp_point(FieldElement::one(), secp.get());
    expect_ok(ctx, generator, "fixed public output is G");
    if (!generator) return;
    const std::array<purify::bppp::PointBytes, 1> output{*generator};
    purify::bppp::ScalarBytes nonce{};
    nonce.fill(0xb7);
    const auto start = std::chrono::steady_clock::now();
    auto proof = purify::bppp::prove_experimental_circuit_zk_norm_arg_with_public_commitments(
        *circuit, *witness, nonce, output, secp.get(), binding(recipient->public_key, old_root->public_key, *ciphertext, context));
    const auto proved = std::chrono::steady_clock::now();
    expect_ok(ctx, proof, "experimental backend proves the honest scalar-encryption relation");
    if (!proof) return;
    // This is extraction algebra, not complete certificate validation. Nonce
    // evidence and Q-to-recipient setup authentication remain external; the
    // canonical_recovery_root suite separately exercises that setup proof.
    const auto slot = purify::bytes_from_ascii("old-root/domain=1/epoch=2/slot=3");
    purify::accountable::ConflictContext conflict{{}, {}, slot};
    std::copy(coalition_point->begin() + 1, coalition_point->end(), conflict.signing_key.begin());
    const auto body_a = purify::bytes_from_ascii("toy decision A");
    const auto body_b = purify::bytes_from_ascii("toy decision B");
    auto challenge_a = purify::accountable::signature_challenge(conflict, body_a, secp.get());
    auto challenge_b = purify::accountable::signature_challenge(conflict, body_b, secp.get());
    expect_ok(ctx, challenge_a, "first toy challenge derives");
    expect_ok(ctx, challenge_b, "second toy challenge derives");
    if (!challenge_a || !challenge_b) return;
    const auto r = FieldElement::from_u64(9);
    auto response_a = purify::accountable::ScalarSignature::deserialize((r + *challenge_a * q).to_bytes_be());
    auto response_b = purify::accountable::ScalarSignature::deserialize((r + *challenge_b * q).to_bytes_be());
    expect_ok(ctx, response_a, "first toy response encodes");
    expect_ok(ctx, response_b, "second toy response encodes");
    if (!response_a || !response_b) return;
    auto extracted = purify::accountable::recover_same_slot_key(conflict, body_a, *response_a, body_b, *response_b, secp.get());
    expect_ok(ctx, extracted, "same-slot responses extract the exact coalition scalar");
    if (!extracted) return;
    ctx.expect(*extracted == q.to_bytes_be(), "extraction preserves the canonical signing scalar and sign");
    auto recovered_recipient = recipient_from_scalar(FieldElement::from_bytes32(*extracted));
    expect_ok(ctx, recovered_recipient, "extracted scalar derives the canonical companion recipient");
    if (!recovered_recipient) return;
    ctx.expect(recovered_recipient->public_key == recipient->public_key, "extracted scalar reaches the registered recipient");
    const auto decrypt_start = std::chrono::steady_clock::now();
    auto decrypted = decrypt_checked(recovered_recipient->secret, recipient->public_key, old_root->public_key, *ciphertext, context, *proof, secp.get());
    const auto recovered = std::chrono::steady_clock::now();
    expect_ok(ctx, decrypted, "public verification precedes successful root recovery");
    if (decrypted) ctx.expect(decrypted->secret == old_root->secret, "decryption recovers both exact canonical old-root scalars");
    if (!decrypted) return;
    for (unsigned char marker : {0x93, 0xa5}) {
        seed.fill(marker);
        auto owner = purify::generate_key(seed);
        expect_ok(ctx, owner, "independent leaf owner is separate from every encryption ephemeral");
        if (!owner) return;
        auto original = shared_pad(old_root->secret, owner->public_key);
        auto recovered_leaf = shared_pad(decrypted->secret, owner->public_key);
        auto owned = shared_pad(owner->secret, old_root->public_key);
        expect_ok(ctx, original, "old root derives the leaf scalar");
        expect_ok(ctx, recovered_leaf, "decrypted old root derives the leaf scalar");
        expect_ok(ctx, owned, "independent owner derives the leaf scalar");
        if (!original || !recovered_leaf || !owned) return;
        ctx.expect(*original == *recovered_leaf && *owned == *recovered_leaf,
                   "extracted coalition scalar unlocks each original owner leaf scalar");
    }
    ctx.expect(ciphertext_bytes(*ciphertext).size() == 192, "ciphertext retains two ephemeral pairs and two field elements");

    auto changed_context = context;
    changed_context.push_back(0);
    auto rejected = verify(recipient->public_key, old_root->public_key, *ciphertext, changed_context, *proof, secp.get());
    ctx.expect(!rejected || !*rejected, "unchanged escrow proof rejects another context");
    rejected = verify(first_ephemeral->public_key, old_root->public_key, *ciphertext, context, *proof, secp.get());
    ctx.expect(!rejected || !*rejected, "unchanged escrow proof rejects another recipient");
    rejected = verify(recipient->public_key, first_ephemeral->public_key, *ciphertext, context, *proof, secp.get());
    ctx.expect(!rejected || !*rejected, "unchanged escrow proof rejects another old root");
    auto changed = *ciphertext;
    changed.masked[0] = changed.masked[0] + FieldElement::one();
    rejected = verify(recipient->public_key, old_root->public_key, changed, context, *proof, secp.get());
    ctx.expect(!rejected || !*rejected, "unchanged escrow proof rejects a changed encrypted scalar");
    changed = *ciphertext;
    std::swap(changed.ephemeral[0], changed.ephemeral[1]);
    rejected = verify(recipient->public_key, old_root->public_key, changed, context, *proof, secp.get());
    ctx.expect(!rejected || !*rejected, "unchanged escrow proof rejects reordered ephemeral keys");
    ctx.expect(!decrypt_checked(first_ephemeral->secret, recipient->public_key, old_root->public_key, *ciphertext, context, *proof, secp.get()),
               "wrong decryption secret rejects even with the correct public ciphertext");
    changed.ephemeral[0] = purify::packed_public_key_space_size();
    ctx.expect(!public_circuit(recipient->public_key, old_root->public_key, changed), "noncanonical ephemeral rejects before circuit construction");

    // Bounds are verified as ordinary arithmetic; no invalid proof is generated.
    for (const auto& limit : {purify::half_n1(), purify::half_n2()}) {
        auto bound = limit;
        bound.sub_assign(UInt256::one());
        purify::Transcript transcript;
        const auto bits = ordinary_bits(transcript, limit);
        const auto exceeds = transcript.evaluate(exceeds_bound(transcript, bits, bound));
        ctx.expect(exceeds && exceeds->is_one(), "payload comparator rejects a scalar above its canonical half-order range");
    }
    for (bool upper : {false, true}) {
        auto payload = key_from_pair(upper ? purify::half_n1() : UInt256::one(), upper ? purify::half_n2() : UInt256::one());
        seed.fill(upper ? 0x75 : 0x74);
        auto e0 = purify::generate_key(seed);
        seed.fill(upper ? 0x87 : 0x86);
        auto e1 = purify::generate_key(seed);
        expect_ok(ctx, payload, "canonical payload boundary key constructs");
        expect_ok(ctx, e0, "boundary first pad is fresh");
        expect_ok(ctx, e1, "boundary second pad is fresh");
        if (!payload || !e0 || !e1) return;
        if (!upper) ctx.expect(payload->secret.packed().is_zero(), "packed zero is the valid scalar pair (1,1)");
        const Opening boundary{payload->secret, {&*e0, &*e1}};
        auto encrypted = encrypt(recipient->public_key, boundary);
        expect_ok(ctx, encrypted, "canonical boundary scalars encrypt");
        if (!encrypted) return;
        auto relation = public_circuit(recipient->public_key, payload->public_key, *encrypted);
        auto values = assignment(recipient->public_key, payload->public_key, *encrypted, boundary);
        expect_ok(ctx, relation, "boundary public relation builds");
        expect_ok(ctx, values, "boundary witness constructs");
        if (relation && values) ctx.expect(relation->evaluate(*values), "minimum and maximum canonical payloads satisfy the native relation");
    }
    const auto proof_bytes = proof->proof.size() + proof->a_commitment.size() + proof->s_commitment.size() + proof->t2.size();
    std::cout << "companion_scalar_escrow gates=" << circuit->n_gates << " constraints=" << circuit->c.size()
              << " inner_proof_bytes=" << proof->proof.size() << " complete_proof_bytes=" << proof_bytes
              << " ciphertext_bytes=192 bridge_bytes=" << proof_bytes + 192
              << " root_and_recipient_bytes=128 context_bytes=" << context.size()
              << " all_public_bytes=" << proof_bytes + 192 + 128 + context.size()
              << " prove_ms=" << std::chrono::duration<double, std::milli>(proved - start).count()
              << " verify_and_decrypt_ms=" << std::chrono::duration<double, std::milli>(recovered - decrypt_start).count() << '\n';
}

} // namespace

void run_companion_scalar_escrow_tests(TestContext& ctx) {
    test_companion_scalar_escrow(ctx);
}
