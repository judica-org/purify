// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <algorithm>
#include <array>
#include <chrono>
#include <iostream>
#include <vector>

#include "construction_receipt_helpers.hpp"
#include "purify/puresign/accountable.hpp"
#include "test_harness.hpp"

namespace {

using purify::Bytes;
using purify::FieldElement;
using purify::Result;
using purify::UInt512;
using purify_test::TestContext;
using purify_test::expect_ok;
namespace setup = purify_test::canonical_root;
namespace escrow = purify_test::scalar_escrow;
namespace receipt = purify_test::construction_receipt;

struct PublishedFixtures {
    receipt::PointBytes coalition;
    UInt512 recipient;
    receipt::Proof setup_proof;
    std::vector<receipt::EncryptionPacket> packets;
    std::vector<UInt512> leaf_owners;
    std::vector<receipt::PointBytes> punishment_keys;
};

// All witnesses are public toy fixtures, scoped to the publishers. The return
// value exposes only public data to the later construction preparer.
Result<PublishedFixtures> publish_independent_roots(const Bytes& context, purify_secp_context* secp) {
    std::array<unsigned char, 32> seed{};
    seed.fill(0x31);
    PURIFY_ASSIGN_OR_RETURN(auto alice, purify::generate_key(seed), "receipt_fixture:alice");
    seed.fill(0x43);
    PURIFY_ASSIGN_OR_RETURN(auto bob, purify::generate_key(seed), "receipt_fixture:bob");
    // Both roots predate the coalition. This centralized fixture is not MPC.
    const auto q = FieldElement::from_u64(6).negate();
    PURIFY_ASSIGN_OR_RETURN(const auto& coalition, setup::secp_point(q, secp), "receipt_fixture:coalition");
    PURIFY_ASSIGN_OR_RETURN(auto recipient, setup::root_from_scalar(q), "receipt_fixture:recipient");
    PURIFY_ASSIGN_OR_RETURN(const auto& setup_circuit,
        setup::public_setup_circuit(recipient.public_key), "receipt_fixture:setup_circuit");
    PURIFY_ASSIGN_OR_RETURN(const auto& setup_witness,
        setup::setup_assignment(recipient.public_key, q), "receipt_fixture:setup_witness");
    purify::bppp::ScalarBytes nonce{};
    nonce.fill(0x81);
    const std::array<receipt::PointBytes, 1> setup_output{coalition};
    PURIFY_ASSIGN_OR_RETURN(auto setup_proof,
        purify::bppp::prove_experimental_circuit_zk_norm_arg_with_public_commitments(
            setup_circuit, setup_witness, nonce, setup_output, secp,
            setup::binding(coalition, recipient.public_key, context)), "receipt_fixture:setup_proof");
    PublishedFixtures out{coalition, recipient.public_key, std::move(setup_proof), {}, {}, {}};
    const std::array<const purify::GeneratedKey*, 2> roots{&alice, &bob};
    for (std::size_t i = 0; i < roots.size(); ++i) {
        seed.fill(static_cast<unsigned char>(0x61 + 2 * i));
        PURIFY_ASSIGN_OR_RETURN(auto first, purify::generate_key(seed), "receipt_fixture:first_pad");
        seed.fill(static_cast<unsigned char>(0x62 + 2 * i));
        PURIFY_ASSIGN_OR_RETURN(auto second, purify::generate_key(seed), "receipt_fixture:second_pad");
        const escrow::Opening opening{roots[i]->secret, {&first, &second}};
        PURIFY_ASSIGN_OR_RETURN(const auto& ciphertext,
            escrow::encrypt(recipient.public_key, opening), "receipt_fixture:encrypt");
        PURIFY_ASSIGN_OR_RETURN(const auto& circuit,
            escrow::public_circuit(recipient.public_key, roots[i]->public_key, ciphertext), "receipt_fixture:circuit");
        PURIFY_ASSIGN_OR_RETURN(const auto& witness,
            escrow::assignment(recipient.public_key, roots[i]->public_key, ciphertext, opening), "receipt_fixture:witness");
        PURIFY_ASSIGN_OR_RETURN(const auto& generator, escrow::secp_point(FieldElement::one(), secp), "receipt_fixture:G");
        const std::array<receipt::PointBytes, 1> output{generator};
        nonce.fill(static_cast<unsigned char>(0xa1 + i));
        PURIFY_ASSIGN_OR_RETURN(auto proof,
            purify::bppp::prove_experimental_circuit_zk_norm_arg_with_public_commitments(
                circuit, witness, nonce, output, secp,
                escrow::binding(recipient.public_key, roots[i]->public_key, ciphertext, context)), "receipt_fixture:proof");
        out.packets.push_back({{roots[i]->public_key, ciphertext}, std::move(proof)});
        seed.fill(static_cast<unsigned char>(0x91 + i));
        PURIFY_ASSIGN_OR_RETURN(auto owner, purify::generate_key(seed), "receipt_fixture:leaf_owner");
        PURIFY_ASSIGN_OR_RETURN(const auto& punishment,
            escrow::shared_pad(owner.secret, roots[i]->public_key), "receipt_fixture:punishment");
        PURIFY_ASSIGN_OR_RETURN(const auto& punishment_key,
            escrow::secp_point(punishment, secp), "receipt_fixture:punishment_key");
        out.leaf_owners.push_back(owner.public_key);
        out.punishment_keys.push_back(punishment_key);
    }
    return out;
}

Result<FieldElement> toy_extracted_scalar(const receipt::PointBytes& coalition, purify_secp_context* secp) {
    const auto slot = purify::bytes_from_ascii("receipt/toy/domain/epoch/slot");
    purify::accountable::ConflictContext conflict{{}, {}, slot};
    std::copy(coalition.begin() + 1, coalition.end(), conflict.signing_key.begin());
    const auto first_body = purify::bytes_from_ascii("first toy decision");
    const auto second_body = purify::bytes_from_ascii("second toy decision");
    PURIFY_ASSIGN_OR_RETURN(const auto& e1,
        purify::accountable::signature_challenge(conflict, first_body, secp), "receipt_fixture:e1");
    PURIFY_ASSIGN_OR_RETURN(const auto& e2,
        purify::accountable::signature_challenge(conflict, second_body, secp), "receipt_fixture:e2");
    const auto q = FieldElement::from_u64(6).negate();
    const auto r = FieldElement::from_u64(9);
    PURIFY_ASSIGN_OR_RETURN(const auto& first,
        purify::accountable::ScalarSignature::deserialize((r + e1 * q).to_bytes_be()), "receipt_fixture:response1");
    PURIFY_ASSIGN_OR_RETURN(const auto& second,
        purify::accountable::ScalarSignature::deserialize((r + e2 * q).to_bytes_be()), "receipt_fixture:response2");
    PURIFY_ASSIGN_OR_RETURN(const auto& exposed,
        purify::accountable::recover_same_slot_key(conflict, first_body, first, second_body, second, secp),
        "receipt_fixture:extract");
    return FieldElement::from_bytes32(exposed);
}

void test_construction_receipt_inputs(TestContext& ctx) {
    auto secp = purify::make_secp_context();
    ctx.expect(secp != nullptr, "receipt context creates");
    if (!secp) return;
    const auto context = purify::bytes_from_ascii("public toy receipt/network/purpose/coalition");
    const auto started = std::chrono::steady_clock::now();
    auto published = publish_independent_roots(context, secp.get());
    const auto published_at = std::chrono::steady_clock::now();
    expect_ok(ctx, published, "independent publishers return only public packets");
    if (!published) return;
    const std::array<UInt512, 2> manifest{
        published->packets[0].encrypted.root, published->packets[1].encrypted.root};
    const auto prepare = [&](std::span<const receipt::EncryptionPacket> packets) {
        return receipt::prepare_inputs(published->coalition, published->recipient, context,
            manifest, published->setup_proof, packets, secp.get());
    };
    auto prepared = prepare(published->packets);
    const auto prepared_at = std::chrono::steady_clock::now();
    expect_ok(ctx, prepared, "public preparer verifies setup and every encryption");
    if (!prepared) return;
    auto encoded = receipt::statement_bytes(prepared->statement);
    expect_ok(ctx, encoded, "candidate public statement has a canonical encoding");
    if (!encoded) return;
    ctx.expect(encoded->size() == 106 + context.size() + 2 * (64 + 192),
               "full fixture encoding counts both registered roots and ciphertexts");
    ctx.expect(prepared->encryption_proofs.size() == 2,
               "future outer prover retains both public child proofs out of band");

    auto reversed = published->packets;
    std::reverse(reversed.begin(), reversed.end());
    auto reordered = prepare(reversed);
    expect_ok(ctx, reordered, "packet arrival order does not require new owner proofs");
    if (!reordered) return;
    auto reordered_bytes = receipt::statement_bytes(reordered->statement);
    ctx.expect(reordered_bytes && *reordered_bytes == *encoded,
               "authenticated manifest fixes statement order independently of arrival");
    auto changed_statement = prepared->statement;
    std::reverse(changed_statement.roots.begin(), changed_statement.roots.end());
    auto changed_bytes = receipt::statement_bytes(changed_statement);
    ctx.expect(changed_bytes && *changed_bytes != *encoded,
               "a different manifest order produces a different outer statement");

    ctx.expect(!prepare(std::span(published->packets).first(1)), "missing owner proof rejects before preparation");
    auto changed_packets = published->packets;
    changed_packets[1] = changed_packets[0];
    ctx.expect(!prepare(changed_packets), "one owner cannot cover two distinct manifest roots");
    const std::array<UInt512, 2> duplicate_manifest{manifest[0], manifest[0]};
    ctx.expect(!receipt::prepare_inputs(published->coalition, published->recipient, context,
        duplicate_manifest, published->setup_proof, published->packets, secp.get()),
        "duplicate manifest roots are not counted twice");
    changed_packets = published->packets;
    std::swap(changed_packets[0].proof, changed_packets[1].proof);
    ctx.expect(!prepare(changed_packets), "proofs remain bound to their exact old roots and ciphertexts");
    changed_packets = published->packets;
    changed_packets[0].encrypted.ciphertext.masked[0] =
        changed_packets[0].encrypted.ciphertext.masked[0] + FieldElement::one();
    ctx.expect(!prepare(changed_packets), "changed ciphertext cannot enter a prepared statement");
    auto changed_context = context;
    changed_context.push_back(0);
    ctx.expect(!receipt::prepare_inputs(published->coalition, published->recipient, changed_context,
        manifest, published->setup_proof, published->packets, secp.get()),
        "setup and encryption proofs share the exact application context");
    auto wrong_coalition = setup::secp_point(FieldElement::one(), secp.get());
    expect_ok(ctx, wrong_coalition, "another even coalition point constructs");
    if (!wrong_coalition) return;
    ctx.expect(!receipt::prepare_inputs(*wrong_coalition, published->recipient, context,
        manifest, published->setup_proof, published->packets, secp.get()),
        "the recipient setup cannot be transferred to another coalition");
    ctx.expect(!receipt::prepare_inputs(published->coalition, manifest[0], context,
        manifest, published->setup_proof, published->packets, secp.get()),
        "a different recipient cannot substitute for the setup recipient");

    const auto child_bytes = receipt::proof_bytes(prepared->setup_proof)
        + receipt::proof_bytes(prepared->encryption_proofs[0])
        + receipt::proof_bytes(prepared->encryption_proofs[1]);
    const auto public_statement = prepared->statement;
    // This is conditional recovery after statement acceptance. No outer proof
    // or receipt verifier exists yet; the preparation check above is a host
    // verifier oracle, not something an on-chain observer may trust.
    published->setup_proof = {};
    published->packets.clear();
    prepared->setup_proof = {};
    prepared->encryption_proofs.clear();
    reordered->setup_proof = {};
    reordered->encryption_proofs.clear();
    reversed.clear();
    changed_packets.clear();
    auto exposed = toy_extracted_scalar(public_statement.coalition, secp.get());
    expect_ok(ctx, exposed, "toy same-slot responses extract the coalition scalar");
    if (!exposed) return;
    auto recipient = setup::recover_root(*exposed, public_statement.coalition,
        public_statement.recipient, secp.get());
    expect_ok(ctx, recipient, "extracted scalar reconstructs the exact recipient");
    if (!recipient) return;
    for (std::size_t i = 0; i < public_statement.roots.size(); ++i) {
        const auto& encrypted = public_statement.roots[i];
        auto recovered = escrow::decrypt_payload(recipient->secret, public_statement.recipient,
            encrypted.root, encrypted.ciphertext);
        expect_ok(ctx, recovered, "public ciphertext recovers its root without the off-chain child proof");
        if (!recovered) return;
        auto punishment = escrow::shared_pad(recovered->secret, published->leaf_owners[i]);
        expect_ok(ctx, punishment, "recovered root derives its anchor punishment scalar");
        if (!punishment) return;
        auto point = escrow::secp_point(*punishment, secp.get());
        ctx.expect(point && *point == published->punishment_keys[i],
                   "receipt-only recovery matches the original owner's punishment key");
    }
    auto changed_ciphertext = public_statement.roots[0].ciphertext;
    changed_ciphertext.masked[0] = changed_ciphertext.masked[0] + FieldElement::one();
    ctx.expect(!escrow::decrypt_payload(recipient->secret, public_statement.recipient,
        public_statement.roots[0].root, changed_ciphertext), "recovery still checks the exact old root");

    std::cout << "construction_receipt roots=2 setup_children=1 encryption_children=2"
              << " off_chain_child_proof_bytes=" << child_bytes
              << " candidate_statement_bytes=" << encoded->size()
              << " recipient_and_ciphertext_bytes=" << 64 + 192 * manifest.size()
              << " compressed_proof_bytes=unimplemented"
              << " publisher_ms=" << std::chrono::duration<double, std::milli>(published_at - started).count()
              << " prepare_ms=" << std::chrono::duration<double, std::milli>(prepared_at - published_at).count() << '\n';
}

} // namespace

void run_construction_receipt_tests(TestContext& ctx) {
    test_construction_receipt_inputs(ctx);
}
