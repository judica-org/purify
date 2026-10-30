// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <algorithm>
#include <array>
#include <span>
#include <utility>
#include <vector>

#include "purify.hpp"
#include "purify/nonce_batch.hpp"
#include "purify_test_helpers.hpp"

namespace {

using purify_test::TestContext;
using purify_test::expect_ok;

// The certificate preparer receives no scalar nonce, secret key, or assignment.
// This is a list of independent proofs, not a succinct proof of their validity.
struct PublicCoalitionPacket {
    std::vector<purify::NonceBatchGroup> groups;
    purify::Bytes proof_bytes;
};

const auto kBinding = purify::bytes_from_ascii("Purify/PublicNonceCertificate/Test/V1");

bool prepare_coalition(TestContext& ctx, purify_secp_context* context,
                       unsigned char coalition, PublicCoalitionPacket& packet) {
    std::vector<purify::GeneratedKey> keys;
    for (unsigned char member = 0; member < 2; ++member) {
        std::array<unsigned char, 32> seed{};
        seed[0] = 0xc8;
        seed[1] = coalition;
        seed[2] = member;
        auto key = purify::generate_key(seed);
        expect_ok(ctx, key, "coalition member key generates");
        if (!key.has_value()) return false;
        keys.push_back(std::move(*key));
    }

    std::vector<std::vector<purify::BulletproofAssignmentData>> assignments;
    std::vector<purify::FieldElement> expected_outputs;
    for (unsigned char domain = 0; domain < 2; ++domain) {
        for (unsigned char slot = 0; slot < 2; ++slot) {
            // These identities do not depend on the certificate batch.
            const purify::Bytes topic{0x82, coalition, domain, slot};
            auto cache = purify::puresign::TopicProofCache::build(topic);
            expect_ok(ctx, cache, "coalition topic template builds");
            if (!cache.has_value()) return false;
            purify::NonceBatchGroup group{cache->eval_input, {}};
            std::vector<purify::BulletproofAssignmentData> members;
            auto total = purify::FieldElement::zero();
            for (const auto& key : keys) {
                auto witness = purify::prove_assignment_data(group.evaluation_input, key.secret);
                expect_ok(ctx, witness, "member builds its topic witness");
                if (!witness.has_value()) return false;
                group.hosts.push_back(witness->public_key);
                total = total + witness->output;
                members.push_back(std::move(witness->assignment));
            }
            packet.groups.push_back(std::move(group));
            assignments.push_back(std::move(members));
            expected_outputs.push_back(total);
        }
    }

    auto circuit = purify::nonce_batch_circuit(packet.groups);
    auto assignment = purify::nonce_batch_assignments(packet.groups, assignments);
    expect_ok(ctx, circuit, "coalition multi-topic circuit builds");
    expect_ok(ctx, assignment, "coalition multi-topic assignment composes");
    if (!circuit.has_value() || !assignment.has_value()) return false;
    std::array<unsigned char, 32> proof_nonce{};
    proof_nonce[0] = 0x9b;
    proof_nonce[1] = coalition;
    const auto generator = purify::bppp::base_generator(context);
    auto proof = purify::prove_experimental_circuit(
        *circuit, *assignment, proof_nonce, generator, context, kBinding);
    expect_ok(ctx, proof, "coalition completes its own multi-topic proof");
    if (!proof.has_value()) return false;
    ctx.expect(proof->commitments.size() == expected_outputs.size(),
               "every coalition slot retains its own public nonce");
    if (proof->commitments.size() != expected_outputs.size()) return false;
    const std::array<unsigned char, 32> zero{};
    for (std::size_t i = 0; i < expected_outputs.size(); ++i) {
        auto expected = purify::bppp::pedersen_commit_char(
            zero, expected_outputs[i].to_bytes_be(), context, generator,
            purify::bppp::value_generator_h(context));
        expect_ok(ctx, expected, "individual slot nonce point constructs");
        if (!expected.has_value()) return false;
        ctx.expect(proof->commitments[i] == *expected,
                   "batching preserves each independently computed nonce");
    }
    auto serialized = proof->serialize();
    expect_ok(ctx, serialized, "coalition proof serializes");
    if (!serialized.has_value()) return false;
    packet.proof_bytes = std::move(*serialized);
    return true;
}

bool verify_public_packet(const PublicCoalitionPacket& packet,
                          purify_secp_context* context) {
    auto circuit = purify::nonce_batch_circuit(packet.groups);
    auto proof = purify::ExperimentalBulletproofProof::deserialize(packet.proof_bytes);
    if (!circuit.has_value() || !proof.has_value()) return false;
    auto verified = purify::verify_experimental_circuit(
        *circuit, *proof, purify::bppp::base_generator(context), context, kBinding);
    return verified.has_value() && *verified;
}

bool verify_public_packets(std::span<const PublicCoalitionPacket> packets,
                           purify_secp_context* context) {
    return !packets.empty() && std::all_of(packets.begin(), packets.end(),
        [&](const auto& packet) { return verify_public_packet(packet, context); });
}

} // namespace

void run_nonce_certificate_tests(TestContext& ctx) {
    auto context = purify::make_secp_context();
    ctx.expect(context != nullptr, "public certificate context creates");
    if (context == nullptr) return;
    std::vector<PublicCoalitionPacket> packets(2);
    if (!prepare_coalition(ctx, context.get(), 0, packets[0])
        || !prepare_coalition(ctx, context.get(), 1, packets[1])) return;

    // Both preparation calls have returned; only public packets cross this API.
    ctx.expect(verify_public_packets(packets, context.get()),
               "public-only preparer verifies two independently completed coalitions");
    std::reverse(packets.begin(), packets.end());
    ctx.expect(verify_public_packets(packets, context.get()),
               "certificate packet order does not change either coalition proof");

    auto changed = packets[0];
    changed.groups[0].evaluation_input.push_back(0x01);
    ctx.expect(!verify_public_packet(changed, context.get()),
               "public verification rejects a different slot input");
    changed = packets[0];
    std::swap(changed.groups[0], changed.groups[1]);
    ctx.expect(!verify_public_packet(changed, context.get()),
               "public verification binds the ordered topic outputs");
    changed = packets[0];
    changed.proof_bytes = packets[1].proof_bytes;
    ctx.expect(!verify_public_packet(changed, context.get()),
               "one coalition proof cannot substitute for another");
    changed = packets[0];
    changed.proof_bytes.pop_back();
    ctx.expect(!verify_public_packet(changed, context.get()),
               "public verification rejects a truncated proof");
}
