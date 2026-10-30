// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <string>
#include <vector>

#include "purify.hpp"
#include "purify_test_helpers.hpp"

namespace {

using purify_test::TestContext;
using purify_test::expect_error;
using purify_test::expect_ok;

struct Members {
    std::vector<purify::UInt512> hosts;
    std::vector<purify::BulletproofAssignmentData> assignments;
    purify::FieldElement total = purify::FieldElement::zero();
};

bool prepare_members(TestContext& ctx, const purify::Bytes& input,
                     std::size_t count, Members& members) {
    for (std::size_t i = 0; i < count; ++i) {
        std::array<unsigned char, 32> seed{};
        seed[0] = 0xa7;
        seed[30] = static_cast<unsigned char>(i >> 8);
        seed[31] = static_cast<unsigned char>(i);
        auto key = purify::generate_key(std::span<const unsigned char>{seed});
        expect_ok(ctx, key, "aggregate member key generation succeeds");
        if (!key.has_value()) return false;
        auto witness = purify::prove_assignment_data(input, key->secret);
        expect_ok(ctx, witness, "each member independently builds its witness");
        if (!witness.has_value()) return false;
        members.hosts.push_back(witness->public_key);
        members.total = members.total + witness->output;
        members.assignments.push_back(std::move(witness->assignment));
    }
    return true;
}

void test_sum_circuit(TestContext& ctx, std::size_t count) {
    const purify::Bytes input = purify::bytes_from_ascii("Purify/AggregateCircuit/Test/V1");
    auto circuit_template = purify::verifier_circuit_template(input);
    expect_ok(ctx, circuit_template, "aggregate circuit template builds");
    if (!circuit_template.has_value()) return;
    Members members;
    if (!prepare_members(ctx, input, count, members)) return;
    auto circuit = circuit_template->instantiate_sum(members.hosts);
    auto assignment = circuit_template->sum_assignments(members.hosts, members.assignments);
    expect_ok(ctx, circuit, "ordered aggregate circuit instantiates");
    expect_ok(ctx, assignment, "valid member assignments compose");
    if (!circuit.has_value() || !assignment.has_value()) return;

    ctx.expect(circuit->n_commitments == 1, "aggregate has exactly one public commitment");
    ctx.expect(circuit->n_bits == 0, "aggregate retains explicit local bit constraints");
    ctx.expect(circuit->n_gates == std::bit_ceil(count * members.assignments[0].left.size()),
               "aggregate pads the combined gate count only once");
    ctx.expect(assignment->commitments.size() == 1 && assignment->commitments[0] == members.total,
               "aggregate commitment is the field sum of all member outputs");
    ctx.expect(circuit->evaluate(*assignment), "aggregate witness satisfies the circuit");

    assignment->commitments[0] = assignment->commitments[0] + purify::FieldElement::one();
    ctx.expect(!circuit->evaluate(*assignment), "circuit rejects a different aggregate nonce");
    assignment->commitments[0] = members.total;
    assignment->left[0] = assignment->left[0] + purify::FieldElement::one();
    ctx.expect(!circuit->evaluate(*assignment), "circuit rejects a changed member witness");
    assignment->left[0] = assignment->left[0] - purify::FieldElement::one();
    const std::size_t last_member = (count - 1) * members.assignments[0].left.size();
    assignment->left[last_member] = assignment->left[last_member] + purify::FieldElement::one();
    ctx.expect(!circuit->evaluate(*assignment), "circuit rejects a changed last member witness");
}

void test_sum_bindings(TestContext& ctx) {
    const purify::Bytes input = purify::bytes_from_ascii("Purify/AggregateCircuit/Bindings/V1");
    auto circuit_template = purify::verifier_circuit_template(input);
    expect_ok(ctx, circuit_template, "binding test template builds");
    if (!circuit_template.has_value()) return;
    Members members;
    if (!prepare_members(ctx, input, 3, members)) return;
    auto assignment = circuit_template->sum_assignments(members.hosts, members.assignments);
    expect_ok(ctx, assignment, "binding test assignment composes");
    if (!assignment.has_value()) return;

    auto reversed_hosts = members.hosts;
    std::reverse(reversed_hosts.begin(), reversed_hosts.end());
    auto reordered = circuit_template->instantiate_sum(reversed_hosts);
    expect_ok(ctx, reordered, "a different ordered roster instantiates");
    if (reordered.has_value()) {
        ctx.expect(!reordered->evaluate(*assignment), "member witnesses bind their ordered hosts");
        auto reversed_assignments = members.assignments;
        std::reverse(reversed_assignments.begin(), reversed_assignments.end());
        auto reversed = circuit_template->sum_assignments(reversed_hosts, reversed_assignments);
        expect_ok(ctx, reversed, "reordering hosts and witnesses together composes");
        if (reversed.has_value()) {
            ctx.expect(reordered->evaluate(*reversed), "consistently reordered aggregate satisfies the circuit");
            ctx.expect(reversed->commitments == assignment->commitments,
                       "consistent reordering preserves the commutative output sum");
        }
    }
    ctx.expect(!circuit_template->sum_assignments(reversed_hosts, members.assignments).has_value(),
               "composition rejects witnesses for a different ordered roster");

    auto other_template = purify::verifier_circuit_template(purify::Bytes{0x99});
    expect_ok(ctx, other_template, "different input template builds");
    if (other_template.has_value()) {
        auto other_circuit = other_template->instantiate_sum(members.hosts);
        expect_ok(ctx, other_circuit, "different input aggregate instantiates");
        if (other_circuit.has_value()) {
            ctx.expect(!other_circuit->evaluate(*assignment), "aggregate witness binds the evaluation input");
        }
    }

    ctx.expect(!circuit_template->instantiate_sum({}).has_value(), "empty roster rejects");
    ctx.expect(!circuit_template->sum_assignments({}, {}).has_value(), "empty witness aggregate rejects");
    auto duplicates = members.hosts;
    duplicates[1] = duplicates[0];
    expect_error(ctx, circuit_template->instantiate_sum(duplicates), purify::ErrorCode::BindingMismatch,
                 "duplicate hosts reject");
    auto invalid_hosts = members.hosts;
    invalid_hosts[0] = purify::UInt512::from_hex(std::string(128, 'f'));
    ctx.expect(!circuit_template->instantiate_sum(invalid_hosts).has_value(), "invalid packed host rejects");

    auto malformed = members.assignments;
    malformed[1].left.pop_back();
    ctx.expect(!circuit_template->sum_assignments(members.hosts, malformed).has_value(),
               "composition rejects malformed member dimensions");
    malformed = members.assignments;
    malformed[1].commitments[0] = malformed[1].commitments[0] + purify::FieldElement::one();
    ctx.expect(!circuit_template->sum_assignments(members.hosts, malformed).has_value(),
               "composition validates each member output before summing");
    malformed.pop_back();
    ctx.expect(!circuit_template->sum_assignments(members.hosts, malformed).has_value(),
               "composition rejects a missing member");
}

void test_sum_proof(TestContext& ctx) {
    auto context = purify::make_secp_context();
    ctx.expect(context != nullptr, "aggregate proof context creates");
    if (context == nullptr) return;
    const purify::Bytes input = purify::bytes_from_ascii("Purify/AggregateCircuit/Proof/V1");
    auto circuit_template = purify::verifier_circuit_template(input);
    expect_ok(ctx, circuit_template, "aggregate proof template builds");
    if (!circuit_template.has_value()) return;
    Members members;
    if (!prepare_members(ctx, input, 3, members)) return;
    auto circuit = circuit_template->instantiate_sum(members.hosts);
    auto assignment = circuit_template->sum_assignments(members.hosts, members.assignments);
    expect_ok(ctx, circuit, "proof circuit instantiates");
    expect_ok(ctx, assignment, "proof assignment composes");
    if (!circuit.has_value() || !assignment.has_value()) return;
    std::array<unsigned char, 32> proof_nonce{};
    proof_nonce.fill(0x52);
    const auto generator = purify::bppp::base_generator(context.get());
    const auto binding = purify::bytes_from_ascii("Purify/AggregateCircuit/ArithmeticProof/V1");
    // Imported arithmetic-circuit backend, not the experimental BP++ wrapper.
    auto proof = purify::prove_experimental_circuit(
        *circuit, *assignment, proof_nonce, generator, context.get(), binding);
    expect_ok(ctx, proof, "aggregate arithmetic proof produces");
    if (!proof.has_value()) return;
    const std::array<unsigned char, 32> zero{};
    auto expected_nonce = purify::bppp::pedersen_commit_char(
        zero, members.total.to_bytes_be(), context.get(), generator,
        purify::bppp::value_generator_h(context.get()));
    expect_ok(ctx, expected_nonce, "independent summed nonce point constructs");
    if (expected_nonce.has_value()) {
        ctx.expect(proof->commitments.front() == *expected_nonce, "proof commits exactly to sum(r_i) times G");
    }
    auto encoded = proof->serialize();
    expect_ok(ctx, encoded, "aggregate proof serializes");
    if (!encoded.has_value()) return;
    auto decoded = purify::ExperimentalBulletproofProof::deserialize(*encoded);
    expect_ok(ctx, decoded, "aggregate proof parses");
    if (!decoded.has_value()) return;
    auto verified = purify::verify_experimental_circuit(
        *circuit, *decoded, generator, context.get(), binding);
    expect_ok(ctx, verified, "aggregate arithmetic verification runs");
    if (verified.has_value()) ctx.expect(*verified, "serialized aggregate arithmetic proof verifies");

    auto changed_binding = binding;
    changed_binding.back() ^= 1;
    auto wrong_binding = purify::verify_experimental_circuit(
        *circuit, *proof, generator, context.get(), changed_binding);
    ctx.expect(!wrong_binding.has_value() || !*wrong_binding, "proof rejects changed statement binding");

    std::reverse(members.hosts.begin(), members.hosts.end());
    auto reordered = circuit_template->instantiate_sum(members.hosts);
    expect_ok(ctx, reordered, "reordered public proof circuit builds");
    if (reordered.has_value()) {
        auto wrong_roster = purify::verify_experimental_circuit(
            *reordered, *proof, generator, context.get(), binding);
        ctx.expect(!wrong_roster.has_value() || !*wrong_roster,
                   "proof rejects a changed roster order even though its nonce sum is unchanged");
    }

    auto other_point = purify::bppp::pedersen_commit_char(
        zero, (members.total + purify::FieldElement::one()).to_bytes_be(),
        context.get(), generator, purify::bppp::value_generator_h(context.get()));
    expect_ok(ctx, other_point, "different valid nonce point constructs");
    if (other_point.has_value()) {
        auto changed_nonce = *proof;
        changed_nonce.commitments.front() = *other_point;
        auto wrong_nonce = purify::verify_experimental_circuit(
            *circuit, changed_nonce, generator, context.get(), binding);
        ctx.expect(!wrong_nonce.has_value() || !*wrong_nonce, "proof rejects a changed aggregate nonce point");
    }
}

} // namespace

void run_aggregate_nonce_tests(TestContext& ctx) {
    test_sum_circuit(ctx, 1);
    test_sum_circuit(ctx, 3);
    test_sum_bindings(ctx);
    test_sum_proof(ctx);
}

void run_aggregate_nonce_100_tests(TestContext& ctx) {
    // Centralized arithmetic validation only: these witnesses are all visible
    // to this test process. This does not exercise an MPC protocol.
    test_sum_circuit(ctx, 100);
}
