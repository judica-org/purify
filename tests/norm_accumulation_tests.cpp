// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <algorithm>
#include <array>
#include <cstddef>
#include <span>
#include <utility>
#include <vector>

#include "../src/protocol/algebraic_circuit_accumulation.hpp"
#include "purify/accumulation.hpp"
#include "test_harness.hpp"

namespace {

using purify::FieldElement;
using purify::NativeBulletproofCircuit;
using purify::bppp::PointBytes;
using purify::bppp::ScalarBytes;
using purify_test::TestContext;
using purify_test::expect_ok;
namespace accum = purify::bppp::accumulation;
namespace candidate = purify::bppp::candidate;

candidate::TranscriptDigest raw_generator_digest(
    std::span<const PointBytes> generators) {
    candidate::TranscriptDigest digest{};
    const auto bytes = std::as_bytes(generators);
    purify_sha256(
        digest.data(),
        reinterpret_cast<const unsigned char*>(bytes.data()),
        bytes.size());
    return digest;
}

purify::Result<PointBytes> scalar_point(const FieldElement& scalar,
                                        purify_secp_context* secp) {
    const ScalarBytes zero{};
    return purify::bppp::pedersen_commit_char(
        zero, scalar.to_bytes_be(), secp,
        purify::bppp::base_generator(secp),
        purify::bppp::base_generator(secp));
}

purify::Result<accum::AlgebraicPreparedNorm>
prepare_hidden_v4_algebraic(
    const accum::Basis& basis,
    const NativeBulletproofCircuit& circuit,
    const purify::BulletproofAssignmentData& assignment,
    unsigned char seed_byte, std::span<const unsigned char> binding,
    purify_secp_context* secp) {
    ScalarBytes seed{};
    seed.fill(seed_byte);
    PURIFY_ASSIGN_OR_RETURN(auto publication,
                            candidate::prove_circuit_zk_norm_arg_v4(
                                circuit, assignment, seed, secp, binding));
    PURIFY_ASSIGN_OR_RETURN(auto prepared,
                            candidate::prepare_circuit_zk_norm_arg_v4(
                                circuit, publication, secp, binding));
    if (!prepared.has_value()) {
        return purify::unexpected_error(purify::ErrorCode::EquationMismatch);
    }
    return accum::prepare_v4_circuit_norm_for_algebraic_reduction(
        basis, std::move(*prepared), secp);
}

void check_v4_algebraic_circuit_adapter(
    TestContext& ctx, purify_secp_context* secp) {
    NativeBulletproofCircuit circuit(4, 1, 0);
    const auto constraint =
        circuit.add_constraint(FieldElement::zero());
    circuit.add_output_term(
        0, constraint, FieldElement::one());
    circuit.add_commitment_term(
        0, constraint, FieldElement::from_int(-1));

    purify::BulletproofAssignmentData assignment;
    assignment.left = {
        FieldElement::from_int(3), FieldElement::from_int(5),
        FieldElement::from_int(9), FieldElement::from_int(11)};
    assignment.right = {
        FieldElement::from_int(4), FieldElement::from_int(6),
        FieldElement::from_int(2), FieldElement::from_int(3)};
    assignment.output = {
        FieldElement::from_int(12), FieldElement::from_int(30),
        FieldElement::from_int(18), FieldElement::from_int(33)};
    assignment.commitments = {FieldElement::from_int(12)};
    ScalarBytes prover_seed{};
    prover_seed.fill(0x64);
    const auto binding =
        purify::bytes_from_ascii("test/v4-algebraic-adapter/v1");

    auto basis = accum::Basis::create(
        8, 8, "test/v4-algebraic-circuit/v1", secp);
    expect_ok(ctx, basis, "V4 algebraic raw basis creates");
    if (!basis) return;
    auto publication = candidate::prove_circuit_zk_norm_arg_v4(
        circuit, assignment, prover_seed, secp, binding);
    expect_ok(ctx, publication, "V4 hidden proof publishes");
    if (!publication) return;
    auto prepared = candidate::prepare_circuit_zk_norm_arg_v4(
        circuit, *publication, secp, binding);
    expect_ok(ctx, prepared,
              "V4 hidden outer statement prepares");
    if (!prepared || !prepared->has_value()) {
        ctx.expect(false,
                   "V4 hidden preparation returns a pending norm");
        return;
    }
    const auto standalone = candidate::verify_circuit_zk_norm_arg_v4(
        circuit, *publication, secp, binding);
    ctx.expect(standalone && *standalone,
               "V4 full verification remains a separate path");

    auto reconstructed =
        candidate::reconstruct_circuit_zk_norm_arg_publication_v4(
            circuit, publication->proof, secp, binding);
    expect_ok(ctx, reconstructed,
              "V4 hidden proof fields reconstruct their publication");
    if (!reconstructed) return;
    ctx.expect(reconstructed->precommitment.bytes() ==
                   publication->precommitment.bytes(),
               "V4 hidden reconstruction derives the exact precommitment");
    auto malformed_round = publication->proof;
    malformed_round.norm_proof[0] = 4;
    ctx.expect(
        !candidate::validate_circuit_zk_norm_arg_proof_v4_encoding(
            circuit, malformed_round, secp),
        "V4 fixed-round validation rejects a noncanonical parity byte");
    auto hidden_dlog = publication->proof;
    hidden_dlog.public_commitment_dlog_response.back() = 1;
    ctx.expect(
        !candidate::validate_circuit_zk_norm_arg_proof_v4_encoding(
            circuit, hidden_dlog, secp),
        "V4 hidden encoding rejects public DLog material");
    auto changed_raw = publication->proof;
    changed_raw.raw_commitment = publication->proof.mask_commitment;
    auto changed_raw_publication =
        candidate::reconstruct_circuit_zk_norm_arg_publication_v4(
            circuit, std::move(changed_raw), secp, binding);
    expect_ok(ctx, changed_raw_publication,
              "V4 changed raw point remains canonical");
    if (!changed_raw_publication) return;
    ctx.expect(changed_raw_publication->precommitment.bytes() !=
                   publication->precommitment.bytes(),
               "V4 precommitment binds the raw point");
    const auto changed_statement =
        purify::bytes_from_ascii("test/v4-algebraic-adapter/changed");
    auto changed_statement_publication =
        candidate::reconstruct_circuit_zk_norm_arg_publication_v4(
            circuit, publication->proof, secp, changed_statement);
    expect_ok(ctx, changed_statement_publication,
              "V4 changed statement reconstructs canonically");
    if (!changed_statement_publication) return;
    ctx.expect(changed_statement_publication->precommitment.bytes() !=
                   publication->precommitment.bytes(),
               "V4 precommitment binds the exact statement");

    auto other_basis = accum::Basis::create(
        8, 8, "test/v4-algebraic-circuit/other", secp);
    expect_ok(ctx, other_basis,
              "V4 alternative semantic basis creates");
    if (!other_basis) return;
    auto other_algebraic =
        accum::prepare_v4_circuit_norm_for_algebraic_reduction(
            *other_basis, **prepared, secp);
    expect_ok(ctx, other_algebraic,
              "purpose owner can select another semantic digest over shared raw points");
    if (!other_algebraic) return;
    auto wrong_shape = accum::Basis::create(
        16, 8, "test/v4-algebraic-circuit/v1", secp);
    expect_ok(ctx, wrong_shape,
              "V4 alternative raw-basis shape creates");
    if (!wrong_shape) return;
    expect_error(
        ctx,
        accum::prepare_v4_circuit_norm_for_algebraic_reduction(
            *wrong_shape, **prepared, secp),
        purify::ErrorCode::BindingMismatch,
        "V4 adapter rejects raw-basis shape substitution");

    const auto expected_binding =
        (**prepared).transcript().prepared_binding.scalar;
    const auto expected_commitment =
        (**prepared).transcript_input().coefficient_commitment;
    const auto expected_residual =
        (**prepared).pending_norm_residual();
    const auto expected_coefficients =
        (**prepared).norm().c_vec;
    const auto& prepared_transcript = (**prepared).transcript();
    const auto& prepared_input = (**prepared).transcript_input();
    auto terminal_n = FieldElement::try_from_bytes32(
        prepared_input.terminal_n);
    auto terminal_l = FieldElement::try_from_bytes32(
        prepared_input.terminal_l);
    auto sqrt_minus_one_inverse = FieldElement::try_from_bytes32(
        purify::UInt256::from_hex(
            "8f52b651807a8b13549be5bd4c5db0dbe4779cc31afbd9d6"
            "1915afdbdcba81c9")
            .to_bytes_be());
    expect_ok(ctx, terminal_n, "V4 terminal n is canonical");
    expect_ok(ctx, terminal_l, "V4 terminal l is canonical");
    expect_ok(ctx, sqrt_minus_one_inverse,
              "Rust leaf square-root inverse is canonical");
    if (!terminal_n || !terminal_l || !sqrt_minus_one_inverse) return;
    auto rho_to_n = FieldElement::one();
    for (std::size_t i = 0; i < basis->n_vec_len(); ++i) {
        rho_to_n = rho_to_n * prepared_transcript.rho.scalar;
    }
    const auto expected_g_scale =
        *terminal_n * rho_to_n *
        prepared_transcript.mul_scale.scalar.inverse();
    std::vector<FieldElement> expected_g_factors;
    std::vector<FieldElement> expected_h_factors;
    expected_g_factors.reserve(prepared_transcript.gammas.size());
    expected_h_factors.reserve(prepared_transcript.gammas.size());
    auto ratio_inverse_power =
        prepared_transcript.mul_ratio.scalar.inverse();
    for (std::size_t i = 0;
         i < prepared_transcript.gammas.size(); ++i) {
        const auto gamma = prepared_transcript.gammas[i].scalar;
        expected_g_factors.push_back(
            i == 0 ? gamma * *sqrt_minus_one_inverse
                   : gamma * ratio_inverse_power);
        if (i != 0) {
            ratio_inverse_power =
                ratio_inverse_power * ratio_inverse_power;
        }
        expected_h_factors.push_back(gamma);
    }
    ctx.expect(expected_g_factors.size() == 3 &&
                   expected_h_factors.size() == 3,
               "V4 adapter fixture reaches the third norm factor");
    auto algebraic =
        accum::prepare_v4_circuit_norm_for_algebraic_reduction(
            *basis, std::move(**prepared), secp);
    expect_ok(ctx, algebraic,
              "V4 pending norm maps to algebraic reduction data");
    if (!algebraic) return;
    ctx.expect(algebraic->prepared_binding() == expected_binding &&
                   algebraic->coefficient_commitment() ==
                       expected_commitment &&
                   algebraic->residual() == expected_residual &&
                   algebraic->c_vec() == expected_coefficients,
               "V4 adapter retains authenticated binding, coefficients, and points");
    const auto& polynomial = algebraic->polynomial();
    ctx.expect(
        polynomial[0].scale == expected_g_scale &&
            polynomial[0].offset == 0 &&
            polynomial[0].factors == expected_g_factors &&
            polynomial[1].scale == *terminal_l &&
            polynomial[1].offset == basis->n_vec_len() &&
            polynomial[1].factors == expected_h_factors,
        "V4 adapter matches both compact Rust leaf polynomial terms");

    auto reduction = accum::prove_algebraic_norm_reduction(
        *basis, *algebraic, secp);
    expect_ok(ctx, reduction,
              "V4 algebraic coefficient reduction proves");
    if (!reduction) return;
    auto claim = accum::verify_algebraic_norm_reduction(
        *basis, *algebraic, *reduction, secp);
    expect_ok(ctx, claim,
              "V4 algebraic coefficient reduction verifies");
    if (!claim) return;
    expect_ok(ctx, accum::decide(*basis, *claim, secp),
              "V4 hidden pending norm reaches mandatory decision");
    ctx.expect(
        !accum::verify_algebraic_norm_reduction(
            *other_basis, *other_algebraic, *reduction, secp),
        "fixed V4 reduction rejects changing the caller-selected semantic digest");

    const auto wrong_binding =
        purify::bytes_from_ascii("test/v4-algebraic-adapter/wrong");
    auto changed_binding = candidate::prepare_circuit_zk_norm_arg_v4(
        circuit, *publication, secp, wrong_binding);
    ctx.expect(changed_binding && !changed_binding->has_value(),
               "V4 preparation rejects binding substitution");

    auto changed_circuit = circuit;
    const auto changed_constraint =
        changed_circuit.add_constraint(FieldElement::one());
    changed_circuit.add_left_term(
        0, changed_constraint, FieldElement::one());
    auto changed_coefficients =
        candidate::prepare_circuit_zk_norm_arg_v4(
            changed_circuit, *publication, secp, binding);
    ctx.expect(changed_coefficients &&
                   !changed_coefficients->has_value(),
               "V4 preparation rejects coefficient-circuit substitution");

    purify::BulletproofAssignmentData second_assignment;
    second_assignment.left = {
        FieldElement::from_int(7), FieldElement::from_int(8),
        FieldElement::from_int(5), FieldElement::from_int(6)};
    second_assignment.right = {
        FieldElement::from_int(2), FieldElement::from_int(3),
        FieldElement::from_int(4), FieldElement::from_int(5)};
    second_assignment.output = {
        FieldElement::from_int(14), FieldElement::from_int(24),
        FieldElement::from_int(20), FieldElement::from_int(30)};
    second_assignment.commitments = {FieldElement::from_int(14)};
    ScalarBytes second_seed{};
    second_seed.fill(0x65);
    auto second_publication =
        candidate::prove_circuit_zk_norm_arg_v4(
            circuit, second_assignment, second_seed, secp, binding);
    expect_ok(ctx, second_publication,
              "second V4 gamma source publishes");
    if (!second_publication) return;
    auto changed_gamma = *publication;
    const auto late_round = expected_h_factors.size() - 1;
    const auto late_round_offset =
        late_round * sizeof(candidate::PackedPointPairV4);
    std::copy_n(
        second_publication->proof.norm_proof.begin() +
            static_cast<std::ptrdiff_t>(late_round_offset),
        sizeof(candidate::PackedPointPairV4),
        changed_gamma.proof.norm_proof.begin() +
            static_cast<std::ptrdiff_t>(late_round_offset));
    auto changed_gamma_prepared =
        candidate::prepare_circuit_zk_norm_arg_v4(
            circuit, changed_gamma, secp, binding);
    expect_ok(ctx, changed_gamma_prepared,
              "changed V4 round remains a pending inner obligation");
    if (!changed_gamma_prepared ||
        !changed_gamma_prepared->has_value()) {
        ctx.expect(false,
                   "changed V4 round has canonical proof encodings");
        return;
    }
    ctx.expect(
        (**changed_gamma_prepared).transcript().gammas[late_round].scalar !=
            expected_h_factors[late_round],
        "late V4 round substitution changes its explicit gamma");
    auto changed_gamma_algebraic =
        accum::prepare_v4_circuit_norm_for_algebraic_reduction(
            *basis, std::move(**changed_gamma_prepared), secp);
    expect_ok(ctx, changed_gamma_algebraic,
              "V4 adapter binds the substituted explicit gamma");
    if (!changed_gamma_algebraic) return;
    auto changed_gamma_reduction =
        accum::prove_algebraic_norm_reduction(
            *basis, *changed_gamma_algebraic, secp);
    expect_ok(ctx, changed_gamma_reduction,
              "changed-gamma coefficient opening proves");
    if (!changed_gamma_reduction) return;
    auto changed_gamma_claim =
        accum::verify_algebraic_norm_reduction(
            *basis, *changed_gamma_algebraic,
            *changed_gamma_reduction, secp);
    expect_ok(ctx, changed_gamma_claim,
              "changed-gamma reduction remains pending");
    if (!changed_gamma_claim) return;
    ctx.expect(!accum::decide(
                   *basis, *changed_gamma_claim, secp),
               "mandatory decision rejects gamma substitution");

    auto public_point = scalar_point(
        assignment.commitments[0], secp);
    expect_ok(ctx, public_point,
              "V4 public commitment point derives");
    if (!public_point) return;
    const std::array<PointBytes, 1> public_points{*public_point};
    auto public_publication =
        candidate::prove_circuit_zk_norm_arg_v4_with_public_commitments(
            circuit, assignment, prover_seed, public_points, secp,
            binding);
    expect_ok(ctx, public_publication, "V4 public proof publishes");
    if (!public_publication) return;
    auto public_prepared = candidate::
        prepare_circuit_zk_norm_arg_v4_with_public_commitments(
            circuit, *public_publication, public_points, secp, binding);
    expect_ok(ctx, public_prepared,
              "V4 public outer statement prepares");
    if (!public_prepared || !public_prepared->has_value()) {
        ctx.expect(false,
                   "V4 public preparation returns a pending norm");
        return;
    }
    auto reconstructed_public = candidate::
        reconstruct_circuit_zk_norm_arg_publication_v4_with_public_commitments(
            circuit, public_publication->proof, public_points, secp,
            binding);
    expect_ok(ctx, reconstructed_public,
              "V4 public proof fields reconstruct their publication");
    if (!reconstructed_public) return;
    ctx.expect(reconstructed_public->precommitment.bytes() ==
                   public_publication->precommitment.bytes(),
               "V4 public reconstruction derives the exact precommitment");
    auto changed_public_point = scalar_point(
        assignment.commitments[0] + FieldElement::one(), secp);
    expect_ok(ctx, changed_public_point,
              "V4 changed public output point derives");
    if (!changed_public_point) return;
    const std::array<PointBytes, 1> changed_public_points{
        *changed_public_point};
    auto changed_public_output = candidate::
        reconstruct_circuit_zk_norm_arg_publication_v4_with_public_commitments(
            circuit, public_publication->proof, changed_public_points,
            secp, binding);
    expect_ok(ctx, changed_public_output,
              "V4 changed public output reconstructs canonically");
    if (!changed_public_output) return;
    ctx.expect(changed_public_output->precommitment.bytes() !=
                   public_publication->precommitment.bytes(),
               "V4 precommitment binds the exact public output");
    auto public_algebraic =
        accum::prepare_v4_circuit_norm_for_algebraic_reduction(
            *basis, **public_prepared, secp);
    expect_ok(ctx, public_algebraic,
              "V4 public pending norm maps to algebraic data");
    if (!public_algebraic) return;
    auto public_reduction = accum::prove_algebraic_norm_reduction(
        *basis, *public_algebraic, secp);
    expect_ok(ctx, public_reduction,
              "V4 public coefficient reduction proves");
    if (!public_reduction) return;
    auto public_claim = accum::verify_algebraic_norm_reduction(
        *basis, *public_algebraic, *public_reduction, secp);
    expect_ok(ctx, public_claim,
              "V4 public coefficient reduction verifies");
    if (!public_claim) return;
    expect_ok(ctx, accum::decide(*basis, *public_claim, secp),
              "V4 public pending norm reaches mandatory decision");
    auto public_parent_constants = candidate::
        derive_circuit_norm_parent_constants_v4_with_public_commitments(
            circuit, public_publication->precommitment, public_points,
            secp, binding);
    expect_ok(ctx, public_parent_constants,
              "V4 public parent constants derive without raw A");
    if (!public_parent_constants) return;
    ctx.expect(
        public_parent_constants->raw_generator_digest ==
                raw_generator_digest(
                    (**public_prepared).raw_generators()) &&
            public_parent_constants->coefficient_commitment ==
                (**public_prepared)
                    .transcript_input()
                    .coefficient_commitment &&
            public_parent_constants->anchored_offset ==
                (**public_prepared).transcript_input().anchored_offset,
        "V4 public parent constants match full preparation");
}

void check_algebraic_suite(TestContext& ctx,
                           purify_secp_context* secp) {
    auto basis = accum::Basis::create(
        4, 4, "test/algebraic-accumulation/v2", secp);
    expect_ok(ctx, basis, "algebraic accumulation basis creates");
    if (!basis) return;

    NativeBulletproofCircuit circuit(2, 1, 0);
    const auto constraint =
        circuit.add_constraint(FieldElement::zero());
    circuit.add_output_term(
        0, constraint, FieldElement::one());
    circuit.add_commitment_term(
        0, constraint, FieldElement::from_int(-1));
    const auto binding =
        purify::bytes_from_ascii("test/algebraic-v4-suite/v1");

    purify::BulletproofAssignmentData first_assignment;
    first_assignment.left = {
        FieldElement::from_int(3), FieldElement::from_int(5)};
    first_assignment.right = {
        FieldElement::from_int(4), FieldElement::from_int(6)};
    first_assignment.output = {
        FieldElement::from_int(12), FieldElement::from_int(30)};
    first_assignment.commitments = {FieldElement::from_int(12)};
    auto algebraic_prepared = prepare_hidden_v4_algebraic(
        *basis, circuit, first_assignment, 0x71, binding, secp);
    expect_ok(ctx, algebraic_prepared,
              "authenticated V4 algebraic fixture prepares");
    if (!algebraic_prepared) return;

    auto reduction = accum::prove_algebraic_norm_reduction(
        *basis, *algebraic_prepared, secp);
    expect_ok(ctx, reduction, "algebraic coefficient reduction proves");
    if (!reduction) return;
    auto reduction_bytes = accum::serialize_algebraic_norm_reduction(
        *basis, *reduction, secp);
    expect_ok(ctx, reduction_bytes,
              "algebraic coefficient reduction serializes");
    if (!reduction_bytes) return;
    ctx.expect((*reduction_bytes)[0] == 2,
               "algebraic reduction has its own version byte");
    auto wrong_reduction_version = *reduction_bytes;
    wrong_reduction_version.front() = 1;
    ctx.expect(!accum::parse_algebraic_norm_reduction(
                   *basis, wrong_reduction_version, secp),
               "version-2 reduction parser rejects version 1");
    auto parsed_reduction =
        accum::parse_algebraic_norm_reduction(
            *basis, *reduction_bytes, secp);
    expect_ok(ctx, parsed_reduction,
              "algebraic coefficient reduction parses");
    if (!parsed_reduction) return;
    auto claim = accum::verify_algebraic_norm_reduction(
        *basis, *algebraic_prepared, *parsed_reduction, secp);
    expect_ok(ctx, claim,
              "algebraic coefficient reduction verifies");
    if (!claim) return;
    expect_ok(ctx, accum::decide(*basis, *claim, secp),
              "algebraic coefficient reduction decides");
    auto changed_reduction = *parsed_reduction;
    auto reduction_evaluation = FieldElement::try_from_bytes32(
        parsed_reduction->coefficient_evaluation);
    expect_ok(ctx, reduction_evaluation,
              "algebraic coefficient evaluation is canonical");
    if (!reduction_evaluation) return;
    changed_reduction.coefficient_evaluation =
        (*reduction_evaluation + FieldElement::one()).to_bytes_be();
    ctx.expect(!accum::verify_algebraic_norm_reduction(
                   *basis, *algebraic_prepared,
                   changed_reduction, secp),
               "algebraic reduction rejects a changed coefficient evaluation");

    purify::BulletproofAssignmentData second_assignment;
    second_assignment.left = {
        FieldElement::from_int(7), FieldElement::from_int(8)};
    second_assignment.right = {
        FieldElement::from_int(2), FieldElement::from_int(3)};
    second_assignment.output = {
        FieldElement::from_int(14), FieldElement::from_int(24)};
    second_assignment.commitments = {FieldElement::from_int(14)};
    auto second_algebraic_prepared = prepare_hidden_v4_algebraic(
        *basis, circuit, second_assignment, 0x72, binding, secp);
    expect_ok(ctx, second_algebraic_prepared,
              "second authenticated V4 fixture prepares");
    if (!second_algebraic_prepared) return;
    ctx.expect(!accum::verify_algebraic_norm_reduction(
                   *basis, *second_algebraic_prepared,
                   *parsed_reduction, secp),
               "algebraic reduction binds its authenticated V4 child");
    auto second_reduction =
        accum::prove_algebraic_norm_reduction(
            *basis, *second_algebraic_prepared, secp);
    expect_ok(ctx, second_reduction,
              "second algebraic reduction proves");
    if (!second_reduction) return;
    auto second_claim =
        accum::verify_algebraic_norm_reduction(
            *basis, *second_algebraic_prepared,
            *second_reduction, secp);
    expect_ok(ctx, second_claim,
              "second algebraic reduction verifies");
    if (!second_claim) return;
    expect_ok(ctx, accum::decide(*basis, *second_claim, secp),
              "second algebraic reduction decides");

    const std::array claims{*claim, *second_claim};
    auto step = accum::prove_algebraic_step(
        *basis, claims, secp);
    expect_ok(ctx, step, "algebraic accumulation step proves");
    if (!step) return;
    auto step_bytes = accum::serialize_algebraic_step(
        *basis, *step, secp);
    expect_ok(ctx, step_bytes,
              "algebraic accumulation step serializes");
    if (!step_bytes) return;
    ctx.expect((*step_bytes)[0] == 2,
               "algebraic step has its own version byte");
    auto wrong_step_version = *step_bytes;
    wrong_step_version.front() = 1;
    ctx.expect(!accum::parse_algebraic_step(*basis, wrong_step_version, secp),
               "version-2 step parser rejects version 1");
    auto parsed_step = accum::parse_algebraic_step(
        *basis, *step_bytes, secp);
    expect_ok(ctx, parsed_step, "algebraic accumulation step parses");
    if (!parsed_step) return;
    ctx.expect(!accum::parse_algebraic_step(
                   *basis, *reduction_bytes, secp),
               "algebraic step parser rejects a coefficient-reduction proof");
    ctx.expect(!accum::parse_algebraic_norm_reduction(
                   *basis, *step_bytes, secp),
               "algebraic reduction parser rejects an accumulation-step proof");
    auto root = accum::verify_algebraic_step(
        *basis, claims, *parsed_step, secp);
    expect_ok(ctx, root, "algebraic accumulation step verifies");
    if (!root) return;
    expect_ok(ctx, accum::decide(*basis, *root, secp),
              "algebraic accumulation root decides");
    auto step_terminal = FieldElement::try_from_bytes32(
        parsed_step->terminal_scalar);
    expect_ok(ctx, step_terminal,
              "algebraic step terminal scalar is canonical");
    if (!step_terminal) return;
    auto changed_step = *parsed_step;
    changed_step.terminal_scalar =
        (*step_terminal + FieldElement::one()).to_bytes_be();
    ctx.expect(!accum::verify_algebraic_step(
                   *basis, claims, changed_step, secp),
               "algebraic step rejects a changed terminal scalar");

    auto root_bytes = accum::serialize_root_claim(
        *basis, *root, secp);
    expect_ok(ctx, root_bytes,
              "algebraic root claim serializes");
    if (!root_bytes) return;
    auto parsed_root = accum::parse_root_claim(*basis, *root_bytes, secp);
    expect_ok(ctx, parsed_root, "canonical algebraic root claim parses");
    if (!parsed_root) return;
    auto reencoded_root = accum::serialize_root_claim(*basis, *parsed_root, secp);
    ctx.expect(reencoded_root && *reencoded_root == *root_bytes,
               "root claim encoding round-trips canonically");
    expect_ok(ctx, accum::decide(*basis, *parsed_root, secp),
              "parsed root passes the final decision");
    ctx.expect(!accum::serialize_root_claim(*basis, *claim, secp),
               "multi-term leaf claim cannot use the final-root codec");
    auto truncated_root = *root_bytes;
    truncated_root.pop_back();
    ctx.expect(!accum::parse_root_claim(*basis, truncated_root, secp),
               "truncated root claim is rejected");
    auto invalid_root = *root_bytes;
    std::fill_n(invalid_root.begin() + 33, 32, 0xff);
    ctx.expect(!accum::parse_root_claim(*basis, invalid_root, secp),
               "noncanonical root scale is rejected");

    const auto changed_factor =
        (root->polynomial()[0].factors[0] + FieldElement::one())
            .to_bytes_be();
    std::copy(changed_factor.begin(), changed_factor.end(),
              root_bytes->begin() + 65);
    auto changed_root = accum::parse_root_claim(
        *basis, *root_bytes, secp);
    expect_ok(ctx, changed_root,
              "changed algebraic root remains a pending obligation");
    if (!changed_root) return;
    ctx.expect(!accum::decide(*basis, *changed_root, secp),
               "final decision rejects a changed algebraic root");
    const std::array reversed_claims{*second_claim, *claim};
    ctx.expect(!accum::verify_algebraic_step(
                   *basis, reversed_claims, *parsed_step, secp),
               "algebraic batching binds ordered claims");

    auto malformed = *parsed_step;
    malformed.left[0][0] = 4;
    ctx.expect(!accum::verify_algebraic_step(
                   *basis, claims, malformed, secp),
               "SHA-256 transcript rejects a noncanonical point");
    auto malformed_bytes = *step_bytes;
    malformed_bytes[1] = 4;
    ctx.expect(!accum::parse_algebraic_step(
                   *basis, malformed_bytes, secp),
               "algebraic codec rejects a noncanonical point");
}

} // namespace

void run_norm_accumulation_tests(TestContext& ctx) {
    auto secp = purify::make_secp_context();
    ctx.expect(secp != nullptr, "norm accumulation context creates");
    if (!secp) return;
    check_v4_algebraic_circuit_adapter(ctx, secp.get());
    check_algebraic_suite(ctx, secp.get());
}
