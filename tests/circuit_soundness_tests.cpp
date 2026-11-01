// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <array>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

#include "../src/bridge/bppp_bridge.h"
#include "../src/protocol/algebraic_circuit_proof.hpp"
#include "../src/protocol/bppp_internal.hpp"
#include "../src/protocol/bulletproof_internal.hpp"
#include "purify.hpp"
#include "purify/bppp.hpp"
#include "purify/curve.hpp"
#include "test_harness.hpp"

namespace {

using purify::BulletproofAssignmentData;
using purify::Bytes;
using purify::FieldElement;
using purify::NativeBulletproofCircuit;
using purify::Result;
using purify::TaggedHash;
using purify::bppp::NormArgInputs;
using purify::bppp::PointBytes;
using purify::bppp::ScalarBytes;
using purify_test::TestContext;

namespace candidate = purify::bppp::candidate;

constexpr std::string_view CIRCUIT_RHO_TAG =
    "Purify/BPPP/CircuitNormArgV3/Rho";
constexpr std::string_view CIRCUIT_MUL_TAG =
    "Purify/BPPP/CircuitNormArgV3/Mul";
constexpr std::string_view CIRCUIT_CONSTRAINT_TAG =
    "Purify/BPPP/CircuitNormArgV3/Constraint";
constexpr std::string_view CIRCUIT_PUBLIC_COMMITMENT_TAG =
    "Purify/BPPP/CircuitNormArgV3/PublicCommitments";
constexpr std::string_view CIRCUIT_PRECOMMIT_TAG =
    "Purify/BPPP/CircuitNormArgV3/Precommit";
constexpr std::string_view CIRCUIT_ZK_CHALLENGE_TAG =
    "Purify/BPPP/CircuitNormArgV3/ZKChallenge";

Result<PointBytes> scalar_point(const FieldElement& scalar,
                                purify_secp_context* context)
{
    const ScalarBytes zero{};
    const auto base = purify::bppp::base_generator(context);
    return purify::bppp::pedersen_commit_char(
        zero, scalar.to_bytes_be(), context, base, base);
}

void append_u64_le(Bytes& out, std::uint64_t value)
{
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<unsigned char>((value >> (8 * i)) & 0xffU));
    }
}

FieldElement derive_nonzero_scalar(std::span<const unsigned char> seed,
                                   std::string_view tag,
                                   std::size_t index)
{
    Bytes prefix(seed.begin(), seed.end());
    append_u64_le(prefix, index);
    const TaggedHash tagged_hash(tag);
    for (std::uint64_t counter = 0; counter < 256; ++counter) {
        Bytes input = prefix;
        append_u64_le(input, counter);
        Result<FieldElement> candidate =
            FieldElement::try_from_bytes32(tagged_hash.digest(input));
        if (candidate.has_value() && !candidate->is_zero()) {
            return *candidate;
        }
    }
    assert(false && "test transcript must derive a canonical nonzero scalar");
    return FieldElement::zero();
}

Bytes bind_public_commitments(std::span<const PointBytes> commitments,
                              std::span<const unsigned char> statement_binding)
{
    Bytes out = purify::bytes_from_ascii(CIRCUIT_PUBLIC_COMMITMENT_TAG);
    append_u64_le(out, commitments.size());
    for (const PointBytes& point : commitments) {
        out.insert(out.end(), point.begin(), point.end());
    }
    append_u64_le(out, statement_binding.size());
    out.insert(out.end(), statement_binding.begin(), statement_binding.end());
    return out;
}

Result<PointBytes> commit_witness_only(const NormArgInputs& inputs,
                                       purify_secp_context* context)
{
    if (inputs.generators.size() !=
        inputs.n_vec.size() + inputs.l_vec.size()) {
        return purify::unexpected_error(
            purify::ErrorCode::SizeMismatch,
            "circuit_soundness:commit_witness_only:generators");
    }

    const auto generator_bytes = std::as_bytes(
        std::span<const PointBytes>(inputs.generators));
    const auto n_bytes =
        std::as_bytes(std::span<const ScalarBytes>(inputs.n_vec));
    const auto l_bytes =
        std::as_bytes(std::span<const ScalarBytes>(inputs.l_vec));
    PointBytes out{};
    if (!purify_bppp_commit_witness_only(
            context,
            reinterpret_cast<const unsigned char*>(generator_bytes.data()),
            inputs.generators.size(),
            reinterpret_cast<const unsigned char*>(n_bytes.data()),
            inputs.n_vec.size(),
            reinterpret_cast<const unsigned char*>(l_bytes.data()),
            inputs.l_vec.size(), out.data())) {
        return purify::unexpected_error(
            purify::ErrorCode::BackendRejectedInput,
            "circuit_soundness:commit_witness_only:backend");
    }
    return out;
}

Result<PointBytes> generator_point(const PointBytes& generator,
                                   purify_secp_context* context)
{
    PointBytes out{};
    if (!purify_bppp_generator_to_point(
            context, generator.data(), out.data())) {
        return purify::unexpected_error(
            purify::ErrorCode::BackendRejectedInput,
            "circuit_soundness:generator_point");
    }
    return out;
}

Result<PointBytes> scale_generator(const PointBytes& generator,
                                   const FieldElement& scalar,
                                   purify_secp_context* context)
{
    PointBytes out{};
    const ScalarBytes encoded = scalar.to_bytes_be();
    if (!purify_bppp_scale_generator(
            context, generator.data(), encoded.data(), out.data())) {
        return purify::unexpected_error(
            purify::ErrorCode::BackendRejectedInput,
            "circuit_soundness:scale_generator");
    }
    return out;
}

Result<PointBytes> scale_point(const PointBytes& point,
                               const FieldElement& scalar,
                               purify_secp_context* context)
{
    PointBytes out{};
    const ScalarBytes encoded = scalar.to_bytes_be();
    if (!purify_point_scale(
            context, point.data(), encoded.data(), out.data())) {
        return purify::unexpected_error(
            purify::ErrorCode::BackendRejectedInput,
            "circuit_soundness:scale_point");
    }
    return out;
}

Result<PointBytes> add_points(const PointBytes& lhs, const PointBytes& rhs,
                              purify_secp_context* context)
{
    PointBytes out{};
    if (!purify_point_add(
            context, lhs.data(), rhs.data(), out.data())) {
        return purify::unexpected_error(
            purify::ErrorCode::BackendRejectedInput,
            "circuit_soundness:add_points");
    }
    return out;
}

FieldElement weighted_inner_product(std::span<const FieldElement> lhs,
                                    std::span<const FieldElement> rhs,
                                    const FieldElement& rho)
{
    assert(lhs.size() == rhs.size());
    const FieldElement mu = rho * rho;
    FieldElement weight = mu;
    FieldElement total = FieldElement::zero();
    for (std::size_t i = 0; i < lhs.size(); ++i) {
        total = total + (weight * lhs[i] * rhs[i]);
        weight = weight * mu;
    }
    return total;
}

FieldElement canonical_sqrt_minus_one(TestContext& ctx)
{
    Result<FieldElement> root =
        purify::bppp::detail::canonical_sqrt_minus_one();
    ctx.expect(root.has_value(),
               "canonical square root of minus one exists");
    if (!root.has_value()) return FieldElement::zero();
    ctx.expect(
        root->to_bytes_be() ==
            purify::UInt256::from_hex(
                "70ad49ae7f8574ecab641a42b3a24f22"
                "d6374023944cc665a6bcaeb0f37bbf78")
                .to_bytes_be(),
        "V3 uses the fixed even square root of minus one");
    return *root;
}


struct RawBasisAttack {
    RawBasisAttack() : circuit(2, 1, 0) {}

    NativeBulletproofCircuit circuit;
    BulletproofAssignmentData assignment;
    Bytes statement;
    PointBytes exact_output{};
    PointBytes wrong_output{};
    PointBytes direct_commitment{};
    PointBytes anchored_commitment{};
    PointBytes combined_commitment{};
    purify::bppp::NormArgProof inner_proof;
    purify::bppp::ExperimentalCircuitZkNormArgProof honest_proof;
    purify::bppp::ExperimentalCircuitZkNormArgProof forged_proof;
};

Result<RawBasisAttack> build_raw_basis_attack(
    TestContext& ctx, purify_secp_context* context)
{
    RawBasisAttack attack;
    const std::size_t row =
        attack.circuit.add_constraint(FieldElement::zero());
    attack.circuit.add_output_term(0, row, FieldElement::one());
    attack.circuit.add_commitment_term(
        0, row, FieldElement::from_int(-1));
    attack.assignment = {
        .left = {FieldElement::one(), FieldElement::zero()},
        .right = {FieldElement::one(), FieldElement::zero()},
        .output = {FieldElement::one(), FieldElement::zero()},
        .commitments = {FieldElement::one()},
    };
    if (!attack.circuit.evaluate(attack.assignment)) {
        return purify::unexpected_error(
            purify::ErrorCode::EquationMismatch,
            "circuit_soundness:raw_basis_assignment");
    }

    PURIFY_ASSIGN_OR_RETURN(
        auto generators, purify::bppp::create_generators(8, context),
        "circuit_soundness:raw_basis_generators");
    const std::vector<FieldElement> raw_n{
        FieldElement::from_u64(2), FieldElement::zero(),
        FieldElement::zero(), FieldElement::zero()};
    const std::vector<FieldElement> raw_l{
        FieldElement::one(), FieldElement::zero(),
        FieldElement::from_u64(5), FieldElement::from_u64(7)};
    NormArgInputs raw_inputs;
    raw_inputs.generators = generators;
    raw_inputs.n_vec = purify::bppp::scalar_bytes(raw_n);
    raw_inputs.l_vec = purify::bppp::scalar_bytes(raw_l);
    PURIFY_ASSIGN_OR_RETURN(
        const auto& raw_a, commit_witness_only(raw_inputs, context),
        "circuit_soundness:raw_basis_precommit");

    const ScalarBytes zero{};
    const auto base = purify::bppp::base_generator(context);
    PURIFY_ASSIGN_OR_RETURN(
        attack.exact_output,
        purify::bppp::pedersen_commit_char(
            zero, FieldElement::one().to_bytes_be(), context, base, base),
        "circuit_soundness:raw_basis_exact_output");
    const FieldElement delta = FieldElement::from_u64(19);
    PURIFY_ASSIGN_OR_RETURN(
        const auto& gu, generator_point(generators[2], context),
        "circuit_soundness:raw_basis_gu");
    PURIFY_ASSIGN_OR_RETURN(
        const auto& gv, generator_point(generators[3], context),
        "circuit_soundness:raw_basis_gv");
    PURIFY_ASSIGN_OR_RETURN(
        const auto& scaled_gu, scale_point(gu, delta, context),
        "circuit_soundness:raw_basis_scaled_gu");
    PURIFY_ASSIGN_OR_RETURN(
        const auto& scaled_gv, scale_point(gv, delta, context),
        "circuit_soundness:raw_basis_scaled_gv");
    PURIFY_ASSIGN_OR_RETURN(
        const auto& public_delta,
        add_points(scaled_gu, scaled_gv, context),
        "circuit_soundness:raw_basis_public_delta");
    PURIFY_ASSIGN_OR_RETURN(
        attack.wrong_output,
        add_points(attack.exact_output, public_delta, context),
        "circuit_soundness:raw_basis_wrong_output");

    attack.statement =
        purify::bytes_from_ascii("raw-basis-padding-attack");
    const std::array<PointBytes, 1> exact_outputs{attack.exact_output};
    ScalarBytes prover_seed{};
    prover_seed.fill(0x93);
    PURIFY_ASSIGN_OR_RETURN(
        attack.honest_proof,
        purify::bppp::
            prove_experimental_circuit_zk_norm_arg_with_public_commitments(
                attack.circuit, attack.assignment, prover_seed,
                exact_outputs, context, attack.statement),
        "circuit_soundness:raw_basis_honest_proof");

    const std::array<PointBytes, 1> wrong_outputs{attack.wrong_output};
    const Bytes bound_binding =
        bind_public_commitments(wrong_outputs, attack.statement);
    PURIFY_ASSIGN_OR_RETURN(
        const auto& binding_digest,
        purify::experimental_circuit_binding_digest(
            attack.circuit, bound_binding),
        "circuit_soundness:raw_basis_binding");
    Bytes precommit_seed = binding_digest;
    precommit_seed.insert(
        precommit_seed.end(), raw_a.begin(), raw_a.end());
    const ScalarBytes challenge_array =
        TaggedHash(CIRCUIT_PRECOMMIT_TAG).digest(precommit_seed);
    const Bytes challenge_digest(
        challenge_array.begin(), challenge_array.end());
    const FieldElement rho = derive_nonzero_scalar(
        challenge_digest, CIRCUIT_RHO_TAG, 0);
    const FieldElement lambda = derive_nonzero_scalar(
        challenge_digest, CIRCUIT_MUL_TAG, 0);
    const FieldElement ratio = derive_nonzero_scalar(
        challenge_digest, CIRCUIT_MUL_TAG, 1);
    const FieldElement row_weight = derive_nonzero_scalar(
        challenge_digest, CIRCUIT_CONSTRAINT_TAG, 0);

    const FieldElement sqrt_minus_one = canonical_sqrt_minus_one(ctx);
    auto transformed_generators = generators;
    FieldElement rho_power = rho;
    FieldElement term = lambda;
    for (std::size_t i = 0; i < 4; ++i) {
        const FieldElement coordinate =
            i % 2 == 0 ? term : sqrt_minus_one * term;
        PURIFY_ASSIGN_OR_RETURN(
            transformed_generators[i],
            scale_generator(generators[i],
                            rho_power * coordinate.inverse(), context),
            "circuit_soundness:raw_basis_transform_generator");
        if (i % 2 == 1) term = term * ratio;
        rho_power = rho_power * rho;
    }

    const FieldElement two = FieldElement::from_u64(2);
    const FieldElement four = FieldElement::from_u64(4);
    const FieldElement second_lambda = lambda * ratio;
    const FieldElement mul0 = four * lambda * lambda;
    const FieldElement mul1 =
        four * second_lambda * second_lambda;
    const FieldElement shifted_padding = row_weight * delta;
    const FieldElement rho_inverse = rho.inverse();
    FieldElement rho_inverse_power = rho_inverse;
    std::vector<FieldElement> hidden_n(4, FieldElement::zero());
    hidden_n[0] = lambda * two * rho_inverse_power;
    rho_inverse_power =
        rho_inverse_power * rho_inverse * rho_inverse;
    hidden_n[2] =
        second_lambda * shifted_padding * rho_inverse_power;
    rho_inverse_power = rho_inverse_power * rho_inverse;
    hidden_n[3] = sqrt_minus_one * second_lambda *
                  shifted_padding * rho_inverse_power;
    const std::vector<FieldElement> c_vec{
        row_weight - mul0, mul1.negate(),
        FieldElement::zero(), FieldElement::zero()};

    NormArgInputs hidden_inputs;
    hidden_inputs.rho = rho.to_bytes_be();
    hidden_inputs.generators = transformed_generators;
    hidden_inputs.n_vec = purify::bppp::scalar_bytes(hidden_n);
    hidden_inputs.l_vec = purify::bppp::scalar_bytes(raw_l);
    hidden_inputs.c_vec = purify::bppp::scalar_bytes(c_vec);
    PURIFY_ASSIGN_OR_RETURN(
        attack.direct_commitment,
        purify::bppp::commit_norm_arg(hidden_inputs, context),
        "circuit_soundness:raw_basis_direct_commitment");
    PURIFY_ASSIGN_OR_RETURN(
        const auto& public_term,
        scale_point(attack.wrong_output, row_weight, context),
        "circuit_soundness:raw_basis_public_term");
    PURIFY_ASSIGN_OR_RETURN(
        attack.anchored_commitment,
        add_points(raw_a, public_term, context),
        "circuit_soundness:raw_basis_anchor");

    std::vector<FieldElement> mask_n(4, FieldElement::zero());
    mask_n[0] = FieldElement::one();
    const std::vector<FieldElement> mask_l(4, FieldElement::zero());
    const FieldElement t2 = weighted_inner_product(mask_n, mask_n, rho);
    const FieldElement linear = two * weighted_inner_product(
        hidden_n, mask_n, rho);
    NormArgInputs mask_inputs = hidden_inputs;
    mask_inputs.n_vec = purify::bppp::scalar_bytes(mask_n);
    mask_inputs.l_vec = purify::bppp::scalar_bytes(mask_l);
    PURIFY_ASSIGN_OR_RETURN(
        const auto& raw_s, commit_witness_only(mask_inputs, context),
        "circuit_soundness:raw_basis_mask_commitment");
    PointBytes s_commitment{};
    if (!purify_bppp_offset_commitment(
            context, raw_s.data(), linear.to_bytes_be().data(),
            s_commitment.data())) {
        return purify::unexpected_error(
            purify::ErrorCode::BackendRejectedInput,
            "circuit_soundness:raw_basis_mask_offset");
    }

    Bytes outer_seed = challenge_digest;
    outer_seed.insert(
        outer_seed.end(), attack.anchored_commitment.begin(),
        attack.anchored_commitment.end());
    outer_seed.insert(
        outer_seed.end(), s_commitment.begin(), s_commitment.end());
    const ScalarBytes t2_bytes = t2.to_bytes_be();
    outer_seed.insert(
        outer_seed.end(), t2_bytes.begin(), t2_bytes.end());
    const FieldElement outer_challenge = derive_nonzero_scalar(
        outer_seed, CIRCUIT_ZK_CHALLENGE_TAG, 0);
    std::vector<FieldElement> masked_n = hidden_n;
    for (std::size_t i = 0; i < masked_n.size(); ++i) {
        masked_n[i] =
            masked_n[i] + outer_challenge * mask_n[i];
    }
    NormArgInputs masked_inputs = hidden_inputs;
    masked_inputs.n_vec = purify::bppp::scalar_bytes(masked_n);
    PURIFY_ASSIGN_OR_RETURN(
        attack.inner_proof,
        purify::bppp::prove_norm_arg(masked_inputs, context),
        "circuit_soundness:raw_basis_inner_proof");

    PURIFY_ASSIGN_OR_RETURN(
        const auto& scaled_s,
        scale_point(s_commitment, outer_challenge, context),
        "circuit_soundness:raw_basis_scaled_mask");
    PURIFY_ASSIGN_OR_RETURN(
        const auto& combined,
        add_points(attack.anchored_commitment, scaled_s, context),
        "circuit_soundness:raw_basis_combined");
    const FieldElement quadratic =
        outer_challenge * outer_challenge * t2;
    if (!purify_bppp_offset_commitment(
            context, combined.data(), quadratic.to_bytes_be().data(),
            attack.combined_commitment.data())) {
        return purify::unexpected_error(
            purify::ErrorCode::BackendRejectedInput,
            "circuit_soundness:raw_basis_quadratic_offset");
    }

    attack.forged_proof = {
        raw_a, s_commitment, t2_bytes,
        attack.honest_proof.public_commitment_dlog_nonce,
        attack.honest_proof.public_commitment_dlog_response,
        attack.inner_proof.proof};
    return attack;
}

void test_public_commitment_dlog_rejects_raw_basis_attack(TestContext& ctx)
{
    purify::SecpContextPtr context = purify::make_secp_context();
    ctx.expect(context != nullptr,
               "raw-basis soundness fixture creates a secp context");
    if (context == nullptr) return;

    Result<std::vector<PointBytes>> one_generator =
        purify::bppp::create_generators(1, context.get());
    ctx.expect(one_generator.has_value(),
               "generator failure-cleanup fixture derives");
    if (!one_generator.has_value()) return;
    ScalarBytes zero_scalar{};
    PointBytes failed_scale_output{};
    failed_scale_output.fill(0xa5);
    ctx.expect(!purify_bppp_scale_generator(
                   context.get(), (*one_generator)[0].data(),
                   zero_scalar.data(), failed_scale_output.data()),
               "generator scaling rejects the zero scalar");
    ctx.expect(failed_scale_output == PointBytes{},
               "failed generator scaling clears its output");

    Result<RawBasisAttack> attack =
        build_raw_basis_attack(ctx, context.get());
    ctx.expect(attack.has_value(),
               "raw-basis wrong-output attack constructs");
    if (!attack.has_value()) return;

    ctx.expect(attack->exact_output != attack->wrong_output,
               "attack publishes a point other than the circuit output");
    ctx.expect(attack->direct_commitment ==
                   attack->anchored_commitment,
               "raw precommit opens to the wrong-output folded relation");
    ctx.expect(attack->combined_commitment ==
                   attack->inner_proof.commitment,
               "attack constructs the complete masked norm commitment");
    ctx.expect(purify::bppp::verify_norm_arg(
                   attack->inner_proof, context.get()),
               "attack's inner masked norm proof verifies independently");

    const std::array<PointBytes, 1> exact_outputs{attack->exact_output};
    Result<bool> honest =
        purify::bppp::
            verify_experimental_circuit_zk_norm_arg_with_public_commitments(
                attack->circuit, attack->honest_proof, exact_outputs,
                context.get(), attack->statement);
    ctx.expect(honest.has_value() && *honest,
               "honest V3 public-output proof verifies");

    const Bytes bound_binding =
        bind_public_commitments(exact_outputs, attack->statement);
    Result<Bytes> binding_digest =
        purify::experimental_circuit_binding_digest(
            attack->circuit, bound_binding);
    ctx.expect(binding_digest.has_value(),
               "independent V3 statement digest derives");
    if (!binding_digest.has_value()) return;
    Bytes precommit_seed = *binding_digest;
    precommit_seed.insert(precommit_seed.end(),
                          attack->honest_proof.a_commitment.begin(),
                          attack->honest_proof.a_commitment.end());
    const ScalarBytes expected_challenge =
        TaggedHash(CIRCUIT_PRECOMMIT_TAG).digest(precommit_seed);
    auto prepared = purify::bppp::detail::
        prepare_experimental_circuit_zk_norm_arg_with_public_commitments(
            attack->circuit, attack->honest_proof, exact_outputs,
            context.get(), attack->statement, nullptr);
    ctx.expect(prepared.has_value() && prepared->has_value(),
               "honest V3 proof prepares its public norm statement");
    if (!prepared.has_value() || !prepared->has_value()) return;
    ctx.expect((*prepared)->challenge_digest == expected_challenge,
               "V3 challenge commits the raw A point before folding");

    const FieldElement canonical_root = canonical_sqrt_minus_one(ctx);
    const FieldElement rho = derive_nonzero_scalar(
        expected_challenge, CIRCUIT_RHO_TAG, 0);
    const FieldElement lambda = derive_nonzero_scalar(
        expected_challenge, CIRCUIT_MUL_TAG, 0);
    Result<std::vector<PointBytes>> raw_generators =
        purify::bppp::create_generators(8, context.get());
    ctx.expect(raw_generators.has_value(),
               "independent V3 raw generator line derives");
    if (!raw_generators.has_value()) return;
    Result<PointBytes> expected_odd_generator = scale_generator(
        (*raw_generators)[1],
        rho * rho * (canonical_root * lambda).inverse(), context.get());
    ctx.expect(expected_odd_generator.has_value(),
               "independent V3 odd generator derives");
    if (!expected_odd_generator.has_value()) return;
    ctx.expect((*prepared)->norm.generators[1] ==
                   *expected_odd_generator,
               "V3 transformed basis uses the canonical square root");

    Result<PointBytes> wrong_base_point = generator_point(
        purify::bppp::value_generator_h(context.get()), context.get());
    ctx.expect(wrong_base_point.has_value(),
               "wrong-base public commitment derives");
    if (!wrong_base_point.has_value()) return;
    const std::array<PointBytes, 1> wrong_base_outputs{*wrong_base_point};
    ScalarBytes wrong_base_seed{};
    wrong_base_seed.fill(0xa7);
    auto wrong_base_proof = purify::bppp::
        prove_experimental_circuit_zk_norm_arg_with_public_commitments(
            attack->circuit, attack->assignment, wrong_base_seed,
            wrong_base_outputs, context.get(), attack->statement);
    bool wrong_base_rejected = !wrong_base_proof.has_value();
    if (wrong_base_proof.has_value()) {
        Result<bool> wrong_base_result = purify::bppp::
            verify_experimental_circuit_zk_norm_arg_with_public_commitments(
                attack->circuit, *wrong_base_proof, wrong_base_outputs,
                context.get(), attack->statement);
        wrong_base_rejected = wrong_base_result.has_value() &&
                              !*wrong_base_result;
    }
    ctx.expect(wrong_base_rejected,
               "a scalar opened on the wrong base cannot produce an accepted proof");
    Result<bool> substituted_base = purify::bppp::
        verify_experimental_circuit_zk_norm_arg_with_public_commitments(
            attack->circuit, attack->honest_proof, wrong_base_outputs,
            context.get(), attack->statement);
    ctx.expect(substituted_base.has_value() && !*substituted_base,
               "the verifier rejects direct public-output base substitution");

    auto tampered = attack->honest_proof;
    Result<FieldElement> response = FieldElement::try_from_bytes32(
        tampered.public_commitment_dlog_response);
    ctx.expect(response.has_value(),
               "honest DLog response is canonical");
    if (!response.has_value()) return;
    tampered.public_commitment_dlog_response =
        (*response + FieldElement::one()).to_bytes_be();
    Result<bool> tampered_result =
        purify::bppp::
            verify_experimental_circuit_zk_norm_arg_with_public_commitments(
                attack->circuit, tampered, exact_outputs, context.get(),
                attack->statement);
    ctx.expect(tampered_result.has_value() && !*tampered_result,
               "changed public-output DLog response rejects");

    const std::array<PointBytes, 1> wrong_outputs{attack->wrong_output};
    Result<bool> forged =
        purify::bppp::
            verify_experimental_circuit_zk_norm_arg_with_public_commitments(
                attack->circuit, attack->forged_proof, wrong_outputs,
                context.get(), attack->statement);
    ctx.expect(forged.has_value() && !*forged,
               "DLog equation rejects an otherwise complete wrong-output proof");
}

void test_v4_native_circuit_proof(TestContext& ctx)
{
    purify::SecpContextPtr context = purify::make_secp_context();
    ctx.expect(context != nullptr, "V4 native proof creates a context");
    if (context == nullptr) return;

    NativeBulletproofCircuit circuit(1, 1, 0);
    const std::size_t constraint =
        circuit.add_constraint(FieldElement::zero());
    circuit.add_output_term(0, constraint, FieldElement::one());
    circuit.add_commitment_term(0, constraint,
                                FieldElement::from_int(-1));

    BulletproofAssignmentData assignment;
    assignment.left = {FieldElement::from_int(3)};
    assignment.right = {FieldElement::from_int(4)};
    assignment.output = {FieldElement::from_int(12)};
    assignment.commitments = {FieldElement::from_int(12)};
    ScalarBytes prover_seed{};
    prover_seed.fill(0x42);
    const Bytes binding = purify::bytes_from_ascii("v4-native-circuit-proof");

    auto publication = candidate::prove_circuit_zk_norm_arg_v4(
        circuit, assignment, prover_seed, context.get(), binding);
    ctx.expect(publication.has_value(), "V4 hidden proof produces");
    if (!publication.has_value()) return;

    auto prepared = candidate::prepare_circuit_zk_norm_arg_v4(
        circuit, *publication, context.get(), binding);
    ctx.expect(prepared.has_value() && prepared->has_value(),
               "V4 hidden proof prepares its recursive leaf witness");
    if (!prepared.has_value() || !prepared->has_value()) return;
    ctx.expect((*prepared)->precommitment().bytes() ==
                   publication->precommitment.bytes(),
               "V4 prepared proof retains the public precommitment");
    ctx.expect((*prepared)->transcript_input().rounds.size() ==
                   (*prepared)->transcript().gammas.size(),
               "V4 prepared proof exposes every authenticated norm round");
    ctx.expect((*prepared)->norm().proof == publication->proof.norm_proof,
               "V4 prepared norm bytes are the exact transcript payload");
    ctx.expect((*prepared)->trusted_public_commitments().empty(),
               "V4 hidden preparation exposes no public commitments");
    ctx.expect(!(*prepared)->raw_generators().empty(),
               "V4 preparation exposes the authenticated raw basis");
    ctx.expect(
        !(*prepared)->transcript().prepared_binding.scalar.is_zero(),
               "V4 terminal binding is a selected nonzero scalar");

    auto verified = candidate::verify_circuit_zk_norm_arg_v4(
        circuit, *publication, context.get(), binding);
    ctx.expect(verified.has_value() && *verified,
               "V4 hidden proof verifies its full native norm equation");

    BulletproofAssignmentData second_assignment;
    second_assignment.left = {FieldElement::from_int(5)};
    second_assignment.right = {FieldElement::from_int(6)};
    second_assignment.output = {FieldElement::from_int(30)};
    second_assignment.commitments = {FieldElement::from_int(30)};
    auto second_publication = candidate::prove_circuit_zk_norm_arg_v4(
        circuit, second_assignment, prover_seed, context.get(), binding);
    ctx.expect(second_publication.has_value(),
               "V4 reused seed proves a different valid assignment");
    if (!second_publication.has_value()) return;
    ctx.expect(second_publication->proof.raw_commitment !=
                   publication->proof.raw_commitment,
               "V4 different assignment changes the raw commitment");
    auto raw_generators = purify::bppp::create_generators(8, context.get());
    ctx.expect(raw_generators.has_value(),
               "V4 seed-reuse raw generators derive");
    if (!raw_generators.has_value()) return;
    NormArgInputs assignment_delta;
    assignment_delta.generators = *raw_generators;
    const std::array<FieldElement, 4> delta_n{
        FieldElement::from_int(4), FieldElement::zero(),
        FieldElement::zero(), FieldElement::zero()};
    const std::array<FieldElement, 4> delta_l{
        FieldElement::from_int(18), FieldElement::zero(),
        FieldElement::from_int(18), FieldElement::zero()};
    assignment_delta.n_vec = purify::bppp::scalar_bytes(delta_n);
    assignment_delta.l_vec = purify::bppp::scalar_bytes(delta_l);
    auto assignment_delta_commitment =
        commit_witness_only(assignment_delta, context.get());
    ctx.expect(assignment_delta_commitment.has_value(),
               "V4 public raw-coordinate delta commits");
    if (!assignment_delta_commitment.has_value()) return;
    auto old_reuse_prediction = add_points(
        publication->proof.raw_commitment, *assignment_delta_commitment,
        context.get());
    ctx.expect(old_reuse_prediction.has_value(),
               "V4 old reused-padding prediction derives");
    if (!old_reuse_prediction.has_value()) return;
    PointBytes hiding_delta{};
    ctx.expect(purify_point_subtract_allow_infinity(
                   context.get(),
                   second_publication->proof.raw_commitment.data(),
                   old_reuse_prediction->data(), hiding_delta.data()) != 0 &&
                   hiding_delta != PointBytes{},
               "V4 assignment binding changes the raw hiding coordinate");
    auto second_verified = candidate::verify_circuit_zk_norm_arg_v4(
        circuit, *second_publication, context.get(), binding);
    ctx.expect(second_verified.has_value() && *second_verified,
               "V4 reused-seed proof verifies for its assignment");

    auto identity_mask = *publication;
    identity_mask.proof.mask_commitment = PointBytes{};
    auto identity_mask_result = candidate::prepare_circuit_zk_norm_arg_v4(
        circuit, identity_mask, context.get(), binding);
    ctx.expect(!identity_mask_result.has_value() ||
                   !identity_mask_result->has_value(),
               "V4 native boundary rejects an identity mask commitment");
    auto identity_raw = *publication;
    identity_raw.proof.raw_commitment = PointBytes{};
    auto identity_raw_result = candidate::prepare_circuit_zk_norm_arg_v4(
        circuit, identity_raw, context.get(), binding);
    ctx.expect(!identity_raw_result.has_value() ||
                   !identity_raw_result->has_value(),
               "V4 native boundary rejects an identity raw commitment");

    auto malformed_pair = *publication;
    malformed_pair.proof.norm_proof[0] = 4;
    auto malformed_pair_result = candidate::verify_circuit_zk_norm_arg_v4(
        circuit, malformed_pair, context.get(), binding);
    ctx.expect(!malformed_pair_result.has_value() ||
                   !*malformed_pair_result,
               "V4 verification rejects malformed packed round parity");

    auto noncanonical_terminal = *publication;
    const ScalarBytes group_order =
        purify::UInt256::from_hex(
            "fffffffffffffffffffffffffffffffebaaedce6af48a03b"
            "bfd25e8cd0364141")
            .to_bytes_be();
    std::copy(group_order.begin(), group_order.end(),
              noncanonical_terminal.proof.norm_proof.end() -
                  group_order.size());
    auto noncanonical_terminal_result =
        candidate::verify_circuit_zk_norm_arg_v4(
            circuit, noncanonical_terminal, context.get(), binding);
    ctx.expect(!noncanonical_terminal_result.has_value() ||
                   !*noncanonical_terminal_result,
               "V4 verification rejects a noncanonical terminal scalar");

    auto changed_terminal = *publication;
    ScalarBytes terminal_l{};
    std::copy_n(changed_terminal.proof.norm_proof.end() - terminal_l.size(),
                terminal_l.size(), terminal_l.begin());
    auto parsed_terminal = FieldElement::try_from_bytes32(terminal_l);
    ctx.expect(parsed_terminal.has_value(),
               "V4 terminal scalar is canonical");
    if (!parsed_terminal.has_value()) return;
    terminal_l = (*parsed_terminal + FieldElement::one()).to_bytes_be();
    std::copy(terminal_l.begin(), terminal_l.end(),
              changed_terminal.proof.norm_proof.end() - terminal_l.size());
    auto changed_terminal_result = candidate::verify_circuit_zk_norm_arg_v4(
        circuit, changed_terminal, context.get(), binding);
    ctx.expect(changed_terminal_result.has_value() &&
                   !*changed_terminal_result,
               "V4 verification rejects a changed bound terminal scalar");

    auto wrong_binding = candidate::verify_circuit_zk_norm_arg_v4(
        circuit, *publication, context.get(),
        purify::bytes_from_ascii("v4-native-circuit-proof-wrong"));
    ctx.expect(wrong_binding.has_value() && !*wrong_binding,
               "V4 public precommitment rejects a changed statement");

    auto public_point = scalar_point(assignment.commitments[0], context.get());
    ctx.expect(public_point.has_value(), "V4 public point derives");
    if (!public_point.has_value()) return;
    const std::array<PointBytes, 1> public_points{*public_point};
    auto public_publication =
        candidate::prove_circuit_zk_norm_arg_v4_with_public_commitments(
            circuit, assignment, prover_seed, public_points, context.get(),
            binding);
    ctx.expect(public_publication.has_value(), "V4 public proof produces");
    if (!public_publication.has_value()) return;
    auto public_verified =
        candidate::verify_circuit_zk_norm_arg_v4_with_public_commitments(
            circuit, *public_publication, public_points, context.get(),
            binding);
    ctx.expect(public_verified.has_value() && *public_verified,
               "V4 public proof verifies its DLog and norm equations");
    auto public_prepared =
        candidate::prepare_circuit_zk_norm_arg_v4_with_public_commitments(
            circuit, *public_publication, public_points, context.get(),
            binding);
    ctx.expect(public_prepared.has_value() && public_prepared->has_value() &&
                   (*public_prepared)->trusted_public_commitments() ==
                       std::vector<PointBytes>(public_points.begin(),
                                               public_points.end()),
               "V4 preparation retains trusted ordered public points");

    auto zero_response = *public_publication;
    zero_response.proof.public_commitment_dlog_response.fill(0);
    auto zero_response_result =
        candidate::verify_circuit_zk_norm_arg_v4_with_public_commitments(
            circuit, zero_response, public_points, context.get(), binding);
    ctx.expect(zero_response_result.has_value() && !*zero_response_result,
               "V4 public verification rejects a zero DLog response");

    auto invalid_nonce = *public_publication;
    invalid_nonce.proof.public_commitment_dlog_nonce.fill(0xff);
    auto invalid_nonce_result =
        candidate::verify_circuit_zk_norm_arg_v4_with_public_commitments(
            circuit, invalid_nonce, public_points, context.get(), binding);
    ctx.expect(!invalid_nonce_result.has_value() || !*invalid_nonce_result,
               "V4 public verification rejects an invalid x-only nonce");

    const std::array<PointBytes, 1> identity_public_points{PointBytes{}};
    auto identity_public_result =
        candidate::verify_circuit_zk_norm_arg_v4_with_public_commitments(
            circuit, *public_publication, identity_public_points,
            context.get(), binding);
    ctx.expect(!identity_public_result.has_value() ||
                   !*identity_public_result,
               "V4 native boundary rejects identity public commitments");

    auto wrong_public_point =
        scalar_point(FieldElement::from_int(13), context.get());
    ctx.expect(wrong_public_point.has_value(), "V4 wrong public point derives");
    if (!wrong_public_point.has_value()) return;
    const std::array<PointBytes, 1> wrong_public_points{*wrong_public_point};
    auto wrong_public =
        candidate::verify_circuit_zk_norm_arg_v4_with_public_commitments(
            circuit, *public_publication, wrong_public_points, context.get(),
            binding);
    ctx.expect(wrong_public.has_value() && !*wrong_public,
               "V4 public precommitment rejects point substitution");

    auto v3 = purify::bppp::prove_experimental_circuit_zk_norm_arg(
        circuit, assignment, prover_seed, context.get(), binding);
    ctx.expect(v3.has_value(), "V3 cross-suite fixture produces");
    if (!v3.has_value()) return;
    auto v4_shape = candidate::CircuitTranscriptShapeV4::create(
        candidate::CircuitCommitmentModeV4::Hidden, 2, 1, 4, 4);
    auto binding_digest =
        purify::experimental_circuit_binding_digest(circuit, binding);
    ctx.expect(v4_shape.has_value() && binding_digest.has_value(),
               "V4 cross-suite precommit inputs derive");
    if (!v4_shape.has_value() || !binding_digest.has_value()) return;
    candidate::TranscriptDigest typed_binding_digest{};
    ctx.expect(binding_digest->size() == typed_binding_digest.size(),
               "V4 cross-suite circuit digest has fixed width");
    if (binding_digest->size() != typed_binding_digest.size()) return;
    std::copy(binding_digest->begin(), binding_digest->end(),
              typed_binding_digest.begin());
    auto transferred_precommitment =
        candidate::derive_circuit_precommitment_v4(
            *v4_shape, typed_binding_digest, {}, v3->a_commitment,
            context.get());
    ctx.expect(transferred_precommitment.has_value(),
               "V4 cross-suite precommitment derives");
    if (!transferred_precommitment.has_value()) return;
    candidate::CircuitZkNormArgPublicationV4 transferred{
        transferred_precommitment->digest,
        {v3->a_commitment, v3->s_commitment, v3->t2,
         v3->public_commitment_dlog_nonce,
         v3->public_commitment_dlog_response, v3->proof}};
    auto transferred_result = candidate::verify_circuit_zk_norm_arg_v4(
        circuit, transferred, context.get(), binding);
    ctx.expect(transferred_result.has_value() && !*transferred_result,
               "V4 verifier rejects a V3 proof with a valid V4 envelope");
}

} // namespace

void run_circuit_soundness_tests(TestContext& ctx)
{
    test_public_commitment_dlog_rejects_raw_basis_attack(ctx);
    test_v4_native_circuit_proof(ctx);
}
