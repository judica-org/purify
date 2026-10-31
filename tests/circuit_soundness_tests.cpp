// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <array>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

#include "../src/bridge/bppp_bridge.h"
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

} // namespace

void run_circuit_soundness_tests(TestContext& ctx)
{
    test_public_commitment_dlog_rejects_raw_basis_attack(ctx);
}
