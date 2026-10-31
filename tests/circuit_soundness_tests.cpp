// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <array>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

#include "../src/bridge/bppp_bridge.h"
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
    "Purify/BPPP/CircuitNormArg/Rho";
constexpr std::string_view CIRCUIT_MUL_TAG =
    "Purify/BPPP/CircuitNormArg/Mul";
constexpr std::string_view CIRCUIT_CONSTRAINT_TAG =
    "Purify/BPPP/CircuitNormArg/Constraint";
constexpr std::string_view CIRCUIT_PUBLIC_COMMITMENT_TAG =
    "Purify/BPPP/CircuitNormArg/PublicCommitments";
constexpr std::string_view CIRCUIT_ZK_CHALLENGE_TAG =
    "Purify/BPPP/CircuitNormArg/ZKChallenge";

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

FieldElement weighted_norm(std::span<const FieldElement> values,
                           const FieldElement& rho)
{
    const FieldElement mu = rho * rho;
    FieldElement weight = mu;
    FieldElement total = FieldElement::zero();
    for (const FieldElement& value : values) {
        total = total + (weight * value * value);
        weight = weight * mu;
    }
    return total;
}

struct FoldedAttack {
    NativeBulletproofCircuit circuit;
    BulletproofAssignmentData invalid_assignment;
    NormArgInputs base_inputs;
    PointBytes public_commitment{};
    FieldElement rho = FieldElement::zero();
    FieldElement public_anchor = FieldElement::zero();
    Bytes binding;
    Bytes binding_digest;
};

Result<FoldedAttack> build_folded_attack(purify_secp_context* context)
{
    FoldedAttack attack{
        .circuit = NativeBulletproofCircuit(2, 1, 0),
        .binding = purify::bytes_from_ascii(
            "daybreak-two-invalid-gates-cancel-after-public-fold"),
    };

    // Keep the public output binding honest. Only the two multiplication
    // equations are false, so the exploit cannot be attributed to an unused
    // public commitment.
    const std::size_t constraint =
        attack.circuit.add_constraint(FieldElement::zero());
    attack.circuit.add_output_term(0, constraint, FieldElement::one());
    attack.circuit.add_commitment_term(
        0, constraint, FieldElement::from_int(-1));

    const ScalarBytes zero{};
    PURIFY_ASSIGN_OR_RETURN(
        attack.public_commitment,
        purify::bppp::pedersen_commit_char(
            zero, purify::bppp::scalar_bytes(FieldElement::one()), context,
            purify::bppp::base_generator(context),
            purify::bppp::base_generator(context)),
        "circuit_soundness:public_commitment");

    const std::array<PointBytes, 1> public_commitments{
        attack.public_commitment};
    const Bytes bound_binding =
        bind_public_commitments(public_commitments, attack.binding);
    PURIFY_ASSIGN_OR_RETURN(
        attack.binding_digest,
        purify::experimental_circuit_binding_digest(attack.circuit,
                                                     bound_binding),
        "circuit_soundness:binding_digest");

    attack.rho = derive_nonzero_scalar(attack.binding_digest,
                                       CIRCUIT_RHO_TAG, 0);
    const FieldElement mul0 = derive_nonzero_scalar(
        attack.binding_digest, CIRCUIT_MUL_TAG, 0);
    const FieldElement mul1 = derive_nonzero_scalar(
        attack.binding_digest, CIRCUIT_MUL_TAG, 1);
    const FieldElement row = derive_nonzero_scalar(
        attack.binding_digest, CIRCUIT_CONSTRAINT_TAG, 0);
    attack.public_anchor = row;

    // Gate residuals are -1 and mul0 / mul1, hence their public weighted
    // sum is zero. The public output constraint remains exactly satisfied.
    const FieldElement second_output = (mul0 * mul1.inverse()).negate();
    attack.invalid_assignment.left = {
        FieldElement::zero(), FieldElement::zero()};
    attack.invalid_assignment.right = {
        FieldElement::zero(), FieldElement::zero()};
    attack.invalid_assignment.output = {
        FieldElement::one(), second_output};
    attack.invalid_assignment.commitments = {FieldElement::one()};

    const std::vector<FieldElement> n_vec(8, FieldElement::zero());
    const std::vector<FieldElement> l_vec{
        FieldElement::one(), second_output,
        FieldElement::zero(), FieldElement::zero()};
    const std::vector<FieldElement> c_vec{
        row - mul0, mul1.negate(),
        FieldElement::zero(), FieldElement::zero()};

    attack.base_inputs.rho = purify::bppp::scalar_bytes(attack.rho);
    PURIFY_ASSIGN_OR_RETURN(
        attack.base_inputs.generators,
        purify::bppp::create_generators(n_vec.size() + l_vec.size(), context),
        "circuit_soundness:generators");
    attack.base_inputs.n_vec = purify::bppp::scalar_bytes(n_vec);
    attack.base_inputs.l_vec = purify::bppp::scalar_bytes(l_vec);
    attack.base_inputs.c_vec = purify::bppp::scalar_bytes(c_vec);
    return attack;
}

void test_masked_public_commitment_wrapper_accepts_invalid_gates(
    TestContext& ctx)
{
    purify::SecpContextPtr context = purify::make_secp_context();
    ctx.expect(context != nullptr,
               "masked soundness fixture creates a secp context");
    if (context == nullptr) return;

    Result<FoldedAttack> attack = build_folded_attack(context.get());
    ctx.expect(attack.has_value(),
               "masked soundness fixture derives the public folding transcript");
    if (!attack.has_value()) return;
    ctx.expect(!attack->circuit.evaluate(attack->invalid_assignment),
               "masked attack witness violates both multiplication gates");
    ctx.expect(
        attack->invalid_assignment.left[0] *
                attack->invalid_assignment.right[0] !=
            attack->invalid_assignment.output[0],
        "first multiplication equation is false");
    ctx.expect(
        attack->invalid_assignment.left[1] *
                attack->invalid_assignment.right[1] !=
            attack->invalid_assignment.output[1],
        "second multiplication equation is false");
    ctx.expect(attack->invalid_assignment.output[0] ==
                   attack->invalid_assignment.commitments[0],
               "public output commitment equation remains true");

    Result<PointBytes> a_witness =
        commit_witness_only(attack->base_inputs, context.get());
    ctx.expect(a_witness.has_value(),
               "masked attacker commits to the invalid folded witness");
    if (!a_witness.has_value()) return;

    std::vector<FieldElement> mask_n_values(8, FieldElement::zero());
    mask_n_values[0] = FieldElement::one();
    const std::vector<FieldElement> mask_l_values(4, FieldElement::zero());
    NormArgInputs mask_inputs = attack->base_inputs;
    mask_inputs.n_vec = purify::bppp::scalar_bytes(mask_n_values);
    mask_inputs.l_vec = purify::bppp::scalar_bytes(mask_l_values);
    Result<PointBytes> s_witness =
        commit_witness_only(mask_inputs, context.get());
    ctx.expect(s_witness.has_value(),
               "masked attacker commits to a nonzero mask");
    if (!s_witness.has_value()) return;

    const FieldElement t2 = weighted_norm(mask_n_values, attack->rho);
    ctx.expect(!t2.is_zero(), "masked attack has a nonzero quadratic mask");

    // The verifier anchors A with +row*G because the public commitment
    // coefficient is -row. Reconstruct that exact challenge input.
    PointBytes anchored_a{};
    ctx.expect(
        purify_bppp_offset_commitment(
            context.get(), a_witness->data(),
            purify::bppp::scalar_bytes(attack->public_anchor).data(),
            anchored_a.data()) != 0,
        "masked attacker reconstructs the verifier's anchored A");

    Bytes challenge_seed = attack->binding_digest;
    challenge_seed.insert(challenge_seed.end(), anchored_a.begin(),
                          anchored_a.end());
    challenge_seed.insert(challenge_seed.end(), s_witness->begin(),
                          s_witness->end());
    const ScalarBytes t2_bytes = purify::bppp::scalar_bytes(t2);
    challenge_seed.insert(challenge_seed.end(), t2_bytes.begin(),
                          t2_bytes.end());
    const FieldElement challenge = derive_nonzero_scalar(
        challenge_seed, CIRCUIT_ZK_CHALLENGE_TAG, 0);

    NormArgInputs masked_inputs = attack->base_inputs;
    std::vector<FieldElement> masked_n(8, FieldElement::zero());
    masked_n[0] = challenge;
    masked_inputs.n_vec = purify::bppp::scalar_bytes(masked_n);
    Result<purify::bppp::NormArgProof> norm_proof =
        purify::bppp::prove_norm_arg(masked_inputs, context.get());
    ctx.expect(norm_proof.has_value(),
               "masked attacker proves the challenge-combined folded relation");
    if (!norm_proof.has_value()) return;

    purify::bppp::ExperimentalCircuitZkNormArgProof forged{
        *a_witness, *s_witness, t2_bytes, norm_proof->proof};
    const std::array<PointBytes, 1> public_commitments{
        attack->public_commitment};
    Result<bool> accepted =
        purify::bppp::verify_experimental_circuit_zk_norm_arg_with_public_commitments(
            attack->circuit, forged, public_commitments, context.get(),
            attack->binding);
    ctx.expect(accepted.has_value() && *accepted,
               "masked public-commitment wrapper accepts two invalid gates after cancellation");
}

} // namespace

void run_circuit_soundness_tests(TestContext& ctx)
{
    test_masked_public_commitment_wrapper_accepts_invalid_gates(ctx);
}
