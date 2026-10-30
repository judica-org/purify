// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <array>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <limits>
#include <utility>

#include "purify.hpp"
#include "purify/bppp.hpp"
#include "test_harness.hpp"

namespace {

using purify_test::TestContext;
using purify_test::expect_ok;
using purify::Bytes;
using purify::FieldElement;
using purify::Result;
using PointPair = std::pair<purify::JacobianPoint, purify::JacobianPoint>;
using Clock = std::chrono::steady_clock;

// This is an honest-witness experiment, not an enrollment verifier. The
// existing experimental proof backend still needs its soundness review.
Result<PointPair> decode_points(const purify::UInt512& encoded) {
    PURIFY_ASSIGN_OR_RETURN(const auto& coords, purify::unpack_public(encoded), "recovery_root:unpack");
    PURIFY_ASSIGN_OR_RETURN(const auto& x1, FieldElement::try_from_uint256(coords.first), "recovery_root:x1");
    PURIFY_ASSIGN_OR_RETURN(const auto& x2, FieldElement::try_from_uint256(coords.second), "recovery_root:x2");
    const auto p1 = purify::curve1().lift_x(x1);
    const auto p2 = purify::curve2().lift_x(x2);
    if (!p1.has_value() || !p2.has_value() || p1->infinity || p2->infinity ||
        !purify::curve1().mul(*p1, purify::order_n1()).infinity ||
        !purify::curve2().mul(*p2, purify::order_n2()).infinity) {
        return purify::unexpected_error(purify::ErrorCode::BackendRejectedInput, "recovery_root:points");
    }
    return PointPair{*p1, *p2};
}

Result<FieldElement> shared_output(const purify::SecretKey& secret, const purify::UInt512& peer) {
    PURIFY_ASSIGN_OR_RETURN(const auto& scalars, purify::unpack_secret(secret.packed()), "recovery_root:secret");
    PURIFY_ASSIGN_OR_RETURN(const auto& points, decode_points(peer), "recovery_root:peer");
    PURIFY_ASSIGN_OR_RETURN(const auto& s1,
        purify::curve1().mul_secret_affine(points.first, scalars.first), "recovery_root:shared1");
    PURIFY_ASSIGN_OR_RETURN(const auto& s2,
        purify::curve2().mul_secret_affine(points.second, scalars.second), "recovery_root:shared2");
    return purify::combine(s1.x, s2.x);
}

Result<purify::NativeBulletproofCircuit> public_circuit(
    const purify::UInt512& root, const purify::UInt512& ephemeral) {
    PURIFY_ASSIGN_OR_RETURN(const auto& points, decode_points(root), "recovery_root:root");
    PURIFY_RETURN_IF_ERROR(decode_points(ephemeral), "recovery_root:ephemeral");
    purify::Transcript transcript;
    PURIFY_ASSIGN_OR_RETURN(const auto& relation,
        purify::circuit_main(transcript, points.first, points.second), "recovery_root:circuit");
    purify::BulletproofTranscript bp;
    PURIFY_RETURN_IF_ERROR(bp.from_transcript(transcript, relation.n_bits), "recovery_root:lower");
    PURIFY_RETURN_IF_ERROR(bp.add_pubkey_and_out(ephemeral, relation.p1x, relation.p2x, relation.out),
                          "recovery_root:public");
    return bp.native_circuit();
}

Result<purify::BulletproofWitnessData> owner_witness(
    const purify::UInt512& root, const purify::GeneratedKey& ephemeral) {
    PURIFY_ASSIGN_OR_RETURN(const auto& points, decode_points(root), "recovery_root:root");
    PURIFY_ASSIGN_OR_RETURN(const auto& scalars,
        purify::unpack_secret(ephemeral.secret.packed()), "recovery_root:owner");
    PURIFY_ASSIGN_OR_RETURN(const auto& output, shared_output(ephemeral.secret, root), "recovery_root:output");
    purify::Transcript transcript;
    PURIFY_ASSIGN_OR_RETURN(const auto& relation,
        purify::circuit_main(transcript, points.first, points.second, scalars.first, scalars.second),
        "recovery_root:witness_circuit");
    purify::BulletproofTranscript bp;
    PURIFY_RETURN_IF_ERROR(bp.from_transcript(transcript, relation.n_bits), "recovery_root:lower");
    PURIFY_RETURN_IF_ERROR(bp.add_pubkey_and_out(ephemeral.public_key, relation.p1x, relation.p2x, relation.out),
                          "recovery_root:public");
    PURIFY_ASSIGN_OR_RETURN(auto assignment, bp.assignment_data(transcript.varmap(), output),
                            "recovery_root:assignment");
    return purify::BulletproofWitnessData{ephemeral.public_key, output, std::move(assignment)};
}

Result<purify::bppp::PointBytes> output_point(const FieldElement& output, purify_secp_context* context) {
    const purify::bppp::ScalarBytes zero{};
    const auto generator = purify::bppp::base_generator(context);
    return purify::bppp::pedersen_commit_char(zero, purify::bppp::scalar_bytes(output), context,
                                             generator, generator);
}

Bytes statement_binding(const purify::UInt512& root, const purify::UInt512& ephemeral,
                        const purify::bppp::PointBytes& output, const Bytes& context) {
    const auto root_bytes = root.to_bytes_be();
    const auto ephemeral_bytes = ephemeral.to_bytes_be();
    const auto digest = purify::TaggedHash("Purify/RecoveryRoot/HonestLeafV1").digest_many<4>(
        {root_bytes, ephemeral_bytes, output, context});
    return Bytes(digest.begin(), digest.end());
}

Result<bool> verify_public_leaf(const purify::UInt512& root, const purify::UInt512& ephemeral,
                               const purify::bppp::PointBytes& output, const Bytes& context,
                               const purify::bppp::ExperimentalCircuitZkNormArgProof& proof,
                               purify_secp_context* secp) {
    PURIFY_ASSIGN_OR_RETURN(const auto& circuit, public_circuit(root, ephemeral), "recovery_root:verify_circuit");
    const std::array<purify::bppp::PointBytes, 1> commitments{output};
    const auto binding = statement_binding(root, ephemeral, output, context);
    return purify::bppp::verify_experimental_circuit_zk_norm_arg_with_public_commitments(
        circuit, proof, commitments, secp, binding);
}

// A measurement envelope only: version || A:64 || P:33 || outer A:33 ||
// outer S:33 || t2:32 || inner length:u32be || inner proof. Root and context
// are supplied by the enclosing registration and are not counted twice.
Bytes measurement_envelope(const purify::UInt512& ephemeral, const purify::bppp::PointBytes& output,
                           const purify::bppp::ExperimentalCircuitZkNormArgProof& proof) {
    Bytes bytes{1};
    const auto ephemeral_bytes = ephemeral.to_bytes_be();
    bytes.insert(bytes.end(), ephemeral_bytes.begin(), ephemeral_bytes.end());
    bytes.insert(bytes.end(), output.begin(), output.end());
    bytes.insert(bytes.end(), proof.a_commitment.begin(), proof.a_commitment.end());
    bytes.insert(bytes.end(), proof.s_commitment.begin(), proof.s_commitment.end());
    bytes.insert(bytes.end(), proof.t2.begin(), proof.t2.end());
    const auto length = static_cast<std::uint32_t>(proof.proof.size());
    for (unsigned shift : {24U, 16U, 8U, 0U}) {
        bytes.push_back(static_cast<unsigned char>(length >> shift));
    }
    bytes.insert(bytes.end(), proof.proof.begin(), proof.proof.end());
    return bytes;
}

void test_companion_root_leaf(TestContext& ctx) {
    auto secp = purify::make_secp_context();
    ctx.expect(secp != nullptr, "recovery-root secp context is available");
    if (!secp) return;

    // Public toy seeds only; this test must never receive operator secrets.
    std::array<unsigned char, 32> root_seed{};
    std::array<unsigned char, 32> owner_seed{};
    std::array<unsigned char, 32> replacement_seed{};
    root_seed.fill(0x31);
    owner_seed.fill(0x72);
    replacement_seed.fill(0xa4);
    auto root = purify::generate_key(root_seed);
    auto owner = purify::generate_key(owner_seed);
    auto replacement = purify::generate_key(replacement_seed);
    expect_ok(ctx, root, "companion recovery-root fixture is generated");
    expect_ok(ctx, owner, "independent ephemeral fixture is generated");
    expect_ok(ctx, replacement, "replacement public-key fixture is generated");
    if (!root || !owner || !replacement) return;

    auto witness = owner_witness(root->public_key, *owner);
    auto recovered = shared_output(root->secret, owner->public_key);
    auto circuit = public_circuit(root->public_key, owner->public_key);
    expect_ok(ctx, witness, "owner builds a leaf witness with no root secret");
    expect_ok(ctx, recovered, "root secret recovers the leaf output with no owner secret");
    expect_ok(ctx, circuit, "verifier builds the relation from public root and ephemeral keys");
    if (!witness || !recovered || !circuit) return;
    ctx.expect(witness->output == *recovered, "both sides derive the same punishment scalar");
    ctx.expect(circuit->evaluate(witness->assignment), "honest assignment satisfies the public circuit");

    auto point = output_point(witness->output, secp.get());
    auto recovered_point = output_point(*recovered, secp.get());
    expect_ok(ctx, point, "owner output maps to a finite exact secp point");
    expect_ok(ctx, recovered_point, "recovered scalar maps to a finite exact secp point");
    if (!point || !recovered_point) return;
    ctx.expect(*point == *recovered_point, "recovery preserves the full output point including parity");

    auto normalized = purify::bppp::scalar_bytes(*recovered);
    std::array<unsigned char, 32> xonly{};
    ctx.expect(purify_bip340_key_from_seckey(secp.get(), normalized.data(), xonly.data()) != 0,
               "recovered scalar normalizes for BIP340 outside the leaf circuit");
    std::array<unsigned char, 32> point_xonly{};
    int parity = 0;
    ctx.expect(purify_bip340_xonly_from_point(secp.get(), point->data(), point_xonly.data(), &parity) != 0,
               "raw full-point output has an x-only spend-key representation");
    ctx.expect(xonly == point_xonly, "normalization retains the advertised spend-key x coordinate");
    const auto expected_scalar = parity == 0 ? *recovered : recovered->negate();
    ctx.expect(normalized == purify::bppp::scalar_bytes(expected_scalar),
               "BIP340 recovery uses the exact scalar selected by raw point parity");

    const auto context = purify::bytes_from_ascii("public toy root/owner/punishment context");
    const auto binding = statement_binding(root->public_key, owner->public_key, *point, context);
    const std::array<purify::bppp::PointBytes, 1> outputs{*point};
    purify::bppp::ScalarBytes nonce{};
    nonce.fill(0x9c);
    const auto prove_start = Clock::now();
    auto proof = purify::bppp::prove_experimental_circuit_zk_norm_arg_with_public_commitments(
        *circuit, witness->assignment, nonce, outputs, secp.get(), binding);
    const auto prove_end = Clock::now();
    expect_ok(ctx, proof, "existing experimental BP++ backend proves the honest leaf assignment");
    if (!proof) return;
    const auto verify_start = Clock::now();
    auto verified = verify_public_leaf(root->public_key, owner->public_key, *point, context, *proof, secp.get());
    const auto verify_end = Clock::now();
    expect_ok(ctx, verified, "leaf verification uses only public inputs");
    if (verified) ctx.expect(*verified, "honest recovery-root leaf proof verifies");

    auto changed_context = context;
    changed_context.push_back(0);
    auto context_result = verify_public_leaf(root->public_key, owner->public_key, *point,
                                              changed_context, *proof, secp.get());
    ctx.expect(!context_result || !*context_result, "unchanged proof rejects a substituted context");
    auto root_result = verify_public_leaf(replacement->public_key, owner->public_key, *point,
                                           context, *proof, secp.get());
    ctx.expect(!root_result || !*root_result, "unchanged proof rejects a substituted recovery root");
    auto owner_result = verify_public_leaf(root->public_key, replacement->public_key, *point,
                                            context, *proof, secp.get());
    ctx.expect(!owner_result || !*owner_result, "unchanged proof rejects a substituted ephemeral key");
    auto other_point = output_point(witness->output + FieldElement::one(), secp.get());
    expect_ok(ctx, other_point, "distinct output-point fixture is valid");
    if (other_point) {
        auto output_result = verify_public_leaf(root->public_key, owner->public_key, *other_point,
                                                 context, *proof, secp.get());
        ctx.expect(!output_result || !*output_result, "unchanged proof rejects a substituted output point");
    }
    auto invalid_root = public_circuit(purify::packed_public_key_space_size(), owner->public_key);
    ctx.expect(!invalid_root, "noncanonical root encoding rejects before circuit construction");
    auto invalid_owner = public_circuit(root->public_key, purify::packed_public_key_space_size());
    ctx.expect(!invalid_owner, "noncanonical ephemeral encoding rejects before circuit construction");

    ctx.expect(proof->proof.size() <= std::numeric_limits<std::uint32_t>::max(),
               "measurement envelope inner proof length fits its fixed field");
    if (proof->proof.size() > std::numeric_limits<std::uint32_t>::max()) return;
    const auto envelope = measurement_envelope(owner->public_key, *point, *proof);
    const auto outer_bytes = proof->a_commitment.size() + proof->s_commitment.size() + proof->t2.size();
    const auto payload_bytes = 64 + point->size() + outer_bytes + proof->proof.size();
    ctx.expect(envelope.size() == payload_bytes + 5, "measurement envelope includes all outer proof fields");
    std::cout << "recovery_root_honest_leaf gates=" << circuit->n_gates
              << " constraints=" << circuit->c.size()
              << " inner_proof_bytes=" << proof->proof.size()
              << " outer_proof_bytes=" << outer_bytes
              << " leaf_payload_bytes=" << payload_bytes
              << " leaf_framed_bytes=" << envelope.size()
              << " prove_ms=" << std::chrono::duration<double, std::milli>(prove_end - prove_start).count()
              << " verify_ms=" << std::chrono::duration<double, std::milli>(verify_end - verify_start).count()
              << '\n';
}

} // namespace

void run_recovery_root_tests(TestContext& ctx) {
    test_companion_root_leaf(ctx);
}
