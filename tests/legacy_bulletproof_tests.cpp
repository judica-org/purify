// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <algorithm>
#include <array>
#include <cstddef>
#include <limits>
#include <vector>

#include "../src/bridge/bppp_bridge.h"
#include "purify.hpp"
#include "purify/bppp.hpp"
#include "test_harness.hpp"

using purify_test::TestContext;
using purify_test::expect_ok;

namespace {

using purify::BulletproofAssignmentData;
using purify::Bytes;
using purify::FieldElement;
using purify::NativeBulletproofCircuit;
using purify::Result;

std::size_t floor_lg_size_t(std::size_t n) {
    std::size_t out = 0;
    while (n > 1) {
        n >>= 1;
        ++out;
    }
    return out;
}

/* The legacy inner-product proof stores a parity bitvector before the x
 * coordinates. This helper jumps to the first serialized L/R x coordinate so
 * the malformed-point regression can tamper with it deterministically.
 */
std::size_t first_inner_product_point_x_offset(std::size_t n_gates) {
    const std::size_t half_n_ab = n_gates < 2 ? n_gates : 2;
    const std::size_t lg_vec_len = floor_lg_size_t(n_gates / 2);
    const std::size_t bitveclen = (2 * lg_vec_len + 7) / 8;
    return 64 + 256 + 1 + 32 + 64 * half_n_ab + bitveclen;
}

void test_experimental_bulletproof_roundtrip(TestContext& ctx) {
    NativeBulletproofCircuit circuit(1, 1, 0);
    std::size_t constraint = circuit.add_constraint(FieldElement::zero());
    circuit.add_output_term(0, constraint, FieldElement::one());
    circuit.add_commitment_term(0, constraint, FieldElement::from_int(-1));

    BulletproofAssignmentData assignment;
    assignment.left = {FieldElement::from_int(3)};
    assignment.right = {FieldElement::from_int(4)};
    assignment.output = {FieldElement::from_int(12)};
    assignment.commitments = {FieldElement::from_int(12)};

    std::array<unsigned char, 32> nonce{};
    for (std::size_t i = 0; i < nonce.size(); ++i) {
        nonce[i] = static_cast<unsigned char>(i + 1);
    }
    Bytes binding = purify::bytes_from_ascii("toy-circuit-binding");

    Result<purify::ExperimentalBulletproofProof> proof =
        purify::prove_experimental_circuit(circuit, assignment, nonce, purify::bppp::base_generator(), binding);
    expect_ok(ctx, proof, "prove_experimental_circuit succeeds on a one-gate circuit");
    if (!proof.has_value()) {
        return;
    }

    ctx.expect(proof->commitment != purify::BulletproofPointBytes{},
               "experimental circuit proof includes a concrete public commitment");

    Result<bool> verified =
        purify::verify_experimental_circuit(circuit, *proof, purify::bppp::base_generator(), binding);
    expect_ok(ctx, verified, "verify_experimental_circuit succeeds on the generated proof");
    if (verified.has_value()) {
        ctx.expect(*verified, "experimental circuit proof verifies");
    }

    Result<Bytes> encoded = proof->serialize();
    expect_ok(ctx, encoded, "ExperimentalBulletproofProof serializes");
    if (!encoded.has_value()) {
        return;
    }
    Result<purify::ExperimentalBulletproofProof> decoded =
        purify::ExperimentalBulletproofProof::deserialize(*encoded);
    expect_ok(ctx, decoded, "ExperimentalBulletproofProof round-trips");
    if (!decoded.has_value()) {
        return;
    }

    Result<bool> reparsed =
        purify::verify_experimental_circuit(circuit, *decoded, purify::bppp::base_generator(), binding);
    expect_ok(ctx, reparsed, "verify_experimental_circuit accepts the reparsed proof");
    if (reparsed.has_value()) {
        ctx.expect(*reparsed, "reparsed experimental circuit proof verifies");
    }

    Result<bool> wrong_binding =
        purify::verify_experimental_circuit(circuit, *proof, purify::bppp::base_generator(),
                                            purify::bytes_from_ascii("toy-circuit-binding-wrong"));
    expect_ok(ctx, wrong_binding, "verify_experimental_circuit runs with a wrong binding");
    if (wrong_binding.has_value()) {
        ctx.expect(!*wrong_binding, "experimental circuit proof is bound to the supplied statement bytes");
    }
}

/* Regression for the "hash one thing, verify another" bug: corrupt the first
 * serialized inner-product point so verification must reject the proof.
 */
void test_experimental_bulletproof_rejects_malformed_inner_product_point(TestContext& ctx) {
    NativeBulletproofCircuit circuit(4, 1, 0);
    std::size_t constraint = circuit.add_constraint(FieldElement::zero());
    circuit.add_output_term(0, constraint, FieldElement::one());
    circuit.add_commitment_term(0, constraint, FieldElement::from_int(-1));

    BulletproofAssignmentData assignment;
    assignment.left = {FieldElement::from_int(3), FieldElement::zero(), FieldElement::zero(), FieldElement::zero()};
    assignment.right = {FieldElement::from_int(4), FieldElement::zero(), FieldElement::zero(), FieldElement::zero()};
    assignment.output = {FieldElement::from_int(12), FieldElement::zero(), FieldElement::zero(), FieldElement::zero()};
    assignment.commitments = {FieldElement::from_int(12)};

    std::array<unsigned char, 32> nonce{};
    for (std::size_t i = 0; i < nonce.size(); ++i) {
        nonce[i] = static_cast<unsigned char>(0x40 + i);
    }
    Bytes binding = purify::bytes_from_ascii("malformed-inner-product-point");

    Result<purify::ExperimentalBulletproofProof> proof =
        purify::prove_experimental_circuit(circuit, assignment, nonce, purify::bppp::base_generator(), binding);
    expect_ok(ctx, proof, "prove_experimental_circuit succeeds on a multi-round circuit");
    if (!proof.has_value()) {
        return;
    }

    purify::ExperimentalBulletproofProof tampered = *proof;
    const std::size_t offset = first_inner_product_point_x_offset(circuit.n_gates);
    ctx.expect(tampered.proof.size() >= offset + 32, "multi-round proof exposes serialized inner-product points");
    if (tampered.proof.size() < offset + 32) {
        return;
    }
    std::fill_n(tampered.proof.begin() + static_cast<std::ptrdiff_t>(offset), 32, static_cast<unsigned char>(0xff));

    Result<bool> verified =
        purify::verify_experimental_circuit(circuit, tampered, purify::bppp::base_generator(), binding);
    expect_ok(ctx, verified, "verify_experimental_circuit runs on a malformed inner-product point proof");
    if (verified.has_value()) {
        ctx.expect(!*verified, "malformed inner-product point encodings are rejected");
    }
}

/* Regression for bridge-side zero-constraint handling. Pure bit/range-style
 * circuits should still round-trip through the legacy ABI.
 */
void test_legacy_bridge_zero_constraint_roundtrip(TestContext& ctx) {
    const purify_bulletproof_row_view empty_rows[1] = {{0, nullptr, nullptr}};
    const purify_bulletproof_circuit_view circuit = {
        1,
        0,
        0,
        0,
        empty_rows,
        empty_rows,
        empty_rows,
        nullptr,
        nullptr,
    };

    std::array<unsigned char, 32> al = FieldElement::from_int(3).to_bytes_be();
    std::array<unsigned char, 32> ar = FieldElement::from_int(4).to_bytes_be();
    std::array<unsigned char, 32> ao = FieldElement::from_int(12).to_bytes_be();
    const purify_bulletproof_assignment_view assignment = {
        1,
        0,
        al.data(),
        ar.data(),
        ao.data(),
        nullptr,
    };

    std::array<unsigned char, 32> nonce{};
    for (std::size_t i = 0; i < nonce.size(); ++i) {
        nonce[i] = static_cast<unsigned char>(0x20 + i);
    }

    std::vector<unsigned char> proof(purify_bulletproof_required_proof_size(1));
    std::size_t proof_len = proof.size();
    int proved = purify_bulletproof_prove_circuit(&circuit, &assignment, nullptr, purify::bppp::base_generator().data(),
                                                  nonce.data(), nullptr, 0, nullptr, proof.data(), &proof_len);
    ctx.expect(proved == 1, "legacy bridge proves zero-explicit-constraint circuits");
    if (proved != 1) {
        return;
    }

    int verified = purify_bulletproof_verify_circuit(&circuit, nullptr, purify::bppp::base_generator().data(),
                                                     nullptr, 0, proof.data(), proof_len);
    ctx.expect(verified == 1, "legacy bridge verifies zero-explicit-constraint circuits");
}

void test_legacy_bridge_rejects_overflowed_sizes(TestContext& ctx) {
    constexpr std::size_t kOverflowGateCount =
        std::size_t{1} << (std::numeric_limits<std::size_t>::digits - 1);
    constexpr std::size_t kOverflowGeneratorCount =
        (std::numeric_limits<std::size_t>::max() / 33u) + 1u;
    constexpr std::size_t kHugeRowSize =
        (std::numeric_limits<std::size_t>::max() / 2u) + 1u;

    purify_bulletproof_backend_resources* bulletproof_resources =
        purify_bulletproof_backend_resources_create(kOverflowGateCount);
    ctx.expect(bulletproof_resources == nullptr,
               "legacy bulletproof backend rejects generator-table size overflow on large gate counts");
    if (bulletproof_resources != nullptr) {
        purify_bulletproof_backend_resources_destroy(bulletproof_resources);
    }

    const auto base_generator = purify::bppp::base_generator();
    purify_bppp_backend_resources* bppp_resources =
        purify_bppp_backend_resources_create(base_generator.data(), kOverflowGeneratorCount);
    ctx.expect(bppp_resources == nullptr,
               "BPPP backend rejects serialized generator length overflow");
    if (bppp_resources != nullptr) {
        purify_bppp_backend_resources_destroy(bppp_resources);
    }

    std::size_t serialized_len = 1;
    int created = purify_bppp_create_generators(kOverflowGeneratorCount, nullptr, &serialized_len);
    ctx.expect(created == 0, "generator creation reports failure when the serialized length would overflow");
    ctx.expect(serialized_len == 0,
               "generator creation zeroes the reported output length when the serialized size cannot be represented");

    const std::array<std::size_t, 1> dummy_indices{0};
    const std::array<unsigned char, 32> dummy_scalar{};
    const std::array<unsigned char, 1> dummy_proof{};
    const purify_bulletproof_row_view overflowing_rows[2] = {
        {kHugeRowSize, dummy_indices.data(), dummy_scalar.data()},
        {kHugeRowSize, dummy_indices.data(), dummy_scalar.data()},
    };
    const purify_bulletproof_circuit_view overflowing_circuit = {
        2,
        0,
        1,
        0,
        overflowing_rows,
        overflowing_rows,
        overflowing_rows,
        nullptr,
        dummy_scalar.data(),
    };
    int verified = purify_bulletproof_verify_circuit(&overflowing_circuit,
                                                     nullptr,
                                                     base_generator.data(),
                                                     nullptr,
                                                     0,
                                                     dummy_proof.data(),
                                                     dummy_proof.size());
    ctx.expect(verified == 0, "legacy bridge rejects overflowed row-entry totals before allocating or parsing");
}

}  // namespace

void run_legacy_bulletproof_tests(TestContext& ctx) {
    test_experimental_bulletproof_roundtrip(ctx);
    test_experimental_bulletproof_rejects_malformed_inner_product_point(ctx);
    test_legacy_bridge_zero_constraint_roundtrip(ctx);
    test_legacy_bridge_rejects_overflowed_sizes(ctx);
}
