// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <algorithm>
#include <memory>
#include <vector>

#include "../src/bridge/bppp_bridge.h"
#include "purify/bppp.hpp"
#include "test_harness.hpp"

namespace {

using purify::FieldElement;
using purify_test::TestContext;
using purify_test::expect_error;
using purify_test::expect_ok;

void check_initial_point_boundary(TestContext& ctx) {
    auto secp = purify::make_secp_context();
    ctx.expect(secp != nullptr, "norm boundary context creates");
    if (!secp) return;
    auto generators = purify::bppp::create_generators(2, secp.get());
    expect_ok(ctx, generators, "norm boundary generators create");
    if (!generators) return;
    purify::bppp::NormArgInputs inputs{
        FieldElement::from_int(3).to_bytes_be(), *generators,
        {FieldElement::from_int(5).to_bytes_be()},
        {FieldElement::from_int(7).to_bytes_be()},
        {FieldElement::from_int(11).to_bytes_be()}};
    auto commitment = purify::bppp::commit_norm_arg(inputs, secp.get());
    expect_ok(ctx, commitment, "finite terminal norm commitment creates");
    if (!commitment) return;

    // With one coordinate in each family there are no folding rounds. The
    // encoding consists only of these two public fixture witness scalars.
    purify::Bytes terminal(inputs.n_vec[0].begin(), inputs.n_vec[0].end());
    terminal.insert(terminal.end(), inputs.l_vec[0].begin(), inputs.l_vec[0].end());
    purify::bppp::NormArgProof proof{
        inputs.rho, *generators, inputs.c_vec, 1, *commitment, terminal};
    ctx.expect(purify::bppp::verify_norm_arg(proof, secp.get()),
               "finite terminal norm statement verifies");

    purify::Bytes generator_bytes;
    for (const auto& generator : *generators) {
        generator_bytes.insert(generator_bytes.end(), generator.begin(), generator.end());
    }
    using Resources = std::unique_ptr<purify_bppp_backend_resources,
        decltype(&purify_bppp_backend_resources_destroy)>;
    Resources resources(purify_bppp_backend_resources_create(
        secp.get(), generator_bytes.data(), generators->size()),
        purify_bppp_backend_resources_destroy);
    ctx.expect(resources != nullptr, "cached norm boundary resources create");
    if (!resources) return;
    const auto cached_verify = [&](const purify::bppp::NormArgProof& candidate) {
        return purify_bppp_verify_norm_arg_with_resources(
            resources.get(), candidate.rho.data(), candidate.c_vec[0].data(), 1, 1,
            candidate.commitment.data(), candidate.proof.data(), candidate.proof.size());
    };
    ctx.expect(cached_verify(proof) != 0, "cached finite terminal statement verifies");

    // The all-zero opening is mathematically an identity commitment. This
    // bridge rejects initial infinity, consistently with its commit/prove
    // encoding. It must not hash an unwritten serialization buffer.
    proof.commitment.fill(0);
    std::fill(proof.proof.begin(), proof.proof.end(), 0);
    ctx.expect(!purify::bppp::verify_norm_arg(proof, secp.get()),
               "initial infinity is rejected before transcript use");
    ctx.expect(cached_verify(proof) == 0,
               "cached verification rejects initial infinity too");
    inputs.n_vec[0].fill(0);
    inputs.l_vec[0].fill(0);
    ctx.expect(!purify::bppp::commit_norm_arg(inputs, secp.get()),
               "norm commitment creation also rejects initial infinity");
}

void check_norm_length_boundary(TestContext& ctx) {
    auto secp = purify::make_secp_context();
    ctx.expect(secp != nullptr, "norm length context creates");
    if (!secp) return;
    auto generators = purify::bppp::create_generators(10, secp.get());
    expect_ok(ctx, generators, "norm length generators create");
    if (!generators) return;
    const auto one = FieldElement::one().to_bytes_be();
    purify::bppp::NormArgInputs inputs{FieldElement::from_int(3).to_bytes_be(),
        *generators, {one, one}, std::vector(8, one), std::vector(8, one)};
    auto commitment = purify::bppp::commit_norm_arg(inputs, secp.get());
    expect_ok(ctx, commitment, "unsupported proof shape still has a mathematical commitment");
    if (!commitment) return;
    ctx.expect(purify_bppp_required_proof_size(2, 8) == 0,
               "proof sizing excludes linear-only norm tails");
    expect_error(ctx, purify::bppp::prove_norm_arg(inputs, secp.get()),
               purify::ErrorCode::InvalidDimensions,
               "ordinary prover rejects norm length below linear length");
    expect_error(ctx, purify::bppp::prove_norm_arg_to_commitment(inputs, *commitment, secp.get()),
               purify::ErrorCode::InvalidDimensions,
               "anchored prover rejects norm length below linear length");
    // Produced and verified by the pre-boundary implementation (28e9152)
    // for the statement above. Removing the verifier guard must accept it.
    const purify::Bytes legacy_proof{
        0x01, 0xfc, 0x99, 0xfc, 0xb7, 0x85, 0x03, 0xa9, 0x03, 0xa8, 0x3e, 0x12,
        0x9a, 0x92, 0x9b, 0x2d, 0x4c, 0x6a, 0x25, 0xd8, 0x6e, 0xf5, 0x91, 0x8a,
        0x9a, 0x31, 0x06, 0xdf, 0x93, 0x3c, 0xcb, 0xfe, 0x4e, 0x63, 0x5d, 0xed,
        0xf0, 0x06, 0x31, 0x22, 0x70, 0x1f, 0x23, 0xa3, 0x73, 0x3a, 0x05, 0xc1,
        0x06, 0xcd, 0x80, 0xbe, 0x99, 0x36, 0x2a, 0x5f, 0xe7, 0x37, 0x75, 0x22,
        0x43, 0xd9, 0x07, 0xb5, 0xcf, 0x00, 0x78, 0x09, 0x21, 0x88, 0x31, 0xa5,
        0xad, 0xd5, 0x1c, 0xcd, 0xe5, 0x98, 0x03, 0x23, 0x67, 0x45, 0xd6, 0xdc,
        0x14, 0xc1, 0x6a, 0xe8, 0x10, 0xfb, 0xfb, 0x37, 0x30, 0xcb, 0xb5, 0x41,
        0xd4, 0xb9, 0x0e, 0x5c, 0x4b, 0x70, 0x3e, 0xae, 0xc0, 0x84, 0xbe, 0xd6,
        0x74, 0x39, 0x83, 0x63, 0xea, 0xe7, 0x48, 0xa0, 0xca, 0xbf, 0xcd, 0x14,
        0xc1, 0xdc, 0x99, 0xfc, 0x93, 0x2c, 0x0a, 0xbf, 0xe5, 0x09, 0x02, 0xe8,
        0x59, 0xd3, 0x10, 0x55, 0x93, 0xb9, 0x7b, 0x8e, 0x32, 0x91, 0x13, 0xb5,
        0x6c, 0x0f, 0x2b, 0xf0, 0x03, 0x5b, 0x8b, 0xa5, 0x1e, 0x66, 0xf6, 0xd5,
        0xdd, 0x0b, 0xec, 0x9d, 0x95, 0x33, 0xfa, 0xb1, 0x63, 0xc1, 0xd5, 0x72,
        0x5b, 0x91, 0x14, 0x83, 0x4b, 0x09, 0x2a, 0xe1, 0xd6, 0x2c, 0xc3, 0xb3,
        0x32, 0x24, 0xe0, 0x79, 0xf7, 0xeb, 0xa2, 0xf0, 0xe4, 0xc2, 0x95, 0xf6,
        0x30, 0x96, 0xe1, 0x05, 0xac, 0x52, 0xdd, 0x12, 0x0f, 0x92, 0xd2, 0x3f,
        0x14, 0xbe, 0xb5, 0xf5, 0x12, 0x87, 0xef, 0xd9, 0x2e, 0xd5, 0x84, 0xa8,
        0xfb, 0x8e, 0x23, 0xce, 0x93, 0xf9, 0x0c, 0xe8, 0xe6, 0x05, 0x39, 0x0b,
        0xcd, 0x77, 0x70, 0xe2, 0x02, 0xc4, 0x79, 0xf0, 0x45, 0xbc, 0x37, 0xe2,
        0x75, 0x93, 0x66, 0xac, 0xd0, 0x5d, 0x63, 0x9b, 0x1c, 0x08, 0x65, 0x24,
        0xd2, 0x86, 0xd4, 0x38, 0x62, 0x4d, 0x73,
    };
    purify::bppp::NormArgProof unsupported{
        inputs.rho, *generators, inputs.c_vec, 2, *commitment, legacy_proof};
    ctx.expect(!purify::bppp::verify_norm_arg(unsupported, secp.get()),
               "ordinary verifier rejects unsupported dimensions before proof parsing");

    purify::Bytes generator_bytes, c_bytes;
    for (const auto& generator : *generators) {
        generator_bytes.insert(generator_bytes.end(), generator.begin(), generator.end());
    }
    for (const auto& c : inputs.c_vec) c_bytes.insert(c_bytes.end(), c.begin(), c.end());
    using Resources = std::unique_ptr<purify_bppp_backend_resources,
        decltype(&purify_bppp_backend_resources_destroy)>;
    Resources resources(purify_bppp_backend_resources_create(
        secp.get(), generator_bytes.data(), generators->size()),
        purify_bppp_backend_resources_destroy);
    ctx.expect(resources != nullptr, "cached norm length resources create");
    if (!resources) return;
    ctx.expect(purify_bppp_verify_norm_arg_with_resources(
        resources.get(), inputs.rho.data(), c_bytes.data(), 8, 2, commitment->data(),
        unsupported.proof.data(), unsupported.proof.size()) == 0,
        "cached verification applies the same norm length boundary");
}

} // namespace

void run_norm_protocol_tests(TestContext& ctx) {
    check_initial_point_boundary(ctx);
    check_norm_length_boundary(ctx);
}
