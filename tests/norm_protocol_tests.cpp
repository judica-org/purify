// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <algorithm>
#include <array>
#include <cstdint>
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

void check_public_digest_transcript(TestContext& ctx) {
    auto secp = purify::make_secp_context();
    ctx.expect(secp != nullptr, "factored norm transcript context creates");
    if (!secp) return;
    // Public toy generators G, 2G and 3G. The bridge accepts generator
    // encodings, but the transcript hashes their canonical SEC1 encodings.
    const std::array<const char*, 3> x_coordinates{
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
        "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"};
    std::vector<purify::bppp::PointBytes> generators;
    for (std::size_t i = 0; i < x_coordinates.size(); ++i) {
        purify::bppp::PointBytes encoded{};
        encoded[0] = i == 2 ? 0x0b : 0x0a;
        const auto x = purify::UInt256::from_hex(x_coordinates[i]).to_bytes_be();
        std::copy(x.begin(), x.end(), encoded.begin() + 1);
        generators.push_back(encoded);
    }
    const auto scalar = [](int value) { return FieldElement::from_int(value).to_bytes_be(); };
    purify::bppp::NormArgInputs inputs{scalar(3), generators,
        {scalar(5), scalar(7)}, {scalar(11)}, {scalar(13)}};
    auto proof = purify::bppp::prove_norm_arg(inputs, secp.get());
    expect_ok(ctx, proof, "honest one-round norm proof produces");
    if (!proof) return;
    ctx.expect(proof->proof.size() == 129, "one-round norm proof has two terminal scalars");
    if (proof->proof.size() != 129) return;
    ctx.expect(purify::bppp::verify_norm_arg(*proof, secp.get()), "factored norm proof verifies");

    const auto append_size = [](purify::Bytes& bytes, std::uint64_t value) {
        for (std::size_t i = 0; i < 8; ++i) bytes.push_back(static_cast<unsigned char>(value >> (8 * i)));
    };
    purify::Bytes public_data(inputs.rho.begin(), inputs.rho.end());
    append_size(public_data, 2);
    append_size(public_data, 3);
    for (auto point : generators) {
        point[0] = 0x02;
        public_data.insert(public_data.end(), point.begin(), point.end());
    }
    append_size(public_data, 1);
    public_data.insert(public_data.end(), inputs.c_vec[0].begin(), inputs.c_vec[0].end());
    const auto digest = purify::TaggedHash("Purify/BPPP/NormArg/PublicDataV1").digest(public_data);
    // Independently generated with Python hashlib over the 187-byte canonical
    // message above and SHA256(tag) || SHA256(tag). No bridge digest API is used.
    ctx.expect(digest == purify::UInt256::from_hex(
        "18ca38e5b6feca046f399f961d6012b3693a10a44a61c87dec769164d4eb9205").to_bytes_be(),
        "public prehash matches independent canonical transcript vector");
    purify::Bytes challenge_input(digest.begin(), digest.end());
    challenge_input.insert(challenge_input.end(), proof->commitment.begin(), proof->commitment.end());
    challenge_input.insert(challenge_input.end(), proof->proof.begin(), proof->proof.begin() + 65);
    append_size(challenge_input, 0);
    const auto gamma = FieldElement::from_bytes32(
        purify::TaggedHash("Purify/BPPP/NormArg/TranscriptV1").digest(challenge_input));
    purify::bppp::ScalarBytes terminal_n{};
    std::copy_n(proof->proof.begin() + 65, terminal_n.size(), terminal_n.begin());
    const auto expected_n = FieldElement::from_int(5) * FieldElement::from_int(3).inverse()
        + gamma * FieldElement::from_int(7);
    ctx.expect(terminal_n == expected_n.to_bytes_be(),
               "native prover uses the independently reconstructed factored challenge");

    purify::Bytes generator_bytes, n_bytes;
    for (const auto& point : generators) generator_bytes.insert(generator_bytes.end(), point.begin(), point.end());
    for (const auto& value : inputs.n_vec) n_bytes.insert(n_bytes.end(), value.begin(), value.end());
    using Resources = std::unique_ptr<purify_bppp_backend_resources,
        decltype(&purify_bppp_backend_resources_destroy)>;
    Resources resources(purify_bppp_backend_resources_create(
        secp.get(), generator_bytes.data(), generators.size()), purify_bppp_backend_resources_destroy);
    ctx.expect(resources != nullptr, "factored norm cached resources create");
    if (!resources) return;
    purify::Bytes cached(proof->proof.size());
    auto cached_size = cached.size();
    ctx.expect(purify_bppp_prove_norm_arg_to_commitment_with_resources(
        resources.get(), inputs.rho.data(), n_bytes.data(), 2, inputs.l_vec[0].data(), 1,
        inputs.c_vec[0].data(), 1, proof->commitment.data(), cached.data(), &cached_size) != 0,
        "cached anchored norm prover uses the factored transcript");
    ctx.expect(cached_size == proof->proof.size() && cached == proof->proof,
               "cached and uncached factored norm proofs are identical");
    ctx.expect(purify_bppp_verify_norm_arg_with_resources(resources.get(), proof->rho.data(),
        proof->c_vec[0].data(), 1, 2, proof->commitment.data(), cached.data(), cached_size) != 0,
        "cached factored norm proof verifies");

    auto changed = *proof;
    changed.rho = scalar(4);
    ctx.expect(!purify::bppp::verify_norm_arg(changed, secp.get()), "unchanged norm proof rejects a different rho");
    changed = *proof;
    changed.c_vec[0] = scalar(14);
    ctx.expect(!purify::bppp::verify_norm_arg(changed, secp.get()), "unchanged norm proof rejects a different public coefficient");
    changed = *proof;
    std::swap(changed.generators[0], changed.generators[1]);
    ctx.expect(!purify::bppp::verify_norm_arg(changed, secp.get()), "unchanged norm proof rejects reordered generators");
    changed = *proof;
    changed.commitment = generators[1];
    changed.commitment[0] = 0x02;
    ctx.expect(!purify::bppp::verify_norm_arg(changed, secp.get()), "unchanged norm proof rejects a different finite commitment");
}

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
    purify::bppp::NormArgProof unsupported{
        inputs.rho, *generators, inputs.c_vec, 2, *commitment, purify::Bytes(259, 0)};
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

void check_pending_norm_equation(TestContext& ctx) {
    using namespace purify::bppp;
    auto secp = purify::make_secp_context();
    ctx.expect(secp != nullptr, "pending norm context creates");
    if (!secp) return;
    auto generators = create_generators(8, secp.get());
    expect_ok(ctx, generators, "pending norm generators create");
    if (!generators) return;
    const auto scalar = [](int value) { return FieldElement::from_int(value).to_bytes_be(); };
    NormArgInputs inputs{scalar(3), {generators->begin(), generators->begin() + 6},
        {scalar(2), scalar(3), scalar(4), scalar(5)},
        {scalar(7), scalar(11)}, {scalar(13), scalar(17)}};
    auto proof = prove_norm_arg(inputs, secp.get());
    expect_ok(ctx, proof, "pending norm fixture proves");
    if (!proof) return;
    ctx.expect(verify_norm_arg(*proof, secp.get()), "ordinary verifier accepts pending fixture");
    std::array<ScalarBytes, 2> gammas{};
    ScalarBytes n{}, l{};
    PointBytes residual{};
    const auto* gs = reinterpret_cast<const unsigned char*>(generators->data());
    const auto* cs = reinterpret_cast<const unsigned char*>(inputs.c_vec.data());
    ctx.expect(purify_bppp_prepare_norm_arg_claim(secp.get(), inputs.rho.data(), gs, 6,
        cs, 2, 4, proof->commitment.data(), proof->proof.data(), proof->proof.size(),
        n.data(), l.data(), reinterpret_cast<unsigned char*>(gammas.data()), 2,
        residual.data()) != 0, "norm transcript prepares a pending equation");
    const auto rho = FieldElement::from_int(3);
    const auto gamma0 = FieldElement::from_bytes32(gammas[0]);
    const auto gamma1 = FieldElement::from_bytes32(gammas[1]);
    const auto terminal_n = FieldElement::from_bytes32(n);
    const auto terminal_l = FieldElement::from_bytes32(l);
    // Enumerate the four G and two H coefficients directly, independently
    // of the later compact-polynomial accumulator's expansion routine.
    const std::array<ScalarBytes, 8> coefficients{
        (terminal_n * rho * rho * rho).to_bytes_be(),
        (terminal_n * rho * rho * gamma0).to_bytes_be(),
        (terminal_n * rho * gamma1).to_bytes_be(),
        (terminal_n * gamma0 * gamma1).to_bytes_be(),
        terminal_l.to_bytes_be(), (terminal_l * gamma0).to_bytes_be(), scalar(0), scalar(0)};
    std::array<PointBytes, 8> basis{};
    ctx.expect(purify_bppp_shift_norm_basis(secp.get(), gs, 8, cs, 2, 4,
        reinterpret_cast<unsigned char*>(basis.data())) != 0, "shifted norm basis creates");
    PointBytes expected{};
    ctx.expect(purify_bppp_public_msm(secp.get(),
        reinterpret_cast<const unsigned char*>(basis.data()),
        reinterpret_cast<const unsigned char*>(coefficients.data()), 8, expected.data()) != 0
        && expected == residual, "pending equation agrees with direct native MSM");

    const PointBytes infinity{};
    auto one = scalar(1);
    ctx.expect(purify_bppp_public_msm(secp.get(), nullptr, nullptr, 0, expected.data()) != 0
        && expected == infinity, "empty public MSM is canonical infinity");
    ctx.expect(purify_bppp_public_msm(secp.get(), infinity.data(), one.data(), 1,
        expected.data()) != 0 && expected == infinity, "public MSM accepts canonical infinity");
    auto malformed = basis[0];
    malformed[0] = 0;
    ctx.expect(purify_bppp_public_msm(secp.get(), malformed.data(), one.data(), 1,
        expected.data()) == 0, "public MSM rejects noncanonical infinity");
}

} // namespace

void run_norm_protocol_tests(TestContext& ctx) {
    check_public_digest_transcript(ctx);
    check_initial_point_boundary(ctx);
    check_norm_length_boundary(ctx);
    check_pending_norm_equation(ctx);
}
