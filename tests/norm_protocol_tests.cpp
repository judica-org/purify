// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <algorithm>
#include <array>
#include <cstddef>
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

struct FixedRoundChallenges {
    std::vector<purify::bppp::ScalarBytes> scalars;
    std::vector<std::array<unsigned char, 65>> pairs;
};

struct ScriptedRoundChallenge {
    bool accept{false};
    purify::bppp::ScalarBytes scalar{};
};

int scripted_round_challenge(void* callback_data,
                             const unsigned char[65], std::size_t,
                             unsigned char challenge32[32]) {
    const auto& script =
        *static_cast<const ScriptedRoundChallenge*>(callback_data);
    if (!script.accept) return 0;
    std::copy(script.scalar.begin(), script.scalar.end(), challenge32);
    return 1;
}

int fixed_round_challenge(void* callback_data,
                          const unsigned char point_pair65[65],
                          std::size_t round,
                          unsigned char challenge32[32]) {
    auto& state = *static_cast<FixedRoundChallenges*>(callback_data);
    if (round != state.scalars.size()) return 0;
    state.scalars.push_back(
        FieldElement::from_u64(19 + round).to_bytes_be());
    std::copy(state.scalars.back().begin(), state.scalars.back().end(),
              challenge32);
    std::array<unsigned char, 65> pair{};
    std::copy_n(point_pair65, pair.size(), pair.begin());
    state.pairs.push_back(pair);
    return 1;
}

void check_secret_msm_zero_terms(TestContext& ctx) {
    using namespace purify::bppp;
    auto secp = purify::make_secp_context();
    ctx.expect(secp != nullptr, "secret MSM boundary context creates");
    if (!secp) return;

    const ScalarBytes zero{};
    const auto one = FieldElement::one().to_bytes_be();
    const ScalarBytes negative_one{
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
        0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
        0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x40};
    const auto base = base_generator(secp.get());
    PointBytes base_point{};
    ctx.expect(purify_bppp_generators_to_points(
                   secp.get(), base.data(), 1, base_point.data()) != 0,
               "base generator converts to a point");

    PointBytes result{};
    ctx.expect(purify_point_scale(
                   secp.get(), base_point.data(), one.data(), result.data()) != 0
                   && result == base_point,
               "secret point scaling preserves a unit term");
    result.fill(0xa5);
    ctx.expect(purify_point_scale(
                   secp.get(), base_point.data(), zero.data(), result.data()) == 0
                   && result == PointBytes{},
               "secret point scaling clears an identity result");
    ctx.expect(purify_bppp_offset_commitment(
                   secp.get(), base_point.data(), zero.data(), result.data()) != 0
                   && result == base_point,
               "secret commitment offset skips a zero term");
    result.fill(0xa5);
    ctx.expect(purify_bppp_offset_commitment(
                   secp.get(), base_point.data(), negative_one.data(),
                   result.data()) == 0
                   && result == PointBytes{},
               "secret commitment offset clears an identity result");

    ctx.expect(purify_pedersen_commit_char(
                   secp.get(), zero.data(), one.data(), base.data(),
                   base.data(), result.data()) != 0
                   && result == base_point,
               "Pedersen commitment skips a zero blind term");
    ctx.expect(purify_pedersen_commit_char(
                   secp.get(), one.data(), zero.data(), base.data(),
                   base.data(), result.data()) != 0
                   && result == base_point,
               "Pedersen commitment skips a zero value term");
    result.fill(0xa5);
    ctx.expect(purify_pedersen_commit_char(
                   secp.get(), zero.data(), zero.data(), base.data(),
                   base.data(), result.data()) == 0
                   && result == PointBytes{},
               "Pedersen commitment clears an identity result");

    auto generators = create_generators(2, secp.get());
    expect_ok(ctx, generators, "secret MSM boundary generators create");
    if (!generators) return;
    std::array<PointBytes, 2> generator_points{};
    ctx.expect(purify_bppp_generators_to_points(
                   secp.get(),
                   reinterpret_cast<const unsigned char*>(generators->data()),
                   generators->size(),
                   reinterpret_cast<unsigned char*>(generator_points.data())) != 0,
               "secret MSM generators convert to points");
    ctx.expect(purify_bppp_commit_witness_only(
                   secp.get(),
                   reinterpret_cast<const unsigned char*>(generators->data()),
                   generators->size(), zero.data(), 1, one.data(), 1,
                   result.data()) != 0
                   && result == generator_points[1],
               "secret MSM skips a zero norm coordinate");
    ctx.expect(purify_bppp_commit_witness_only(
                   secp.get(),
                   reinterpret_cast<const unsigned char*>(generators->data()),
                   generators->size(), one.data(), 1, zero.data(), 1,
                   result.data()) != 0
                   && result == generator_points[0],
               "secret MSM skips a zero linear coordinate");
    ctx.expect(purify_bppp_commit_witness_only(
                   secp.get(),
                   reinterpret_cast<const unsigned char*>(generators->data()),
                   generators->size(), zero.data(), 1, zero.data(), 1,
                   result.data()) == 0,
               "secret MSM rejects an identity commitment");

    const auto alternate = value_generator_h(secp.get());
    std::array<PointBytes, 4> cancellation_generators{
        base, base, alternate, alternate};
    const std::array<ScalarBytes, 2> cancellation_n{one, negative_one};
    const std::array<ScalarBytes, 2> cancellation_l{one, zero};
    PointBytes alternate_point{};
    ctx.expect(purify_bppp_generators_to_points(
                   secp.get(), alternate.data(), 1,
                   alternate_point.data()) != 0,
               "alternate generator converts to a point");
    const int cancellation_ok = purify_bppp_commit_witness_only(
        secp.get(),
        reinterpret_cast<const unsigned char*>(
            cancellation_generators.data()),
        cancellation_generators.size(),
        reinterpret_cast<const unsigned char*>(cancellation_n.data()),
        cancellation_n.size(),
        reinterpret_cast<const unsigned char*>(cancellation_l.data()),
        cancellation_l.size(), result.data());
    ctx.expect(cancellation_ok != 0,
               "secret MSM accepts intermediate cancellation");
    if (cancellation_ok != 0) {
        ctx.expect(result == alternate_point,
                   "secret MSM recovers after intermediate cancellation");
    }

    auto differential_generators = create_generators(8, secp.get());
    expect_ok(ctx, differential_generators,
              "secret MSM differential generators create");
    if (!differential_generators) return;
    std::array<PointBytes, 8> differential_points{};
    ctx.expect(purify_bppp_generators_to_points(
                   secp.get(),
                   reinterpret_cast<const unsigned char*>(
                       differential_generators->data()),
                   differential_generators->size(),
                   reinterpret_cast<unsigned char*>(
                       differential_points.data())) != 0,
               "secret MSM differential generators convert");
    bool differential_match = true;
    for (std::size_t sample = 0; sample < 16; ++sample) {
        std::array<ScalarBytes, 8> scalars{};
        for (std::size_t i = 0; i < scalars.size(); ++i) {
            if ((sample + i) % 5 != 0) {
                scalars[i] = FieldElement::from_u64(
                    (sample + 1) * (i + 3)).to_bytes_be();
            }
        }
        PointBytes secret_result{};
        PointBytes public_result{};
        differential_match &= purify_bppp_commit_witness_only(
            secp.get(),
            reinterpret_cast<const unsigned char*>(
                differential_generators->data()),
            differential_generators->size(),
            reinterpret_cast<const unsigned char*>(scalars.data()), 4,
            reinterpret_cast<const unsigned char*>(scalars.data() + 4), 4,
            secret_result.data()) != 0;
        differential_match &= purify_bppp_public_msm(
            secp.get(),
            reinterpret_cast<const unsigned char*>(
                differential_points.data()),
            reinterpret_cast<const unsigned char*>(scalars.data()),
            scalars.size(), public_result.data()) != 0;
        differential_match &= secret_result == public_result;
    }
    ctx.expect(differential_match,
               "secret MSM matches public MSM across mixed zero terms");
}

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
    purify::bppp::PointBytes finite_point{};
    ctx.expect(purify_bppp_generator_to_point(
                   secp.get(), (*generators)[0].data(),
                   finite_point.data()) != 0,
               "point subtraction fixture converts a generator");
    purify::bppp::PointBytes point_difference{};
    point_difference.fill(0xa5);
    ctx.expect(purify_point_subtract_allow_infinity(
                   secp.get(), finite_point.data(), finite_point.data(),
                   point_difference.data()) != 0 &&
                   point_difference == purify::bppp::PointBytes{},
               "point subtraction canonically encodes infinity");
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
    // Start from an honest proof using the current public-data transcript.
    // Change only its public shape, keeping its commitment and proof bytes.
    // This checks rejection, not whether the dimension guard alone rejects it.
    purify::bppp::NormArgInputs supported_inputs{inputs.rho, *generators,
        std::vector(8, one), std::vector(2, one), std::vector(2, one)};
    auto supported = purify::bppp::prove_norm_arg(supported_inputs, secp.get());
    expect_ok(ctx, supported, "supported norm shape produces an honest proof");
    if (!supported) return;
    ctx.expect(purify::bppp::verify_norm_arg(*supported, secp.get()),
               "honest norm proof verifies before its public shape changes");
    auto unsupported = *supported;
    unsupported.n_vec_len = 2;
    unsupported.c_vec = inputs.c_vec;
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
        resources.get(), inputs.rho.data(), c_bytes.data(), 8, 2, unsupported.commitment.data(),
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
    const auto coefficient_evaluation = FieldElement::from_int(13) + FieldElement::from_int(17) * gamma0;
    const std::array<ScalarBytes, 9> coefficients{
        (terminal_n * rho * rho * rho).to_bytes_be(),
        (terminal_n * rho * rho * gamma0).to_bytes_be(),
        (terminal_n * rho * gamma1).to_bytes_be(),
        (terminal_n * gamma0 * gamma1).to_bytes_be(),
        terminal_l.to_bytes_be(), (terminal_l * gamma0).to_bytes_be(), scalar(0), scalar(0),
        (terminal_l * coefficient_evaluation).to_bytes_be()};
    std::array<PointBytes, 9> basis{};
    ctx.expect(purify_bppp_generators_to_points(secp.get(), gs, 8,
        reinterpret_cast<unsigned char*>(basis.data())) != 0, "unshifted norm basis creates");
    const auto encoded_base = base_generator(secp.get());
    ctx.expect(purify_bppp_generators_to_points(secp.get(), encoded_base.data(), 1,
        basis[8].data()) != 0, "standard base converts to SEC1");
    PointBytes expected{};
    ctx.expect(purify_bppp_public_msm(secp.get(),
        reinterpret_cast<const unsigned char*>(basis.data()),
        reinterpret_cast<const unsigned char*>(coefficients.data()), basis.size(), expected.data()) != 0
        && expected == residual, "unshifted pending equation includes the direct coefficient fold");

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
    bool malformed_batch_rejected = true;
    for (std::size_t i = 0; i < 256; ++i) {
        expected.fill(0xa5);
        malformed_batch_rejected &=
            purify_bppp_public_msm(secp.get(), malformed.data(), one.data(),
                                   1, expected.data()) == 0
            && expected == infinity;
    }
    ctx.expect(malformed_batch_rejected,
               "small malformed MSMs reject without retaining output state");
}

void check_protocol_owned_round_challenges(TestContext& ctx) {
    using namespace purify::bppp;
    auto secp = purify::make_secp_context();
    ctx.expect(secp != nullptr,
               "protocol challenge context creates");
    if (!secp) return;

    auto generators = create_generators(8, secp.get());
    expect_ok(ctx, generators,
              "protocol challenge generators create");
    if (!generators) return;
    const auto scalar = [](int value) {
        return FieldElement::from_int(value).to_bytes_be();
    };
    NormArgInputs inputs{
        scalar(3), *generators,
        {scalar(2), scalar(3), scalar(4), scalar(5)},
        {scalar(7), scalar(11), scalar(13), scalar(17)},
        {scalar(19), scalar(23), scalar(29), scalar(31)}};
    auto commitment = commit_norm_arg(inputs, secp.get());
    expect_ok(ctx, commitment,
              "protocol challenge commitment creates");
    if (!commitment) return;

    purify::Bytes proof(purify_bppp_required_proof_size(
        inputs.n_vec.size(), inputs.c_vec.size()));
    std::size_t proof_size = proof.size();
    FixedRoundChallenges challenges;
    const int proved =
        purify_bppp_prove_norm_arg_to_commitment_with_callback(
            secp.get(), inputs.rho.data(),
            reinterpret_cast<const unsigned char*>(generators->data()),
            generators->size(),
            reinterpret_cast<const unsigned char*>(inputs.n_vec.data()),
            inputs.n_vec.size(),
            reinterpret_cast<const unsigned char*>(inputs.l_vec.data()),
            inputs.l_vec.size(),
            reinterpret_cast<const unsigned char*>(inputs.c_vec.data()),
            inputs.c_vec.size(), commitment->data(),
            fixed_round_challenge, &challenges, proof.data(), &proof_size);
    ctx.expect(proved != 0 && proof_size == proof.size(),
               "protocol challenge prover succeeds");
    if (proved == 0) return;
    ctx.expect(challenges.scalars.size() == 2 &&
                   challenges.pairs.size() == 2,
               "protocol challenge callback runs once per round");
    bool pairs_match = challenges.pairs.size() == 2;
    for (std::size_t round = 0;
         pairs_match && round < challenges.pairs.size(); ++round) {
        pairs_match = std::equal(
            challenges.pairs[round].begin(),
            challenges.pairs[round].end(),
            proof.begin() + static_cast<std::ptrdiff_t>(65 * round));
    }
    ctx.expect(pairs_match,
               "callback sees each exact emitted point pair");

    const auto callback_rejects = [&](ScriptedRoundChallenge& script) {
        purify::Bytes rejected_proof(proof.size());
        std::size_t rejected_size = rejected_proof.size();
        return purify_bppp_prove_norm_arg_to_commitment_with_callback(
                   secp.get(), inputs.rho.data(),
                   reinterpret_cast<const unsigned char*>(
                       generators->data()),
                   generators->size(),
                   reinterpret_cast<const unsigned char*>(
                       inputs.n_vec.data()),
                   inputs.n_vec.size(),
                   reinterpret_cast<const unsigned char*>(
                       inputs.l_vec.data()),
                   inputs.l_vec.size(),
                   reinterpret_cast<const unsigned char*>(
                       inputs.c_vec.data()),
                   inputs.c_vec.size(), commitment->data(),
                   scripted_round_challenge, &script,
                   rejected_proof.data(), &rejected_size) == 0;
    };
    ScriptedRoundChallenge rejected_callback;
    ctx.expect(callback_rejects(rejected_callback),
               "protocol prover rejects callback failure");
    ScriptedRoundChallenge zero_callback{true, {}};
    ctx.expect(callback_rejects(zero_callback),
               "protocol prover rejects a zero callback challenge");
    ScriptedRoundChallenge noncanonical_callback{
        true,
        purify::UInt256::from_hex(
            "fffffffffffffffffffffffffffffffebaaedce6af48a03b"
            "bfd25e8cd0364141")
            .to_bytes_be()};
    ctx.expect(callback_rejects(noncanonical_callback),
               "protocol prover rejects a noncanonical callback challenge");

    const auto* gamma_bytes = reinterpret_cast<const unsigned char*>(
        challenges.scalars.data());
    const int verified = purify_bppp_verify_norm_arg_with_challenges(
        secp.get(), inputs.rho.data(),
        reinterpret_cast<const unsigned char*>(generators->data()),
        generators->size(),
        reinterpret_cast<const unsigned char*>(inputs.c_vec.data()),
        inputs.c_vec.size(), inputs.n_vec.size(), commitment->data(),
        proof.data(), proof.size(), gamma_bytes,
        challenges.scalars.size());
    ctx.expect(verified != 0,
               "protocol challenge verifier accepts exact replay");
    ctx.expect(purify_bppp_verify_norm_arg_with_challenges(
                   secp.get(), inputs.rho.data(),
                   reinterpret_cast<const unsigned char*>(
                       generators->data()),
                   generators->size(),
                   reinterpret_cast<const unsigned char*>(
                       inputs.c_vec.data()),
                   inputs.c_vec.size(), inputs.n_vec.size(),
                   commitment->data(), proof.data(), proof.size(),
                   gamma_bytes, challenges.scalars.size() - 1) == 0,
               "protocol verifier rejects a short challenge vector");
    ctx.expect(purify_bppp_verify_norm_arg(
                   secp.get(), inputs.rho.data(),
                   reinterpret_cast<const unsigned char*>(
                       generators->data()),
                   generators->size(),
                   reinterpret_cast<const unsigned char*>(
                       inputs.c_vec.data()),
                   inputs.c_vec.size(), inputs.n_vec.size(),
                   commitment->data(), proof.data(), proof.size()) == 0,
               "SHA transcript cannot accept protocol challenges");

    auto changed = challenges.scalars;
    changed[0] = scalar(41);
    ctx.expect(purify_bppp_verify_norm_arg_with_challenges(
                   secp.get(), inputs.rho.data(),
                   reinterpret_cast<const unsigned char*>(
                       generators->data()),
                   generators->size(),
                   reinterpret_cast<const unsigned char*>(
                       inputs.c_vec.data()),
                   inputs.c_vec.size(), inputs.n_vec.size(),
                   commitment->data(), proof.data(), proof.size(),
                   reinterpret_cast<const unsigned char*>(changed.data()),
                   changed.size()) == 0,
               "changed protocol challenge rejects the proof");
    changed = challenges.scalars;
    changed[0].fill(0);
    ctx.expect(purify_bppp_verify_norm_arg_with_challenges(
                   secp.get(), inputs.rho.data(),
                   reinterpret_cast<const unsigned char*>(
                       generators->data()),
                   generators->size(),
                   reinterpret_cast<const unsigned char*>(
                       inputs.c_vec.data()),
                   inputs.c_vec.size(), inputs.n_vec.size(),
                   commitment->data(), proof.data(), proof.size(),
                   reinterpret_cast<const unsigned char*>(changed.data()),
                   changed.size()) == 0,
               "zero protocol challenge rejects the proof");
    changed[0] = noncanonical_callback.scalar;
    ctx.expect(purify_bppp_verify_norm_arg_with_challenges(
                   secp.get(), inputs.rho.data(),
                   reinterpret_cast<const unsigned char*>(
                       generators->data()),
                   generators->size(),
                   reinterpret_cast<const unsigned char*>(
                       inputs.c_vec.data()),
                   inputs.c_vec.size(), inputs.n_vec.size(),
                   commitment->data(), proof.data(), proof.size(),
                   reinterpret_cast<const unsigned char*>(changed.data()),
                   changed.size()) == 0,
               "noncanonical protocol challenge rejects the proof");

    ScalarBytes terminal_n{}, terminal_l{};
    PointBytes residual{};
    ctx.expect(
        purify_bppp_prepare_norm_arg_claim_with_challenges(
            secp.get(), inputs.rho.data(),
            reinterpret_cast<const unsigned char*>(generators->data()),
            generators->size(),
            reinterpret_cast<const unsigned char*>(inputs.c_vec.data()),
            inputs.c_vec.size(), inputs.n_vec.size(), commitment->data(),
            proof.data(), proof.size(), gamma_bytes,
            challenges.scalars.size(), terminal_n.data(),
            terminal_l.data(), residual.data()) != 0,
        "protocol challenges prepare the matching pending claim");
    ctx.expect(residual != PointBytes{},
               "protocol challenge pending residual is finite");
}

} // namespace

void run_norm_protocol_tests(TestContext& ctx) {
    check_secret_msm_zero_terms(ctx);
    check_public_digest_transcript(ctx);
    check_initial_point_boundary(ctx);
    check_norm_length_boundary(ctx);
    check_pending_norm_equation(ctx);
    check_protocol_owned_round_challenges(ctx);
}
