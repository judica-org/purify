// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <algorithm>
#include <array>
#include <cstddef>
#include <span>
#include <utility>
#include <vector>

#include "purify/accumulation.hpp"
#include "test_harness.hpp"

namespace {

using purify::FieldElement;
using purify::bppp::NormArgProof;
using purify::bppp::PointBytes;
using purify::bppp::ScalarBytes;
using purify_test::TestContext;
using purify_test::expect_ok;
namespace accum = purify::bppp::accumulation;

enum class ZeroFamily { Neither, Norm, Linear };

std::vector<ScalarBytes> coefficients(std::size_t count) {
    std::vector<ScalarBytes> out;
    for (std::size_t i = 0; i < count; ++i) {
        out.push_back(FieldElement::from_int(static_cast<int>(17 + i)).to_bytes_be());
    }
    return out;
}

// Each owner returns only its public bundle. All original n/l witnesses have
// left scope before a caller prepares or accumulates any of these proofs.
purify::Result<NormArgProof> publish_norm(const accum::Basis& basis, int owner,
                                       purify_secp_context* secp,
                                       ZeroFamily zero = ZeroFamily::Neither) {
    purify::bppp::NormArgInputs inputs;
    inputs.rho = FieldElement::from_int(3 + owner).to_bytes_be();
    inputs.generators = basis.norm_generators();
    inputs.c_vec = basis.c_vec();
    for (std::size_t i = 0; i < basis.n_vec_len(); ++i) {
        const auto value = zero == ZeroFamily::Norm ? 0 : 5 + owner + static_cast<int>(i);
        inputs.n_vec.push_back(FieldElement::from_int(value).to_bytes_be());
    }
    for (std::size_t i = 0; i < basis.c_vec().size(); ++i) {
        const auto value = zero == ZeroFamily::Linear ? 0 : 11 + owner + static_cast<int>(i);
        inputs.l_vec.push_back(FieldElement::from_int(value).to_bytes_be());
    }
    return purify::bppp::prove_norm_arg(inputs, secp);
}

purify::Result<std::vector<accum::PendingClaim>> public_claims(
    TestContext& ctx, const accum::Basis& basis, std::span<const NormArgProof> proofs,
    purify_secp_context* secp) {
    std::vector<accum::PendingClaim> claims;
    for (const auto& proof : proofs) {
        ctx.expect(purify::bppp::verify_norm_arg(proof, secp),
                   "independently published standalone norm proof verifies");
        PURIFY_ASSIGN_OR_RETURN(auto claim, accum::prepare_norm(basis, proof, secp),
                                "test:prepare_public_norm");
        expect_ok(ctx, accum::decide(basis, claim, secp),
                  "prepared norm obligation agrees with standalone verification");
        claims.push_back(std::move(claim));
    }
    return claims;
}

void check_honest_batches(TestContext& ctx, purify_secp_context* secp) {
    struct Shape { std::size_t norm; std::size_t linear; };
    for (const auto shape : {Shape{1, 1}, Shape{4, 4}, Shape{8, 2}}) {
        auto basis = accum::Basis::create(shape.norm, coefficients(shape.linear),
                                          "test/nonce-norm/v1", secp);
        expect_ok(ctx, basis, "homogeneous norm basis creates");
        if (!basis) return;
        std::vector<NormArgProof> proofs;
        const auto owners = shape.norm == 8 ? 100 : 2;
        for (int owner = 0; owner < owners; ++owner) {
            auto proof = publish_norm(*basis, owner, secp);
            expect_ok(ctx, proof, "independent owner publishes a norm proof");
            if (!proof) return;
            proofs.push_back(std::move(*proof));
        }
        auto claims = public_claims(ctx, *basis, proofs, secp);
        expect_ok(ctx, claims, "all public norm bundles prepare");
        if (!claims) return;
        for (const std::size_t count : {1U, 2U, 100U}) {
            if (count > claims->size()) continue;
            const auto inputs = std::span<const accum::PendingClaim>(*claims).first(count);
            auto step = accum::prove_step(*basis, inputs, secp);
            expect_ok(ctx, step, "public accumulation proves for one, two or 100 owners");
            if (!step) return;
            auto pending = accum::verify_step(*basis, inputs, *step, secp);
            expect_ok(ctx, pending, "honest accumulation step returns a pending obligation");
            if (!pending) return;
            expect_ok(ctx, accum::decide(*basis, *pending, secp),
                      "final MSM discharges an honest public accumulation");
        }

        if (shape.norm != 8) continue;
        // Retain and verify every transition while reducing 100 independent
        // leaves. Intermediate claims are pending; only the root is decided.
        auto level = *claims;
        while (level.size() > 1) {
            std::vector<accum::PendingClaim> next;
            for (std::size_t i = 0; i < level.size(); i += 2) {
                if (i + 1 == level.size()) {
                    next.push_back(level[i]);
                    continue;
                }
                const auto pair = std::span<const accum::PendingClaim>(level).subspan(i, 2);
                auto step = accum::prove_step(*basis, pair, secp);
                expect_ok(ctx, step, "binary tree step proves from public child claims");
                if (!step) return;
                auto parent = accum::verify_step(*basis, pair, *step, secp);
                expect_ok(ctx, parent, "binary tree transition verifies");
                if (!parent) return;
                next.push_back(std::move(*parent));
            }
            level = std::move(next);
        }
        expect_ok(ctx, accum::decide(*basis, level.front(), secp),
                  "final decision accepts the verified 100-owner transition tree");
    }
}

void check_changed_norm(TestContext& ctx, const accum::Basis& basis,
                        const NormArgProof& changed, purify_secp_context* secp) {
    ctx.expect(!purify::bppp::verify_norm_arg(changed, secp),
               "unchanged standalone proof rejects an altered public statement");
    auto pending = accum::prepare_norm(basis, changed, secp);
    // Preparation parses and replays the transcript. It does not accept the
    // norm relation, so a parseable altered statement may remain pending.
    if (pending) {
        ctx.expect(!accum::decide(basis, *pending, secp),
                   "final decision rejects the altered norm obligation");
    }
}

void check_bindings_and_encodings(TestContext& ctx, purify_secp_context* secp) {
    const auto c = coefficients(2);
    auto basis = accum::Basis::create(4, c, "test/escrow-norm/v1", secp);
    expect_ok(ctx, basis, "binding-test basis creates");
    if (!basis) return;
    auto first = publish_norm(*basis, 1, secp);
    auto second = publish_norm(*basis, 2, secp);
    expect_ok(ctx, first, "first binding fixture publishes");
    expect_ok(ctx, second, "second binding fixture publishes");
    if (!first || !second) return;
    const std::array proofs{*first, *second};
    auto claims = public_claims(ctx, *basis, proofs, secp);
    expect_ok(ctx, claims, "binding-test public inputs prepare");
    if (!claims) return;
    auto step = accum::prove_step(*basis, *claims, secp);
    expect_ok(ctx, step, "honest binding-test step proves");
    if (!step) return;

    auto encoded = accum::serialize_step(*basis, *step, secp);
    expect_ok(ctx, encoded, "honest accumulation step serializes");
    if (!encoded) return;
    auto decoded = accum::parse_step(*basis, *encoded, secp);
    expect_ok(ctx, decoded, "canonical accumulation step parses");
    if (!decoded) return;
    auto decoded_claim = accum::verify_step(*basis, *claims, *decoded, secp);
    expect_ok(ctx, decoded_claim, "serialized public accumulation step verifies");
    if (!decoded_claim) return;
    expect_ok(ctx, accum::decide(*basis, *decoded_claim, secp),
              "serialized public accumulation preserves final decision");
    auto reencoded = accum::serialize_step(*basis, *decoded, secp);
    expect_ok(ctx, reencoded, "decoded accumulation step serializes");
    ctx.expect(reencoded && *reencoded == *encoded,
               "accumulation step has a stable canonical encoding");

    auto bad_encoding = *encoded;
    bad_encoding[0] = 2;
    ctx.expect(!accum::parse_step(*basis, bad_encoding, secp),
               "unsupported accumulation encoding version is rejected");
    bad_encoding = *encoded;
    bad_encoding.pop_back();
    ctx.expect(!accum::parse_step(*basis, bad_encoding, secp),
               "truncated accumulation encoding is rejected");
    bad_encoding = *encoded;
    bad_encoding.push_back(0);
    ctx.expect(!accum::parse_step(*basis, bad_encoding, secp),
               "trailing accumulation encoding bytes are rejected");
    bad_encoding = *encoded;
    const auto scalar_offset = 1 + 66 * step->left.size();
    std::fill_n(bad_encoding.begin() + static_cast<std::ptrdiff_t>(scalar_offset), 32, 0xff);
    ctx.expect(!accum::parse_step(*basis, bad_encoding, secp),
               "noncanonical accumulation scalar bytes are rejected");
    bad_encoding = *encoded;
    std::fill(bad_encoding.end() - 33, bad_encoding.end(), 0);
    bad_encoding.back() = 1;
    ctx.expect(!accum::parse_step(*basis, bad_encoding, secp),
               "noncanonical identity point encoding is rejected");

    auto changed = *first;
    changed.rho = FieldElement::from_int(99).to_bytes_be();
    check_changed_norm(ctx, *basis, changed, secp);
    changed = *first;
    changed.commitment = second->commitment;
    check_changed_norm(ctx, *basis, changed, secp);
    changed = *first;
    changed.c_vec[0] = FieldElement::from_int(99).to_bytes_be();
    ctx.expect(!accum::prepare_norm(*basis, changed, secp),
               "different exact c-vector cannot enter the same accumulation bucket");
    changed = *first;
    std::swap(changed.generators[0], changed.generators[1]);
    ctx.expect(!accum::prepare_norm(*basis, changed, secp),
               "reordered norm generators cannot enter the same accumulation bucket");
    changed = *first;
    changed.n_vec_len = 2;
    ctx.expect(!accum::prepare_norm(*basis, changed, secp),
               "different norm dimensions cannot enter the same accumulation bucket");

    for (const bool noncanonical : {false, true}) {
        changed = *first;
        changed.rho.fill(noncanonical ? 0xff : 0);
        ctx.expect(!accum::prepare_norm(*basis, changed, secp),
                   "zero and noncanonical rho encodings are rejected");
    }
    changed = *first;
    changed.commitment.fill(0);
    ctx.expect(!accum::prepare_norm(*basis, changed, secp),
               "initial norm infinity is rejected before accumulation");
    changed = *first;
    changed.commitment[0] = 0x04;
    ctx.expect(!accum::prepare_norm(*basis, changed, secp),
               "malformed norm commitment encoding is rejected");
    changed = *first;
    changed.proof.pop_back();
    ctx.expect(!accum::prepare_norm(*basis, changed, secp),
               "truncated norm transcript is rejected");
    changed = *first;
    changed.proof.push_back(0);
    ctx.expect(!accum::prepare_norm(*basis, changed, secp),
               "trailing norm transcript bytes are rejected");
    changed = *first;
    std::fill(changed.proof.end() - 32, changed.proof.end(), 0xff);
    ctx.expect(!accum::prepare_norm(*basis, changed, secp),
               "noncanonical norm terminal scalar is rejected");

    auto changed_step = *step;
    auto terminal = FieldElement::try_from_bytes32(step->terminal_scalar);
    expect_ok(ctx, terminal, "honest step terminal scalar is canonical");
    if (!terminal) return;
    changed_step.terminal_scalar = (*terminal + FieldElement::one()).to_bytes_be();
    ctx.expect(!accum::verify_step(*basis, *claims, changed_step, secp),
               "fixed accumulation proof rejects a changed terminal scalar");
    changed_step = *step;
    changed_step.terminal_scalar.fill(0xff);
    ctx.expect(!accum::verify_step(*basis, *claims, changed_step, secp),
               "noncanonical accumulation terminal scalar is rejected");
    changed_step = *step;
    changed_step.left[0] = basis->points()[0];
    ctx.expect(!accum::verify_step(*basis, *claims, changed_step, secp),
               "fixed accumulation proof rejects a changed finite round point");
    changed_step = *step;
    changed_step.folded_generator = basis->points()[1];
    ctx.expect(!accum::verify_step(*basis, *claims, changed_step, secp),
               "fixed accumulation proof rejects a changed folded generator");
    changed_step = *step;
    changed_step.right[0][0] = 0x04;
    ctx.expect(!accum::verify_step(*basis, *claims, changed_step, secp),
               "malformed accumulation round point is rejected");
    changed_step = *step;
    changed_step.left.pop_back();
    ctx.expect(!accum::verify_step(*basis, *claims, changed_step, secp),
               "missing accumulation round is rejected");
    changed_step = *step;
    changed_step.right.push_back(PointBytes{});
    ctx.expect(!accum::verify_step(*basis, *claims, changed_step, secp),
               "extra accumulation round is rejected");

    auto reordered = *claims;
    std::reverse(reordered.begin(), reordered.end());
    ctx.expect(!accum::verify_step(*basis, reordered, *step, secp),
               "fixed accumulation proof binds the ordered child claims");
    const auto omitted = std::span<const accum::PendingClaim>(*claims).first(1);
    ctx.expect(!accum::verify_step(*basis, omitted, *step, secp),
               "fixed accumulation proof rejects an omitted child claim");
    ctx.expect(!accum::prove_step(*basis, {}, secp), "empty accumulation is rejected");

    auto other_c = c;
    other_c[0] = FieldElement::from_int(99).to_bytes_be();
    auto wrong_c = accum::Basis::create(4, other_c, "test/escrow-norm/v1", secp);
    auto wrong_domain = accum::Basis::create(4, c, "test/setup-norm/v1", secp);
    auto wrong_shape = accum::Basis::create(8, c, "test/escrow-norm/v1", secp);
    expect_ok(ctx, wrong_c, "alternative coefficient basis creates");
    expect_ok(ctx, wrong_domain, "alternative semantic basis creates");
    expect_ok(ctx, wrong_shape, "alternative dimension basis creates");
    if (!wrong_c || !wrong_domain || !wrong_shape) return;
    // Semantic domains bind prepared claims and transitions. A standalone
    // norm proof has no application-domain field of its own.
    for (const auto* other : {&*wrong_c, &*wrong_domain, &*wrong_shape}) {
        ctx.expect(!accum::prove_step(*other, *claims, secp),
                   "claims cannot be accumulated under another basis or domain");
        ctx.expect(!accum::verify_step(*other, *claims, *step, secp),
                   "fixed step cannot be replayed under another basis or domain");
        ctx.expect(!accum::decide(*other, claims->front(), secp),
                   "final decision requires the claim's exact basis and domain");
    }
    ctx.expect(!accum::prepare_norm(*wrong_c, *first, secp),
               "standalone proof rejects a basis with different coefficients");
    ctx.expect(!accum::Basis::create(1, c, "test/invalid-shape", secp),
               "basis rejects a linear family larger than the norm family");
    ctx.expect(!accum::Basis::create(4, c, "", secp),
               "basis requires an explicit semantic domain");
}

void check_zero_families(TestContext& ctx, purify_secp_context* secp) {
    auto basis = accum::Basis::create(4, std::vector<ScalarBytes>(4),
                                      "test/zero-family/v1", secp);
    expect_ok(ctx, basis, "zero-coefficient basis creates");
    if (!basis) return;
    for (const auto zero : {ZeroFamily::Norm, ZeroFamily::Linear}) {
        auto proof = publish_norm(*basis, 5, secp, zero);
        expect_ok(ctx, proof, "zero witness family still gives an honest finite norm proof");
        if (!proof) return;
        ctx.expect(proof->commitment != PointBytes{}, "zero-family norm commitment remains finite");
        const std::array proofs{*proof};
        auto claims = public_claims(ctx, *basis, proofs, secp);
        expect_ok(ctx, claims, "zero-family norm prepares and decides");
        if (!claims) return;
        auto step = accum::prove_step(*basis, *claims, secp);
        expect_ok(ctx, step, "zero-family accumulation proves");
        if (!step) return;
        const auto& zero_round = zero == ZeroFamily::Norm ? step->left[0] : step->right[0];
        ctx.expect(zero_round == PointBytes{},
                   "honest zero family exercises canonical identity round encoding");
        auto encoded = accum::serialize_step(*basis, *step, secp);
        expect_ok(ctx, encoded, "honest identity round serializes");
        if (!encoded) return;
        auto decoded = accum::parse_step(*basis, *encoded, secp);
        expect_ok(ctx, decoded, "honest identity round parses");
        if (!decoded) return;
        auto pending = accum::verify_step(*basis, *claims, *decoded, secp);
        expect_ok(ctx, pending, "honest identity round verifies");
        if (!pending) return;
        expect_ok(ctx, accum::decide(*basis, *pending, secp),
                  "honest identity round preserves final decision");
    }
}

void check_reference_vector(TestContext& ctx, purify_secp_context* secp) {
    const auto scalar = [](int value) { return FieldElement::from_int(value).to_bytes_be(); };
    const std::array c{scalar(20), scalar(21)};
    auto basis = accum::Basis::create(4, c, "honest-test", secp);
    expect_ok(ctx, basis, "independent reference basis creates");
    if (!basis) return;
    const auto norm = [&] {
        purify::bppp::NormArgInputs inputs{scalar(3), basis->norm_generators(),
            {scalar(2), scalar(3), scalar(4), scalar(5)}, {scalar(10), scalar(11)},
            {scalar(20), scalar(21)}};
        return purify::bppp::prove_norm_arg(inputs, secp);
    }();
    expect_ok(ctx, norm, "independent reference owner publishes norm proof");
    if (!norm) return;
    auto claim = accum::prepare_norm(*basis, *norm, secp);
    expect_ok(ctx, claim, "independent reference norm prepares");
    if (!claim) return;
    const std::array claims{*claim};
    auto proof = accum::prove_step(*basis, claims, secp);
    expect_ok(ctx, proof, "independent reference accumulation proves");
    if (!proof) return;
    auto encoded = accum::serialize_step(*basis, *proof, secp);
    expect_ok(ctx, encoded, "independent reference accumulation serializes");
    if (!encoded) return;
    accum::Digest digest{};
    purify_sha256(digest.data(), encoded->data(), encoded->size());
    // reference_norm_accumulation.py independently reconstructs the norm
    // transcript, polynomial commitment and every IPA round for this fixture.
    ctx.expect(digest == purify::UInt256::from_hex(
        "662b6b3d9dd73e60a8ab438e184c83844db9a1b7affecb20128f57b33f75add5").to_bytes_be(),
        "native accumulation encoding matches the independent Python vector");
}

} // namespace

void run_norm_accumulation_tests(TestContext& ctx) {
    auto secp = purify::make_secp_context();
    ctx.expect(secp != nullptr, "norm accumulation context creates");
    if (!secp) return;
    check_honest_batches(ctx, secp.get());
    check_bindings_and_encodings(ctx, secp.get());
    check_zero_families(ctx, secp.get());
    check_reference_vector(ctx, secp.get());
}
