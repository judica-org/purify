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

std::vector<ScalarBytes> coefficients(std::size_t count, int owner) {
    std::vector<ScalarBytes> out;
    for (std::size_t i = 0; i < count; ++i) {
        out.push_back(FieldElement::from_int(17 + owner + static_cast<int>(i)).to_bytes_be());
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
    inputs.c_vec = zero == ZeroFamily::Neither ? coefficients(basis.l_vec_len(), owner)
                                              : std::vector<ScalarBytes>(basis.l_vec_len());
    for (std::size_t i = 0; i < basis.n_vec_len(); ++i) {
        const auto value = zero == ZeroFamily::Norm ? 0 : 5 + owner + static_cast<int>(i);
        inputs.n_vec.push_back(FieldElement::from_int(value).to_bytes_be());
    }
    for (std::size_t i = 0; i < basis.l_vec_len(); ++i) {
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
        PURIFY_ASSIGN_OR_RETURN(auto prepared, accum::prepare_norm(basis, proof, secp),
                                "test:prepare_public_norm");
        PURIFY_ASSIGN_OR_RETURN(auto reduction, accum::prove_norm_reduction(basis, prepared, secp),
                                "test:prove_public_reduction");
        PURIFY_ASSIGN_OR_RETURN(auto claim, accum::verify_norm_reduction(basis, prepared, reduction, secp),
                                "test:verify_public_reduction");
        expect_ok(ctx, accum::decide(basis, claim, secp),
                  "authenticated norm reduction agrees with standalone verification");
        claims.push_back(std::move(claim));
    }
    return claims;
}

void check_honest_batches(TestContext& ctx, purify_secp_context* secp) {
    struct Shape { std::size_t norm; std::size_t linear; };
    for (const auto shape : {Shape{1, 1}, Shape{4, 4}, Shape{8, 2}}) {
        auto basis = accum::Basis::create(shape.norm, shape.linear,
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
        ctx.expect(proofs.front().c_vec != proofs.back().c_vec,
                   "independent owners use different public coefficients on one basis");
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
                        const NormArgProof& changed, const accum::NormReductionProof& original,
                        purify_secp_context* secp) {
    ctx.expect(!purify::bppp::verify_norm_arg(changed, secp),
               "unchanged standalone proof rejects an altered public statement");
    auto prepared = accum::prepare_norm(basis, changed, secp);
    // Preparation parses and replays the transcript. It does not accept the
    // norm relation, so a parseable altered statement may remain pending.
    if (prepared) {
        auto pending = accum::verify_norm_reduction(basis, *prepared, original, secp);
        if (!pending) return;
        ctx.expect(!accum::decide(basis, *pending, secp),
                   "final decision rejects the altered norm obligation");
    }
}

void check_reduction_encoding(TestContext& ctx, const accum::Basis& basis,
                              const accum::PreparedNorm& prepared,
                              const accum::NormReductionProof& reduction,
                              purify_secp_context* secp) {
    auto encoded = accum::serialize_norm_reduction(basis, reduction, secp);
    expect_ok(ctx, encoded, "honest coefficient opening serializes");
    if (!encoded) return;
    auto parsed = accum::parse_norm_reduction(basis, *encoded, secp);
    expect_ok(ctx, parsed, "honest coefficient opening parses");
    if (!parsed) return;
    auto claim = accum::verify_norm_reduction(basis, prepared, *parsed, secp);
    expect_ok(ctx, claim, "serialized coefficient opening authenticates the norm reduction");
    if (!claim) return;
    expect_ok(ctx, accum::decide(basis, *claim, secp), "serialized norm reduction decides");
    auto reencoded = accum::serialize_norm_reduction(basis, *parsed, secp);
    ctx.expect(reencoded && *reencoded == *encoded, "coefficient opening encoding is canonical");

    auto evaluation = FieldElement::try_from_bytes32(reduction.coefficient_evaluation);
    expect_ok(ctx, evaluation, "honest coefficient evaluation is canonical");
    if (!evaluation) return;
    auto changed = reduction;
    changed.coefficient_evaluation = (*evaluation + FieldElement::one()).to_bytes_be();
    ctx.expect(!accum::verify_norm_reduction(basis, prepared, changed, secp),
               "fixed coefficient opening rejects a changed claimed evaluation");
    changed = reduction;
    changed.coefficient_opening.left[0] = basis.points()[0];
    ctx.expect(!accum::verify_norm_reduction(basis, prepared, changed, secp),
               "fixed coefficient opening rejects a changed finite round point");
    changed = reduction;
    changed.coefficient_opening.folded_generator = basis.points()[1];
    ctx.expect(!accum::verify_norm_reduction(basis, prepared, changed, secp),
               "fixed coefficient opening rejects a changed folded generator");
    changed = reduction;
    changed.coefficient_opening.right.pop_back();
    ctx.expect(!accum::verify_norm_reduction(basis, prepared, changed, secp),
               "coefficient opening rejects the wrong round count");

    auto bytes = *encoded;
    bytes[0] = 2;
    ctx.expect(!accum::parse_norm_reduction(basis, bytes, secp),
               "unsupported coefficient opening version is rejected");
    bytes = *encoded;
    bytes.pop_back();
    ctx.expect(!accum::parse_norm_reduction(basis, bytes, secp),
               "truncated coefficient opening is rejected");
    bytes = *encoded;
    bytes.push_back(0);
    ctx.expect(!accum::parse_norm_reduction(basis, bytes, secp),
               "trailing coefficient opening bytes are rejected");
    bytes = *encoded;
    std::fill_n(bytes.begin() + 1, 32, 0xff);
    ctx.expect(!accum::parse_norm_reduction(basis, bytes, secp),
               "noncanonical coefficient evaluation is rejected");
    bytes = *encoded;
    std::fill(bytes.end() - 65, bytes.end() - 33, 0xff);
    ctx.expect(!accum::parse_norm_reduction(basis, bytes, secp),
               "noncanonical coefficient opening terminal scalar is rejected");
    bytes = *encoded;
    std::fill(bytes.end() - 33, bytes.end(), 0);
    bytes.back() = 1;
    ctx.expect(!accum::parse_norm_reduction(basis, bytes, secp),
               "noncanonical coefficient opening identity is rejected");
}

void check_bindings_and_encodings(TestContext& ctx, purify_secp_context* secp) {
    auto basis = accum::Basis::create(4, 2, "test/escrow-norm/v1", secp);
    expect_ok(ctx, basis, "binding-test basis creates");
    if (!basis) return;
    auto first = publish_norm(*basis, 1, secp);
    auto second = publish_norm(*basis, 2, secp);
    expect_ok(ctx, first, "first binding fixture publishes");
    expect_ok(ctx, second, "second binding fixture publishes");
    if (!first || !second) return;
    auto prepared = accum::prepare_norm(*basis, *first, secp);
    expect_ok(ctx, prepared, "first norm statement authenticates its coefficients");
    if (!prepared) return;
    auto reduction = accum::prove_norm_reduction(*basis, *prepared, secp);
    expect_ok(ctx, reduction, "honest norm reduction proves from public inputs");
    if (!reduction) return;
    check_reduction_encoding(ctx, *basis, *prepared, *reduction, secp);
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
    check_changed_norm(ctx, *basis, changed, *reduction, secp);
    changed = *first;
    changed.commitment = second->commitment;
    check_changed_norm(ctx, *basis, changed, *reduction, secp);
    changed = *first;
    changed.c_vec[0] = FieldElement::from_int(99).to_bytes_be();
    check_changed_norm(ctx, *basis, changed, *reduction, secp);
    auto changed_coefficients = accum::prepare_norm(*basis, changed, secp);
    expect_ok(ctx, changed_coefficients, "changed canonical coefficients still parse");
    if (!changed_coefficients) return;
    ctx.expect(changed_coefficients->coefficient_commitment() != prepared->coefficient_commitment(),
               "coefficient authentication binds the exact public vector");
    ctx.expect(!accum::verify_norm_reduction(*basis, *changed_coefficients, *reduction, secp),
               "fixed reduction rejects a changed authenticated coefficient commitment");
    changed = *first;
    std::swap(changed.c_vec[0], changed.c_vec[1]);
    check_changed_norm(ctx, *basis, changed, *reduction, secp);
    changed = *first;
    const auto terminal_start = changed.proof.size() - 64;
    ScalarBytes terminal_n{};
    std::copy_n(changed.proof.begin() + static_cast<std::ptrdiff_t>(terminal_start), 32, terminal_n.begin());
    auto n = FieldElement::try_from_bytes32(terminal_n);
    expect_ok(ctx, n, "honest norm terminal scalar is canonical");
    if (!n) return;
    const auto other_n = (*n + FieldElement::one()).to_bytes_be();
    std::copy(other_n.begin(), other_n.end(), changed.proof.begin() + static_cast<std::ptrdiff_t>(terminal_start));
    check_changed_norm(ctx, *basis, changed, *reduction, secp);
    changed = *first;
    std::swap(changed.generators[0], changed.generators[1]);
    ctx.expect(!accum::prepare_norm(*basis, changed, secp),
               "reordered norm generators cannot enter the same accumulation bucket");
    changed = *first;
    changed.n_vec_len = 2;
    ctx.expect(!accum::prepare_norm(*basis, changed, secp),
               "different norm dimensions cannot enter the same accumulation bucket");
    changed = *first;
    changed.c_vec.pop_back();
    ctx.expect(!accum::prepare_norm(*basis, changed, secp),
               "coefficient authentication rejects a vector with the wrong dimension");
    changed = *first;
    changed.c_vec[0].fill(0xff);
    ctx.expect(!accum::prepare_norm(*basis, changed, secp),
               "coefficient authentication rejects noncanonical field elements");

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

    auto wrong_linear = accum::Basis::create(4, 4, "test/escrow-norm/v1", secp);
    auto wrong_domain = accum::Basis::create(4, 2, "test/setup-norm/v1", secp);
    auto wrong_shape = accum::Basis::create(8, 2, "test/escrow-norm/v1", secp);
    expect_ok(ctx, wrong_linear, "alternative linear dimension basis creates");
    expect_ok(ctx, wrong_domain, "alternative semantic basis creates");
    expect_ok(ctx, wrong_shape, "alternative dimension basis creates");
    if (!wrong_linear || !wrong_domain || !wrong_shape) return;
    // Semantic domains bind prepared claims and transitions. A standalone
    // norm proof has no application-domain field of its own.
    for (const auto* other : {&*wrong_linear, &*wrong_domain, &*wrong_shape}) {
        ctx.expect(!accum::verify_norm_reduction(*other, *prepared, *reduction, secp),
                   "fixed norm reduction binds its prepared basis and domain");
        ctx.expect(!accum::prove_step(*other, *claims, secp),
                   "claims cannot be accumulated under another basis or domain");
        ctx.expect(!accum::verify_step(*other, *claims, *step, secp),
                   "fixed step cannot be replayed under another basis or domain");
        ctx.expect(!accum::decide(*other, claims->front(), secp),
                   "final decision requires the claim's exact basis and domain");
    }
    auto other_domain_prepared = accum::prepare_norm(*wrong_domain, *first, secp);
    expect_ok(ctx, other_domain_prepared, "raw standalone norm can be prepared for another application domain");
    if (!other_domain_prepared) return;
    ctx.expect(!accum::verify_norm_reduction(*wrong_domain, *other_domain_prepared, *reduction, secp),
               "fixed reduction cannot be relabeled into another application domain");
    ctx.expect(!accum::prepare_norm(*wrong_linear, *first, secp),
               "standalone proof rejects a basis with different linear dimension");
    ctx.expect(!accum::Basis::create(1, 2, "test/invalid-shape", secp),
               "basis rejects a linear family larger than the norm family");
    ctx.expect(!accum::Basis::create(4, 2, "", secp),
               "basis requires an explicit semantic domain");
}

void check_zero_families(TestContext& ctx, purify_secp_context* secp) {
    auto basis = accum::Basis::create(4, 4,
                                      "test/zero-family/v1", secp);
    expect_ok(ctx, basis, "zero-coefficient basis creates");
    if (!basis) return;
    for (const auto zero : {ZeroFamily::Norm, ZeroFamily::Linear}) {
        auto proof = publish_norm(*basis, 5, secp, zero);
        expect_ok(ctx, proof, "zero witness family still gives an honest finite norm proof");
        if (!proof) return;
        ctx.expect(proof->commitment != PointBytes{}, "zero-family norm commitment remains finite");
        ctx.expect(purify::bppp::verify_norm_arg(*proof, secp), "honest zero-family standalone norm verifies");
        auto prepared = accum::prepare_norm(*basis, *proof, secp);
        expect_ok(ctx, prepared, "zero-family norm prepares");
        if (!prepared) return;
        ctx.expect(prepared->coefficient_commitment() == PointBytes{},
                   "zero coefficient vector has the canonical identity commitment");
        auto reduction = accum::prove_norm_reduction(*basis, *prepared, secp);
        expect_ok(ctx, reduction, "zero coefficient opening proves");
        if (!reduction) return;
        ctx.expect(reduction->coefficient_evaluation == ScalarBytes{},
                   "zero coefficient vector has zero tensor evaluation");
        ctx.expect(reduction->coefficient_opening.terminal_scalar == ScalarBytes{},
                   "honest zero coefficient opening accepts a zero terminal scalar");
        ctx.expect(std::all_of(reduction->coefficient_opening.left.begin(),
            reduction->coefficient_opening.left.end(), [](const auto& p) { return p == PointBytes{}; }) &&
            std::all_of(reduction->coefficient_opening.right.begin(),
            reduction->coefficient_opening.right.end(), [](const auto& p) { return p == PointBytes{}; }),
            "honest zero coefficient opening exercises identity round encodings");
        auto reduction_bytes = accum::serialize_norm_reduction(*basis, *reduction, secp);
        expect_ok(ctx, reduction_bytes, "honest identity coefficient rounds serialize");
        if (!reduction_bytes) return;
        auto parsed_reduction = accum::parse_norm_reduction(*basis, *reduction_bytes, secp);
        expect_ok(ctx, parsed_reduction, "honest identity coefficient rounds parse");
        if (!parsed_reduction) return;
        auto claim = accum::verify_norm_reduction(*basis, *prepared, *parsed_reduction, secp);
        expect_ok(ctx, claim, "zero coefficient opening authenticates both norm obligations");
        if (!claim) return;
        expect_ok(ctx, accum::decide(*basis, *claim, secp), "zero-family fused norm claim decides");
        const std::array claims{*claim};
        auto step = accum::prove_step(*basis, claims, secp);
        expect_ok(ctx, step, "zero-family accumulation proves");
        if (!step) return;
        auto encoded = accum::serialize_step(*basis, *step, secp);
        expect_ok(ctx, encoded, "honest identity round serializes");
        if (!encoded) return;
        auto decoded = accum::parse_step(*basis, *encoded, secp);
        expect_ok(ctx, decoded, "honest identity round parses");
        if (!decoded) return;
        auto pending = accum::verify_step(*basis, claims, *decoded, secp);
        expect_ok(ctx, pending, "honest identity round verifies");
        if (!pending) return;
        expect_ok(ctx, accum::decide(*basis, *pending, secp),
                  "honest identity round preserves final decision");
    }
}

void check_reference_vector(TestContext& ctx, purify_secp_context* secp) {
    const auto scalar = [](int value) { return FieldElement::from_int(value).to_bytes_be(); };
    auto basis = accum::Basis::create(4, 2, "honest-test", secp);
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
    auto prepared = accum::prepare_norm(*basis, *norm, secp);
    expect_ok(ctx, prepared, "independent reference norm prepares");
    if (!prepared) return;
    auto reduction = accum::prove_norm_reduction(*basis, *prepared, secp);
    expect_ok(ctx, reduction, "independent reference coefficient opening proves");
    if (!reduction) return;
    auto reduction_bytes = accum::serialize_norm_reduction(*basis, *reduction, secp);
    expect_ok(ctx, reduction_bytes, "independent reference coefficient opening serializes");
    if (!reduction_bytes) return;
    accum::Digest reduction_digest{};
    purify_sha256(reduction_digest.data(), reduction_bytes->data(), reduction_bytes->size());
    ctx.expect(reduction_digest == purify::UInt256::from_hex(
        "430ba5e3a0183d278ad3cb5251d081f70b27586db3e407a899b59660c8d59d87").to_bytes_be(),
        "native coefficient opening encoding matches the independent Python vector");
    auto claim = accum::verify_norm_reduction(*basis, *prepared, *reduction, secp);
    expect_ok(ctx, claim, "independent reference norm reduction verifies");
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
        "b3a14ad17548fed019e02a5d90063be232826750d1f5987a72b22013585f7b1b").to_bytes_be(),
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
