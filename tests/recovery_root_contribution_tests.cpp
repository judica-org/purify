// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <algorithm>
#include <array>
#include <chrono>
#include <iostream>
#include <span>
#include <type_traits>
#include <utility>
#include <vector>

#include "purify.hpp"
#include "purify/bppp.hpp"
#include "purify/puresign/accountable_roster.hpp"
#include "purify/puresign/bppp.hpp"
#include "purify/puresign/coalition_formation.hpp"
#include "purify/puresign/recovery_root.hpp"
#include "../src/puresign/recovery_root_internal.hpp"
#include "test_harness.hpp"

namespace {

using purify::FieldElement;
using purify::Result;
using purify::bppp::PointBytes;
using purify_test::TestContext;
using purify_test::expect_error;
using purify_test::expect_ok;

static_assert(!std::is_copy_constructible_v<
              purify::accountable::VerifiedDistributedRecoverySetup>);
static_assert(!std::is_copy_assignable_v<
              purify::accountable::VerifiedDistributedRecoverySetup>);
static_assert(std::is_move_constructible_v<
              purify::accountable::VerifiedDistributedRecoverySetup>);
static_assert(std::is_move_assignable_v<
              purify::accountable::VerifiedDistributedRecoverySetup>);

std::array<unsigned char, 32> raw_generator_digest(
    std::span<const PointBytes> generators) {
    std::array<unsigned char, 32> digest{};
    const auto bytes = std::as_bytes(generators);
    purify_sha256(
        digest.data(),
        reinterpret_cast<const unsigned char*>(bytes.data()),
        bytes.size());
    return digest;
}

struct ContributionFixture {
    purify::accountable::NonceHostBoundSigningRoster roster;
    purify::accountable::CoalitionFormation formation;
    std::vector<FieldElement> member_secrets;
};

Result<PointBytes> secp_point(const FieldElement& scalar,
                              purify_secp_context* secp_context) {
    const purify::bppp::ScalarBytes zero{};
    const auto generator = purify::bppp::base_generator(secp_context);
    return purify::bppp::pedersen_commit_char(
        zero, scalar.to_bytes_be(), secp_context, generator, generator);
}

Result<ContributionFixture> make_fixture(
    purify_secp_context* secp_context) {
    std::vector<FieldElement> secrets{
        FieldElement::from_u64(7), FieldElement::from_u64(11),
        FieldElement::from_u64(19)};
    std::vector<PointBytes> member_keys;
    member_keys.reserve(secrets.size());
    for (auto& secret : secrets) {
        PURIFY_ASSIGN_OR_RETURN(
            auto point, secp_point(secret, secp_context),
            "recovery_contribution_test:member_point");
        if (point[0] == 0x03) {
            secret = secret.negate();
            point[0] = 0x02;
        }
        member_keys.push_back(std::move(point));
    }
    PURIFY_ASSIGN_OR_RETURN(
        auto roster,
        purify::accountable::SigningRoster::aggregate(member_keys,
                                                       secp_context),
        "recovery_contribution_test:roster");

    std::vector<purify::puresign_plusplus::PublicKey> hosts;
    hosts.reserve(member_keys.size());
    for (std::size_t i = 0; i < member_keys.size(); ++i) {
        std::array<unsigned char, 32> seed{};
        seed[0] = 0xc1;
        seed[1] = static_cast<unsigned char>(i + 1);
        PURIFY_ASSIGN_OR_RETURN(
            auto generated, purify::generate_key(seed),
            "recovery_contribution_test:host_secret");
        PURIFY_ASSIGN_OR_RETURN(
            auto host,
            purify::puresign_plusplus::PublicKey::from_secret(
                generated.secret, secp_context),
            "recovery_contribution_test:host");
        std::copy(member_keys[i].begin() + 1, member_keys[i].end(),
                  host.bip340_pubkey.begin());
        hosts.push_back(std::move(host));
    }

    purify::accountable::CoalitionFormationInput input{};
    input.genesis_hash.fill(0x11);
    input.deployment_id.fill(0x22);
    input.permit.transaction_id.fill(0x33);
    input.permit.output_index = 4;
    input.manifest_digest.fill(0x44);
    PURIFY_ASSIGN_OR_RETURN(
        auto formation,
        purify::accountable::CoalitionFormation::create(input),
        "recovery_contribution_test:formation");
    PURIFY_ASSIGN_OR_RETURN(
        auto bound,
        purify::accountable::bind_formation_nonce_hosts(
            std::move(roster), formation, hosts, secp_context),
        "recovery_contribution_test:bound_roster");
    return ContributionFixture{
        std::move(bound), std::move(formation), std::move(secrets)};
}

std::size_t negative_odd_weighted_member(
    const ContributionFixture& fixture,
    purify_secp_context* secp_context) {
    const auto half = purify::prime_p().shifted_right(1);
    for (std::size_t i = 0; i < fixture.member_secrets.size(); ++i) {
        const auto scalar = fixture.roster.members()[i].coefficient *
                            fixture.member_secrets[i];
        const auto point = secp_point(scalar, secp_context);
        if (point && (*point)[0] == 0x03 &&
            half < scalar.to_uint256()) {
            return i;
        }
    }
    return fixture.member_secrets.size();
}

std::size_t positive_centered_member(
    const ContributionFixture& fixture) {
    const auto half = purify::prime_p().shifted_right(1);
    for (std::size_t i = 0; i < fixture.member_secrets.size(); ++i) {
        const auto scalar = fixture.roster.members()[i].coefficient *
                            fixture.member_secrets[i];
        if (!scalar.is_zero() && !(half < scalar.to_uint256())) return i;
    }
    return fixture.member_secrets.size();
}

Result<purify::accountable::RecoveryRootShare> share_from_effective_scalar(
    const FieldElement& effective_scalar) {
    const auto half = purify::prime_p().shifted_right(1);
    const bool negative = half < effective_scalar.to_uint256();
    const auto magnitude = negative
                               ? effective_scalar.negate().to_uint256()
                               : effective_scalar.to_uint256();
    auto first = purify::curve1().mul(purify::generator1(), magnitude);
    auto second = purify::curve2().mul(purify::generator2(), magnitude);
    if (negative) {
        first = purify::curve1().negate(first);
        second = purify::curve2().negate(second);
    }
    const auto first_affine = purify::curve1().affine(first);
    const auto second_affine = purify::curve2().affine(second);
    purify::Bytes encoded;
    encoded.reserve(purify::accountable::RecoveryRootShare::kSerializedSize);
    for (const auto& point : {first_affine, second_affine}) {
        encoded.push_back(
            static_cast<unsigned char>(point.y.is_odd() ? 0x03 : 0x02));
        const auto x = point.x.to_bytes_be();
        encoded.insert(encoded.end(), x.begin(), x.end());
    }
    return purify::accountable::RecoveryRootShare::deserialize(encoded);
}

void test_recovery_root_contribution(TestContext& ctx) {
    auto secp = purify::make_secp_context();
    ctx.expect(secp != nullptr, "contribution secp context creates");
    if (!secp) return;

#if PURIFY_USE_LEGACY_FIELD_HASHES
    auto suite_share = share_from_effective_scalar(FieldElement::one());
    expect_ok(ctx, suite_share,
              "legacy suite contribution share derives syntactically");
    if (!suite_share) return;
    expect_error(
        ctx,
        purify::accountable::testing::
            recovery_root_contribution_circuit_shape_for_testing(
                *suite_share),
        purify::ErrorCode::UnsupportedSymbol,
        "contribution circuit rejects legacy field hashes");
#endif

    auto fixture = make_fixture(secp.get());
    expect_ok(ctx, fixture, "formation-bound contribution fixture creates");
    if (!fixture) return;

    expect_error(
        ctx,
        purify::accountable::verify_distributed_recovery_setup(
            fixture->roster, fixture->formation, {}, secp.get()),
        purify::ErrorCode::SizeMismatch,
        "distributed setup rejects incomplete coverage before verification");

    ctx.expect(fixture->roster.aggregate_was_negated(),
               "fixture exercises aggregate-key parity normalization");
    const std::size_t member_index =
        negative_odd_weighted_member(*fixture, secp.get());
    ctx.expect(member_index < fixture->member_secrets.size(),
               "fixture contains a negative centered odd weighted member");
    if (member_index >= fixture->member_secrets.size()) return;

#if PURIFY_USE_LEGACY_FIELD_HASHES
    expect_error(
        ctx,
        purify::accountable::prove_recovery_root_contribution(
            fixture->roster, fixture->formation, member_index,
            fixture->member_secrets[member_index], secp.get()),
        purify::ErrorCode::UnsupportedSymbol,
        "contribution proving rejects the legacy field-hash suite");
    return;
#endif

    purify::bppp::ExperimentalCircuitCache proof_cache;
    const auto started = std::chrono::steady_clock::now();
    auto contribution =
        purify::accountable::prove_recovery_root_contribution(
            fixture->roster, fixture->formation, member_index,
            fixture->member_secrets[member_index], secp.get(),
            &proof_cache);
    const auto proved = std::chrono::steady_clock::now();
    expect_ok(ctx, contribution, "centered member contribution proves");
    if (!contribution) return;

    auto shape = purify::accountable::testing::
        recovery_root_contribution_circuit_shape_for_testing(
            contribution->share());
    expect_ok(ctx, shape, "contribution circuit shape derives");
    if (!shape) return;
    ctx.expect(shape->relation_multiplications == 1442 &&
                   shape->padded_gates == 8192,
               "contribution circuit pins 1442 multiplications and 8192 gates");

    const auto& member = fixture->roster.members()[member_index];
    const auto effective =
        member.coefficient * fixture->member_secrets[member_index];
    const auto weighted = secp_point(effective, secp.get());
    expect_ok(ctx, weighted, "weighted member point derives");
    ctx.expect(weighted && weighted->front() == 0x03,
               "fixture keeps the exact odd weighted member output");
    const auto half = purify::prime_p().shifted_right(1);
    const bool negative = half < effective.to_uint256();
    const auto magnitude = negative
                               ? effective.negate().to_uint256()
                               : effective.to_uint256();
    auto first = purify::curve1().mul(purify::generator1(), magnitude);
    auto second = purify::curve2().mul(purify::generator2(), magnitude);
    if (negative) {
        first = purify::curve1().negate(first);
        second = purify::curve2().negate(second);
    }
    const auto expected_first = purify::curve1().affine(first);
    const auto expected_second = purify::curve2().affine(second);
    ctx.expect(contribution->share().first().x == expected_first.x &&
                   contribution->share().first().y == expected_first.y &&
                   contribution->share().second().x == expected_second.x &&
                   contribution->share().second().y == expected_second.y,
               "one centered scalar fixes both exact signed shares");

    auto opposite_sign_bytes = contribution->share().serialize();
    opposite_sign_bytes[0] = static_cast<unsigned char>(
        opposite_sign_bytes[0] == 0x02 ? 0x03 : 0x02);
    opposite_sign_bytes[33] = static_cast<unsigned char>(
        opposite_sign_bytes[33] == 0x02 ? 0x03 : 0x02);
    auto opposite_sign =
        purify::accountable::RecoveryRootShare::deserialize(
            opposite_sign_bytes);
    expect_ok(ctx, opposite_sign,
              "opposite signed companion share parses");
    if (opposite_sign) {
        auto opposite_satisfies = purify::accountable::testing::
            recovery_root_contribution_assignment_satisfies_for_testing(
                *opposite_sign, contribution->share(), effective);
        expect_ok(ctx, opposite_satisfies,
                  "opposite signed assignment evaluates");
        ctx.expect(opposite_satisfies && !*opposite_satisfies,
                   "circuit rejects both opposite companion signs");
    }

    auto split_sign_bytes = contribution->share().serialize();
    split_sign_bytes[0] = static_cast<unsigned char>(
        split_sign_bytes[0] == 0x02 ? 0x03 : 0x02);
    auto split_sign =
        purify::accountable::RecoveryRootShare::deserialize(
            split_sign_bytes);
    expect_ok(ctx, split_sign,
              "split signed companion share parses");
    if (split_sign) {
        auto split_satisfies = purify::accountable::testing::
            recovery_root_contribution_assignment_satisfies_for_testing(
                *split_sign, contribution->share(), effective);
        expect_ok(ctx, split_satisfies,
                  "split signed assignment evaluates");
        ctx.expect(split_satisfies && !*split_satisfies,
                   "circuit rejects disagreeing companion signs");
    }

    auto accepted =
        purify::accountable::verify_recovery_root_contribution(
            fixture->roster, fixture->formation, member_index,
            *contribution, secp.get(), &proof_cache);
    const auto verified = std::chrono::steady_clock::now();
    expect_ok(ctx, accepted, "honest contribution verification runs");
    ctx.expect(accepted && *accepted,
               "honest formation-bound contribution verifies");

    auto encoded = contribution->serialize(secp.get());
    expect_ok(ctx, encoded, "contribution serializes canonically");
    if (!encoded) return;
    ctx.expect(encoded->size() ==
                       purify::accountable::RecoveryRootContribution::
                           kSerializedSize &&
                   encoded->front() == 1,
               "contribution has the fixed 1203-byte v1 encoding");
    auto parsed =
        purify::accountable::RecoveryRootContribution::deserialize(
            *encoded, secp.get());
    expect_ok(ctx, parsed, "contribution encoding reparses");
    if (!parsed) return;
    const auto reencoded = parsed->serialize(secp.get());
    ctx.expect(reencoded && *reencoded == *encoded,
               "contribution encoding round trips exactly");

    auto accumulator = purify::accountable::
        ConstructionLeafAccumulator::create(secp.get());
    expect_ok(ctx, accumulator,
              "shared construction leaf accumulator creates");
    if (!accumulator) return;
    ctx.expect(
        accumulator->basis().n_vec_len() ==
                purify::accountable::ConstructionLeafAccumulator::
                    kNormVectorLength &&
            accumulator->basis().l_vec_len() ==
                purify::accountable::ConstructionLeafAccumulator::
                    kNormVectorLength,
        "contribution uses the 16384-element construction basis");
    auto prepared = accumulator->prepare(
        fixture->roster, fixture->formation, member_index, *parsed,
        secp.get(), &proof_cache);
    expect_ok(ctx, prepared,
              "contribution prepares as a construction leaf");
    if (!prepared) return;
    auto parent_constants = accumulator->derive_parent_constants(
        fixture->roster, fixture->formation, member_index,
        parsed->share(), prepared->circuit_precommitment(), secp.get());
    expect_ok(ctx, parent_constants,
              "contribution parent constants derive from public inputs");
    if (!parent_constants) return;
    ctx.expect(
        parent_constants->raw_generator_digest ==
                raw_generator_digest(
                    accumulator->basis().norm_generators()) &&
            parent_constants->coefficient_commitment ==
                prepared->norm().coefficient_commitment(),
        "contribution constants match the shared prepared proof family");

    purify::Bytes descriptor;
    descriptor.reserve(130);
    const auto append_descriptor = [&descriptor](const auto& value) {
        descriptor.insert(descriptor.end(), value.begin(), value.end());
    };
    append_descriptor(parent_constants->circuit_binding_digest);
    append_descriptor(prepared->circuit_precommitment());
    append_descriptor(parent_constants->coefficient_commitment);
    append_descriptor(parent_constants->anchored_offset);
    ctx.expect(descriptor.size() == 130,
               "public contribution inputs derive one 130-byte descriptor");
    expect_error(
        ctx,
        accumulator->derive_parent_constants(
            fixture->roster, fixture->formation, member_index,
            parsed->share(), purify::bppp::ScalarBytes{}, secp.get()),
        purify::ErrorCode::RangeViolation,
        "contribution parent constants reject a zero precommitment");

    const auto other_index = (member_index + 1) %
                             fixture->member_secrets.size();
    auto wrong_member =
        purify::accountable::verify_recovery_root_contribution(
            fixture->roster, fixture->formation, other_index, *parsed,
            secp.get());
    ctx.expect(wrong_member && !*wrong_member,
               "member index and exact weighted key are proof-bound");

    purify::accountable::CoalitionFormationInput alternate_input{
        fixture->formation.genesis_hash(),
        fixture->formation.deployment_id(),
        fixture->formation.permit(),
        fixture->formation.manifest_digest()};
    alternate_input.manifest_digest[0] ^= 1;
    auto alternate_formation =
        purify::accountable::CoalitionFormation::create(alternate_input);
    expect_ok(ctx, alternate_formation,
              "alternate formation fixture creates");
    if (alternate_formation) {
        expect_error(
            ctx,
            purify::accountable::verify_recovery_root_contribution(
                fixture->roster, *alternate_formation, member_index,
                *parsed, secp.get()),
            purify::ErrorCode::BindingMismatch,
            "contribution rejects another formation core");
    }

    auto changed_share = *encoded;
    changed_share[1] =
        static_cast<unsigned char>(changed_share[1] == 0x02 ? 0x03 : 0x02);
    auto changed =
        purify::accountable::RecoveryRootContribution::deserialize(
            changed_share, secp.get());
    expect_ok(ctx, changed, "opposite full-point parity remains canonical");
    if (changed) {
        auto changed_result =
            purify::accountable::verify_recovery_root_contribution(
                fixture->roster, fixture->formation, member_index,
                *changed, secp.get());
        ctx.expect(changed_result && !*changed_result,
                   "proof rejects a changed companion-point sign");
    }

    auto invalid_share = std::array<unsigned char,
                                    purify::accountable::
                                        RecoveryRootShare::kSerializedSize>{};
    invalid_share[0] = 0x04;
    expect_error(
        ctx,
        purify::accountable::RecoveryRootShare::deserialize(invalid_share),
        purify::ErrorCode::RangeViolation,
        "share parser rejects a non-compressed point prefix");
    expect_error(
        ctx,
        purify::accountable::RecoveryRootContribution::deserialize(
            std::span<const unsigned char>(*encoded).first(
                encoded->size() - 1),
            secp.get()),
        purify::ErrorCode::InvalidFixedSize,
        "contribution parser rejects truncation");
    expect_error(
        ctx,
        purify::accountable::prove_recovery_root_contribution(
            fixture->roster, fixture->formation, member_index,
            fixture->member_secrets[other_index], secp.get()),
        purify::ErrorCode::BindingMismatch,
        "another member secret cannot authorize this contribution");

    const std::size_t positive_index = positive_centered_member(*fixture);
    ctx.expect(positive_index < fixture->member_secrets.size(),
               "fixture contains a positive centered member");
    if (positive_index < fixture->member_secrets.size()) {
        const auto positive_effective =
            fixture->roster.members()[positive_index].coefficient *
            fixture->member_secrets[positive_index];
        auto positive_share =
            share_from_effective_scalar(positive_effective);
        expect_ok(ctx, positive_share,
                  "positive centered companion share derives");
        if (positive_share) {
            auto positive_satisfies = purify::accountable::testing::
                recovery_root_contribution_assignment_satisfies_for_testing(
                    *positive_share, *positive_share, positive_effective);
            expect_ok(ctx, positive_satisfies,
                      "positive centered assignment evaluates");
            ctx.expect(positive_satisfies && *positive_satisfies,
                       "positive centered assignment satisfies the circuit");
        }
    }

    std::cout
        << "recovery_root_contribution relation_muls="
        << shape->relation_multiplications
        << " padded_gates=" << shape->padded_gates
        << " wire_bytes=" << encoded->size()
        << " prove_ms="
        << std::chrono::duration<double, std::milli>(proved - started).count()
        << " verify_ms="
        << std::chrono::duration<double, std::milli>(verified - proved).count()
        << '\n';
}

} // namespace

void run_recovery_root_contribution_tests(TestContext& ctx) {
    test_recovery_root_contribution(ctx);
}
