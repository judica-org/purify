// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <span>
#include <utility>
#include <vector>

#include "purify.hpp"
#include "purify/bppp.hpp"
#include "purify/curve.hpp"
#include "purify/puresign/bppp.hpp"
#include "purify/puresign/recovery_root.hpp"
#include "../src/puresign/recovery_root_internal.hpp"
#include "test_harness.hpp"

namespace {

using purify::FieldElement;
using purify::Result;
using purify::UInt256;
using purify::UInt512;
using purify::accountable::RecoveryRootShare;
using purify::bppp::PointBytes;
using purify_test::TestContext;
using purify_test::expect_error;
using purify_test::expect_ok;

Result<RecoveryRootShare> share_from_signed_magnitude(
    const UInt256& magnitude, bool negative) {
    auto first = purify::curve1().mul(purify::generator1(), magnitude);
    auto second = purify::curve2().mul(purify::generator2(), magnitude);
    if (negative) {
        first = purify::curve1().negate(first);
        second = purify::curve2().negate(second);
    }
    if (first.infinity || second.infinity) {
        return purify::unexpected_error(
            purify::ErrorCode::RangeViolation,
            "recovery_share_test:infinite_share");
    }
    const auto first_affine = purify::curve1().affine(first);
    const auto second_affine = purify::curve2().affine(second);
    purify::Bytes encoded;
    encoded.reserve(RecoveryRootShare::kSerializedSize);
    for (const auto& point : {first_affine, second_affine}) {
        encoded.push_back(
            static_cast<unsigned char>(point.y.is_odd() ? 0x03 : 0x02));
        const auto x = point.x.to_bytes_be();
        encoded.insert(encoded.end(), x.begin(), x.end());
    }
    return RecoveryRootShare::deserialize(encoded);
}

Result<PointBytes> secp_point(const FieldElement& scalar,
                              purify_secp_context* secp_context) {
    const purify::bppp::ScalarBytes zero{};
    const auto generator = purify::bppp::base_generator(secp_context);
    return purify::bppp::pedersen_commit_char(
        zero, scalar.to_bytes_be(), secp_context, generator, generator);
}

struct RosterFixture {
    purify::accountable::NonceHostBoundSigningRoster roster;
    FieldElement aggregate_scalar;
    std::vector<FieldElement> member_secrets;
    std::vector<FieldElement> effective_scalars;
};

Result<RosterFixture> make_roster_fixture(
    std::vector<FieldElement> secrets, unsigned char fixture_tag,
    purify_secp_context* secp_context) {
    std::vector<PointBytes> keys;
    keys.reserve(secrets.size());
    for (auto& secret : secrets) {
        PURIFY_ASSIGN_OR_RETURN(
            auto key, secp_point(secret, secp_context),
            "recovery_share_test:member_key");
        if (key[0] == 0x03) {
            secret = secret.negate();
            key[0] = 0x02;
        }
        keys.push_back(std::move(key));
    }
    PURIFY_ASSIGN_OR_RETURN(
        auto roster,
        purify::accountable::SigningRoster::aggregate(keys, secp_context),
        "recovery_share_test:roster");
    auto aggregate_scalar = FieldElement::zero();
    std::vector<FieldElement> effective_scalars;
    effective_scalars.reserve(secrets.size());
    for (std::size_t i = 0; i < secrets.size(); ++i) {
        const auto effective =
            roster.members()[i].coefficient * secrets[i];
        aggregate_scalar = aggregate_scalar + effective;
        effective_scalars.push_back(effective);
    }

    std::vector<purify::puresign_plusplus::PublicKey> hosts;
    hosts.reserve(keys.size());
    for (std::size_t i = 0; i < keys.size(); ++i) {
        std::array<unsigned char, 32> seed{};
        seed[0] = fixture_tag;
        seed[1] = static_cast<unsigned char>(i + 1);
        PURIFY_ASSIGN_OR_RETURN(
            auto generated, purify::generate_key(seed),
            "recovery_share_test:host_secret");
        PURIFY_ASSIGN_OR_RETURN(
            auto host,
            purify::puresign_plusplus::PublicKey::from_secret(
                generated.secret, secp_context),
            "recovery_share_test:host");
        std::copy(keys[i].begin() + 1, keys[i].end(),
                  host.bip340_pubkey.begin());
        hosts.push_back(std::move(host));
    }
    purify::accountable::CoalitionCoreDigest core{};
    core.fill(fixture_tag);
    PURIFY_ASSIGN_OR_RETURN(
        auto bound,
        purify::accountable::bind_nonce_hosts(
            std::move(roster), core, hosts, secp_context),
        "recovery_share_test:bound_roster");
    return RosterFixture{
        std::move(bound), aggregate_scalar, std::move(secrets),
        std::move(effective_scalars)};
}

Result<std::vector<RecoveryRootShare>> split_signed_total(
    UInt512 magnitude, std::size_t member_count, bool negative) {
    if (member_count == 0 ||
        member_count > std::numeric_limits<std::uint32_t>::max()) {
        return purify::unexpected_error(
            purify::ErrorCode::RangeViolation,
            "recovery_share_test:split_count");
    }
    const auto remainder = magnitude.divmod_small(
        static_cast<std::uint32_t>(member_count));
    PURIFY_ASSIGN_OR_RETURN(
        const auto base, purify::try_narrow<4>(magnitude),
        "recovery_share_test:split_magnitude");
    std::vector<RecoveryRootShare> shares;
    shares.reserve(member_count);
    for (std::size_t i = 0; i < member_count; ++i) {
        auto part = base;
        if (i < remainder) part.add_small(1);
        if (part.is_zero() ||
            purify::prime_p().shifted_right(1) < part) {
            return purify::unexpected_error(
                purify::ErrorCode::RangeViolation,
                "recovery_share_test:split_centered");
        }
        PURIFY_ASSIGN_OR_RETURN(
            auto share, share_from_signed_magnitude(part, negative),
            "recovery_share_test:split_share");
        shares.push_back(std::move(share));
    }
    return shares;
}

Result<UInt256> expected_centered_component(
    const UInt512& magnitude, bool negative, const UInt256& order,
    const UInt256& half_order) {
    auto remainder = purify::divmod_same(
        magnitude, purify::widen<8>(order)).second;
    PURIFY_ASSIGN_OR_RETURN(
        auto residue, purify::try_narrow<4>(remainder),
        "recovery_share_test:component_narrow");
    if (negative && !residue.is_zero()) {
        auto negated = order;
        negated.sub_assign(residue);
        residue = negated;
    }
    if (residue.is_zero()) {
        return purify::unexpected_error(
            purify::ErrorCode::EquationMismatch,
            "recovery_share_test:zero_component");
    }
    if (half_order < residue) {
        auto centered = order;
        centered.sub_assign(residue);
        residue = centered;
    }
    return residue;
}

void expect_recovery(
    TestContext& ctx, const RosterFixture& fixture,
    const UInt512& magnitude, bool negative,
    purify_secp_context* secp_context, const char* label) {
    auto shares = split_signed_total(
        magnitude, fixture.roster.members().size(), negative);
    expect_ok(ctx, shares, label);
    if (!shares) return;
    auto aggregate =
        purify::accountable::aggregate_recovery_root_shares(*shares);
    expect_ok(ctx, aggregate, label);
    if (!aggregate) return;
    auto recovered = purify::accountable::recover_aggregated_recovery_root(
        fixture.roster, *aggregate, fixture.aggregate_scalar,
        secp_context);
    expect_ok(ctx, recovered, label);
    if (!recovered) return;
    ctx.expect(recovered->public_key == aggregate->recovery_root(), label);

    auto unpacked = purify::unpack_secret(recovered->secret.packed());
    auto expected_first = expected_centered_component(
        magnitude, negative, purify::order_n1(), purify::half_n1());
    auto expected_second = expected_centered_component(
        magnitude, negative, purify::order_n2(), purify::half_n2());
    expect_ok(ctx, unpacked, label);
    expect_ok(ctx, expected_first, label);
    expect_ok(ctx, expected_second, label);
    ctx.expect(unpacked && expected_first && expected_second &&
                   unpacked->first == *expected_first &&
                   unpacked->second == *expected_second,
               label);
}

void test_recovery_share_aggregation(TestContext& ctx) {
    expect_error(
        ctx,
        purify::accountable::aggregate_recovery_root_shares({}),
        purify::ErrorCode::EmptyInput,
        "an empty recovery-share roster is rejected");
    expect_ok(
        ctx,
        purify::accountable::testing::
            recovery_root_share_count_valid_for_testing(100),
        "ordinary recovery-share counts are accepted");
    if constexpr (std::numeric_limits<std::size_t>::max() >
                  purify::accountable::RecoveryRootShareAggregate::
                      kMaxMembers) {
        expect_error(
            ctx,
            purify::accountable::testing::
                recovery_root_share_count_valid_for_testing(
                    purify::accountable::RecoveryRootShareAggregate::
                        kMaxMembers + 1),
            purify::ErrorCode::RangeViolation,
            "recovery-share counts above uint32 are rejected");
    }

    std::array<unsigned char, RecoveryRootShare::kSerializedSize> malformed{};
    malformed[0] = 0x04;
    expect_error(ctx, RecoveryRootShare::deserialize(malformed),
                 purify::ErrorCode::RangeViolation,
                 "malformed recovery-share points are rejected");

    const std::array<std::pair<std::uint64_t, bool>, 3> signed_magnitudes{{
        {5U, false}, {2U, true}, {11U, false},
    }};
    std::vector<RecoveryRootShare> shares;
    for (const auto& [magnitude, negative] : signed_magnitudes) {
        auto share = share_from_signed_magnitude(
            UInt256::from_u64(magnitude), negative);
        expect_ok(ctx, share, "finite recovery share derives");
        if (!share) return;
        shares.push_back(std::move(*share));
    }
    auto aggregate =
        purify::accountable::aggregate_recovery_root_shares(shares);
    expect_ok(ctx, aggregate, "finite recovery shares aggregate");
    if (!aggregate) return;

    const auto expected_first = purify::curve1().affine(
        purify::curve1().mul(purify::generator1(), UInt256::from_u64(14)));
    const auto expected_second = purify::curve2().affine(
        purify::curve2().mul(purify::generator2(), UInt256::from_u64(14)));
    const auto expected_root = purify::pack_public(
        expected_first.x.to_uint256(), expected_second.x.to_uint256());
    ctx.expect(
        aggregate->member_count() == shares.size() &&
            aggregate->first_sum().x == expected_first.x &&
            aggregate->first_sum().y == expected_first.y &&
            aggregate->second_sum().x == expected_second.x &&
            aggregate->second_sum().y == expected_second.y &&
            aggregate->recovery_root() == expected_root,
        "aggregate retains exact sums and derives the x-only root");

    std::vector<RecoveryRootShare> cancelling;
    for (const bool negative : {false, true}) {
        auto share = share_from_signed_magnitude(UInt256::from_u64(5),
                                                 negative);
        expect_ok(ctx, share, "cancelling recovery share derives");
        if (!share) return;
        cancelling.push_back(std::move(*share));
    }
    expect_error(
        ctx,
        purify::accountable::aggregate_recovery_root_shares(cancelling),
        purify::ErrorCode::EquationMismatch,
        "an aggregate at infinity is rejected");

    auto first_magnitude = purify::order_n1();
    const auto remainder = first_magnitude.divmod_small(3);
    auto last_magnitude = first_magnitude;
    last_magnitude.add_small(remainder);
    const auto half_secp_order = purify::prime_p().shifted_right(1);
    ctx.expect(!(half_secp_order < first_magnitude) &&
                   !(half_secp_order < last_magnitude),
               "one-curve cancellation uses centered share magnitudes");
    std::vector<RecoveryRootShare> first_curve_cancelling;
    for (const auto& magnitude :
         {first_magnitude, first_magnitude, last_magnitude}) {
        auto share = share_from_signed_magnitude(magnitude, false);
        expect_ok(ctx, share, "one-curve cancelling share derives");
        if (!share) return;
        first_curve_cancelling.push_back(std::move(*share));
    }
    expect_error(
        ctx,
        purify::accountable::aggregate_recovery_root_shares(
            first_curve_cancelling),
        purify::ErrorCode::EquationMismatch,
        "infinity on either companion curve rejects the aggregate");
}

void test_signed_carry_recovery(TestContext& ctx) {
    auto secp = purify::make_secp_context();
    ctx.expect(secp != nullptr, "recovery secp context creates");
    if (!secp) return;
    auto fixture = make_roster_fixture(
        {FieldElement::from_u64(7), FieldElement::from_u64(11),
         FieldElement::from_u64(19), FieldElement::from_u64(23),
         FieldElement::from_u64(29)},
        0xd1, secp.get());
    expect_ok(ctx, fixture, "recovery roster fixture creates");
    if (!fixture) return;
    auto exposed_point = secp_point(fixture->aggregate_scalar, secp.get());
    ctx.expect(exposed_point && (*exposed_point)[0] == 0x02,
               "exposed scalar is the exact normalized aggregate key");

    expect_error(
        ctx,
        purify::accountable::derive_recovery_root_share(
            fixture->roster.signing_roster(), 0, FieldElement::zero(),
            secp.get()),
        purify::ErrorCode::RangeViolation,
        "pre-formation share derivation rejects a zero secret");
    expect_error(
        ctx,
        purify::accountable::derive_recovery_root_share(
            fixture->roster.signing_roster(),
            fixture->member_secrets.size(), fixture->member_secrets[0],
            secp.get()),
        purify::ErrorCode::IndexOutOfRange,
        "pre-formation share derivation rejects an absent member");
    expect_error(
        ctx,
        purify::accountable::derive_recovery_root_share(
            fixture->roster.signing_roster(), 0,
            fixture->member_secrets[1], secp.get()),
        purify::ErrorCode::BindingMismatch,
        "pre-formation share derivation rejects another member secret");

    std::vector<RecoveryRootShare> actual_shares;
    actual_shares.reserve(fixture->effective_scalars.size());
    const auto half_secp_order = purify::prime_p().shifted_right(1);
    bool saw_positive = false;
    bool saw_negative = false;
    for (std::size_t index = 0;
         index < fixture->effective_scalars.size(); ++index) {
        const auto& effective = fixture->effective_scalars[index];
        const bool negative = half_secp_order < effective.to_uint256();
        saw_negative = saw_negative || negative;
        saw_positive = saw_positive || !negative;
        const auto magnitude = negative
            ? effective.negate().to_uint256()
            : effective.to_uint256();
        auto expected = share_from_signed_magnitude(magnitude, negative);
        auto derived = purify::accountable::derive_recovery_root_share(
            fixture->roster.signing_roster(), index,
            fixture->member_secrets[index], secp.get());
        expect_ok(ctx, expected,
                  "reference pre-formation recovery share derives");
        expect_ok(ctx, derived,
                  "member derives its pre-formation recovery share");
        if (!expected || !derived) return;
        ctx.expect(
            derived->serialize() == expected->serialize(),
            "pre-formation share preserves the exact centered sign");
        actual_shares.push_back(std::move(*derived));
    }
    ctx.expect(saw_positive && saw_negative,
               "pre-formation derivation covers both centered signs");
    auto actual_aggregate =
        purify::accountable::aggregate_recovery_root_shares(actual_shares);
    expect_ok(ctx, actual_aggregate,
              "actual weighted member shares aggregate");
    if (!actual_aggregate) return;
    auto actual_recovered =
        purify::accountable::recover_aggregated_recovery_root(
            fixture->roster, *actual_aggregate,
            fixture->aggregate_scalar, secp.get());
    expect_ok(ctx, actual_recovered,
              "actual weighted member shares recover");
    ctx.expect(actual_recovered &&
                   actual_recovered->public_key ==
                       actual_aggregate->recovery_root(),
               "roster coefficients and aggregate parity recover exactly");

    const auto scalar = fixture->aggregate_scalar.to_uint256();
    const auto scalar_wide = purify::widen<8>(scalar);
    const auto prime_wide = purify::widen<8>(purify::prime_p());
    const bool scalar_is_upper =
        purify::prime_p().shifted_right(1) < scalar;

    auto endpoint_magnitude = prime_wide;
    endpoint_magnitude.mul_small(scalar_is_upper ? 3 : 2);
    if (scalar_is_upper) {
        endpoint_magnitude.sub_assign(scalar_wide);
    } else {
        endpoint_magnitude.add_assign(scalar_wide);
    }
    expect_recovery(
        ctx, *fixture, endpoint_magnitude, scalar_is_upper, secp.get(),
        scalar_is_upper
            ? "lower carry endpoint recovers the exact root"
            : "upper carry endpoint recovers the exact root");

    auto opposite_magnitude = prime_wide;
    if (scalar_is_upper) {
        opposite_magnitude.add_assign(scalar_wide);
    } else {
        opposite_magnitude.mul_small(2);
        opposite_magnitude.sub_assign(scalar_wide);
    }
    expect_recovery(
        ctx, *fixture, opposite_magnitude, !scalar_is_upper, secp.get(),
        "the opposite carry sign recovers the exact root");

    auto endpoint_shares = split_signed_total(
        endpoint_magnitude, fixture->roster.members().size(),
        scalar_is_upper);
    if (!endpoint_shares) return;
    auto endpoint_aggregate =
        purify::accountable::aggregate_recovery_root_shares(
            *endpoint_shares);
    if (!endpoint_aggregate) return;

    auto sign_flipped_shares = split_signed_total(
        endpoint_magnitude, fixture->roster.members().size(),
        !scalar_is_upper);
    if (!sign_flipped_shares) return;
    auto sign_flipped_aggregate =
        purify::accountable::aggregate_recovery_root_shares(
            *sign_flipped_shares);
    if (!sign_flipped_aggregate) return;
    ctx.expect(sign_flipped_aggregate->recovery_root() ==
                   endpoint_aggregate->recovery_root(),
               "opposite full sums retain the same x-only root");
    expect_error(
        ctx,
        purify::accountable::recover_aggregated_recovery_root(
            fixture->roster, *sign_flipped_aggregate,
            fixture->aggregate_scalar, secp.get()),
        purify::ErrorCode::EquationMismatch,
        "recovery authenticates both exact full-point signs");

    auto wrong_scalar = fixture->aggregate_scalar + FieldElement::one();
    if (wrong_scalar.is_zero()) {
        wrong_scalar = wrong_scalar + FieldElement::one();
    }
    expect_error(
        ctx,
        purify::accountable::recover_aggregated_recovery_root(
            fixture->roster, *endpoint_aggregate, wrong_scalar,
            secp.get()),
        purify::ErrorCode::BindingMismatch,
        "recovery rejects a scalar other than the normalized aggregate key");

    std::vector<RecoveryRootShare> short_shares;
    for (std::uint64_t value : {2U, 3U, 5U}) {
        auto share = share_from_signed_magnitude(
            UInt256::from_u64(value), false);
        if (!share) return;
        short_shares.push_back(std::move(*share));
    }
    auto short_aggregate =
        purify::accountable::aggregate_recovery_root_shares(short_shares);
    if (!short_aggregate) return;
    expect_error(
        ctx,
        purify::accountable::recover_aggregated_recovery_root(
            fixture->roster, *short_aggregate,
            fixture->aggregate_scalar, secp.get()),
        purify::ErrorCode::SizeMismatch,
        "recovery rejects a root built for another member count");

    auto unmatched_magnitude = endpoint_magnitude;
    unmatched_magnitude.add_small(1);
    auto unmatched_shares = split_signed_total(
        unmatched_magnitude, fixture->roster.members().size(),
        scalar_is_upper);
    if (!unmatched_shares) return;
    auto unmatched_aggregate =
        purify::accountable::aggregate_recovery_root_shares(
            *unmatched_shares);
    if (!unmatched_aggregate) return;
    expect_error(
        ctx,
        purify::accountable::recover_aggregated_recovery_root(
            fixture->roster, *unmatched_aggregate,
            fixture->aggregate_scalar, secp.get()),
        purify::ErrorCode::EquationMismatch,
        "recovery rejects full points outside every allowed carry");
}

void test_small_carry_searches(TestContext& ctx) {
    auto secp = purify::make_secp_context();
    ctx.expect(secp != nullptr, "small recovery secp context creates");
    if (!secp) return;
    const auto half_secp_order = purify::prime_p().shifted_right(1);
    const auto prime_wide = purify::widen<8>(purify::prime_p());

    auto lower_singleton = make_roster_fixture(
        {FieldElement::from_u64(2)}, 0xa1, secp.get());
    expect_ok(ctx, lower_singleton, "lower singleton fixture creates");
    if (!lower_singleton) return;
    const auto lower_singleton_scalar =
        lower_singleton->aggregate_scalar.to_uint256();
    ctx.expect(lower_singleton->roster.members().size() == 1 &&
                   !(half_secp_order < lower_singleton_scalar),
               "lower singleton selects the k=0 endpoint");
    expect_recovery(
        ctx, *lower_singleton,
        purify::widen<8>(lower_singleton_scalar), false, secp.get(),
        "singleton k=0 endpoint recovers");

    auto upper_singleton = make_roster_fixture(
        {FieldElement::from_u64(3)}, 0xa2, secp.get());
    expect_ok(ctx, upper_singleton, "upper singleton fixture creates");
    if (!upper_singleton) return;
    const auto upper_singleton_scalar =
        upper_singleton->aggregate_scalar.to_uint256();
    ctx.expect(upper_singleton->roster.members().size() == 1 &&
                   half_secp_order < upper_singleton_scalar,
               "upper singleton selects the k=-1 endpoint");
    auto upper_singleton_magnitude = prime_wide;
    upper_singleton_magnitude.sub_assign(
        purify::widen<8>(upper_singleton_scalar));
    expect_recovery(
        ctx, *upper_singleton, upper_singleton_magnitude, true,
        secp.get(), "singleton k=-1 endpoint recovers");

    auto even_fixture = make_roster_fixture(
        {FieldElement::from_u64(2), FieldElement::from_u64(3),
         FieldElement::from_u64(5), FieldElement::from_u64(7)},
        0xa3, secp.get());
    expect_ok(ctx, even_fixture, "even recovery fixture creates");
    if (!even_fixture) return;
    ctx.expect(even_fixture->roster.members().size() == 4 &&
                   even_fixture->roster.aggregate_was_negated(),
               "even fixture pins aggregate parity normalization");
    const auto even_scalar =
        purify::widen<8>(even_fixture->aggregate_scalar.to_uint256());

    auto even_lower_magnitude = prime_wide;
    even_lower_magnitude.mul_small(2);
    even_lower_magnitude.sub_assign(even_scalar);
    expect_recovery(
        ctx, *even_fixture, even_lower_magnitude, true, secp.get(),
        "even roster lower k=-2 endpoint recovers");

    auto even_upper_magnitude = prime_wide;
    even_upper_magnitude.add_assign(even_scalar);
    expect_recovery(
        ctx, *even_fixture, even_upper_magnitude, false, secp.get(),
        "even roster upper k=1 endpoint recovers");
}

} // namespace

void run_recovery_root_share_tests(TestContext& ctx) {
    test_recovery_share_aggregation(ctx);
    test_signed_carry_recovery(ctx);
    test_small_carry_searches(ctx);
}
