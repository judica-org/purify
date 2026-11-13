// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <array>
#include <span>
#include <vector>

#include "purify/curve.hpp"
#include "purify/puresign/recovery_root.hpp"
#include "test_harness.hpp"

namespace {

using purify::Result;
using purify::UInt256;
using purify::accountable::RecoveryRootShare;
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

void test_recovery_share_aggregation(TestContext& ctx) {
    expect_error(
        ctx,
        purify::accountable::aggregate_recovery_root_shares({}),
        purify::ErrorCode::EmptyInput,
        "an empty recovery-share roster is rejected");

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

} // namespace

void run_recovery_root_share_tests(TestContext& ctx) {
    test_recovery_share_aggregation(ctx);
}
