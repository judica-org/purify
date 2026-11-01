// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "../src/protocol/coordinate_field.hpp"
#include "test_harness.hpp"

namespace {

using purify::UInt256;
using purify::bppp::candidate::CoordinateFieldElement;
using purify_test::expect_error;
using purify_test::expect_ok;
using purify_test::TestContext;

void check_canonical_arithmetic(TestContext& ctx) {
    const auto modulus =
        UInt256::from_hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
    expect_error(ctx, CoordinateFieldElement::from_bytes_be(modulus.to_bytes_be()),
                 purify::ErrorCode::RangeViolation, "coordinate modulus is not canonical");

    const auto reduced_zero = CoordinateFieldElement::from_reduced_bytes_be(modulus.to_bytes_be());
    ctx.expect(reduced_zero.is_zero(), "coordinate reduction maps p to zero");

    UInt256 modulus_plus_one = modulus;
    modulus_plus_one.add_small(1);
    const auto reduced_one =
        CoordinateFieldElement::from_reduced_bytes_be(modulus_plus_one.to_bytes_be());
    ctx.expect(reduced_one == CoordinateFieldElement::one(),
               "coordinate reduction maps p plus one to one");

    CoordinateFieldElement::Encoding all_ones{};
    all_ones.fill(0xff);
    ctx.expect(CoordinateFieldElement::from_reduced_bytes_be(all_ones) ==
                   CoordinateFieldElement::from_u64(0x1'0000'03d0ULL),
               "coordinate reduction handles the maximum integer");

    UInt256 maximum = modulus;
    maximum.sub_assign(UInt256::one());
    auto maximum_field = CoordinateFieldElement::from_bytes_be(maximum.to_bytes_be());
    expect_ok(ctx, maximum_field, "p minus one is a canonical coordinate value");
    if (!maximum_field) return;
    ctx.expect(*maximum_field + CoordinateFieldElement::one() == CoordinateFieldElement::zero(),
               "coordinate addition reduces modulo p");
    ctx.expect(CoordinateFieldElement::zero() - CoordinateFieldElement::one() == *maximum_field,
               "coordinate subtraction reduces modulo p");
    ctx.expect(*maximum_field * *maximum_field == CoordinateFieldElement::one(),
               "coordinate multiplication reduces modulo p");

    const auto seven = CoordinateFieldElement::from_u64(7);
    auto inverse = seven.inverse();
    expect_ok(ctx, inverse, "nonzero coordinate inverse exists");
    if (!inverse) return;
    ctx.expect(seven * *inverse == CoordinateFieldElement::one(),
               "coordinate inverse multiplies to one");
    expect_error(ctx, CoordinateFieldElement::zero().inverse(), purify::ErrorCode::RangeViolation,
                 "zero has no coordinate inverse");
}

} // namespace

void run_coordinate_field_tests(TestContext& ctx) { check_canonical_arithmetic(ctx); }
