// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <assert.h>

#include "common.h"
#include "curve_model_helpers.h"

int main(void) {
    purify_curve curve1;
    purify_fe x;
    purify_fe z;
    purify_jacobian_point lifted;
    purify_affine_point affine;
    purify_jacobian_point projective;
    purify_affine_point recovered;
    purify_jacobian_point negated;
    purify_jacobian_point roundtrip;
    purify_jacobian_point infinity;
    purify_affine_point infinity_affine;

    purify_cbmc_make_curve1(&curve1);
    purify_fe_set_u64(&x, nondet_uint64_t() % 107u);
    PURIFY_CBMC_ASSUME(purify_curve_lift_x(&lifted, &curve1, &x) != 0);
    purify_curve_affine(&affine, &curve1, &lifted);
    purify_fe_set_u64(&z, 1u + (nondet_uint64_t() % 106u));
    purify_cbmc_projective_from_affine(&projective, &affine, &z);

    purify_curve_affine(&recovered, &curve1, &projective);
    assert(purify_cbmc_affine_eq(&recovered, &affine));

    purify_curve_negate(&negated, &projective);
    assert(purify_cbmc_point_on_curve(&curve1, &negated));
    purify_curve_negate(&roundtrip, &negated);
    assert(purify_cbmc_jacobian_eq(&curve1, &roundtrip, &projective));

    purify_curve_jacobian_infinity(&infinity);
    purify_curve_affine(&infinity_affine, &curve1, &infinity);
    assert(infinity_affine.infinity != 0);
    purify_curve_negate(&negated, &infinity);
    assert(negated.infinity != 0);
    assert(purify_fe_is_zero(&negated.z) != 0);

    return 0;
}
