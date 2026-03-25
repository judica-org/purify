// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <assert.h>

#include "curve_model_helpers.h"
#include "verification/cbmc/model_small_field_constants.h"

static void purify_cbmc_lift_fixed_point(purify_jacobian_point* out, const purify_curve* curve, uint64_t x_value) {
    purify_fe x;
    purify_fe_set_u64(&x, x_value);
    assert(purify_curve_lift_x(out, curve, &x) != 0);
}

int main(void) {
    purify_curve curve1;
    purify_curve curve2;
    purify_jacobian_point infinity;
    purify_jacobian_point p1;
    purify_jacobian_point p2;
    purify_jacobian_point sum;
    purify_jacobian_point doubled;
    purify_jacobian_point negated;
    uint64_t n1[4];
    uint64_t n2[4];

    purify_cbmc_make_curve1(&curve1);
    purify_cbmc_make_curve2(&curve2);
    purify_curve_jacobian_infinity(&infinity);
    purify_cbmc_lift_fixed_point(&p1, &curve1, PURIFY_CBMC_MODEL_CURVE1_X_U64);
    purify_cbmc_lift_fixed_point(&p2, &curve2, PURIFY_CBMC_MODEL_CURVE2_X_U64);

    assert(purify_cbmc_point_on_curve(&curve1, &p1));
    assert(purify_cbmc_point_on_curve(&curve2, &p2));

    purify_curve_add(&sum, &curve1, &infinity, &p1);
    assert(purify_cbmc_jacobian_eq(&curve1, &sum, &p1));
    purify_curve_add(&sum, &curve1, &p1, &infinity);
    assert(purify_cbmc_jacobian_eq(&curve1, &sum, &p1));

    purify_curve_negate(&negated, &p1);
    purify_curve_add(&sum, &curve1, &p1, &negated);
    assert(sum.infinity != 0 || purify_fe_is_zero(&sum.z) != 0);

    purify_curve_double(&doubled, &curve1, &p1);
    purify_curve_add(&sum, &curve1, &p1, &p1);
    assert(purify_cbmc_jacobian_eq(&curve1, &sum, &doubled));

    purify_curve_order_n1(n1);
    purify_curve_mul(&sum, &curve1, &p1, n1);
    assert(sum.infinity != 0 || purify_fe_is_zero(&sum.z) != 0);

    purify_curve_order_n2(n2);
    purify_curve_mul(&sum, &curve2, &p2, n2);
    assert(sum.infinity != 0 || purify_fe_is_zero(&sum.z) != 0);

    return 0;
}
