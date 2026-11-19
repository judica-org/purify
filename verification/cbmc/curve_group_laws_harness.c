// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <assert.h>

#include "common.h"
#include "curve_model_helpers.h"

static void purify_cbmc_assert_group_laws(const purify_curve* curve, const purify_jacobian_point* point, const uint64_t order[4]) {
    purify_jacobian_point infinity;
    purify_jacobian_point sum;
    purify_jacobian_point doubled;
    purify_jacobian_point negated;

    assert(purify_cbmc_point_on_curve(curve, point));

    purify_curve_jacobian_infinity(&infinity);
    purify_curve_add(&sum, curve, &infinity, point);
    assert(purify_cbmc_jacobian_eq(curve, &sum, point));
    purify_curve_add(&sum, curve, point, &infinity);
    assert(purify_cbmc_jacobian_eq(curve, &sum, point));

    purify_curve_negate(&negated, point);
    purify_curve_add(&sum, curve, point, &negated);
    assert(sum.infinity != 0 || purify_fe_is_zero(&sum.z) != 0);

    purify_curve_double(&doubled, curve, point);
    purify_curve_add(&sum, curve, point, point);
    assert(purify_cbmc_jacobian_eq(curve, &sum, &doubled));

    purify_curve_mul(&sum, curve, point, order);
    assert(sum.infinity != 0 || purify_fe_is_zero(&sum.z) != 0);
}

int main(void) {
    purify_curve curve1;
    purify_curve curve2;
    purify_jacobian_point p1;
    purify_jacobian_point p2;
    uint64_t n1[4];
    uint64_t n2[4];

    purify_cbmc_make_curve1(&curve1);
    purify_cbmc_make_curve2(&curve2);
    PURIFY_CBMC_ASSUME(purify_cbmc_make_arbitrary_point(&p1, &curve1) != 0);
    PURIFY_CBMC_ASSUME(purify_cbmc_make_arbitrary_point(&p2, &curve2) != 0);

    purify_curve_order_n1(n1);
    purify_cbmc_assert_group_laws(&curve1, &p1, n1);

    purify_curve_order_n2(n2);
    purify_cbmc_assert_group_laws(&curve2, &p2, n2);

    return 0;
}
