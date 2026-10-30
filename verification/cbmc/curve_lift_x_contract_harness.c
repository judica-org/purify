// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <assert.h>

#include "common.h"
#include "curve_model_helpers.h"

static void purify_cbmc_check_curve(const purify_curve* curve, uint64_t x_u64) {
    purify_fe x;
    purify_jacobian_point point;
    int is_x_coord;
    int lifted;

    purify_fe_set_u64(&x, x_u64);
    is_x_coord = purify_curve_is_x_coord(curve, &x);
    lifted = purify_curve_lift_x(&point, curve, &x);
    assert((is_x_coord != 0) == (lifted != 0));
    if (lifted == 0) {
        return;
    }

    assert(point.infinity == 0);
    assert(purify_fe_eq(&point.x, &x) != 0);
    assert(purify_fe_is_one(&point.z) != 0);
    assert(purify_cbmc_point_on_curve(curve, &point));
}

int main(void) {
    purify_curve curve1;
    purify_curve curve2;

    purify_cbmc_make_curve1(&curve1);
    purify_cbmc_make_curve2(&curve2);
    purify_cbmc_check_curve(&curve1, nondet_uint64_t() % 107u);
    purify_cbmc_check_curve(&curve2, nondet_uint64_t() % 107u);

    return 0;
}
