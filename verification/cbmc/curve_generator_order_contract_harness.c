// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <assert.h>

#include "curve_model_helpers.h"

static void purify_cbmc_make_generator_point(purify_jacobian_point* out, uint64_t x, uint64_t y) {
    purify_fe_set_u64(&out->x, x);
    purify_fe_set_u64(&out->y, y);
    purify_fe_set_u64(&out->z, 1u);
    out->infinity = 0;
}

int main(void) {
    purify_curve curve1;
    purify_curve curve2;
    purify_jacobian_point point1;
    purify_jacobian_point point2;
    purify_jacobian_point checked;
    uint64_t order[4];

    purify_cbmc_make_curve1(&curve1);
    purify_cbmc_make_curve2(&curve2);
    purify_cbmc_make_generator_point(&point1, 78u, 53u);
    purify_cbmc_make_generator_point(&point2, 76u, 10u);

    assert(purify_cbmc_point_on_curve(&curve1, &point1));
    purify_curve_order_n1(order);
    purify_curve_mul(&checked, &curve1, &point1, order);
    assert(checked.infinity != 0 || purify_fe_is_zero(&checked.z) != 0);

    assert(purify_cbmc_point_on_curve(&curve2, &point2));
    purify_curve_order_n2(order);
    purify_curve_mul(&checked, &curve2, &point2, order);
    assert(checked.infinity != 0 || purify_fe_is_zero(&checked.z) != 0);

    return 0;
}
