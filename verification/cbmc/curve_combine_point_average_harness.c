// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <assert.h>

#include "common.h"
#include "curve_model_helpers.h"

static void purify_cbmc_average_x_coordinates(purify_fe* out, const purify_fe* lhs, const purify_fe* rhs) {
    purify_fe sum;
    purify_fe two;
    purify_fe two_inverse;

    purify_fe_add(&sum, lhs, rhs);
    purify_fe_set_u64(&two, 2u);
    purify_fe_inverse(&two_inverse, &two);
    purify_fe_mul(out, &sum, &two_inverse);
}

int main(void) {
    purify_curve curve1;
    purify_curve curve2;
    purify_fe x1;
    purify_fe x2;
    purify_fe field_di;
    purify_fe untwisted_x2;
    purify_fe combined;
    purify_fe oracle;
    purify_jacobian_point p;
    purify_jacobian_point q_twist;
    purify_jacobian_point q_untwisted;
    purify_jacobian_point neg_q;
    purify_jacobian_point sum;
    purify_jacobian_point diff;
    purify_affine_point sum_affine;
    purify_affine_point diff_affine;

    purify_cbmc_make_curve1(&curve1);
    purify_cbmc_make_curve2(&curve2);
    purify_fe_set_u64(&x1, nondet_uint64_t() % 107u);
    purify_fe_set_u64(&x2, nondet_uint64_t() % 107u);
    PURIFY_CBMC_ASSUME(purify_curve_lift_x(&p, &curve1, &x1) != 0);
    PURIFY_CBMC_ASSUME(purify_curve_lift_x(&q_twist, &curve2, &x2) != 0);

    purify_curve_field_di(&field_di);
    purify_fe_mul(&untwisted_x2, &x2, &field_di);
    assert(purify_curve_lift_x(&q_untwisted, &curve1, &untwisted_x2) != 0);
    PURIFY_CBMC_ASSUME(purify_fe_eq(&x1, &untwisted_x2) == 0);

    purify_curve_combine(&combined, &x1, &x2);
    purify_curve_add(&sum, &curve1, &p, &q_untwisted);
    purify_curve_negate(&neg_q, &q_untwisted);
    purify_curve_add(&diff, &curve1, &p, &neg_q);

    assert(sum.infinity == 0 && purify_fe_is_zero(&sum.z) == 0);
    assert(diff.infinity == 0 && purify_fe_is_zero(&diff.z) == 0);
    assert(purify_cbmc_point_on_curve(&curve1, &sum));
    assert(purify_cbmc_point_on_curve(&curve1, &diff));

    purify_curve_affine(&sum_affine, &curve1, &sum);
    purify_curve_affine(&diff_affine, &curve1, &diff);
    purify_cbmc_average_x_coordinates(&oracle, &sum_affine.x, &diff_affine.x);
    assert(purify_fe_eq(&combined, &oracle) != 0);

    return 0;
}
