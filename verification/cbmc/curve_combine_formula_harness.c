// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <assert.h>

#include "common.h"
#include "curve.h"

static void purify_cbmc_compute_combine_formula(purify_fe* out, const purify_fe* x1, const purify_fe* x2) {
    purify_fe field_a;
    purify_fe field_b;
    purify_fe field_di;
    purify_fe two;
    purify_fe u;
    purify_fe v;
    purify_fe uv;
    purify_fe u_plus_v;
    purify_fe denom;
    purify_fe w;
    purify_fe numer;
    purify_fe tmp;

    purify_curve_field_a(&field_a);
    purify_curve_field_b(&field_b);
    purify_curve_field_di(&field_di);
    purify_fe_set_u64(&two, 2u);

    u = *x1;
    purify_fe_mul(&v, x2, &field_di);
    purify_fe_sub(&denom, &u, &v);
    purify_fe_inverse(&w, &denom);
    purify_fe_add(&u_plus_v, &u, &v);
    purify_fe_mul(&uv, &u, &v);
    purify_fe_add(&tmp, &field_a, &uv);
    purify_fe_mul(&numer, &u_plus_v, &tmp);
    purify_fe_mul(&tmp, &two, &field_b);
    purify_fe_add(&numer, &numer, &tmp);
    purify_fe_mul(&w, &w, &w);
    purify_fe_mul(out, &numer, &w);
}

int main(void) {
    purify_fe x1;
    purify_fe x2;
    purify_fe direct;
    purify_fe formula;
    purify_fe field_di;
    purify_fe v;
    purify_fe denom;

    purify_fe_set_u64(&x1, nondet_uint64_t());
    purify_fe_set_u64(&x2, nondet_uint64_t());
    purify_curve_field_di(&field_di);
    purify_fe_mul(&v, &x2, &field_di);
    purify_fe_sub(&denom, &x1, &v);
    PURIFY_CBMC_ASSUME(purify_fe_is_zero(&denom) == 0);

    purify_curve_combine(&direct, &x1, &x2);
    purify_cbmc_compute_combine_formula(&formula, &x1, &x2);
    assert(purify_fe_eq(&direct, &formula) != 0);

    return 0;
}
