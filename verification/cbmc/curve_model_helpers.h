// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include <assert.h>

#include "curve.h"

static inline void purify_cbmc_make_curve1(purify_curve* out) {
    purify_curve_field_a(&out->a);
    purify_curve_field_b(&out->b);
    purify_curve_order_n1(out->n);
}

static inline void purify_cbmc_make_curve2(purify_curve* out) {
    purify_fe a;
    purify_fe b;
    purify_fe d;

    purify_curve_field_a(&a);
    purify_curve_field_b(&b);
    purify_curve_field_d(&d);
    purify_fe_mul(&out->a, &a, &d);
    purify_fe_mul(&out->a, &out->a, &d);
    purify_fe_mul(&out->b, &b, &d);
    purify_fe_mul(&out->b, &out->b, &d);
    purify_fe_mul(&out->b, &out->b, &d);
    purify_curve_order_n2(out->n);
}

static inline int purify_cbmc_affine_eq(const purify_affine_point* lhs, const purify_affine_point* rhs) {
    if (lhs->infinity != 0 || rhs->infinity != 0) {
        return lhs->infinity == rhs->infinity;
    }
    return purify_fe_eq(&lhs->x, &rhs->x) != 0 && purify_fe_eq(&lhs->y, &rhs->y) != 0;
}

static inline int purify_cbmc_jacobian_eq(const purify_curve* curve,
                                          const purify_jacobian_point* lhs,
                                          const purify_jacobian_point* rhs) {
    purify_affine_point lhs_affine;
    purify_affine_point rhs_affine;

    if ((lhs->infinity != 0 || purify_fe_is_zero(&lhs->z) != 0) &&
        (rhs->infinity != 0 || purify_fe_is_zero(&rhs->z) != 0)) {
        return 1;
    }

    purify_curve_affine(&lhs_affine, curve, lhs);
    purify_curve_affine(&rhs_affine, curve, rhs);
    return purify_cbmc_affine_eq(&lhs_affine, &rhs_affine);
}

static inline int purify_cbmc_point_on_curve(const purify_curve* curve, const purify_jacobian_point* point) {
    purify_affine_point affine;
    purify_fe lhs;
    purify_fe rhs;
    purify_fe x2;
    purify_fe x3;
    purify_fe ax;

    if (point->infinity != 0 || purify_fe_is_zero(&point->z) != 0) {
        return 1;
    }

    purify_curve_affine(&affine, curve, point);
    purify_fe_mul(&lhs, &affine.y, &affine.y);
    purify_fe_mul(&x2, &affine.x, &affine.x);
    purify_fe_mul(&x3, &x2, &affine.x);
    purify_fe_mul(&ax, &curve->a, &affine.x);
    purify_fe_add(&rhs, &x3, &ax);
    purify_fe_add(&rhs, &rhs, &curve->b);
    return purify_fe_eq(&lhs, &rhs) != 0;
}

static inline void purify_cbmc_projective_from_affine(purify_jacobian_point* out,
                                                       const purify_affine_point* affine,
                                                       const purify_fe* z) {
    purify_fe z2;
    purify_fe z3;

    if (affine->infinity != 0) {
        purify_curve_jacobian_infinity(out);
        return;
    }

    purify_fe_mul(&z2, z, z);
    purify_fe_mul(&z3, &z2, z);
    purify_fe_mul(&out->x, &affine->x, &z2);
    purify_fe_mul(&out->y, &affine->y, &z3);
    out->z = *z;
    out->infinity = 0;
}
