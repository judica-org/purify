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
    purify_jacobian_point doubled;
    purify_jacobian_point in_place;
    purify_jacobian_point added;

    purify_cbmc_make_curve1(&curve1);
    purify_fe_set_u64(&x, nondet_uint64_t() % 107u);
    PURIFY_CBMC_ASSUME(purify_curve_lift_x(&lifted, &curve1, &x) != 0);
    purify_curve_affine(&affine, &curve1, &lifted);
    purify_fe_set_u64(&z, 2u + (nondet_uint64_t() % 105u));
    purify_cbmc_projective_from_affine(&projective, &affine, &z);

    purify_curve_double(&doubled, &curve1, &projective);
    in_place = projective;
    purify_curve_double(&in_place, &curve1, &in_place);
    purify_curve_add(&added, &curve1, &projective, &projective);

    assert(purify_cbmc_jacobian_eq(&curve1, &doubled, &in_place));
    assert(purify_cbmc_jacobian_eq(&curve1, &doubled, &added));

    return 0;
}
