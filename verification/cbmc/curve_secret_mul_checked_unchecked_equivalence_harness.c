// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <assert.h>

#include "curve_model_helpers.h"

void purify_curve_mul_secret_affine_unchecked(purify_affine_point* out, const purify_curve* curve,
                                              const purify_jacobian_point* point, const uint64_t scalar[4]);

int main(void) {
    purify_curve curve1;
    purify_jacobian_point point;
    purify_affine_point checked;
    purify_affine_point unchecked;
    uint64_t scalar[4];

    purify_cbmc_make_curve1(&curve1);
    PURIFY_CBMC_ASSUME(purify_cbmc_make_arbitrary_point(&point, &curve1) != 0);

    purify_u256_set_u64(scalar, 1u + (nondet_uint64_t() % 108u));
    assert(purify_curve_mul_secret_affine(&checked, &curve1, &point, scalar) != 0);
    purify_curve_mul_secret_affine_unchecked(&unchecked, &curve1, &point, scalar);
    assert(purify_cbmc_affine_eq(&checked, &unchecked));

    return 0;
}
