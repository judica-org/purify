// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <assert.h>

#include "curve_model_helpers.h"

int main(void) {
    purify_curve curve1;
    purify_jacobian_point point;
    purify_affine_point affine;
    purify_affine_point result;
    uint64_t one[4] = {1, 0, 0, 0};

    purify_cbmc_make_curve1(&curve1);
    PURIFY_CBMC_ASSUME(purify_cbmc_make_arbitrary_point(&point, &curve1) != 0);
    purify_curve_affine(&affine, &curve1, &point);

    assert(purify_curve_mul_secret_affine(&result, &curve1, &point, one) != 0);
    assert(purify_cbmc_affine_eq(&result, &affine));
    return 0;
}
