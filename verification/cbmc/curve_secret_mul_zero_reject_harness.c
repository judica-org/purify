// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <assert.h>

#include "curve_model_helpers.h"
#include "verification/cbmc/model_small_field_constants.h"

int main(void) {
    purify_curve curve1;
    purify_fe x;
    purify_jacobian_point point;
    purify_affine_point result;
    uint64_t zero[4] = {0, 0, 0, 0};

    purify_cbmc_make_curve1(&curve1);
    purify_fe_set_u64(&x, PURIFY_CBMC_MODEL_CURVE1_X_U64);
    assert(purify_curve_lift_x(&point, &curve1, &x) != 0);

    assert(purify_curve_mul_secret_affine(&result, &curve1, &point, zero) == 0);
    return 0;
}
