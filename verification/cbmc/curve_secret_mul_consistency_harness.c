// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <assert.h>

#include "curve_model_helpers.h"
#include "purify/uint.h"

int main(void) {
    purify_curve curve1;
    purify_jacobian_point p1;
    purify_jacobian_point public_result;
    purify_affine_point public_affine;
    purify_affine_point secret_affine;
    uint64_t scalar1[4];

    purify_cbmc_make_curve1(&curve1);
    PURIFY_CBMC_ASSUME(purify_cbmc_make_arbitrary_point(&p1, &curve1) != 0);

    purify_u256_set_u64(scalar1, 1u + (nondet_uint64_t() % 108u));
    purify_curve_mul(&public_result, &curve1, &p1, scalar1);
    purify_curve_affine(&public_affine, &curve1, &public_result);
    assert(purify_curve_mul_secret_affine(&secret_affine, &curve1, &p1, scalar1) != 0);
    assert(purify_cbmc_affine_eq(&public_affine, &secret_affine));

    return 0;
}
