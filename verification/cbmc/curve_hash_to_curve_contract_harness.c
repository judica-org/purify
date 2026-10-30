// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <assert.h>

#include "curve_model_helpers.h"

int main(void) {
    purify_curve curve1;
    purify_jacobian_point point1_a;
    const size_t data_len = 0u;

    purify_cbmc_make_curve1(&curve1);

    assert(purify_curve_hash_to_curve(NULL, &curve1, NULL, data_len) == 0);
    assert(purify_curve_hash_to_curve(&point1_a, NULL, NULL, data_len) == 0);
    assert(purify_curve_hash_to_curve(&point1_a, &curve1, NULL, 1u) == 0);

    return 0;
}
