// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <assert.h>

#include "common.h"
#include "curve_model_helpers.h"

int main(void) {
    purify_curve curve1;
    size_t data_len;
    purify_jacobian_point point1_a;
    purify_jacobian_point point1_b;
    int ok1_a;
    int ok1_b;

    purify_cbmc_make_curve1(&curve1);
    data_len = 0u;

    assert(purify_curve_hash_to_curve(NULL, &curve1, NULL, data_len) == 0);
    assert(purify_curve_hash_to_curve(&point1_a, NULL, NULL, data_len) == 0);
    assert(purify_curve_hash_to_curve(&point1_a, &curve1, NULL, 1u) == 0);

    ok1_a = purify_curve_hash_to_curve(&point1_a, &curve1, NULL, data_len);
    ok1_b = purify_curve_hash_to_curve(&point1_b, &curve1, NULL, data_len);
    assert(ok1_a == ok1_b);
    if (ok1_a != 0) {
        assert(purify_cbmc_jacobian_eq(&curve1, &point1_a, &point1_b));
        assert(purify_cbmc_point_on_curve(&curve1, &point1_a));
        assert(point1_a.infinity == 0 && purify_fe_is_zero(&point1_a.z) == 0);
    }

    return 0;
}
