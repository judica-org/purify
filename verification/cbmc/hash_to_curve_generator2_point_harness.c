// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <assert.h>

#include "curve_model_helpers.h"

static const unsigned char kGenerator2Label[] = "Generator/2";

static int purify_cbmc_fe_eq_u64(const purify_fe* value, uint64_t expected_u64) {
    purify_fe expected;
    purify_fe_set_u64(&expected, expected_u64);
    return purify_fe_eq(value, &expected) != 0;
}

int main(void) {
    purify_curve curve2;
    purify_jacobian_point point2;

    purify_cbmc_make_curve2(&curve2);

    assert(purify_curve_hash_to_curve(&point2, &curve2, kGenerator2Label, sizeof(kGenerator2Label) - 1u) != 0);
    assert(point2.infinity == 0);
    assert(purify_cbmc_point_on_curve(&curve2, &point2));
    assert(purify_cbmc_fe_eq_u64(&point2.x, 76u));
    assert(purify_cbmc_fe_eq_u64(&point2.y, 10u));
    assert(purify_cbmc_fe_eq_u64(&point2.z, 1u));

    return 0;
}
