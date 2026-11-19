// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <assert.h>

#include "common.h"
#include "curve_model_helpers.h"

int main(void) {
    purify_curve curve1;
    purify_fe lhs_x;
    purify_fe rhs_x;
    purify_fe lhs_z;
    purify_fe rhs_z;
    purify_jacobian_point lhs_lifted;
    purify_jacobian_point rhs_lifted;
    purify_affine_point lhs_affine;
    purify_affine_point rhs_affine;
    purify_jacobian_point lhs_projective;
    purify_jacobian_point rhs_projective;
    purify_jacobian_point mixed_sum;
    purify_jacobian_point full_sum;

    purify_cbmc_make_curve1(&curve1);
    purify_fe_set_u64(&lhs_x, nondet_uint64_t() % 107u);
    purify_fe_set_u64(&rhs_x, nondet_uint64_t() % 107u);
    PURIFY_CBMC_ASSUME(purify_curve_lift_x(&lhs_lifted, &curve1, &lhs_x) != 0);
    PURIFY_CBMC_ASSUME(purify_curve_lift_x(&rhs_lifted, &curve1, &rhs_x) != 0);

    purify_curve_affine(&lhs_affine, &curve1, &lhs_lifted);
    purify_curve_affine(&rhs_affine, &curve1, &rhs_lifted);
    purify_fe_set_u64(&lhs_z, 2u + (nondet_uint64_t() % 105u));
    purify_fe_set_u64(&rhs_z, 2u + (nondet_uint64_t() % 105u));
    purify_cbmc_projective_from_affine(&lhs_projective, &lhs_affine, &lhs_z);
    purify_cbmc_projective_from_affine(&rhs_projective, &rhs_affine, &rhs_z);

    purify_curve_add_mixed(&mixed_sum, &curve1, &lhs_projective, &rhs_affine);
    purify_curve_add(&full_sum, &curve1, &lhs_projective, &rhs_projective);
    assert(purify_cbmc_jacobian_eq(&curve1, &mixed_sum, &full_sum));

    return 0;
}
