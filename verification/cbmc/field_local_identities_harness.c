// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <assert.h>

#include "common.h"
#include "field.h"
#include "verification/cbmc/model_small_field_constants.h"

int main(void) {
    purify_fe a;
    purify_fe b;
    purify_fe roundtrip;
    purify_fe neg_from_i64;
    purify_fe pos_five;
    purify_fe negated_five;
    purify_fe square;
    purify_fe sqrt_out;
    purify_fe resquared;
    purify_fe zero;
    purify_fe non_square;

    purify_fe_set_u64(&a, nondet_uint64_t());
    purify_fe_set_u64(&b, nondet_uint64_t());

    purify_fe_sub(&roundtrip, &a, &b);
    purify_fe_add(&roundtrip, &roundtrip, &b);
    assert(purify_fe_eq(&roundtrip, &a) != 0);

    purify_fe_set_i64(&neg_from_i64, -5);
    purify_fe_set_u64(&pos_five, 5u);
    purify_fe_negate(&negated_five, &pos_five);
    assert(purify_fe_eq(&neg_from_i64, &negated_five) != 0);

    purify_fe_square(&square, &a);
    assert(purify_fe_sqrt(&sqrt_out, &square) != 0);
    purify_fe_square(&resquared, &sqrt_out);
    assert(purify_fe_eq(&resquared, &square) != 0);

    purify_fe_set_zero(&zero);
    assert(purify_fe_sqrt(&sqrt_out, &zero) != 0);
    assert(purify_fe_is_zero(&sqrt_out) != 0);

    purify_fe_set_u64(&non_square, PURIFY_CBMC_MODEL_FIELD_NON_SQUARE_U64);
    assert(purify_fe_is_square(&non_square) == 0);
    assert(purify_fe_legendre_symbol(&non_square) == -1);
    assert(purify_fe_sqrt(&sqrt_out, &non_square) == 0);

    return 0;
}
