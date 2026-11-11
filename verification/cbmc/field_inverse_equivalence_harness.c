// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <assert.h>

#include "common.h"
#include "field.h"

int main(void) {
    purify_fe a;
    purify_fe inv_consttime;
    purify_fe inv_var;
    purify_fe product;

    purify_fe_set_u64(&a, nondet_uint64_t());

    purify_fe_inverse(&inv_consttime, &a);
    purify_fe_inverse_var(&inv_var, &a);

    assert(purify_fe_eq(&inv_consttime, &inv_var) != 0);

    purify_fe_mul(&product, &a, &inv_consttime);
    if (purify_fe_is_zero(&a) != 0) {
        assert(purify_fe_is_zero(&inv_consttime) != 0);
        assert(purify_fe_is_zero(&product) != 0);
    } else {
        assert(purify_fe_is_one(&product) != 0);
    }

    purify_fe_mul(&product, &a, &inv_var);
    if (purify_fe_is_zero(&a) != 0) {
        assert(purify_fe_is_zero(&inv_var) != 0);
        assert(purify_fe_is_zero(&product) != 0);
    } else {
        assert(purify_fe_is_one(&product) != 0);
    }

    return 0;
}
