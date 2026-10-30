// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <assert.h>
#include <string.h>

#include "common.h"
#include "purify/uint.h"

int main(void) {
    uint64_t numerator[8];
    uint64_t denominator[8];
    uint64_t quotient_var[8] = {0};
    uint64_t remainder_var[8] = {0};
    uint64_t quotient_ct[8] = {0};
    uint64_t remainder_ct[8] = {0};
    int ok_var;
    int ok_ct;

    purify_cbmc_nondet_words(numerator, 8u);
    purify_cbmc_nondet_words(denominator, 8u);
    PURIFY_CBMC_ASSUME(!purify_u512_is_zero(denominator));

    ok_var = purify_u512_try_divmod_same(quotient_var, remainder_var, numerator, denominator);
    ok_ct = purify_u512_try_divmod_same_consttime(quotient_ct, remainder_ct, numerator, denominator);

    assert(ok_var == ok_ct);
    if (ok_var != 0) {
        assert(purify_cbmc_words_eq(quotient_var, quotient_ct, 8u));
        assert(purify_cbmc_words_eq(remainder_var, remainder_ct, 8u));
    }

    return 0;
}
