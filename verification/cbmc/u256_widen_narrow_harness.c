// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <assert.h>

#include "common.h"
#include "purify/uint.h"

int main(void) {
    uint64_t value[4];
    uint64_t widened320[5];
    uint64_t widened512[8];
    uint64_t narrowed[4];
    uint64_t noncanonical320[5];
    uint64_t noncanonical512[8];

    purify_cbmc_nondet_words(value, 4u);
    purify_u320_widen_u256(widened320, value);
    purify_u512_widen_u256(widened512, value);

    assert(purify_u256_try_narrow_u320(narrowed, widened320) != 0);
    assert(purify_cbmc_words_eq(narrowed, value, 4u));

    assert(purify_u256_try_narrow_u512(narrowed, widened512) != 0);
    assert(purify_cbmc_words_eq(narrowed, value, 4u));

    purify_cbmc_nondet_words(noncanonical320, 5u);
    PURIFY_CBMC_ASSUME(noncanonical320[4] != 0);
    assert(purify_u256_try_narrow_u320(narrowed, noncanonical320) == 0);

    purify_cbmc_nondet_words(noncanonical512, 8u);
    PURIFY_CBMC_ASSUME(purify_cbmc_any_high_words_nonzero(noncanonical512, 4u, 8u));
    assert(purify_u256_try_narrow_u512(narrowed, noncanonical512) == 0);

    return 0;
}
