// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <assert.h>

#include "common.h"
#include "purify/uint.h"

int main(void) {
    uint64_t value[4];
    uint64_t shifted[4];
    uint64_t roundtrip[4];
    size_t shift = nondet_size_t();

    purify_cbmc_nondet_words(value, 4u);

    PURIFY_CBMC_ASSUME(shift < 256u);
    PURIFY_CBMC_ASSUME(purify_cbmc_u256_shift_left_is_lossless(value, shift));

    purify_u256_shifted_left(shifted, value, shift);
    purify_u256_shifted_right(roundtrip, shifted, shift);

    assert(purify_cbmc_words_eq(value, roundtrip, 4u));
    return 0;
}
