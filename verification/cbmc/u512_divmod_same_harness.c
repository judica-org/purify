// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <assert.h>
#include <string.h>

#include "common.h"
#include "purify/uint.h"

static int purify_cbmc_reconstruct_divmod(uint64_t out[8], const uint64_t quotient[8],
                                          const uint64_t denominator[8], const uint64_t remainder[8]) {
    size_t i;

    memcpy(out, remainder, 8u * sizeof(uint64_t));
    for (i = 0; i < 512u; ++i) {
        if (purify_u512_bit(quotient, i) != 0) {
            uint64_t shifted[8];
            purify_u512_shifted_left(shifted, denominator, i);
            if (purify_u512_try_add(out, shifted) == 0) {
                return 0;
            }
        }
    }

    return 1;
}

int main(void) {
    uint64_t numerator[8];
    uint64_t denominator[8];
    uint64_t quotient[8];
    uint64_t remainder[8];
    uint64_t reconstructed[8];

    purify_cbmc_nondet_words(numerator, 8u);
    purify_cbmc_nondet_words(denominator, 8u);
    PURIFY_CBMC_ASSUME(!purify_u512_is_zero(denominator));

    assert(purify_u512_try_divmod_same(quotient, remainder, numerator, denominator) != 0);
    assert(purify_u512_compare(remainder, denominator) < 0);
    assert(purify_cbmc_reconstruct_divmod(reconstructed, quotient, denominator, remainder) != 0);
    assert(purify_cbmc_words_eq(reconstructed, numerator, 8u));

    return 0;
}
