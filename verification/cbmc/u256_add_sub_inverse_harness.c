// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <assert.h>
#include <string.h>

#include "common.h"
#include "purify/uint.h"

int main(void) {
    uint64_t value[4];
    uint64_t addend[4];
    uint64_t original[4];
    uint64_t mutated[4];

    purify_cbmc_nondet_words(value, 4u);
    purify_cbmc_nondet_words(addend, 4u);
    memcpy(original, value, sizeof(original));

    memcpy(mutated, value, sizeof(mutated));
    if (purify_u256_try_add(mutated, addend) != 0) {
        assert(purify_u256_try_sub(mutated, addend) != 0);
        assert(purify_cbmc_words_eq(mutated, original, 4u));
    }

    memcpy(mutated, value, sizeof(mutated));
    if (purify_u256_try_sub(mutated, addend) != 0) {
        assert(purify_u256_try_add(mutated, addend) != 0);
        assert(purify_cbmc_words_eq(mutated, original, 4u));
    }

    return 0;
}
