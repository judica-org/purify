// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <assert.h>

#include "common.h"
#include "purify/uint.h"

int main(void) {
    unsigned char input[32];
    unsigned char encoded[32];
    uint64_t value[4];
    uint64_t reparsed[4];

    purify_cbmc_nondet_bytes(input, sizeof(input));

    purify_u256_from_bytes_be(value, input, sizeof(input));
    purify_u256_to_bytes_be(encoded, value);
    purify_u256_from_bytes_be(reparsed, encoded, sizeof(encoded));

    assert(purify_cbmc_bytes_eq(encoded, input, sizeof(input)));
    assert(purify_cbmc_words_eq(value, reparsed, 4u));
    return 0;
}
