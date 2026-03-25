// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <assert.h>

#include "common.h"
#include "curve_encoding_helpers.h"

int main(void) {
    uint64_t packed[8];
    uint64_t space[8];
    uint64_t z1[4];
    uint64_t z2[4];
    uint64_t repacked[8];

    purify_cbmc_nondet_words(packed, 8u);
    purify_curve_packed_secret_key_space_size(space);
    PURIFY_CBMC_ASSUME(purify_u512_compare(packed, space) < 0);

    assert(purify_curve_unpack_secret(z1, z2, packed) != 0);
    purify_cbmc_encode_secret_value(repacked, z1, z2);
    assert(purify_cbmc_words_eq(repacked, packed, 8u));

    return 0;
}
