// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <assert.h>

#include "common.h"
#include "curve.h"

int main(void) {
    uint64_t x1[4];
    uint64_t x2[4];
    uint64_t unpacked1[4];
    uint64_t unpacked2[4];
    uint64_t packed[8];

    purify_u256_set_u64(x1, nondet_uint64_t() % 107u);
    purify_u256_set_u64(x2, nondet_uint64_t() % 107u);

    purify_curve_pack_public(packed, x1, x2);
    assert(purify_curve_is_valid_public_key(packed) != 0);
    assert(purify_curve_unpack_public(unpacked1, unpacked2, packed) != 0);
    assert(purify_u256_compare(unpacked1, x1) == 0);
    assert(purify_u256_compare(unpacked2, x2) == 0);

    return 0;
}
