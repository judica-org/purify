// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <assert.h>

#include "common.h"
#include "curve_encoding_helpers.h"

int main(void) {
    uint64_t z1[4];
    uint64_t z2[4];
    uint64_t packed_secret[8];
    uint64_t unpacked1[4];
    uint64_t unpacked2[4];

    purify_u256_set_u64(z1, 1u + (nondet_uint64_t() % 54u));
    purify_u256_set_u64(z2, 1u + (nondet_uint64_t() % 53u));

    purify_cbmc_encode_secret_value(packed_secret, z1, z2);
    assert(purify_curve_is_valid_secret_key(packed_secret) != 0);
    assert(purify_curve_unpack_secret(unpacked1, unpacked2, packed_secret) != 0);
    assert(purify_u256_compare(unpacked1, z1) == 0);
    assert(purify_u256_compare(unpacked2, z2) == 0);

    return 0;
}
