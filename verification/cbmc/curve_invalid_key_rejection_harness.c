// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <assert.h>

#include "common.h"
#include "curve.h"

int main(void) {
    uint64_t invalid_secret[8];
    uint64_t invalid_public[8];
    uint64_t secret_space[8];
    uint64_t public_space[8];
    uint64_t first[4];
    uint64_t second[4];

    purify_cbmc_nondet_words(invalid_secret, 8u);
    purify_cbmc_nondet_words(invalid_public, 8u);
    purify_curve_packed_secret_key_space_size(secret_space);
    purify_curve_packed_public_key_space_size(public_space);

    PURIFY_CBMC_ASSUME(purify_u512_compare(invalid_secret, secret_space) >= 0);
    PURIFY_CBMC_ASSUME(purify_u512_compare(invalid_public, public_space) >= 0);

    assert(purify_curve_is_valid_secret_key(invalid_secret) == 0);
    assert(purify_curve_unpack_secret(first, second, invalid_secret) == 0);
    assert(purify_curve_is_valid_public_key(invalid_public) == 0);
    assert(purify_curve_unpack_public(first, second, invalid_public) == 0);

    return 0;
}
