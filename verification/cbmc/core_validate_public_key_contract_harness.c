// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <assert.h>

#include "common.h"
#include "core_validation_helpers.h"

int main(void) {
    unsigned char candidate[PURIFY_PUBLIC_KEY_BYTES];
    unsigned char below[PURIFY_PUBLIC_KEY_BYTES];
    unsigned char at[PURIFY_PUBLIC_KEY_BYTES];
    unsigned char above[PURIFY_PUBLIC_KEY_BYTES];

    purify_cbmc_nondet_bytes(candidate, PURIFY_PUBLIC_KEY_BYTES);
    if (purify_cbmc_compare_be(candidate, kPurifyCbmcPackedPublicKeySpaceSize, PURIFY_PUBLIC_KEY_BYTES) < 0) {
        assert(purify_validate_public_key(candidate) == PURIFY_ERROR_OK);
    } else {
        assert(purify_validate_public_key(candidate) == PURIFY_ERROR_RANGE_VIOLATION);
    }

    assert(purify_validate_public_key(NULL) == PURIFY_ERROR_MISSING_VALUE);

    purify_cbmc_copy_bytes(below, kPurifyCbmcPackedPublicKeySpaceSize, PURIFY_PUBLIC_KEY_BYTES);
    assert(purify_cbmc_decrement_be(below, PURIFY_PUBLIC_KEY_BYTES) != 0);
    assert(purify_validate_public_key(below) == PURIFY_ERROR_OK);

    purify_cbmc_copy_bytes(at, kPurifyCbmcPackedPublicKeySpaceSize, PURIFY_PUBLIC_KEY_BYTES);
    assert(purify_validate_public_key(at) == PURIFY_ERROR_RANGE_VIOLATION);

    purify_cbmc_copy_bytes(above, kPurifyCbmcPackedPublicKeySpaceSize, PURIFY_PUBLIC_KEY_BYTES);
    assert(purify_cbmc_increment_be(above, PURIFY_PUBLIC_KEY_BYTES) != 0);
    assert(purify_validate_public_key(above) == PURIFY_ERROR_RANGE_VIOLATION);

    return 0;
}
