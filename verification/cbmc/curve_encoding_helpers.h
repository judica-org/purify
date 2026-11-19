// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include <assert.h>
#include <string.h>

#include "curve.h"

static inline void purify_cbmc_encode_secret_value(uint64_t out[8], const uint64_t z1[4], const uint64_t z2[4]) {
    uint64_t half_n1[4];
    uint64_t lhs[4];
    uint64_t rhs[4];
    uint64_t wide_lhs[8];

    purify_curve_half_n1(half_n1);
    memcpy(lhs, z1, sizeof(lhs));
    memcpy(rhs, z2, sizeof(rhs));
    assert(purify_u256_try_sub(lhs, (const uint64_t[4]){UINT64_C(1), 0, 0, 0}) != 0);
    assert(purify_u256_try_sub(rhs, (const uint64_t[4]){UINT64_C(1), 0, 0, 0}) != 0);
    purify_u512_multiply_u256(out, half_n1, rhs);
    purify_u512_widen_u256(wide_lhs, lhs);
    assert(purify_u512_try_add(out, wide_lhs) != 0);
}
