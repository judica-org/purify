// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <assert.h>

#include "curve.h"

int main(void) {
    uint64_t half_n1[4];
    uint64_t half_n2[4];
    uint64_t order_n1[4];
    uint64_t order_n2[4];
    uint64_t secret_space[8];
    uint64_t derived_secret_space[8];
    uint64_t public_space[8];
    uint64_t derived_public_space[8];
    uint64_t last_secret[8];
    uint64_t last_public[8];
    uint64_t max_x[4];
    uint64_t unpacked1[4];
    uint64_t unpacked2[4];
    uint64_t packed_max_public[8];
    uint64_t doubled[8];

    purify_curve_half_n1(half_n1);
    purify_curve_half_n2(half_n2);
    purify_curve_order_n1(order_n1);
    purify_curve_order_n2(order_n2);
    purify_curve_packed_secret_key_space_size(secret_space);
    purify_curve_packed_public_key_space_size(public_space);

    purify_u512_widen_u256(doubled, half_n1);
    assert(purify_u512_try_add(doubled, doubled) != 0);
    assert(purify_u512_try_add_small(doubled, 1u) != 0);
    assert(purify_u512_compare(doubled, (const uint64_t[8]){order_n1[0], order_n1[1], order_n1[2], order_n1[3], 0, 0, 0, 0}) == 0);

    purify_u512_widen_u256(doubled, half_n2);
    assert(purify_u512_try_add(doubled, doubled) != 0);
    assert(purify_u512_try_add_small(doubled, 1u) != 0);
    assert(purify_u512_compare(doubled, (const uint64_t[8]){order_n2[0], order_n2[1], order_n2[2], order_n2[3], 0, 0, 0, 0}) == 0);

    purify_u512_multiply_u256(derived_secret_space, half_n1, half_n2);
    assert(purify_u512_compare(derived_secret_space, secret_space) == 0);

    purify_curve_prime_p(max_x);
    purify_u512_multiply_u256(derived_public_space, max_x, max_x);
    assert(purify_u512_compare(derived_public_space, public_space) == 0);

    purify_u256_try_sub(max_x, (const uint64_t[4]){UINT64_C(1), 0, 0, 0});
    purify_curve_pack_public(packed_max_public, max_x, max_x);
    assert(purify_u512_compare(packed_max_public, public_space) < 0);

    for (int i = 0; i < 8; ++i) {
        last_secret[i] = secret_space[i];
        last_public[i] = public_space[i];
    }
    assert(purify_u512_try_sub(last_secret, (const uint64_t[8]){UINT64_C(1), 0, 0, 0, 0, 0, 0, 0}) != 0);
    assert(purify_u512_try_sub(last_public, (const uint64_t[8]){UINT64_C(1), 0, 0, 0, 0, 0, 0, 0}) != 0);

    assert(purify_curve_unpack_secret(unpacked1, unpacked2, last_secret) != 0);
    assert(purify_u256_compare(unpacked1, half_n1) == 0);
    assert(purify_u256_compare(unpacked2, half_n2) == 0);

    assert(purify_curve_unpack_public(unpacked1, unpacked2, last_public) != 0);
    assert(purify_u256_compare(unpacked1, max_x) == 0);
    assert(purify_u256_compare(unpacked2, max_x) == 0);

    assert(purify_curve_is_valid_secret_key(secret_space) == 0);
    assert(purify_curve_is_valid_public_key(public_space) == 0);

    return 0;
}
