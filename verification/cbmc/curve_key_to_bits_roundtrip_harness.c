// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <assert.h>
#include <stddef.h>

#include "common.h"
#include "curve.h"
#include "purify/uint.h"

static int purify_cbmc_decode_key_bits(uint64_t out[4], const int* bits, size_t bit_len) {
    size_t i;

    purify_u256_set_zero(out);
    if (bit_len > 256u) {
        return 0;
    }
    if (bit_len != 0u) {
        if (bits[0] != 0 && bits[0] != 1) {
            return 0;
        }
        if (bits[0] != 0 && purify_u256_try_set_bit(out, 0u) == 0) {
            return 0;
        }
    }
    i = 1u;
    while (i < bit_len) {
        if (bit_len - i >= 3u) {
            const int enc0 = bits[i];
            const int enc1 = bits[i + 1u];
            const int enc2 = bits[i + 2u];
            const int orig2 = enc2 ^ 1;
            const int invert = orig2 == 0 ? 1 : 0;
            const int orig0 = enc0 ^ invert;
            const int orig1 = enc1 ^ invert;

            if ((enc0 & ~1) != 0 || (enc1 & ~1) != 0 || (enc2 & ~1) != 0) {
                return 0;
            }
            if (orig0 != 0 && purify_u256_try_set_bit(out, i) == 0) {
                return 0;
            }
            if (orig1 != 0 && purify_u256_try_set_bit(out, i + 1u) == 0) {
                return 0;
            }
            if (orig2 != 0 && purify_u256_try_set_bit(out, i + 2u) == 0) {
                return 0;
            }
            i += 3u;
        } else {
            size_t j;
            for (j = i; j < bit_len; ++j) {
                if ((bits[j] & ~1) != 0) {
                    return 0;
                }
                if (bits[j] != 0 && purify_u256_try_set_bit(out, j) == 0) {
                    return 0;
                }
            }
            break;
        }
    }
    return purify_u256_try_add_small(out, 1u);
}

int main(void) {
    size_t bit_len;
    uint64_t max_value_u64;
    uint64_t value_u64;
    uint64_t max_value[4];
    uint64_t value[4];
    uint64_t decoded[4];
    int bits[7];
    const size_t out_len = 7u;

    max_value_u64 = 1u + (nondet_uint64_t() % 100u);
    value_u64 = 1u + (nondet_uint64_t() % max_value_u64);
    purify_u256_set_u64(max_value, max_value_u64);
    purify_u256_set_u64(value, value_u64);
    bit_len = purify_u256_bit_length(max_value);

    assert(purify_curve_key_to_bits(bits, out_len, value, max_value) != 0);
    assert(purify_cbmc_decode_key_bits(decoded, bits, bit_len) != 0);
    assert(purify_u256_compare(decoded, value) == 0);

    return 0;
}
