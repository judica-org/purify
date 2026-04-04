// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <assert.h>
#include <stddef.h>

#include "common.h"
#include "field.h"

static void purify_cbmc_u64_to_be32(unsigned char out[32], uint64_t value) {
    size_t i;
    for (i = 0; i < 32u; ++i) {
        out[i] = 0u;
    }
    for (i = 0; i < 8u; ++i) {
        out[31u - i] = (unsigned char)(value & 0xffu);
        value >>= 8;
    }
}

int main(void) {
    const uint64_t canonical_value = nondet_uint64_t() % 107u;
    unsigned char canonical_bytes[32];
    unsigned char roundtrip_bytes[32];
    uint64_t canonical_words[4];
    uint64_t roundtrip_words[4];
    purify_fe from_bytes;
    purify_fe from_words;

    purify_cbmc_u64_to_be32(canonical_bytes, canonical_value);
    purify_u256_set_u64(canonical_words, canonical_value);

    assert(purify_fe_set_b32(&from_bytes, canonical_bytes) != 0);
    purify_fe_get_b32(roundtrip_bytes, &from_bytes);
    assert(purify_cbmc_bytes_eq(roundtrip_bytes, canonical_bytes, sizeof(canonical_bytes)));
    purify_fe_get_u256(roundtrip_words, &from_bytes);
    assert(purify_cbmc_words_eq(roundtrip_words, canonical_words, 4u));

    assert(purify_fe_set_u256(&from_words, canonical_words) != 0);
    purify_fe_get_u256(roundtrip_words, &from_words);
    assert(purify_cbmc_words_eq(roundtrip_words, canonical_words, 4u));

    purify_cbmc_u64_to_be32(canonical_bytes, 107u);
    assert(purify_fe_set_b32(&from_bytes, canonical_bytes) == 0);
    assert(purify_fe_set_u256(&from_words, (const uint64_t[4]){UINT64_C(107), 0, 0, 0}) == 0);
    assert(purify_fe_set_u256(&from_words, (const uint64_t[4]){0, UINT64_C(1), 0, 0}) == 0);

    return 0;
}
