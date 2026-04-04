// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "purify/secp_bridge.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "verification/cbmc/model_small_field_constants.h"

static uint64_t purify_cbmc_modulus(void) {
    return PURIFY_CBMC_MODEL_FIELD_PRIME_U64;
}

static void purify_cbmc_scalar_store(purify_scalar* out, uint64_t value) {
    out->words[0] = value % purify_cbmc_modulus();
    out->words[1] = 0;
    out->words[2] = 0;
    out->words[3] = 0;
}

static uint64_t purify_cbmc_scalar_load(const purify_scalar* value) {
    return value->words[0] % purify_cbmc_modulus();
}

void purify_scalar_set_int(purify_scalar* out, unsigned int value) {
    purify_cbmc_scalar_store(out, value);
}

void purify_scalar_set_u64(purify_scalar* out, uint64_t value) {
    purify_cbmc_scalar_store(out, value);
}

void purify_scalar_set_b32(purify_scalar* out, const unsigned char input32[32], int* overflow) {
    uint64_t value = 0;
    size_t i;

    *overflow = 0;
    for (i = 0; i < 24u; ++i) {
        if (input32[i] != 0) {
            *overflow = 1;
            purify_cbmc_scalar_store(out, 0);
            return;
        }
    }

    for (i = 24u; i < 32u; ++i) {
        value = (value << 8) | (uint64_t)input32[i];
    }

    if (value >= purify_cbmc_modulus()) {
        *overflow = 1;
        purify_cbmc_scalar_store(out, 0);
        return;
    }

    purify_cbmc_scalar_store(out, value);
}

void purify_scalar_get_b32(unsigned char output32[32], const purify_scalar* value) {
    uint64_t input = purify_cbmc_scalar_load(value);
    size_t i;

    memset(output32, 0, 32u);
    for (i = 0; i < 8u; ++i) {
        output32[31u - i] = (unsigned char)(input & 0xffu);
        input >>= 8;
    }
}

int purify_scalar_is_zero(const purify_scalar* value) {
    return purify_cbmc_scalar_load(value) == 0;
}

int purify_scalar_is_one(const purify_scalar* value) {
    return purify_cbmc_scalar_load(value) == 1u;
}

int purify_scalar_is_even(const purify_scalar* value) {
    return (purify_cbmc_scalar_load(value) & 1u) == 0;
}

int purify_scalar_eq(const purify_scalar* lhs, const purify_scalar* rhs) {
    return purify_cbmc_scalar_load(lhs) == purify_cbmc_scalar_load(rhs);
}

void purify_scalar_negate(purify_scalar* out, const purify_scalar* value) {
    const uint64_t input = purify_cbmc_scalar_load(value);
    if (input == 0) {
        purify_cbmc_scalar_store(out, 0);
        return;
    }
    purify_cbmc_scalar_store(out, purify_cbmc_modulus() - input);
}

static uint64_t purify_cbmc_mod_inverse(uint64_t value) {
    uint64_t candidate;
    const uint64_t modulus = purify_cbmc_modulus();

    if (value == 0) {
        return 0;
    }

    for (candidate = 1; candidate < modulus; ++candidate) {
        if ((candidate * value) % modulus == 1u) {
            return candidate;
        }
    }

    return 0;
}

void purify_scalar_inverse(purify_scalar* out, const purify_scalar* value) {
    purify_cbmc_scalar_store(out, purify_cbmc_mod_inverse(purify_cbmc_scalar_load(value)));
}

void purify_scalar_inverse_var(purify_scalar* out, const purify_scalar* value) {
    purify_scalar_inverse(out, value);
}

int purify_scalar_add(purify_scalar* out, const purify_scalar* lhs, const purify_scalar* rhs) {
    purify_cbmc_scalar_store(out, purify_cbmc_scalar_load(lhs) + purify_cbmc_scalar_load(rhs));
    return 0;
}

void purify_scalar_mul(purify_scalar* out, const purify_scalar* lhs, const purify_scalar* rhs) {
    purify_cbmc_scalar_store(out, purify_cbmc_scalar_load(lhs) * purify_cbmc_scalar_load(rhs));
}

void purify_scalar_cmov(purify_scalar* dst, const purify_scalar* src, int flag) {
    if (flag != 0) {
        *dst = *src;
    }
}

void purify_sha256(unsigned char output32[32], const unsigned char* data, size_t data_len) {
    size_t i;
    unsigned char accum = 0;

    if (data_len != 0u && data != NULL) {
        for (i = 0; i < data_len; ++i) {
            accum = (unsigned char)(accum + data[i] + (unsigned char)i);
        }
    }

    for (i = 0; i < 32u; ++i) {
        output32[i] = (unsigned char)(accum + (unsigned char)i);
    }
}

int purify_sha256_many(unsigned char output32[32],
                       const unsigned char* const* items,
                       const size_t* item_lens,
                       size_t items_count) {
    size_t i;
    size_t j;
    unsigned char accum = 0;

    if ((items_count != 0u) && (items == NULL || item_lens == NULL)) {
        return 0;
    }

    for (i = 0; i < items_count; ++i) {
        if (item_lens[i] != 0u && items[i] == NULL) {
            return 0;
        }
        for (j = 0; j < item_lens[i]; ++j) {
            accum = (unsigned char)(accum + items[i][j] + (unsigned char)(i + j));
        }
    }

    for (i = 0; i < 32u; ++i) {
        output32[i] = (unsigned char)(accum + (unsigned char)(31u - i));
    }

    return 1;
}

void purify_hmac_sha256(unsigned char output32[32],
                        const unsigned char* key, size_t key_len,
                        const unsigned char* data, size_t data_len) {
    size_t i;
    unsigned char accum = 0;

    if (key_len != 0u && key != NULL) {
        for (i = 0; i < key_len; ++i) {
            accum = (unsigned char)(accum + key[i] + (unsigned char)(i * 3u));
        }
    }
    if (data_len != 0u && data != NULL) {
        for (i = 0; i < data_len; ++i) {
            accum = (unsigned char)(accum + data[i] + (unsigned char)(i * 5u));
        }
    }

    for (i = 0; i < 32u; ++i) {
        output32[i] = (unsigned char)(accum ^ (unsigned char)(i * 7u));
    }
}
