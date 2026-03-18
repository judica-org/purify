// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct purify_scalar {
    uint64_t words[4];
} purify_scalar;

void purify_scalar_set_int(purify_scalar* out, unsigned int value);
void purify_scalar_set_u64(purify_scalar* out, uint64_t value);
void purify_scalar_set_b32(purify_scalar* out, const unsigned char input32[32], int* overflow);
void purify_scalar_get_b32(unsigned char output32[32], const purify_scalar* value);

int purify_scalar_is_zero(const purify_scalar* value);
int purify_scalar_is_one(const purify_scalar* value);
int purify_scalar_is_even(const purify_scalar* value);
int purify_scalar_eq(const purify_scalar* lhs, const purify_scalar* rhs);

void purify_scalar_negate(purify_scalar* out, const purify_scalar* value);
void purify_scalar_inverse_var(purify_scalar* out, const purify_scalar* value);
int purify_scalar_add(purify_scalar* out, const purify_scalar* lhs, const purify_scalar* rhs);
void purify_scalar_mul(purify_scalar* out, const purify_scalar* lhs, const purify_scalar* rhs);

void purify_hmac_sha256(unsigned char output32[32],
                        const unsigned char* key, size_t key_len,
                        const unsigned char* data, size_t data_len);

#ifdef __cplusplus
}
#endif
