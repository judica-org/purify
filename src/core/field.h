// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include <stdint.h>

#include "purify/uint.h"
#include "purify/secp_bridge.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct purify_fe {
    purify_scalar value;
} purify_fe;

void purify_fe_set_zero(purify_fe* out);
void purify_fe_set_u64(purify_fe* out, uint64_t value);
void purify_fe_set_i64(purify_fe* out, int64_t value);
int purify_fe_set_b32(purify_fe* out, const unsigned char input32[32]);
int purify_fe_set_u256(purify_fe* out, const uint64_t value[4]);
void purify_fe_get_b32(unsigned char output32[32], const purify_fe* value);
void purify_fe_get_u256(uint64_t out[4], const purify_fe* value);

int purify_fe_is_zero(const purify_fe* value);
int purify_fe_is_one(const purify_fe* value);
int purify_fe_is_odd(const purify_fe* value);
int purify_fe_eq(const purify_fe* lhs, const purify_fe* rhs);

void purify_fe_negate(purify_fe* out, const purify_fe* value);
void purify_fe_cmov(purify_fe* dst, const purify_fe* src, int flag);
void purify_fe_inverse(purify_fe* out, const purify_fe* value);
void purify_fe_inverse_var(purify_fe* out, const purify_fe* value);
void purify_fe_add(purify_fe* out, const purify_fe* lhs, const purify_fe* rhs);
void purify_fe_sub(purify_fe* out, const purify_fe* lhs, const purify_fe* rhs);
void purify_fe_mul(purify_fe* out, const purify_fe* lhs, const purify_fe* rhs);
void purify_fe_square(purify_fe* out, const purify_fe* value);
void purify_fe_pow(purify_fe* out, const purify_fe* value, const uint64_t exponent[4]);

int purify_fe_is_square(const purify_fe* value);
int purify_fe_legendre_symbol(const purify_fe* value);
int purify_fe_sqrt(purify_fe* out, const purify_fe* value);

#ifdef __cplusplus
}
#endif
