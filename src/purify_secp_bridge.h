// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file purify_secp_bridge.h
 * @brief Narrow C ABI exposing secp256k1 scalar and HMAC helpers to the C++ headers.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Opaque scalar storage compatible with secp256k1-zkp internal scalar storage. */
typedef struct purify_scalar {
    uint64_t words[4];
} purify_scalar;

/** @brief Initializes a scalar from an unsigned integer. */
void purify_scalar_set_int(purify_scalar* out, unsigned int value);
/** @brief Initializes a scalar from a 64-bit unsigned integer. */
void purify_scalar_set_u64(purify_scalar* out, uint64_t value);
/** @brief Parses a big-endian 32-byte scalar. */
void purify_scalar_set_b32(purify_scalar* out, const unsigned char input32[32], int* overflow);
/** @brief Serializes a scalar as 32 big-endian bytes. */
void purify_scalar_get_b32(unsigned char output32[32], const purify_scalar* value);

/** @brief Returns nonzero when the scalar is zero. */
int purify_scalar_is_zero(const purify_scalar* value);
/** @brief Returns nonzero when the scalar is one. */
int purify_scalar_is_one(const purify_scalar* value);
/** @brief Returns nonzero when the scalar is even. */
int purify_scalar_is_even(const purify_scalar* value);
/** @brief Returns nonzero when two scalars are equal. */
int purify_scalar_eq(const purify_scalar* lhs, const purify_scalar* rhs);

/** @brief Computes the additive inverse of a scalar. */
void purify_scalar_negate(purify_scalar* out, const purify_scalar* value);
/** @brief Computes the multiplicative inverse of a scalar. */
void purify_scalar_inverse_var(purify_scalar* out, const purify_scalar* value);
/** @brief Adds two scalars modulo the backend field. */
int purify_scalar_add(purify_scalar* out, const purify_scalar* lhs, const purify_scalar* rhs);
/** @brief Multiplies two scalars modulo the backend field. */
void purify_scalar_mul(purify_scalar* out, const purify_scalar* lhs, const purify_scalar* rhs);

/**
 * @brief Computes HMAC-SHA256 over a byte string.
 * @param output32 Output MAC buffer.
 * @param key Pointer to key bytes, or NULL when key_len is zero.
 * @param key_len Key length in bytes.
 * @param data Pointer to message bytes, or NULL when data_len is zero.
 * @param data_len Message length in bytes.
 */
void purify_hmac_sha256(unsigned char output32[32],
                        const unsigned char* key, size_t key_len,
                        const unsigned char* data, size_t data_len);

#ifdef __cplusplus
}
#endif
