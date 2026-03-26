// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file purify/secp_bridge.h
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
/** @brief Computes the multiplicative inverse of a scalar in constant time. */
void purify_scalar_inverse(purify_scalar* out, const purify_scalar* value);
/** @brief Computes the multiplicative inverse of a scalar. */
void purify_scalar_inverse_var(purify_scalar* out, const purify_scalar* value);
/** @brief Adds two scalars modulo the backend field. */
int purify_scalar_add(purify_scalar* out, const purify_scalar* lhs, const purify_scalar* rhs);
/** @brief Multiplies two scalars modulo the backend field. */
void purify_scalar_mul(purify_scalar* out, const purify_scalar* lhs, const purify_scalar* rhs);
/** @brief Conditionally assigns `src` into `dst` when `flag` is nonzero. */
void purify_scalar_cmov(purify_scalar* dst, const purify_scalar* src, int flag);

/**
 * @brief Computes SHA-256 over a byte string.
 * @param output32 Output digest buffer.
 * @param data Pointer to message bytes, or NULL when data_len is zero.
 * @param data_len Message length in bytes.
 */
void purify_sha256(unsigned char output32[32], const unsigned char *data,
                   size_t data_len);

/**
 * @brief Computes SHA-256 over a set of byte strings.
 * @param output32 Output digest buffer.
 * @param items Array of item pointers. Each item may be NULL only when the
 * corresponding length is zero.
 * @param item_lens Array of item lengths in bytes.
 * @param items_count Number of items in both arrays.
 * @return Nonzero on success, zero on invalid input.
 */
int purify_sha256_many(unsigned char output32[32],
                       const unsigned char *const *items,
                       const size_t *item_lens,
                       size_t items_count);

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

/**
 * @brief Canonicalizes a valid secp256k1 secret key for BIP340 and derives its x-only public key.
 *
 * The input/output `seckey32` buffer is rewritten in place to the even-Y canonical secret scalar
 * corresponding to the returned x-only public key. Returns zero when the input scalar is invalid.
 */
int purify_bip340_key_from_seckey(unsigned char seckey32[32], unsigned char xonly_pubkey32[32]);

/**
 * @brief Canonicalizes a valid secp256k1 nonce scalar for BIP340 and derives its x-only public nonce.
 *
 * The input/output `scalar32` buffer is rewritten in place to the even-Y representative corresponding
 * to the returned x-only public nonce. Returns zero when the input scalar is invalid or zero.
 */
int purify_bip340_nonce_from_scalar(unsigned char scalar32[32], unsigned char xonly_nonce32[32]);

/**
 * @brief Converts a compressed secp256k1 point into its x-only public key encoding.
 *
 * Returns zero when the point encoding is invalid. When `parity_out` is not null it receives the
 * original point parity as returned by `secp256k1_xonly_pubkey_from_pubkey` (`0` for even Y,
 * `1` for odd Y).
 */
int purify_bip340_xonly_from_point(const unsigned char point33[33], unsigned char xonly32[32], int* parity_out);

/** @brief Returns nonzero when the x-only public key encoding parses successfully. */
int purify_bip340_validate_xonly_pubkey(const unsigned char xonly_pubkey32[32]);

/**
 * @brief Returns nonzero when the 64-byte BIP340 signature has a syntactically valid encoding.
 *
 * This only checks the standalone encoding shape (`r` as a valid x-only point and `s` as a scalar
 * below the curve order). It does not verify the signature against a message or public key.
 */
int purify_bip340_validate_signature(const unsigned char sig64[64]);

/**
 * @brief Signs a message with a caller-supplied BIP340 nonce scalar.
 *
 * `seckey32` must be a valid secp256k1 secret key. `nonce32` must be a non-zero canonical nonce
 * scalar whose public point has even Y, for example the output of `purify_bip340_nonce_from_scalar`.
 * Returns zero when any input is invalid.
 */
int purify_bip340_sign_with_fixed_nonce(unsigned char sig64[64],
                                        const unsigned char* msg, size_t msglen,
                                        const unsigned char seckey32[32],
                                        const unsigned char nonce32[32]);

/**
 * @brief Verifies a BIP340 signature against a serialized x-only public key.
 * @return Nonzero when the signature verifies.
 */
int purify_bip340_verify(const unsigned char sig64[64],
                         const unsigned char* msg, size_t msglen,
                         const unsigned char xonly_pubkey32[32]);

#ifdef __cplusplus
}
#endif
