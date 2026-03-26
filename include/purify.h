// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file purify.h
 * @brief Public C core for Purify key validation, key derivation, key generation, and evaluation.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#define PURIFY_SECRET_KEY_BYTES 64u
#define PURIFY_PUBLIC_KEY_BYTES 64u
#define PURIFY_FIELD_ELEMENT_BYTES 32u
#define PURIFY_BIP340_SECRET_KEY_BYTES 32u
#define PURIFY_BIP340_XONLY_PUBKEY_BYTES 32u

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Machine-readable status code returned by the Purify C core. */
typedef enum purify_error_code {
    PURIFY_ERROR_OK = 0,
    PURIFY_ERROR_INVALID_HEX,
    PURIFY_ERROR_INVALID_HEX_LENGTH,
    PURIFY_ERROR_INVALID_FIXED_SIZE,
    PURIFY_ERROR_OVERFLOW,
    PURIFY_ERROR_UNDERFLOW,
    PURIFY_ERROR_NARROWING_OVERFLOW,
    PURIFY_ERROR_DIVISION_BY_ZERO,
    PURIFY_ERROR_BIT_INDEX_OUT_OF_RANGE,
    PURIFY_ERROR_RANGE_VIOLATION,
    PURIFY_ERROR_EMPTY_INPUT,
    PURIFY_ERROR_SIZE_MISMATCH,
    PURIFY_ERROR_MISSING_VALUE,
    PURIFY_ERROR_INVALID_SYMBOL,
    PURIFY_ERROR_UNSUPPORTED_SYMBOL,
    PURIFY_ERROR_UNINITIALIZED_STATE,
    PURIFY_ERROR_INDEX_OUT_OF_RANGE,
    PURIFY_ERROR_INVALID_DIMENSIONS,
    PURIFY_ERROR_NON_BOOLEAN_VALUE,
    PURIFY_ERROR_EQUATION_MISMATCH,
    PURIFY_ERROR_BINDING_MISMATCH,
    PURIFY_ERROR_IO_OPEN_FAILED,
    PURIFY_ERROR_IO_WRITE_FAILED,
    PURIFY_ERROR_ENTROPY_UNAVAILABLE,
    PURIFY_ERROR_BACKEND_REJECTED_INPUT,
    PURIFY_ERROR_HASH_TO_CURVE_EXHAUSTED,
    PURIFY_ERROR_UNEXPECTED_SIZE,
    PURIFY_ERROR_GENERATOR_ORDER_CHECK_FAILED,
    PURIFY_ERROR_INTERNAL_MISMATCH,
    PURIFY_ERROR_TRANSCRIPT_CHECK_FAILED,
} purify_error_code;

/** @brief Seed/public-key bundle returned by the C core key-generation entry points. */
typedef struct purify_generated_key {
    unsigned char secret_key[PURIFY_SECRET_KEY_BYTES];
    unsigned char public_key[PURIFY_PUBLIC_KEY_BYTES];
} purify_generated_key;

/** @brief Canonical BIP340 keypair derived from one packed Purify secret. */
typedef struct purify_bip340_key {
    unsigned char secret_key[PURIFY_BIP340_SECRET_KEY_BYTES];
    unsigned char xonly_public_key[PURIFY_BIP340_XONLY_PUBKEY_BYTES];
} purify_bip340_key;

/** @brief Returns a stable programmatic name for one status code. */
const char* purify_error_name(purify_error_code code);

/** @brief Returns a human-facing description for one status code. */
const char* purify_error_message(purify_error_code code);

/**
 * @brief Fills a caller-owned buffer with secure operating-system randomness.
 * @param bytes Buffer to fill. May be `NULL` only when `bytes_len == 0`.
 * @param bytes_len Buffer length in bytes.
 * @return `PURIFY_ERROR_OK` on success.
 */
purify_error_code purify_fill_secure_random(unsigned char* bytes, size_t bytes_len);

/**
 * @brief Validates one packed Purify secret key.
 * @param secret_key 64-byte packed Purify secret.
 * @return `PURIFY_ERROR_OK` when the packed secret is canonical.
 */
purify_error_code purify_validate_secret_key(const unsigned char secret_key[PURIFY_SECRET_KEY_BYTES]);

/**
 * @brief Validates one packed Purify public key.
 * @param public_key 64-byte packed Purify public key.
 * @return `PURIFY_ERROR_OK` when the packed public key is canonical.
 */
purify_error_code purify_validate_public_key(const unsigned char public_key[PURIFY_PUBLIC_KEY_BYTES]);

/**
 * @brief Generates one random Purify keypair.
 * @param out Output bundle.
 * @return `PURIFY_ERROR_OK` on success.
 */
purify_error_code purify_generate_key(purify_generated_key* out);

/**
 * @brief Deterministically derives one Purify keypair from seed material.
 * @param out Output bundle.
 * @param seed Seed bytes. May be `NULL` only when `seed_len == 0`.
 * @param seed_len Seed length in bytes. Values shorter than 16 bytes are rejected.
 * Aliasing: supported when `seed` points anywhere inside `out`.
 * @return `PURIFY_ERROR_OK` on success.
 */
purify_error_code purify_generate_key_from_seed(purify_generated_key* out, const unsigned char* seed, size_t seed_len);

/**
 * @brief Derives the packed public key corresponding to one packed Purify secret.
 * @param out_public_key Output 64-byte packed Purify public key.
 * @param secret_key Input 64-byte packed Purify secret.
 * Aliasing: supported when `out_public_key` overlaps `secret_key`.
 * @return `PURIFY_ERROR_OK` on success.
 */
purify_error_code purify_derive_public_key(unsigned char out_public_key[PURIFY_PUBLIC_KEY_BYTES],
                                           const unsigned char secret_key[PURIFY_SECRET_KEY_BYTES]);

/**
 * @brief Derives one canonical BIP340 keypair from one packed Purify secret.
 * @param out Output BIP340 keypair.
 * @param secret_key Input 64-byte packed Purify secret.
 * Aliasing: supported when `out` overlaps `secret_key`.
 * @return `PURIFY_ERROR_OK` on success.
 */
purify_error_code purify_derive_bip340_key(purify_bip340_key* out,
                                           const unsigned char secret_key[PURIFY_SECRET_KEY_BYTES]);

/**
 * @brief Evaluates the Purify PRF for one packed secret and message.
 * @param out_field_element Output 32-byte big-endian field element.
 * @param secret_key Input 64-byte packed Purify secret.
 * @param message Message bytes. May be `NULL` only when `message_len == 0`.
 * @param message_len Message length in bytes.
 * Aliasing: supported when `out_field_element` overlaps `secret_key` and/or `message`.
 * @return `PURIFY_ERROR_OK` on success.
 */
purify_error_code purify_eval(unsigned char out_field_element[PURIFY_FIELD_ELEMENT_BYTES],
                              const unsigned char secret_key[PURIFY_SECRET_KEY_BYTES],
                              const unsigned char* message,
                              size_t message_len);

#ifdef __cplusplus
}
#endif
