// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "purify_core.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "purify_secp_bridge.h"

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>
#elif defined(__linux__)
#include <errno.h>
#include <sys/random.h>
#include <unistd.h>
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <unistd.h>
#else
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#endif

static const unsigned char kPackedSecretKeySpaceSize[PURIFY_SECRET_KEY_BYTES] = {
    0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d,
    0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
    0xb2, 0x92, 0x66, 0xf8, 0xfd, 0xd3, 0x36, 0x23,
    0x17, 0x0b, 0xa9, 0x62, 0x08, 0xc6, 0x3e, 0x47,
    0x58, 0xfb, 0xa2, 0xd2, 0xca, 0xf0, 0xc1, 0x8d,
    0xc4, 0x8a, 0xf1, 0x1c, 0xeb, 0xe3, 0xf4, 0x64,
};

static const unsigned char kPackedPublicKeySpaceSize[PURIFY_PUBLIC_KEY_BYTES] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfd,
    0x75, 0x5d, 0xb9, 0xcd, 0x5e, 0x91, 0x40, 0x77,
    0x7f, 0xa4, 0xbd, 0x19, 0xa0, 0x6c, 0x82, 0x83,
    0x9d, 0x67, 0x1c, 0xd5, 0x81, 0xc6, 0x9b, 0xc5,
    0xe6, 0x97, 0xf5, 0xe4, 0x5b, 0xcd, 0x07, 0xc5,
    0x2e, 0xc3, 0x73, 0xa8, 0xbd, 0xc5, 0x98, 0xb4,
    0x49, 0x3f, 0x50, 0xa1, 0x38, 0x0e, 0x12, 0x81,
};

static const char* const kErrorNames[] = {
    "ok",
    "invalid_hex",
    "invalid_hex_length",
    "invalid_fixed_size",
    "overflow",
    "underflow",
    "narrowing_overflow",
    "division_by_zero",
    "bit_index_out_of_range",
    "range_violation",
    "empty_input",
    "size_mismatch",
    "missing_value",
    "invalid_symbol",
    "unsupported_symbol",
    "uninitialized_state",
    "index_out_of_range",
    "invalid_dimensions",
    "non_boolean_value",
    "equation_mismatch",
    "binding_mismatch",
    "io_open_failed",
    "io_write_failed",
    "entropy_unavailable",
    "backend_rejected_input",
    "hash_to_curve_exhausted",
    "unexpected_size",
    "generator_order_check_failed",
    "internal_mismatch",
    "transcript_check_failed",
};

static const char* const kErrorMessages[] = {
    "success",
    "hex input contains a non-hexadecimal character",
    "hex input has an invalid length",
    "input does not have the required fixed size",
    "operation overflowed the target representation",
    "operation underflowed the target representation",
    "narrowing conversion would discard non-zero bits",
    "division by zero is not permitted",
    "bit index is outside the valid range",
    "input is outside the documented valid range",
    "input must not be empty",
    "related inputs do not have matching sizes",
    "required value is missing",
    "symbol encoding is malformed",
    "symbol is well-formed but not supported",
    "object must be initialized before this operation",
    "index is outside the valid range",
    "inputs imply an invalid shape or dimension",
    "value violates a required boolean constraint",
    "value violates a required equality constraint",
    "prepared state is bound to a different secret, message, or topic",
    "unable to open the requested file or stream",
    "unable to write the requested file or stream",
    "unable to obtain secure operating-system randomness",
    "the cryptographic backend rejected the supplied input",
    "hash-to-curve sampling exhausted all retry attempts",
    "backend returned an unexpected serialized size",
    "fixed generator failed its subgroup order check",
    "internal consistency check failed",
    "internally generated transcript failed validation",
};

static void purify_core_secure_clear(void* data, size_t size) {
    volatile unsigned char* out = (volatile unsigned char*)data;
    while (size != 0) {
        *out = 0;
        ++out;
        --size;
    }
}

static int purify_core_compare_be(const unsigned char* lhs, const unsigned char* rhs, size_t size) {
    size_t i = 0;
    for (i = 0; i < size; ++i) {
        if (lhs[i] < rhs[i]) {
            return -1;
        }
        if (lhs[i] > rhs[i]) {
            return 1;
        }
    }
    return 0;
}

static purify_error_code purify_core_validate_below(const unsigned char* value,
                                                    size_t size,
                                                    const unsigned char* upper_bound) {
    if (value == NULL) {
        return PURIFY_ERROR_MISSING_VALUE;
    }
    if (purify_core_compare_be(value, upper_bound, size) >= 0) {
        return PURIFY_ERROR_RANGE_VIOLATION;
    }
    return PURIFY_ERROR_OK;
}

static purify_error_code purify_core_hkdf_sha256(unsigned char* out,
                                                 size_t out_len,
                                                 const unsigned char* ikm,
                                                 size_t ikm_len,
                                                 const unsigned char* salt,
                                                 size_t salt_len,
                                                 const unsigned char* info,
                                                 size_t info_len) {
    static const unsigned char kZeroSalt[32] = {0};
    unsigned char prk[32];
    unsigned char t[32];
    size_t offset = 0;
    size_t block_index = 0;

    if (out_len != 0 && out == NULL) {
        return PURIFY_ERROR_MISSING_VALUE;
    }
    if (ikm_len != 0 && ikm == NULL) {
        return PURIFY_ERROR_MISSING_VALUE;
    }
    if (salt_len != 0 && salt == NULL) {
        return PURIFY_ERROR_MISSING_VALUE;
    }
    if (info_len != 0 && info == NULL) {
        return PURIFY_ERROR_MISSING_VALUE;
    }

    memset(prk, 0, sizeof(prk));
    memset(t, 0, sizeof(t));
    purify_hmac_sha256(prk,
                       salt_len == 0 ? kZeroSalt : salt,
                       salt_len == 0 ? sizeof(kZeroSalt) : salt_len,
                       ikm,
                       ikm_len);

    while (offset < out_len) {
        const size_t prev_len = block_index == 0 ? 0 : sizeof(t);
        const size_t input_len = prev_len + info_len + 1;
        unsigned char* input = (unsigned char*)malloc(input_len == 0 ? 1 : input_len);
        size_t copy_len;
        if (input == NULL) {
            purify_core_secure_clear(prk, sizeof(prk));
            purify_core_secure_clear(t, sizeof(t));
            return PURIFY_ERROR_INTERNAL_MISMATCH;
        }
        if (prev_len != 0) {
            memcpy(input, t, prev_len);
        }
        if (info_len != 0) {
            memcpy(input + prev_len, info, info_len);
        }
        input[input_len - 1] = (unsigned char)(block_index + 1);
        purify_hmac_sha256(t, prk, sizeof(prk), input, input_len);
        purify_core_secure_clear(input, input_len);
        free(input);

        copy_len = sizeof(t);
        if (copy_len > out_len - offset) {
            copy_len = out_len - offset;
        }
        memcpy(out + offset, t, copy_len);
        offset += copy_len;
        ++block_index;
    }

    purify_core_secure_clear(prk, sizeof(prk));
    purify_core_secure_clear(t, sizeof(t));
    return PURIFY_ERROR_OK;
}

const char* purify_error_name(purify_error_code code) {
    const size_t count = sizeof(kErrorNames) / sizeof(kErrorNames[0]);
    const unsigned int index = (unsigned int)code;
    if (index >= count) {
        return "unknown";
    }
    return kErrorNames[index];
}

const char* purify_error_message(purify_error_code code) {
    const size_t count = sizeof(kErrorMessages) / sizeof(kErrorMessages[0]);
    const unsigned int index = (unsigned int)code;
    if (index >= count) {
        return "unknown status code";
    }
    return kErrorMessages[index];
}

purify_error_code purify_fill_secure_random(unsigned char* bytes, size_t bytes_len) {
    if (bytes_len != 0 && bytes == NULL) {
        return PURIFY_ERROR_MISSING_VALUE;
    }
#if defined(_WIN32)
    while (bytes_len != 0) {
        ULONG chunk = (ULONG)(bytes_len > 0xFFFFFFFFu ? 0xFFFFFFFFu : bytes_len);
        NTSTATUS status = BCryptGenRandom(NULL, bytes, chunk, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (status < 0) {
            return PURIFY_ERROR_ENTROPY_UNAVAILABLE;
        }
        bytes += chunk;
        bytes_len -= chunk;
    }
    return PURIFY_ERROR_OK;
#elif defined(__linux__)
    while (bytes_len != 0) {
        ssize_t written = getrandom(bytes, bytes_len, 0);
        if (written > 0) {
            bytes += (size_t)written;
            bytes_len -= (size_t)written;
            continue;
        }
        if (written < 0 && errno == EINTR) {
            continue;
        }
        return PURIFY_ERROR_ENTROPY_UNAVAILABLE;
    }
    return PURIFY_ERROR_OK;
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
    arc4random_buf(bytes, bytes_len);
    return PURIFY_ERROR_OK;
#else
    FILE* file = fopen("/dev/urandom", "rb");
    size_t read_count;
    if (file == NULL) {
        return PURIFY_ERROR_ENTROPY_UNAVAILABLE;
    }
    read_count = fread(bytes, 1, bytes_len, file);
    fclose(file);
    if (read_count != bytes_len) {
        return PURIFY_ERROR_ENTROPY_UNAVAILABLE;
    }
    return PURIFY_ERROR_OK;
#endif
}

purify_error_code purify_validate_secret_key(const unsigned char secret_key[PURIFY_SECRET_KEY_BYTES]) {
    return purify_core_validate_below(secret_key, PURIFY_SECRET_KEY_BYTES, kPackedSecretKeySpaceSize);
}

purify_error_code purify_validate_public_key(const unsigned char public_key[PURIFY_PUBLIC_KEY_BYTES]) {
    return purify_core_validate_below(public_key, PURIFY_PUBLIC_KEY_BYTES, kPackedPublicKeySpaceSize);
}

purify_error_code purify_core_sample_secret_key(unsigned char out_secret_key[PURIFY_SECRET_KEY_BYTES]) {
    purify_error_code status;
    if (out_secret_key == NULL) {
        return PURIFY_ERROR_MISSING_VALUE;
    }
    memset(out_secret_key, 0, PURIFY_SECRET_KEY_BYTES);
    while (1) {
        status = purify_fill_secure_random(out_secret_key, PURIFY_SECRET_KEY_BYTES);
        if (status != PURIFY_ERROR_OK) {
            purify_core_secure_clear(out_secret_key, PURIFY_SECRET_KEY_BYTES);
            return status;
        }
        out_secret_key[0] &= 0x3f;
        if (purify_core_compare_be(out_secret_key, kPackedSecretKeySpaceSize, PURIFY_SECRET_KEY_BYTES) < 0) {
            return PURIFY_ERROR_OK;
        }
    }
}

purify_error_code purify_core_seed_secret_key(unsigned char out_secret_key[PURIFY_SECRET_KEY_BYTES],
                                              const unsigned char* seed,
                                              size_t seed_len) {
    static const unsigned char kInfo[] = "Purify/KeyGen";
    unsigned char salt[1];
    unsigned int attempt;
    purify_error_code status;

    if (out_secret_key == NULL) {
        return PURIFY_ERROR_MISSING_VALUE;
    }
    memset(out_secret_key, 0, PURIFY_SECRET_KEY_BYTES);
    if (seed_len != 0 && seed == NULL) {
        return PURIFY_ERROR_MISSING_VALUE;
    }
    if (seed_len < 16) {
        return PURIFY_ERROR_RANGE_VIOLATION;
    }

    for (attempt = 0; attempt < 256; ++attempt) {
        salt[0] = (unsigned char)attempt;
        status = purify_core_hkdf_sha256(out_secret_key,
                                         PURIFY_SECRET_KEY_BYTES,
                                         seed,
                                         seed_len,
                                         salt,
                                         sizeof(salt),
                                         kInfo,
                                         sizeof(kInfo) - 1);
        if (status != PURIFY_ERROR_OK) {
            purify_core_secure_clear(out_secret_key, PURIFY_SECRET_KEY_BYTES);
            return status;
        }
        out_secret_key[0] &= 0x3f;
        if (purify_core_compare_be(out_secret_key, kPackedSecretKeySpaceSize, PURIFY_SECRET_KEY_BYTES) < 0) {
            return PURIFY_ERROR_OK;
        }
    }

    purify_core_secure_clear(out_secret_key, PURIFY_SECRET_KEY_BYTES);
    return PURIFY_ERROR_INTERNAL_MISMATCH;
}
