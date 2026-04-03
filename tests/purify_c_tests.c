// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/core/core.h"
#include "../src/core/curve.h"
#include "../src/core/field.h"
#include "purify.h"
#include "purify/secp_bridge.h"
#include "purify/uint.h"

static int failures = 0;

static void expect(int condition, const char* message) {
    if (!condition) {
        ++failures;
        fprintf(stderr, "FAIL: %s\n", message);
    }
}

static void expect_code(int condition, const char* message, int code) {
    if (!condition) {
        ++failures;
        fprintf(stderr, "FAIL: %s (%d)\n", message, code);
    }
}

static int all_zero(const unsigned char* data, size_t len) {
    size_t i;
    for (i = 0; i < len; ++i) {
        if (data[i] != 0) {
            return 0;
        }
    }
    return 1;
}

static void to_hex(char* out, const unsigned char* data, size_t len) {
    static const char kHex[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < len; ++i) {
        out[2 * i] = kHex[data[i] >> 4];
        out[2 * i + 1] = kHex[data[i] & 0x0f];
    }
    out[2 * len] = '\0';
}

typedef struct splitmix64 {
    uint64_t state;
} splitmix64;

#if defined(__clang__)
__attribute__((no_sanitize("unsigned-integer-overflow")))
#endif
static uint64_t splitmix64_next(splitmix64* rng) {
    uint64_t z = (rng->state += UINT64_C(0x9e3779b97f4a7c15));
    z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
    return z ^ (z >> 31);
}

static void splitmix64_fill(splitmix64* rng, unsigned char* out, size_t len) {
    size_t i;
    for (i = 0; i < len; ++i) {
        out[i] = (unsigned char)(splitmix64_next(rng) & 0xffu);
    }
}

static int u256_eq(const uint64_t lhs[4], const uint64_t rhs[4]) {
    return purify_u256_compare(lhs, rhs) == 0;
}

static int u320_eq(const uint64_t lhs[5], const uint64_t rhs[5]) {
    return purify_u320_compare(lhs, rhs) == 0;
}

static int u512_eq(const uint64_t lhs[8], const uint64_t rhs[8]) {
    return purify_u512_compare(lhs, rhs) == 0;
}

static void make_curve1(purify_curve* out) {
    purify_curve_field_a(&out->a);
    purify_curve_field_b(&out->b);
    purify_curve_order_n1(out->n);
}

static void make_curve2(purify_curve* out) {
    purify_fe a;
    purify_fe b;
    purify_fe d;

    purify_curve_field_a(&a);
    purify_curve_field_b(&b);
    purify_curve_field_d(&d);
    purify_fe_mul(&out->a, &a, &d);
    purify_fe_mul(&out->a, &out->a, &d);
    purify_fe_mul(&out->b, &b, &d);
    purify_fe_mul(&out->b, &out->b, &d);
    purify_fe_mul(&out->b, &out->b, &d);
    purify_curve_order_n2(out->n);
}

static void make_generator(purify_jacobian_point* out, const purify_curve* curve, const char* label) {
    const unsigned char* data = (const unsigned char*)label;
    const size_t len = strlen(label);
    const int ok = purify_curve_hash_to_curve(out, curve, data, len);
    expect(ok != 0, "purify_curve_hash_to_curve derives a generator point");
}

static int affine_eq(const purify_affine_point* lhs, const purify_affine_point* rhs) {
    if (lhs->infinity != 0 || rhs->infinity != 0) {
        return lhs->infinity == rhs->infinity;
    }
    return purify_fe_eq(&lhs->x, &rhs->x) != 0 && purify_fe_eq(&lhs->y, &rhs->y) != 0;
}

static int jacobian_eq(const purify_curve* curve, const purify_jacobian_point* lhs, const purify_jacobian_point* rhs) {
    purify_affine_point lhs_affine;
    purify_affine_point rhs_affine;

    if ((lhs->infinity != 0 || purify_fe_is_zero(&lhs->z) != 0) &&
        (rhs->infinity != 0 || purify_fe_is_zero(&rhs->z) != 0)) {
        return 1;
    }

    purify_curve_affine(&lhs_affine, curve, lhs);
    purify_curve_affine(&rhs_affine, curve, rhs);
    return affine_eq(&lhs_affine, &rhs_affine);
}

static int point_on_curve(const purify_curve* curve, const purify_jacobian_point* point) {
    purify_affine_point affine;
    purify_fe lhs;
    purify_fe rhs;
    purify_fe x2;
    purify_fe x3;
    purify_fe ax;

    if (point->infinity != 0 || purify_fe_is_zero(&point->z) != 0) {
        return 1;
    }

    purify_curve_affine(&affine, curve, point);
    purify_fe_mul(&lhs, &affine.y, &affine.y);
    purify_fe_mul(&x2, &affine.x, &affine.x);
    purify_fe_mul(&x3, &x2, &affine.x);
    purify_fe_mul(&ax, &curve->a, &affine.x);
    purify_fe_add(&rhs, &x3, &ax);
    purify_fe_add(&rhs, &rhs, &curve->b);
    return purify_fe_eq(&lhs, &rhs) != 0;
}

static void compute_combine_formula(purify_fe* out, const purify_fe* x1, const purify_fe* x2) {
    purify_fe field_a;
    purify_fe field_b;
    purify_fe field_di;
    purify_fe two;
    purify_fe u;
    purify_fe v;
    purify_fe uv;
    purify_fe u_plus_v;
    purify_fe denom;
    purify_fe w;
    purify_fe numer;
    purify_fe tmp;

    purify_curve_field_a(&field_a);
    purify_curve_field_b(&field_b);
    purify_curve_field_di(&field_di);
    purify_fe_set_u64(&two, 2);

    u = *x1;
    purify_fe_mul(&v, x2, &field_di);
    purify_fe_sub(&denom, &u, &v);
    purify_fe_inverse(&w, &denom);
    purify_fe_add(&u_plus_v, &u, &v);
    purify_fe_mul(&uv, &u, &v);
    purify_fe_add(&tmp, &field_a, &uv);
    purify_fe_mul(&numer, &u_plus_v, &tmp);
    purify_fe_mul(&tmp, &two, &field_b);
    purify_fe_add(&numer, &numer, &tmp);
    purify_fe_mul(&w, &w, &w);
    purify_fe_mul(out, &numer, &w);
}

static void encode_secret_value(uint64_t out[8], const uint64_t z1[4], const uint64_t z2[4]) {
    uint64_t half_n1[4];
    uint64_t lhs[4];
    uint64_t rhs[4];
    uint64_t wide_lhs[8];

    purify_curve_half_n1(half_n1);
    memcpy(lhs, z1, sizeof(lhs));
    memcpy(rhs, z2, sizeof(rhs));
    expect(purify_u256_try_sub(lhs, (const uint64_t[4]){UINT64_C(1), 0, 0, 0}) != 0,
           "encode_secret_value subtracts one from z1");
    expect(purify_u256_try_sub(rhs, (const uint64_t[4]){UINT64_C(1), 0, 0, 0}) != 0,
           "encode_secret_value subtracts one from z2");
    purify_u512_multiply_u256(out, half_n1, rhs);
    purify_u512_widen_u256(wide_lhs, lhs);
    expect(purify_u512_try_add(out, wide_lhs) != 0, "encode_secret_value combines the mixed-radix limbs");
}

static int decode_key_bits(uint64_t out[4], const int* bits, size_t bit_len) {
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
            int enc0 = bits[i];
            int enc1 = bits[i + 1u];
            int enc2 = bits[i + 2u];
            int orig2 = enc2 ^ 1;
            int invert = orig2 == 0 ? 1 : 0;
            int orig0 = enc0 ^ invert;
            int orig1 = enc1 ^ invert;

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

static int manual_eval_core(unsigned char out32[32],
                            const unsigned char secret_key[PURIFY_SECRET_KEY_BYTES],
                            const unsigned char* message,
                            size_t message_len) {
    purify_curve curve1;
    purify_curve curve2;
    uint64_t packed[8];
    uint64_t secret1[4];
    uint64_t secret2[4];
    purify_jacobian_point m1;
    purify_jacobian_point m2;
    purify_affine_point q1;
    purify_affine_point q2;
    purify_fe combined;
    unsigned char* tagged1;
    unsigned char* tagged2;
    static const char kEvalPrefix1[] = "Eval/1/";
    static const char kEvalPrefix2[] = "Eval/2/";

    if (purify_validate_secret_key(secret_key) != PURIFY_ERROR_OK) {
        return 0;
    }

    tagged1 = (unsigned char*)malloc(sizeof(kEvalPrefix1) - 1u + message_len);
    tagged2 = (unsigned char*)malloc(sizeof(kEvalPrefix2) - 1u + message_len);
    if (tagged1 == NULL || tagged2 == NULL) {
        free(tagged1);
        free(tagged2);
        return 0;
    }

    memcpy(tagged1, kEvalPrefix1, sizeof(kEvalPrefix1) - 1u);
    memcpy(tagged2, kEvalPrefix2, sizeof(kEvalPrefix2) - 1u);
    if (message_len != 0u) {
        memcpy(tagged1 + sizeof(kEvalPrefix1) - 1u, message, message_len);
        memcpy(tagged2 + sizeof(kEvalPrefix2) - 1u, message, message_len);
    }

    purify_u512_from_bytes_be(packed, secret_key, PURIFY_SECRET_KEY_BYTES);
    if (purify_curve_unpack_secret(secret1, secret2, packed) == 0) {
        free(tagged1);
        free(tagged2);
        return 0;
    }

    make_curve1(&curve1);
    make_curve2(&curve2);
    if (purify_curve_hash_to_curve(&m1, &curve1, tagged1, sizeof(kEvalPrefix1) - 1u + message_len) == 0 ||
        purify_curve_hash_to_curve(&m2, &curve2, tagged2, sizeof(kEvalPrefix2) - 1u + message_len) == 0 ||
        purify_curve_mul_secret_affine(&q1, &curve1, &m1, secret1) == 0 ||
        purify_curve_mul_secret_affine(&q2, &curve2, &m2, secret2) == 0) {
        free(tagged1);
        free(tagged2);
        return 0;
    }

    purify_curve_combine(&combined, &q1.x, &q2.x);
    purify_fe_get_b32(out32, &combined);
    free(tagged1);
    free(tagged2);
    return 1;
}

static void test_error_strings(void) {
    int code;
    for (code = (int)PURIFY_ERROR_OK; code <= (int)PURIFY_ERROR_TRANSCRIPT_CHECK_FAILED; ++code) {
        const char* name = purify_error_name((purify_error_code)code);
        const char* message = purify_error_message((purify_error_code)code);
        expect_code(name != NULL && name[0] != '\0' && strcmp(name, "unknown") != 0,
                    "purify_error_name returns a stable string for known codes", code);
        expect_code(message != NULL && message[0] != '\0' && strcmp(message, "unknown status code") != 0,
                    "purify_error_message returns a stable string for known codes", code);
    }

    expect(strcmp(purify_error_name((purify_error_code)9999), "unknown") == 0,
           "purify_error_name uses the unknown fallback for out-of-range codes");
    expect(strcmp(purify_error_message((purify_error_code)9999), "unknown status code") == 0,
           "purify_error_message uses the unknown fallback for out-of-range codes");
}

static void test_secure_random(void) {
    unsigned char random_a[32];
    unsigned char random_b[32];

    expect(purify_fill_secure_random(NULL, 0) == PURIFY_ERROR_OK,
           "purify_fill_secure_random accepts a null zero-length buffer");
    expect(purify_fill_secure_random(NULL, 1) == PURIFY_ERROR_MISSING_VALUE,
           "purify_fill_secure_random rejects a null non-empty buffer");
    expect(purify_fill_secure_random(random_a, sizeof(random_a)) == PURIFY_ERROR_OK,
           "purify_fill_secure_random succeeds");
    expect(purify_fill_secure_random(random_b, sizeof(random_b)) == PURIFY_ERROR_OK,
           "purify_fill_secure_random succeeds twice");
    expect(!all_zero(random_a, sizeof(random_a)),
           "purify_fill_secure_random produces non-zero output for one sample");
    expect(memcmp(random_a, random_b, sizeof(random_a)) != 0,
           "purify_fill_secure_random produces distinct outputs for two samples");
}

static void test_core_keygen(void) {
    unsigned char secret_a[PURIFY_SECRET_KEY_BYTES];
    unsigned char secret_b[PURIFY_SECRET_KEY_BYTES];
    unsigned char seed[32];
    unsigned char short_seed[15];
    splitmix64 rng = {UINT64_C(0x123456789abcdef0)};

    splitmix64_fill(&rng, seed, sizeof(seed));
    splitmix64_fill(&rng, short_seed, sizeof(short_seed));

    expect(purify_core_sample_secret_key(NULL) == PURIFY_ERROR_MISSING_VALUE,
           "purify_core_sample_secret_key rejects a null output pointer");
    expect(purify_core_sample_secret_key(secret_a) == PURIFY_ERROR_OK,
           "purify_core_sample_secret_key succeeds");
    expect(purify_validate_secret_key(secret_a) == PURIFY_ERROR_OK,
           "purify_core_sample_secret_key returns a canonical packed secret");
    expect(!all_zero(secret_a, sizeof(secret_a)),
           "purify_core_sample_secret_key does not return the all-zero secret");

    expect(purify_core_seed_secret_key(NULL, seed, sizeof(seed)) == PURIFY_ERROR_MISSING_VALUE,
           "purify_core_seed_secret_key rejects a null output pointer");
    expect(purify_core_seed_secret_key(secret_a, NULL, 1) == PURIFY_ERROR_MISSING_VALUE,
           "purify_core_seed_secret_key rejects null non-empty seed material");
    expect(purify_core_seed_secret_key(secret_a, NULL, 0) == PURIFY_ERROR_RANGE_VIOLATION,
           "purify_core_seed_secret_key rejects empty seed material");
    expect(purify_core_seed_secret_key(secret_a, short_seed, sizeof(short_seed)) == PURIFY_ERROR_RANGE_VIOLATION,
           "purify_core_seed_secret_key rejects short seed material");
    expect(purify_core_seed_secret_key(secret_a, seed, sizeof(seed)) == PURIFY_ERROR_OK,
           "purify_core_seed_secret_key succeeds");
    expect(purify_core_seed_secret_key(secret_b, seed, sizeof(seed)) == PURIFY_ERROR_OK,
           "purify_core_seed_secret_key is repeatable");
    expect(memcmp(secret_a, secret_b, sizeof(secret_a)) == 0,
           "purify_core_seed_secret_key is deterministic");
    expect(purify_validate_secret_key(secret_a) == PURIFY_ERROR_OK,
           "purify_core_seed_secret_key returns a canonical packed secret");
}

static void test_uint_core(void) {
    unsigned char bytes32[32];
    unsigned char bytes40[40];
    unsigned char bytes64[64];
    unsigned char roundtrip32[32];
    unsigned char roundtrip40[40];
    unsigned char roundtrip64[64];
    uint64_t value256[4];
    uint64_t other256[4];
    uint64_t tmp256[4];
    uint64_t max256[4];
    uint64_t value320[5];
    uint64_t other320[5];
    uint64_t tmp320[5];
    uint64_t max320[5];
    uint64_t value512[8];
    uint64_t other512[8];
    uint64_t tmp512[8];
    uint64_t max512[8];
    uint64_t wide256_320[5];
    uint64_t wide256_512[8];
    uint64_t quotient[8];
    uint64_t remainder[8];
    uint64_t denominator[8];
    uint64_t numerator[8];
    size_t i;
    uint32_t rem32;
    uint32_t rem40;
    uint32_t rem64;

    for (i = 0; i < sizeof(bytes32); ++i) {
        bytes32[i] = (unsigned char)(i + 1u);
    }
    for (i = 0; i < sizeof(bytes40); ++i) {
        bytes40[i] = (unsigned char)(0x80u + i);
    }
    for (i = 0; i < sizeof(bytes64); ++i) {
        bytes64[i] = (unsigned char)(0x40u + i);
    }

    purify_u256_set_zero(value256);
    expect(purify_u256_is_zero(value256) != 0, "purify_u256_set_zero produces zero");
    expect(purify_u256_bit_length(value256) == 0u,
           "purify_u256_bit_length returns zero for zero");
    purify_u256_set_u64(value256, UINT64_C(0x0123456789abcdef));
    expect(purify_u256_is_zero(value256) == 0, "purify_u256_set_u64 produces a non-zero value");
    purify_u256_to_bytes_be(roundtrip32, value256);
    expect(roundtrip32[24] == 0x01 && roundtrip32[31] == 0xef,
           "purify_u256_to_bytes_be serializes big-endian limbs");
    purify_u256_from_bytes_be(other256, bytes32, sizeof(bytes32));
    purify_u256_to_bytes_be(roundtrip32, other256);
    expect(memcmp(roundtrip32, bytes32, sizeof(bytes32)) == 0,
           "purify_u256_from_bytes_be round-trips through purify_u256_to_bytes_be");
    expect(purify_u256_compare(value256, other256) < 0,
           "purify_u256_compare orders distinct values");
    expect(purify_u256_compare(other256, other256) == 0,
           "purify_u256_compare reports equality");
    purify_u256_set_zero(value256);
    value256[0] = UINT64_MAX;
    expect(purify_u256_try_add_small(value256, 1u) != 0 &&
           value256[0] == 0u && value256[1] == 1u,
           "purify_u256_try_add_small carries across limbs");
    for (i = 0; i < 4u; ++i) {
        max256[i] = UINT64_MAX;
    }
    expect(purify_u256_try_add_small(max256, 1u) == 0,
           "purify_u256_try_add_small reports overflow");
    purify_u256_set_u64(value256, 7u);
    expect(purify_u256_try_mul_small(value256, 9u) != 0, "purify_u256_try_mul_small succeeds in range");
    purify_u256_set_u64(other256, 63u);
    expect(u256_eq(value256, other256), "purify_u256_try_mul_small computes the product");
    for (i = 0; i < 4u; ++i) {
        max256[i] = UINT64_MAX;
    }
    expect(purify_u256_try_mul_small(max256, 2u) == 0,
           "purify_u256_try_mul_small reports overflow");
    purify_u256_set_u64(value256, 5u);
    purify_u256_set_u64(other256, 7u);
    expect(purify_u256_try_add(value256, other256) != 0, "purify_u256_try_add succeeds in range");
    purify_u256_set_u64(tmp256, 12u);
    expect(u256_eq(value256, tmp256), "purify_u256_try_add computes the sum");
    expect(purify_u256_try_sub(value256, other256) != 0, "purify_u256_try_sub succeeds in range");
    purify_u256_set_u64(tmp256, 5u);
    expect(u256_eq(value256, tmp256), "purify_u256_try_sub computes the difference");
    expect(purify_u256_try_sub(value256, other256) == 0,
           "purify_u256_try_sub reports underflow");
    purify_u256_set_zero(value256);
    expect(purify_u256_try_set_bit(value256, 130u) != 0,
           "purify_u256_try_set_bit accepts in-range bit indices");
    expect(purify_u256_bit(value256, 130u) != 0 && purify_u256_bit(value256, 129u) == 0,
           "purify_u256_bit observes set bits");
    expect(purify_u256_bit_length(value256) == 131u,
           "purify_u256_bit_length reports the highest set bit plus one");
    expect(purify_u256_try_set_bit(value256, 256u) == 0,
           "purify_u256_try_set_bit rejects out-of-range indices");
    expect(purify_u256_bit(value256, 256u) == 0,
           "purify_u256_bit returns zero for out-of-range indices");
    purify_u256_set_u64(value256, 1u);
    purify_u256_shifted_left(tmp256, value256, 65u);
    expect(tmp256[0] == 0u && tmp256[1] == 2u,
           "purify_u256_shifted_left shifts across limb boundaries");
    purify_u256_shifted_right(other256, tmp256, 65u);
    expect(u256_eq(other256, value256),
           "purify_u256_shifted_right inverts purify_u256_shifted_left on a sample");
    purify_u256_shift_right_one(tmp256);
    purify_u256_set_zero(other256);
    other256[1] = 1u;
    expect(u256_eq(tmp256, other256),
           "purify_u256_shift_right_one shifts across limb boundaries");
    for (i = 0; i < 4u; ++i) {
        max256[i] = UINT64_MAX;
    }
    purify_u256_mask_bits(max256, 130u);
    expect(max256[0] == UINT64_MAX && max256[1] == UINT64_MAX &&
           max256[2] == 3u && max256[3] == 0u,
           "purify_u256_mask_bits clears bits above the requested width");
    purify_u256_from_bytes_be(value256, bytes32, sizeof(bytes32));
    memcpy(tmp256, value256, sizeof(tmp256));
    rem32 = purify_u256_divmod_small(tmp256, 97u);
    memcpy(other256, tmp256, sizeof(other256));
    expect(purify_u256_try_mul_small(other256, 97u) != 0 &&
           purify_u256_try_add_small(other256, rem32) != 0 &&
           u256_eq(other256, value256),
           "purify_u256_divmod_small preserves quotient * divisor + remainder");

    purify_u320_set_zero(value320);
    expect(purify_u320_is_zero(value320) != 0, "purify_u320_set_zero produces zero");
    expect(purify_u320_bit_length(value320) == 0u,
           "purify_u320_bit_length returns zero for zero");
    purify_u320_set_u64(value320, UINT64_C(0xfedcba9876543210));
    purify_u320_to_bytes_be(roundtrip40, value320);
    expect(roundtrip40[32] == 0xfe && roundtrip40[39] == 0x10,
           "purify_u320_to_bytes_be serializes big-endian limbs");
    purify_u320_from_bytes_be(other320, bytes40, sizeof(bytes40));
    purify_u320_to_bytes_be(roundtrip40, other320);
    expect(memcmp(roundtrip40, bytes40, sizeof(bytes40)) == 0,
           "purify_u320_from_bytes_be round-trips through purify_u320_to_bytes_be");
    purify_u320_set_u64(tmp320, 1u);
    expect(purify_u320_compare(value320, tmp320) > 0,
           "purify_u320_compare orders distinct values");
    purify_u320_set_zero(value320);
    value320[0] = UINT64_MAX;
    expect(purify_u320_try_add_small(value320, 1u) != 0 &&
           value320[0] == 0u && value320[1] == 1u,
           "purify_u320_try_add_small carries across limbs");
    for (i = 0; i < 5u; ++i) {
        max320[i] = UINT64_MAX;
    }
    expect(purify_u320_try_add_small(max320, 1u) == 0,
           "purify_u320_try_add_small reports overflow");
    purify_u320_set_u64(value320, 21u);
    expect(purify_u320_try_mul_small(value320, 11u) != 0, "purify_u320_try_mul_small succeeds in range");
    purify_u320_set_u64(other320, 231u);
    expect(u320_eq(value320, other320), "purify_u320_try_mul_small computes the product");
    for (i = 0; i < 5u; ++i) {
        max320[i] = UINT64_MAX;
    }
    expect(purify_u320_try_mul_small(max320, 2u) == 0,
           "purify_u320_try_mul_small reports overflow");
    purify_u320_set_u64(value320, 33u);
    purify_u320_set_u64(other320, 44u);
    expect(purify_u320_try_add(value320, other320) != 0, "purify_u320_try_add succeeds in range");
    purify_u320_set_u64(tmp320, 77u);
    expect(u320_eq(value320, tmp320), "purify_u320_try_add computes the sum");
    expect(purify_u320_try_sub(value320, other320) != 0, "purify_u320_try_sub succeeds in range");
    purify_u320_set_u64(tmp320, 33u);
    expect(u320_eq(value320, tmp320), "purify_u320_try_sub computes the difference");
    expect(purify_u320_try_sub(value320, other320) == 0,
           "purify_u320_try_sub reports underflow");
    purify_u320_set_zero(value320);
    expect(purify_u320_try_set_bit(value320, 260u) != 0,
           "purify_u320_try_set_bit accepts in-range bit indices");
    expect(purify_u320_bit(value320, 260u) != 0 && purify_u320_bit(value320, 319u) == 0,
           "purify_u320_bit observes set bits");
    expect(purify_u320_bit_length(value320) == 261u,
           "purify_u320_bit_length reports the highest set bit plus one");
    expect(purify_u320_try_set_bit(value320, 320u) == 0,
           "purify_u320_try_set_bit rejects out-of-range indices");
    purify_u320_set_u64(value320, 1u);
    purify_u320_shifted_left(tmp320, value320, 129u);
    expect(tmp320[2] == 2u, "purify_u320_shifted_left shifts across limb boundaries");
    purify_u320_shifted_right(other320, tmp320, 129u);
    expect(u320_eq(other320, value320),
           "purify_u320_shifted_right inverts purify_u320_shifted_left on a sample");
    purify_u320_shift_right_one(tmp320);
    purify_u320_set_zero(other320);
    other320[2] = 1u;
    expect(u320_eq(tmp320, other320),
           "purify_u320_shift_right_one shifts across limb boundaries");
    for (i = 0; i < 5u; ++i) {
        max320[i] = UINT64_MAX;
    }
    purify_u320_mask_bits(max320, 193u);
    expect(max320[0] == UINT64_MAX && max320[1] == UINT64_MAX &&
           max320[2] == UINT64_MAX && max320[3] == 1u && max320[4] == 0u,
           "purify_u320_mask_bits clears bits above the requested width");
    purify_u320_from_bytes_be(value320, bytes40, sizeof(bytes40));
    memcpy(tmp320, value320, sizeof(tmp320));
    rem40 = purify_u320_divmod_small(tmp320, 101u);
    memcpy(other320, tmp320, sizeof(other320));
    expect(purify_u320_try_mul_small(other320, 101u) != 0 &&
           purify_u320_try_add_small(other320, rem40) != 0 &&
           u320_eq(other320, value320),
           "purify_u320_divmod_small preserves quotient * divisor + remainder");
    purify_u256_set_u64(value256, UINT64_C(0xdecafbad));
    purify_u320_widen_u256(wide256_320, value256);
    expect(wide256_320[0] == UINT64_C(0xdecafbad) && wide256_320[4] == 0u,
           "purify_u320_widen_u256 extends a u256 with zero high limbs");
    expect(purify_u256_try_narrow_u320(tmp256, wide256_320) != 0 && u256_eq(tmp256, value256),
           "purify_u256_try_narrow_u320 narrows values that fit");
    wide256_320[4] = 1u;
    expect(purify_u256_try_narrow_u320(tmp256, wide256_320) == 0,
           "purify_u256_try_narrow_u320 rejects values that do not fit");

    purify_u512_set_zero(value512);
    expect(purify_u512_is_zero(value512) != 0, "purify_u512_set_zero produces zero");
    expect(purify_u512_bit_length(value512) == 0u,
           "purify_u512_bit_length returns zero for zero");
    purify_u512_set_u64(value512, UINT64_C(0x0f0e0d0c0b0a0908));
    purify_u512_to_bytes_be(roundtrip64, value512);
    expect(roundtrip64[56] == 0x0f && roundtrip64[63] == 0x08,
           "purify_u512_to_bytes_be serializes big-endian limbs");
    purify_u512_from_bytes_be(other512, bytes64, sizeof(bytes64));
    purify_u512_to_bytes_be(roundtrip64, other512);
    expect(memcmp(roundtrip64, bytes64, sizeof(bytes64)) == 0,
           "purify_u512_from_bytes_be round-trips through purify_u512_to_bytes_be");
    expect(purify_u512_compare(value512, other512) < 0,
           "purify_u512_compare orders distinct values");
    purify_u512_set_zero(value512);
    value512[0] = UINT64_MAX;
    expect(purify_u512_try_add_small(value512, 1u) != 0 &&
           value512[0] == 0u && value512[1] == 1u,
           "purify_u512_try_add_small carries across limbs");
    for (i = 0; i < 8u; ++i) {
        max512[i] = UINT64_MAX;
    }
    expect(purify_u512_try_add_small(max512, 1u) == 0,
           "purify_u512_try_add_small reports overflow");
    purify_u512_set_u64(value512, 17u);
    expect(purify_u512_try_mul_small(value512, 19u) != 0, "purify_u512_try_mul_small succeeds in range");
    purify_u512_set_u64(other512, 323u);
    expect(u512_eq(value512, other512), "purify_u512_try_mul_small computes the product");
    for (i = 0; i < 8u; ++i) {
        max512[i] = UINT64_MAX;
    }
    expect(purify_u512_try_mul_small(max512, 2u) == 0,
           "purify_u512_try_mul_small reports overflow");
    purify_u512_set_u64(value512, 144u);
    purify_u512_set_u64(other512, 55u);
    expect(purify_u512_try_add(value512, other512) != 0, "purify_u512_try_add succeeds in range");
    purify_u512_set_u64(tmp512, 199u);
    expect(u512_eq(value512, tmp512), "purify_u512_try_add computes the sum");
    expect(purify_u512_try_sub(value512, other512) != 0, "purify_u512_try_sub succeeds in range");
    purify_u512_set_u64(tmp512, 144u);
    expect(u512_eq(value512, tmp512), "purify_u512_try_sub computes the difference");
    expect(purify_u512_try_sub(value512, other512) != 0,
           "purify_u512_try_sub handles a second subtraction that stays non-negative");
    purify_u512_set_zero(value512);
    expect(purify_u512_try_set_bit(value512, 511u) != 0,
           "purify_u512_try_set_bit accepts the top in-range bit");
    expect(purify_u512_bit(value512, 511u) != 0 && purify_u512_bit(value512, 512u) == 0,
           "purify_u512_bit observes set bits");
    expect(purify_u512_bit_length(value512) == 512u,
           "purify_u512_bit_length reports the highest set bit plus one");
    expect(purify_u512_try_set_bit(value512, 512u) == 0,
           "purify_u512_try_set_bit rejects out-of-range indices");
    purify_u512_set_u64(value512, 1u);
    purify_u512_shifted_left(tmp512, value512, 257u);
    expect(tmp512[4] == 2u, "purify_u512_shifted_left shifts across limb boundaries");
    purify_u512_shifted_right(other512, tmp512, 257u);
    expect(u512_eq(other512, value512),
           "purify_u512_shifted_right inverts purify_u512_shifted_left on a sample");
    purify_u512_shift_right_one(tmp512);
    purify_u512_set_zero(other512);
    other512[4] = 1u;
    expect(u512_eq(tmp512, other512),
           "purify_u512_shift_right_one shifts across limb boundaries");
    for (i = 0; i < 8u; ++i) {
        max512[i] = UINT64_MAX;
    }
    purify_u512_mask_bits(max512, 321u);
    expect(max512[0] == UINT64_MAX && max512[1] == UINT64_MAX &&
           max512[2] == UINT64_MAX && max512[3] == UINT64_MAX &&
           max512[4] == UINT64_MAX && max512[5] == 1u &&
           max512[6] == 0u && max512[7] == 0u,
           "purify_u512_mask_bits clears bits above the requested width");
    purify_u512_from_bytes_be(value512, bytes64, sizeof(bytes64));
    memcpy(tmp512, value512, sizeof(tmp512));
    rem64 = purify_u512_divmod_small(tmp512, 103u);
    memcpy(other512, tmp512, sizeof(other512));
    expect(purify_u512_try_mul_small(other512, 103u) != 0 &&
           purify_u512_try_add_small(other512, rem64) != 0 &&
           u512_eq(other512, value512),
           "purify_u512_divmod_small preserves quotient * divisor + remainder");
    purify_u256_set_u64(value256, UINT64_C(0x0123456789abcdef));
    purify_u512_widen_u256(wide256_512, value256);
    expect(wide256_512[0] == UINT64_C(0x0123456789abcdef) && wide256_512[7] == 0u,
           "purify_u512_widen_u256 extends a u256 with zero high limbs");
    expect(purify_u256_try_narrow_u512(tmp256, wide256_512) != 0 && u256_eq(tmp256, value256),
           "purify_u256_try_narrow_u512 narrows values that fit");
    wide256_512[7] = 1u;
    expect(purify_u256_try_narrow_u512(tmp256, wide256_512) == 0,
           "purify_u256_try_narrow_u512 rejects values that do not fit");
    purify_u256_set_zero(value256);
    value256[0] = UINT64_MAX;
    purify_u256_set_u64(other256, 2u);
    purify_u512_multiply_u256(value512, value256, other256);
    expect(value512[0] == UINT64_MAX - 1u && value512[1] == 1u,
           "purify_u512_multiply_u256 propagates carry into higher limbs");
    purify_u256_set_u64(value256, 12345u);
    purify_u256_set_u64(other256, 67890u);
    purify_u512_multiply_u256(numerator, value256, other256);
    purify_u256_set_u64(tmp256, 42u);
    purify_u512_widen_u256(wide256_512, tmp256);
    expect(purify_u512_try_add(numerator, wide256_512) != 0,
           "constructing a division sample stays within u512");
    purify_u512_widen_u256(denominator, value256);
    expect(purify_u512_try_divmod_same(quotient, remainder, numerator, denominator) != 0,
           "purify_u512_try_divmod_same divides a constructed sample");
    expect(purify_u512_try_divmod_same_consttime(other512, tmp512, numerator, denominator) != 0 &&
           u512_eq(other512, quotient) && u512_eq(tmp512, remainder),
           "purify_u512_try_divmod_same_consttime matches the standard divider on a sample");
    expect(purify_u256_try_narrow_u512(tmp256, quotient) != 0 && u256_eq(tmp256, other256),
           "purify_u512_try_divmod_same returns the expected quotient");
    expect(purify_u256_try_narrow_u512(tmp256, remainder) != 0,
           "purify_u512_try_divmod_same returns a narrow remainder when expected");
    purify_u256_set_u64(value256, 42u);
    expect(u256_eq(tmp256, value256), "purify_u512_try_divmod_same returns the expected remainder");
    purify_u512_set_u64(numerator, 10u);
    purify_u512_set_u64(denominator, 11u);
    expect(purify_u512_try_divmod_same(quotient, remainder, numerator, denominator) != 0 &&
           purify_u512_is_zero(quotient) != 0 && u512_eq(remainder, numerator),
           "purify_u512_try_divmod_same handles numerator < denominator");
    expect(purify_u512_try_divmod_same_consttime(other512, tmp512, numerator, denominator) != 0 &&
           purify_u512_is_zero(other512) != 0 && u512_eq(tmp512, numerator),
           "purify_u512_try_divmod_same_consttime handles numerator < denominator");
    purify_u512_set_zero(denominator);
    expect(purify_u512_try_divmod_same(quotient, remainder, numerator, denominator) == 0,
           "purify_u512_try_divmod_same rejects division by zero");
    expect(purify_u512_try_divmod_same_consttime(other512, tmp512, numerator, denominator) == 0,
           "purify_u512_try_divmod_same_consttime rejects division by zero");
}

static void test_secp_bridge(void) {
    purify_secp_context* context = purify_secp_context_create();
    purify_scalar scalar_a;
    purify_scalar scalar_b;
    purify_scalar scalar_c;
    purify_scalar scalar_d;
    unsigned char bytes32[32];
    unsigned char digest32[32];
    unsigned char digest_many32[32];
    unsigned char hmac32[32];
    unsigned char seckey32[32] = {0};
    unsigned char xonly32[32];
    unsigned char nonce32[32] = {0};
    unsigned char nonce_pub32[32];
    unsigned char sig64[64];
    int parity = -1;
    static const unsigned char kSha256Abc[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    static const unsigned char kHmacHiThere[32] = {
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
        0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
        0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
        0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,
    };
    static const unsigned char kSecpGeneratorCompressed[33] = {
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb,
        0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
        0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28,
        0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17,
        0x98,
    };
    static const unsigned char kSecpGeneratorXonly[32] = {
        0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac,
        0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
        0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9,
        0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
    };
    static const unsigned char kHmacKey[20] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    };
    static const unsigned char kMsgHiThere[] = "Hi There";
    static const unsigned char kMsgAbc[] = "abc";
    static const unsigned char* kItems[2] = {kMsgAbc, kMsgAbc + 1};
    static const size_t kItemLens[2] = {1u, 2u};
    static const unsigned char kSignMsg[] = "c api bridge sign";

    expect(context != NULL, "purify_secp_context_create returns a reusable bridge context");
    if (context == NULL) {
        return;
    }

    purify_scalar_set_int(&scalar_a, 1u);
    expect(purify_scalar_is_zero(&scalar_a) == 0, "purify_scalar_is_zero rejects one");
    expect(purify_scalar_is_one(&scalar_a) != 0, "purify_scalar_set_int initializes one");
    purify_scalar_get_b32(bytes32, &scalar_a);
    expect(bytes32[31] == 1u && all_zero(bytes32, 31u),
           "purify_scalar_get_b32 serializes one canonically");

    purify_scalar_set_u64(&scalar_b, 2u);
    expect(purify_scalar_is_even(&scalar_b) != 0, "purify_scalar_is_even recognizes even scalars");
    purify_scalar_add(&scalar_c, &scalar_a, &scalar_b);
    expect(purify_scalar_eq(&scalar_c, &scalar_b) == 0, "purify_scalar_eq distinguishes unequal values");
    purify_scalar_get_b32(bytes32, &scalar_c);
    expect(bytes32[31] == 3u, "purify_scalar_add computes one plus two");
    expect(purify_scalar_is_even(&scalar_c) == 0, "purify_scalar_is_even recognizes odd scalars");
    purify_scalar_set_b32(&scalar_d, bytes32, &parity);
    expect(parity == 0 && purify_scalar_eq(&scalar_c, &scalar_d) != 0,
           "purify_scalar_set_b32 parses canonical scalar encodings");
    purify_scalar_set_b32(&scalar_d,
                          (const unsigned char[32]){
                              0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                              0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
                              0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3c,
                              0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x42,
                          },
                          &parity);
    expect(parity != 0, "purify_scalar_set_b32 reports overflow on out-of-range encodings");

    purify_scalar_mul(&scalar_c, &scalar_b, &scalar_b);
    purify_scalar_get_b32(bytes32, &scalar_c);
    expect(bytes32[31] == 4u, "purify_scalar_mul computes two squared");
    purify_scalar_negate(&scalar_d, &scalar_b);
    purify_scalar_add(&scalar_d, &scalar_d, &scalar_b);
    expect(purify_scalar_is_zero(&scalar_d) != 0, "purify_scalar_negate produces an additive inverse");

    purify_scalar_set_u64(&scalar_d, 7u);
    purify_scalar_inverse(&scalar_b, &scalar_d);
    purify_scalar_inverse_var(&scalar_c, &scalar_d);
    purify_scalar_mul(&scalar_b, &scalar_b, &scalar_d);
    purify_scalar_mul(&scalar_c, &scalar_c, &scalar_d);
    expect(purify_scalar_is_one(&scalar_b) != 0, "purify_scalar_inverse produces a multiplicative inverse");
    expect(purify_scalar_is_one(&scalar_c) != 0, "purify_scalar_inverse_var produces a multiplicative inverse");

    purify_scalar_set_u64(&scalar_a, 5u);
    purify_scalar_set_u64(&scalar_b, 9u);
    purify_scalar_cmov(&scalar_a, &scalar_b, 0);
    purify_scalar_get_b32(bytes32, &scalar_a);
    expect(bytes32[31] == 5u, "purify_scalar_cmov keeps the destination when the flag is zero");
    purify_scalar_cmov(&scalar_a, &scalar_b, 1);
    purify_scalar_get_b32(bytes32, &scalar_a);
    expect(bytes32[31] == 9u, "purify_scalar_cmov overwrites the destination when the flag is one");

    purify_sha256(digest32, kMsgAbc, sizeof(kMsgAbc) - 1u);
    expect(memcmp(digest32, kSha256Abc, sizeof(digest32)) == 0,
           "purify_sha256 matches the SHA-256 abc test vector");
    expect(purify_sha256_many(digest_many32, kItems, kItemLens, 2u) != 0,
           "purify_sha256_many accepts valid segmented input");
    expect(memcmp(digest_many32, digest32, sizeof(digest32)) == 0,
           "purify_sha256_many matches purify_sha256 on concatenated input");
    expect(purify_sha256_many(digest_many32, NULL, NULL, 0u) != 0,
           "purify_sha256_many accepts an empty segment list");
    expect(purify_sha256_many(digest_many32,
                              (const unsigned char* const[]){NULL},
                              (const size_t[]){1u},
                              1u) == 0,
           "purify_sha256_many rejects null non-empty segments");

    purify_hmac_sha256(hmac32, kHmacKey, sizeof(kHmacKey), kMsgHiThere, sizeof(kMsgHiThere) - 1u);
    expect(memcmp(hmac32, kHmacHiThere, sizeof(hmac32)) == 0,
           "purify_hmac_sha256 matches the RFC 4231 test vector");

    seckey32[31] = 1u;
    expect(purify_bip340_key_from_seckey(context, seckey32, xonly32) == 1,
           "purify_bip340_key_from_seckey accepts secret key one");
    expect(purify_bip340_validate_xonly_pubkey(context, xonly32) == 1,
           "purify_bip340_key_from_seckey produces a valid x-only public key");
    expect(purify_bip340_validate_xonly_pubkey(context, (const unsigned char[32]){
               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
           }) == 0,
           "purify_bip340_validate_xonly_pubkey rejects out-of-range coordinates");

    memset(xonly32, 0, sizeof(xonly32));
    expect(purify_bip340_xonly_from_point(context, kSecpGeneratorCompressed, xonly32, &parity) == 1,
           "purify_bip340_xonly_from_point parses the compressed secp generator");
    expect(memcmp(xonly32, kSecpGeneratorXonly, sizeof(xonly32)) == 0,
           "purify_bip340_xonly_from_point returns the generator x-coordinate");
    expect(parity == 0, "purify_bip340_xonly_from_point reports the generator parity");

    memset(nonce32, 0, sizeof(nonce32));
    nonce32[31] = 2u;
    expect(purify_bip340_nonce_from_scalar(context, nonce32, nonce_pub32) == 1,
           "purify_bip340_nonce_from_scalar accepts a non-zero scalar");
    expect(purify_bip340_validate_xonly_pubkey(context, nonce_pub32) == 1,
           "purify_bip340_nonce_from_scalar produces a valid x-only public key");

    memset(sig64, 0, sizeof(sig64));
    expect(purify_bip340_sign_with_fixed_nonce(context, sig64, kSignMsg, sizeof(kSignMsg) - 1u, seckey32, nonce32) == 1,
           "purify_bip340_sign_with_fixed_nonce signs with a prepared nonce");
    expect(purify_bip340_validate_signature(context, sig64) == 1,
           "purify_bip340_validate_signature accepts a generated signature");
    expect(purify_bip340_verify(context, sig64, kSignMsg, sizeof(kSignMsg) - 1u, xonly32) == 1,
           "purify_bip340_verify accepts the matching signature");
    sig64[0] ^= 1u;
    expect(purify_bip340_verify(context, sig64, kSignMsg, sizeof(kSignMsg) - 1u, xonly32) == 0,
           "purify_bip340_verify rejects a tampered signature");
    expect(purify_bip340_validate_signature(context, (const unsigned char[64]){0}) == 0,
           "purify_bip340_validate_signature rejects the zero signature");

    purify_secp_context_destroy(context);
}

static void test_public_c_api(void) {
    purify_secp_context* context = purify_secp_context_create();
    unsigned char derived_public_key[PURIFY_PUBLIC_KEY_BYTES];
    unsigned char eval_a[PURIFY_FIELD_ELEMENT_BYTES];
    unsigned char eval_b[PURIFY_FIELD_ELEMENT_BYTES];
    unsigned char eval_manual[PURIFY_FIELD_ELEMENT_BYTES];
    unsigned char invalid_secret[PURIFY_SECRET_KEY_BYTES];
    unsigned char invalid_public[PURIFY_PUBLIC_KEY_BYTES];
    unsigned char zero_secret[PURIFY_SECRET_KEY_BYTES] = {0};
    unsigned char zero_public[PURIFY_PUBLIC_KEY_BYTES] = {0};
    uint64_t secret_space[8];
    uint64_t public_space[8];
    purify_generated_key first = {{0}, {0}};
    purify_generated_key second = {{0}, {0}};
    purify_generated_key random_key = {{0}, {0}};
    purify_bip340_key bip340 = {{0}, {0}};
    char hex[2 * PURIFY_PUBLIC_KEY_BYTES + 1];
    splitmix64 rng = {UINT64_C(0x0f1e2d3c4b5a6978)};
    const unsigned char seed[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    const unsigned char short_seed[8] = {0};
    const unsigned char min_seed[16] = {
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    };
    const unsigned char message[] = "c api smoke";
    const unsigned char other_message[] = "c api smoke?";
    int i;

    expect(context != NULL, "purify_secp_context_create succeeds for the public C API tests");
    if (context == NULL) {
        return;
    }

    purify_curve_packed_secret_key_space_size(secret_space);
    purify_u512_to_bytes_be(invalid_secret, secret_space);
    purify_curve_packed_public_key_space_size(public_space);
    purify_u512_to_bytes_be(invalid_public, public_space);

    expect(purify_validate_secret_key(zero_secret) == PURIFY_ERROR_OK,
           "purify_validate_secret_key accepts the smallest packed secret");
    expect(purify_validate_public_key(zero_public) == PURIFY_ERROR_OK,
           "purify_validate_public_key accepts the smallest packed public key");
    expect(purify_validate_secret_key(NULL) == PURIFY_ERROR_MISSING_VALUE,
           "purify_validate_secret_key rejects null input");
    expect(purify_validate_public_key(NULL) == PURIFY_ERROR_MISSING_VALUE,
           "purify_validate_public_key rejects null input");
    expect(purify_validate_secret_key(invalid_secret) == PURIFY_ERROR_RANGE_VIOLATION,
           "purify_validate_secret_key rejects the exclusive upper bound");
    expect(purify_validate_public_key(invalid_public) == PURIFY_ERROR_RANGE_VIOLATION,
           "purify_validate_public_key rejects the exclusive upper bound");

    expect(purify_generate_key(NULL) == PURIFY_ERROR_MISSING_VALUE,
           "purify_generate_key rejects a null output pointer");
    expect(purify_generate_key(&random_key) == PURIFY_ERROR_OK,
           "purify_generate_key succeeds");
    expect(purify_validate_secret_key(random_key.secret_key) == PURIFY_ERROR_OK,
           "purify_generate_key returns a canonical packed secret");
    expect(purify_validate_public_key(random_key.public_key) == PURIFY_ERROR_OK,
           "purify_generate_key returns a canonical packed public key");
    expect(purify_derive_public_key(derived_public_key, random_key.secret_key) == PURIFY_ERROR_OK,
           "purify_generate_key output derives a public key");
    expect(memcmp(derived_public_key, random_key.public_key, sizeof(derived_public_key)) == 0,
           "purify_generate_key public key matches purify_derive_public_key");

    expect(purify_generate_key_from_seed(NULL, seed, sizeof(seed)) == PURIFY_ERROR_MISSING_VALUE,
           "purify_generate_key_from_seed rejects a null output pointer");
    expect(purify_generate_key_from_seed(&first, NULL, 1) == PURIFY_ERROR_MISSING_VALUE,
           "purify_generate_key_from_seed rejects null non-empty seed material");
    expect(purify_generate_key_from_seed(&first, NULL, 0) == PURIFY_ERROR_RANGE_VIOLATION,
           "purify_generate_key_from_seed rejects empty seed material");
    expect(purify_generate_key_from_seed(&first, short_seed, sizeof(short_seed)) == PURIFY_ERROR_RANGE_VIOLATION,
           "purify_generate_key_from_seed rejects short seed material");
    expect(purify_generate_key_from_seed(&first, seed, sizeof(seed)) == PURIFY_ERROR_OK,
           "purify_generate_key_from_seed succeeds");
    expect(purify_generate_key_from_seed(&second, seed, sizeof(seed)) == PURIFY_ERROR_OK,
           "purify_generate_key_from_seed succeeds twice");
    expect(memcmp(&first, &second, sizeof(first)) == 0,
           "purify_generate_key_from_seed is deterministic");
    expect(purify_generate_key_from_seed(&second, min_seed, sizeof(min_seed)) == PURIFY_ERROR_OK,
           "purify_generate_key_from_seed accepts the minimum supported seed length");
    to_hex(hex, first.secret_key, sizeof(first.secret_key));
    expect(strcmp(hex,
                  "244033992dfe583985332da27b7cdfddaf05df5c5c3bc8db763af6dd75f07ee28737e8d9a8d5592a3f10944c89f6ae82e53f76ae9dc17c77c22cf7a352cdb59c")
               == 0,
           "purify_generate_key_from_seed preserves the legacy packed-secret test vector");
    to_hex(hex, first.public_key, sizeof(first.public_key));
#if PURIFY_USE_LEGACY_FIELD_HASHES
    expect(strcmp(hex,
                  "c000e3169636f34eb81b1d25280219abd1bb2f1185c6b55780e53f2a3b95d97b2b1576df976499bcc7687673d7efeb5621d2e5c6c2939aa4a57276185b6bf09e")
               == 0,
           "purify_generate_key_from_seed preserves the legacy packed-public-key test vector");
#else
    expect(strcmp(hex,
                  "79b928249e7889d70fe96c9b748d9d3863f5ac48e66340c5c8962aba2f12bd0985bb7f26a806cf0bfc8f149984117903917723d62bd4059475f6287c05622397")
               == 0,
           "purify_generate_key_from_seed preserves the legacy packed-public-key test vector");
#endif
    {
        purify_generated_key aliased_seed_key = {{0}, {0}};
        memcpy(aliased_seed_key.secret_key, seed, sizeof(seed));
        expect(purify_generate_key_from_seed(&aliased_seed_key, aliased_seed_key.secret_key, sizeof(seed)) == PURIFY_ERROR_OK,
               "purify_generate_key_from_seed accepts seed storage inside the output bundle");
        expect(memcmp(&aliased_seed_key, &first, sizeof(first)) == 0,
               "purify_generate_key_from_seed aliasing matches the non-aliased result");
    }

    expect(purify_derive_public_key(NULL, first.secret_key) == PURIFY_ERROR_MISSING_VALUE,
           "purify_derive_public_key rejects a null output pointer");
    expect(purify_derive_public_key(derived_public_key, NULL) == PURIFY_ERROR_MISSING_VALUE,
           "purify_derive_public_key rejects a null secret pointer");
    expect(purify_derive_public_key(derived_public_key, invalid_secret) == PURIFY_ERROR_RANGE_VIOLATION,
           "purify_derive_public_key rejects out-of-range packed secrets");
    expect(purify_derive_public_key(derived_public_key, first.secret_key) == PURIFY_ERROR_OK,
           "purify_derive_public_key succeeds");
    expect(memcmp(derived_public_key, first.public_key, sizeof(derived_public_key)) == 0,
           "purify_derive_public_key matches seeded key generation");
    {
        unsigned char aliased_public_key[PURIFY_PUBLIC_KEY_BYTES];
        memcpy(aliased_public_key, first.secret_key, sizeof(aliased_public_key));
        expect(purify_derive_public_key(aliased_public_key, aliased_public_key) == PURIFY_ERROR_OK,
               "purify_derive_public_key accepts identical input and output pointers");
        expect(memcmp(aliased_public_key, first.public_key, sizeof(aliased_public_key)) == 0,
               "purify_derive_public_key aliasing matches the non-aliased result");
    }

    expect(purify_derive_bip340_key(NULL, first.secret_key) == PURIFY_ERROR_MISSING_VALUE,
           "purify_derive_bip340_key rejects a null output pointer");
    expect(purify_derive_bip340_key(&bip340, NULL) == PURIFY_ERROR_MISSING_VALUE,
           "purify_derive_bip340_key rejects a null secret pointer");
    expect(purify_derive_bip340_key(&bip340, invalid_secret) == PURIFY_ERROR_RANGE_VIOLATION,
           "purify_derive_bip340_key rejects out-of-range packed secrets");
    expect(purify_derive_bip340_key(&bip340, first.secret_key) == PURIFY_ERROR_OK,
           "purify_derive_bip340_key succeeds");
    expect(!all_zero(bip340.secret_key, sizeof(bip340.secret_key)),
           "purify_derive_bip340_key produces a non-zero BIP340 secret");
    expect(purify_bip340_validate_xonly_pubkey(context, bip340.xonly_public_key) == 1,
           "purify_derive_bip340_key produces a valid x-only public key");
    {
        unsigned char canonical_secret[PURIFY_BIP340_SECRET_KEY_BYTES];
        unsigned char canonical_xonly[PURIFY_BIP340_XONLY_PUBKEY_BYTES];
        memcpy(canonical_secret, bip340.secret_key, sizeof(canonical_secret));
        expect(purify_bip340_key_from_seckey(context, canonical_secret, canonical_xonly) == 1,
               "purify_derive_bip340_key returns a canonical BIP340 secret");
        expect(memcmp(canonical_secret, bip340.secret_key, sizeof(canonical_secret)) == 0 &&
               memcmp(canonical_xonly, bip340.xonly_public_key, sizeof(canonical_xonly)) == 0,
               "purify_derive_bip340_key is stable under purify_bip340_key_from_seckey");
    }
    {
        unsigned char aliased_bip340[sizeof(purify_bip340_key)];
        memcpy(aliased_bip340, first.secret_key, PURIFY_SECRET_KEY_BYTES);
        expect(purify_derive_bip340_key((purify_bip340_key*)aliased_bip340, aliased_bip340) == PURIFY_ERROR_OK,
               "purify_derive_bip340_key accepts secret storage inside the output struct");
        expect(memcmp(aliased_bip340, &bip340, sizeof(bip340)) == 0,
               "purify_derive_bip340_key aliasing matches the non-aliased result");
    }

    expect(purify_eval(NULL, first.secret_key, message, sizeof(message) - 1u) == PURIFY_ERROR_MISSING_VALUE,
           "purify_eval rejects a null output pointer");
    expect(purify_eval(eval_a, NULL, message, sizeof(message) - 1u) == PURIFY_ERROR_MISSING_VALUE,
           "purify_eval rejects a null secret pointer");
    expect(purify_eval(eval_a, first.secret_key, NULL, 1u) == PURIFY_ERROR_MISSING_VALUE,
           "purify_eval rejects a null non-empty message pointer");
    expect(purify_eval(eval_a, invalid_secret, message, sizeof(message) - 1u) == PURIFY_ERROR_RANGE_VIOLATION,
           "purify_eval rejects out-of-range packed secrets");
    expect(purify_eval(eval_a, first.secret_key, message, sizeof(message) - 1u) == PURIFY_ERROR_OK,
           "purify_eval succeeds");
    expect(purify_eval(eval_b, first.secret_key, message, sizeof(message) - 1u) == PURIFY_ERROR_OK,
           "purify_eval is repeatable");
    expect(memcmp(eval_a, eval_b, sizeof(eval_a)) == 0,
           "purify_eval is deterministic");
    expect(!all_zero(eval_a, sizeof(eval_a)),
           "purify_eval produces a non-zero field element for one sample");
    expect(purify_eval(eval_b, first.secret_key, NULL, 0u) == PURIFY_ERROR_OK,
           "purify_eval accepts a null zero-length message");
    expect(purify_eval(eval_b, first.secret_key, other_message, sizeof(other_message) - 1u) == PURIFY_ERROR_OK &&
           memcmp(eval_a, eval_b, sizeof(eval_a)) != 0,
           "purify_eval depends on the message bytes");
    expect(manual_eval_core(eval_manual, first.secret_key, message, sizeof(message) - 1u) != 0,
           "manual core eval path succeeds");
    expect(memcmp(eval_manual, eval_a, sizeof(eval_a)) == 0,
           "purify_eval matches the direct C core evaluation path");
    {
        unsigned char aliased_eval_secret[PURIFY_SECRET_KEY_BYTES];
        unsigned char aliased_eval_message[PURIFY_FIELD_ELEMENT_BYTES];
        memcpy(aliased_eval_secret, first.secret_key, sizeof(aliased_eval_secret));
        memset(aliased_eval_message, 0, sizeof(aliased_eval_message));
        memcpy(aliased_eval_message, message, sizeof(message) - 1u);
        expect(purify_eval(aliased_eval_secret, aliased_eval_secret, message, sizeof(message) - 1u) == PURIFY_ERROR_OK,
               "purify_eval accepts output overlapping the secret input");
        expect(memcmp(aliased_eval_secret, eval_a, sizeof(eval_a)) == 0,
               "purify_eval with aliased secret input matches the non-aliased result");
        expect(purify_eval(aliased_eval_message, first.secret_key, aliased_eval_message, sizeof(message) - 1u) == PURIFY_ERROR_OK,
               "purify_eval accepts output overlapping the message input");
        expect(memcmp(aliased_eval_message, eval_a, sizeof(eval_a)) == 0,
               "purify_eval with aliased message input matches the non-aliased result");
    }

    for (i = 0; i < 24; ++i) {
        unsigned char loop_seed[48];
        unsigned char loop_message[29];
        purify_generated_key loop_key = {{0}, {0}};
        purify_bip340_key loop_bip340 = {{0}, {0}};
        size_t seed_len = 16u + (size_t)(splitmix64_next(&rng) % 33u);
        size_t msg_len = (size_t)(splitmix64_next(&rng) % sizeof(loop_message));

        splitmix64_fill(&rng, loop_seed, seed_len);
        splitmix64_fill(&rng, loop_message, msg_len);
        expect(purify_generate_key_from_seed(&loop_key, loop_seed, seed_len) == PURIFY_ERROR_OK,
               "purify_generate_key_from_seed succeeds across the property matrix");
        expect(purify_validate_secret_key(loop_key.secret_key) == PURIFY_ERROR_OK,
               "generated property-matrix secrets validate");
        expect(purify_validate_public_key(loop_key.public_key) == PURIFY_ERROR_OK,
               "generated property-matrix public keys validate");
        expect(purify_derive_public_key(derived_public_key, loop_key.secret_key) == PURIFY_ERROR_OK,
               "purify_derive_public_key succeeds across the property matrix");
        expect(memcmp(derived_public_key, loop_key.public_key, sizeof(derived_public_key)) == 0,
               "purify_derive_public_key matches generate_key_from_seed across the property matrix");
        expect(purify_derive_bip340_key(&loop_bip340, loop_key.secret_key) == PURIFY_ERROR_OK,
               "purify_derive_bip340_key succeeds across the property matrix");
        expect(purify_bip340_validate_xonly_pubkey(context, loop_bip340.xonly_public_key) == 1,
               "property-matrix BIP340 public keys validate");
        expect(purify_eval(eval_a, loop_key.secret_key, loop_message, msg_len) == PURIFY_ERROR_OK,
               "purify_eval succeeds across the property matrix");
        expect(purify_eval(eval_b, loop_key.secret_key, loop_message, msg_len) == PURIFY_ERROR_OK,
               "purify_eval is repeatable across the property matrix");
        expect(memcmp(eval_a, eval_b, sizeof(eval_a)) == 0,
               "purify_eval stays deterministic across the property matrix");
        expect(manual_eval_core(eval_manual, loop_key.secret_key, loop_message, msg_len) != 0,
               "manual core eval succeeds across the property matrix");
        expect(memcmp(eval_a, eval_manual, sizeof(eval_a)) == 0,
               "purify_eval matches direct C core evaluation across the property matrix");
    }

    purify_secp_context_destroy(context);
}

static void test_field_core(void) {
    purify_fe zero;
    purify_fe one;
    purify_fe two;
    purify_fe three;
    purify_fe neg_five;
    purify_fe pos_five;
    purify_fe tmp_a;
    purify_fe tmp_b;
    purify_fe tmp_saved;
    purify_fe sqrt_out;
    purify_fe non_square;
    uint64_t u256[4];
    uint64_t prime_p[4];
    unsigned char bytes32[32];
    unsigned char prime_bytes[32];
    splitmix64 rng = {UINT64_C(0x3141592653589793)};
    int found_non_square = 0;
    int i;

    purify_curve_prime_p(prime_p);
    purify_u256_to_bytes_be(prime_bytes, prime_p);

    purify_fe_set_zero(&zero);
    purify_fe_set_u64(&one, 1u);
    purify_fe_set_u64(&two, 2u);
    purify_fe_set_u64(&three, 3u);
    purify_fe_set_i64(&neg_five, -5);
    purify_fe_set_u64(&pos_five, 5u);

    expect(purify_fe_is_zero(&zero) != 0, "purify_fe_set_zero produces zero");
    expect(purify_fe_is_one(&one) != 0, "purify_fe_set_u64 produces one");
    expect(purify_fe_is_odd(&three) != 0 && purify_fe_is_odd(&two) == 0,
           "purify_fe_is_odd distinguishes odd and even values");
    purify_fe_get_u256(u256, &three);
    expect(u256[0] == 3u && u256[1] == 0u && u256[2] == 0u && u256[3] == 0u,
           "purify_fe_get_u256 round-trips a small field element");
    purify_fe_get_b32(bytes32, &three);
    expect(bytes32[31] == 3u && all_zero(bytes32, 31u),
           "purify_fe_get_b32 serializes a small field element canonically");
    expect(purify_fe_set_b32(&tmp_a, bytes32) != 0 && purify_fe_eq(&tmp_a, &three) != 0,
           "purify_fe_set_b32 round-trips a canonical field element");
    expect(purify_fe_set_u256(&tmp_a, u256) != 0 && purify_fe_eq(&tmp_a, &three) != 0,
           "purify_fe_set_u256 round-trips a canonical field element");
    expect(purify_fe_set_u256(&tmp_a, prime_p) == 0,
           "purify_fe_set_u256 rejects the field modulus");
    expect(purify_fe_set_b32(&tmp_a, prime_bytes) == 0,
           "purify_fe_set_b32 rejects the field modulus");
    purify_fe_set_i64(&tmp_a, 5);
    expect(purify_fe_eq(&tmp_a, &pos_five) != 0,
           "purify_fe_set_i64 handles positive values");
    purify_fe_negate(&tmp_a, &pos_five);
    expect(purify_fe_eq(&tmp_a, &neg_five) != 0,
           "purify_fe_set_i64 matches purify_fe_negate on negative input");

    purify_fe_set_u64(&tmp_a, 11u);
    purify_fe_set_u64(&tmp_b, 19u);
    tmp_saved = tmp_a;
    purify_fe_cmov(&tmp_a, &tmp_b, 0);
    expect(purify_fe_eq(&tmp_a, &tmp_saved) != 0,
           "purify_fe_cmov with flag zero leaves the destination unchanged");
    purify_fe_cmov(&tmp_a, &tmp_b, 1);
    expect(purify_fe_eq(&tmp_a, &tmp_b) != 0,
           "purify_fe_cmov with flag one overwrites the destination");

    expect(purify_fe_is_square(&zero) != 0,
           "purify_fe_is_square treats zero as a quadratic residue");
    expect(purify_fe_legendre_symbol(&zero) == 0,
           "purify_fe_legendre_symbol returns zero for zero");
    expect(purify_fe_sqrt(&sqrt_out, &zero) != 0 && purify_fe_is_zero(&sqrt_out) != 0,
           "purify_fe_sqrt(0) succeeds and returns 0");

    for (i = 2; i < 1024; ++i) {
        purify_fe_set_u64(&non_square, (uint64_t)i);
        if (purify_fe_is_square(&non_square) == 0) {
            found_non_square = 1;
            break;
        }
    }
    expect(found_non_square != 0, "field test finds a small quadratic non-residue");
    if (found_non_square != 0) {
        expect(purify_fe_legendre_symbol(&non_square) == -1,
               "purify_fe_legendre_symbol returns -1 for non-residues");
        expect(purify_fe_sqrt(&sqrt_out, &non_square) == 0,
               "purify_fe_sqrt rejects quadratic non-residues");
    }

    for (i = 0; i < 64; ++i) {
        purify_fe a;
        purify_fe b;
        purify_fe c;
        purify_fe lhs;
        purify_fe rhs;
        purify_fe inv;
        purify_fe inv_var;
        uint64_t exponent[4];

        purify_fe_set_u64(&a, splitmix64_next(&rng));
        purify_fe_set_u64(&b, splitmix64_next(&rng));
        purify_fe_set_u64(&c, splitmix64_next(&rng));

        purify_fe_add(&lhs, &a, &b);
        purify_fe_add(&rhs, &b, &a);
        expect(purify_fe_eq(&lhs, &rhs) != 0, "field addition is commutative");

        purify_fe_mul(&lhs, &a, &b);
        purify_fe_mul(&rhs, &b, &a);
        expect(purify_fe_eq(&lhs, &rhs) != 0, "field multiplication is commutative");

        purify_fe_add(&lhs, &a, &b);
        purify_fe_add(&lhs, &lhs, &c);
        purify_fe_add(&rhs, &b, &c);
        purify_fe_add(&rhs, &a, &rhs);
        expect(purify_fe_eq(&lhs, &rhs) != 0, "field addition is associative");

        purify_fe_mul(&lhs, &a, &b);
        purify_fe_mul(&lhs, &lhs, &c);
        purify_fe_mul(&rhs, &b, &c);
        purify_fe_mul(&rhs, &a, &rhs);
        expect(purify_fe_eq(&lhs, &rhs) != 0, "field multiplication is associative");

        purify_fe_add(&lhs, &b, &c);
        purify_fe_mul(&lhs, &a, &lhs);
        purify_fe_mul(&rhs, &a, &b);
        purify_fe_mul(&tmp_a, &a, &c);
        purify_fe_add(&rhs, &rhs, &tmp_a);
        expect(purify_fe_eq(&lhs, &rhs) != 0, "field multiplication distributes over addition");

        purify_fe_sub(&lhs, &a, &b);
        purify_fe_add(&lhs, &lhs, &b);
        expect(purify_fe_eq(&lhs, &a) != 0, "field subtraction undoes addition");

        purify_fe_negate(&lhs, &a);
        purify_fe_add(&lhs, &lhs, &a);
        expect(purify_fe_is_zero(&lhs) != 0, "field negation produces an additive inverse");

        purify_fe_square(&lhs, &a);
        purify_fe_mul(&rhs, &a, &a);
        expect(purify_fe_eq(&lhs, &rhs) != 0, "field squaring matches multiplication by self");

        purify_u256_set_zero(exponent);
        purify_fe_pow(&lhs, &a, exponent);
        expect(purify_fe_is_one(&lhs) != 0, "field exponentiation to zero returns one");
        purify_u256_set_u64(exponent, 1u);
        purify_fe_pow(&lhs, &a, exponent);
        expect(purify_fe_eq(&lhs, &a) != 0, "field exponentiation to one returns the base");
        purify_u256_set_u64(exponent, 2u);
        purify_fe_pow(&lhs, &a, exponent);
        expect(purify_fe_eq(&lhs, &rhs) != 0, "field exponentiation to two matches square");

        if (purify_fe_is_zero(&a) == 0) {
            purify_fe_inverse(&inv, &a);
            purify_fe_inverse_var(&inv_var, &a);
            purify_fe_mul(&lhs, &a, &inv);
            purify_fe_mul(&rhs, &a, &inv_var);
            expect(purify_fe_is_one(&lhs) != 0, "field inverse produces a multiplicative inverse");
            expect(purify_fe_is_one(&rhs) != 0, "field inverse_var produces a multiplicative inverse");
        }

        purify_fe_square(&rhs, &a);
        expect(purify_fe_is_square(&rhs) != 0, "field squares are quadratic residues");
        expect(purify_fe_legendre_symbol(&rhs) >= 0, "field squares have non-negative Legendre symbol");
        expect(purify_fe_sqrt(&lhs, &rhs) != 0, "field squares admit square roots");
        purify_fe_square(&lhs, &lhs);
        expect(purify_fe_eq(&lhs, &rhs) != 0, "purify_fe_sqrt returns a square root");
    }
}

static void test_curve_core(void) {
    purify_curve curve1;
    purify_curve curve2;
    purify_jacobian_point infinity;
    purify_jacobian_point generator1;
    purify_jacobian_point generator2;
    purify_jacobian_point generator1_b;
    purify_jacobian_point p;
    purify_jacobian_point q;
    purify_jacobian_point r;
    purify_jacobian_point sum;
    purify_jacobian_point doubled;
    purify_jacobian_point lifted;
    purify_jacobian_point negated;
    purify_affine_point affine1;
    purify_affine_point affine2;
    purify_affine_point secret_affine;
    purify_fe field_d;
    purify_fe field_di;
    purify_fe combine_direct;
    purify_fe combine_formula;
    uint64_t p_mod[4];
    uint64_t n1[4];
    uint64_t n2[4];
    uint64_t half1[4];
    uint64_t half2[4];
    uint64_t two_p[5];
    uint64_t expected_two_p[5];
    uint64_t secret_space[8];
    uint64_t public_space[8];
    uint64_t expected_space[8];
    uint64_t z1[4];
    uint64_t z2[4];
    uint64_t packed_secret[8];
    uint64_t unpacked1[4];
    uint64_t unpacked2[4];
    uint64_t packed_public[8];
    uint64_t unpacked_x1[4];
    uint64_t unpacked_x2[4];
    uint64_t max_x[4];
    uint64_t small_max[4];
    int bits[16];
    splitmix64 rng = {UINT64_C(0xabcdef0123456789)};
    int i;

    make_curve1(&curve1);
    make_curve2(&curve2);
    purify_curve_prime_p(p_mod);
    purify_curve_order_n1(n1);
    purify_curve_order_n2(n2);
    purify_curve_half_n1(half1);
    purify_curve_half_n2(half2);
    purify_curve_two_p(two_p);
    purify_curve_packed_secret_key_space_size(secret_space);
    purify_curve_packed_public_key_space_size(public_space);

    purify_u320_widen_u256(expected_two_p, p_mod);
    expect(purify_u320_try_mul_small(expected_two_p, 2u) != 0, "two_p derivation multiplies by two");
    expect(u320_eq(two_p, expected_two_p), "purify_curve_two_p matches 2 * p");

    purify_u512_multiply_u256(expected_space, half1, half2);
    expect(u512_eq(secret_space, expected_space), "packed secret space size matches half_n1 * half_n2");
    purify_u512_multiply_u256(expected_space, p_mod, p_mod);
    expect(u512_eq(public_space, expected_space), "packed public space size matches p^2");

    purify_u512_widen_u256(expected_space, half1);
    expect(purify_u512_try_add(expected_space, expected_space) != 0, "deriving order_n1 doubles half_n1");
    expect(purify_u512_try_add_small(expected_space, 1u) != 0, "deriving order_n1 adds one");
    purify_u512_widen_u256(secret_space, n1);
    expect(u512_eq(expected_space, secret_space), "half_n1 is floor(order_n1 / 2)");

    purify_u512_widen_u256(expected_space, half2);
    expect(purify_u512_try_add(expected_space, expected_space) != 0, "deriving order_n2 doubles half_n2");
    expect(purify_u512_try_add_small(expected_space, 1u) != 0, "deriving order_n2 adds one");
    purify_u512_widen_u256(secret_space, n2);
    expect(u512_eq(expected_space, secret_space), "half_n2 is floor(order_n2 / 2)");

    purify_curve_field_d(&field_d);
    purify_curve_field_di(&field_di);
    purify_fe_mul(&combine_direct, &field_d, &field_di);
    expect(purify_fe_is_one(&combine_direct) != 0, "field_d * field_di == 1");
    expect(purify_curve_is_valid_secret_key((const uint64_t[8]){0}) != 0,
           "purify_curve_is_valid_secret_key accepts the smallest packed secret");
    expect(purify_curve_is_valid_public_key((const uint64_t[8]){0}) != 0,
           "purify_curve_is_valid_public_key accepts the smallest packed public key");

    expect(purify_curve_hash_to_curve(NULL, &curve1, (const unsigned char*)"x", 1u) == 0,
           "purify_curve_hash_to_curve rejects a null output pointer");
    expect(purify_curve_hash_to_curve(&p, NULL, (const unsigned char*)"x", 1u) == 0,
           "purify_curve_hash_to_curve rejects a null curve pointer");
    expect(purify_curve_hash_to_curve(&p, &curve1, NULL, 1u) == 0,
           "purify_curve_hash_to_curve rejects null non-empty input");
    expect(purify_curve_hash_to_curve(&p, &curve1, NULL, 0u) != 0,
           "purify_curve_hash_to_curve accepts a null zero-length input");
    expect(point_on_curve(&curve1, &p), "purify_curve_hash_to_curve handles the empty input");

    purify_curve_jacobian_infinity(&infinity);
    purify_curve_affine(&affine1, &curve1, &infinity);
    expect(affine1.infinity != 0, "purify_curve_affine maps Jacobian infinity to affine infinity");
    purify_curve_negate(&negated, &infinity);
    expect(negated.infinity != 0, "purify_curve_negate preserves infinity");

    make_generator(&generator1, &curve1, "Generator/1");
    make_generator(&generator1_b, &curve1, "Generator/1");
    make_generator(&generator2, &curve2, "Generator/2");
    {
        purify_jacobian_point malformed = generator1;
        purify_fe_set_zero(&malformed.z);
        malformed.infinity = 0;
        purify_curve_affine(&affine1, &curve1, &malformed);
        expect(affine1.infinity != 0,
               "purify_curve_affine treats z == 0 as infinity even without the infinity flag");
    }
    expect(jacobian_eq(&curve1, &generator1, &generator1_b),
           "purify_curve_hash_to_curve is deterministic on the same input");
    expect(point_on_curve(&curve1, &generator1), "curve1 generator lies on the curve");
    expect(point_on_curve(&curve2, &generator2), "curve2 generator lies on the curve");

    purify_curve_mul(&p, &curve1, &generator1, n1);
    expect(p.infinity != 0 || purify_fe_is_zero(&p.z) != 0,
           "curve1 generator has the documented subgroup order");
    purify_curve_mul(&p, &curve2, &generator2, n2);
    expect(p.infinity != 0 || purify_fe_is_zero(&p.z) != 0,
           "curve2 generator has the documented subgroup order");

    purify_curve_affine(&affine1, &curve1, &generator1);
    expect(affine1.infinity == 0, "curve1 generator has affine coordinates");
    expect(purify_curve_is_x_coord(&curve1, &affine1.x) != 0,
           "purify_curve_is_x_coord accepts the x-coordinate of a real point");
    expect(purify_curve_lift_x(&lifted, &curve1, &affine1.x) != 0,
           "purify_curve_lift_x lifts a valid x-coordinate");
    expect(point_on_curve(&curve1, &lifted), "purify_curve_lift_x returns a point on the curve");
    purify_curve_affine(&affine2, &curve1, &lifted);
    expect(purify_fe_eq(&affine1.x, &affine2.x) != 0,
           "purify_curve_lift_x preserves the x-coordinate");
    {
        int found_invalid_x = 0;
        for (i = 0; i < 512; ++i) {
            purify_fe candidate;
            purify_fe_set_u64(&candidate, (uint64_t)i);
            if (purify_curve_is_x_coord(&curve1, &candidate) == 0) {
                found_invalid_x = 1;
                expect(purify_curve_lift_x(&lifted, &curve1, &candidate) == 0,
                       "purify_curve_lift_x rejects non-x-coordinates");
                break;
            }
        }
        expect(found_invalid_x != 0, "curve test finds a small invalid x-coordinate");
    }

    purify_curve_add(&sum, &curve1, &infinity, &generator1);
    expect(jacobian_eq(&curve1, &sum, &generator1),
           "purify_curve_add uses infinity as a left identity");
    purify_curve_add(&sum, &curve1, &generator1, &infinity);
    expect(jacobian_eq(&curve1, &sum, &generator1),
           "purify_curve_add uses infinity as a right identity");
    purify_curve_add_mixed(&sum, &curve1, &infinity, &affine1);
    expect(jacobian_eq(&curve1, &sum, &generator1),
           "purify_curve_add_mixed uses infinity as a left identity");

    purify_curve_negate(&negated, &generator1);
    purify_curve_add(&sum, &curve1, &generator1, &negated);
    expect(sum.infinity != 0 || purify_fe_is_zero(&sum.z) != 0,
           "purify_curve_add(P, -P) returns infinity");
    purify_curve_affine(&affine2, &curve1, &negated);
    purify_curve_add_mixed(&sum, &curve1, &generator1, &affine2);
    expect(sum.infinity != 0 || purify_fe_is_zero(&sum.z) != 0,
           "purify_curve_add_mixed(P, -P) returns infinity");

    purify_curve_double(&doubled, &curve1, &generator1);
    purify_curve_add(&sum, &curve1, &generator1, &generator1);
    expect(jacobian_eq(&curve1, &doubled, &sum),
           "purify_curve_double matches purify_curve_add(P, P)");

    purify_u256_set_zero(z1);
    purify_curve_mul(&sum, &curve1, &generator1, z1);
    expect(sum.infinity != 0 || purify_fe_is_zero(&sum.z) != 0,
           "purify_curve_mul(P, 0) returns infinity");
    purify_u256_set_u64(z1, 1u);
    purify_curve_mul(&sum, &curve1, &generator1, z1);
    expect(jacobian_eq(&curve1, &sum, &generator1),
           "purify_curve_mul(P, 1) returns P");
    purify_u256_set_u64(z1, 2u);
    purify_curve_mul(&sum, &curve1, &generator1, z1);
    expect(jacobian_eq(&curve1, &sum, &doubled),
           "purify_curve_mul(P, 2) matches purify_curve_double");
    expect(purify_curve_mul_secret_affine(&secret_affine, &curve1, &generator1, z1) != 0,
           "purify_curve_mul_secret_affine succeeds for non-zero scalars");
    purify_curve_affine(&affine1, &curve1, &sum);
    expect(affine_eq(&secret_affine, &affine1),
           "purify_curve_mul_secret_affine matches affine(purify_curve_mul)");
    purify_u256_set_u64(z1, 1u);
    expect(purify_curve_mul_secret_affine(&secret_affine, &curve1, &doubled, z1) != 0,
           "purify_curve_mul_secret_affine accepts normalized-Jacobian inputs");
    purify_curve_affine(&affine1, &curve1, &doubled);
    expect(affine_eq(&secret_affine, &affine1),
           "purify_curve_mul_secret_affine normalizes Jacobian inputs before multiplying");
    purify_u256_set_zero(z1);
    expect(purify_curve_mul_secret_affine(&secret_affine, &curve1, &generator1, z1) == 0,
           "purify_curve_mul_secret_affine rejects the point at infinity result for scalar zero");
    purify_u256_set_u64(z1, 1u);
    expect(purify_curve_mul_secret_affine(&secret_affine, &curve1, &infinity, z1) == 0,
           "purify_curve_mul_secret_affine rejects an infinity input point");

    purify_curve_affine(&affine1, &curve1, &generator1);
    purify_curve_add_mixed(&sum, &curve1, &generator1, &affine1);
    expect(jacobian_eq(&curve1, &sum, &doubled),
           "purify_curve_add_mixed matches doubling when adding the affine generator");

    for (i = 0; i < 20; ++i) {
        uint64_t scalar_a[4];
        uint64_t scalar_b[4];
        uint64_t scalar_sum[4];
        uint64_t secret_words[8];
        uint64_t packed_x[8];
        uint64_t one_u256[4];
        uint64_t value_u256[4];
        uint64_t decoded_u256[4];
        uint64_t scalar_c[4];
        uint64_t out_len = 0;
        purify_jacobian_point assoc_lhs;
        purify_jacobian_point assoc_rhs;

        purify_u256_set_u64(scalar_a, 1u + (splitmix64_next(&rng) % 32u));
        purify_u256_set_u64(scalar_b, splitmix64_next(&rng) % 32u);
        purify_u256_set_u64(scalar_c, 1u + (splitmix64_next(&rng) % 32u));
        memcpy(scalar_sum, scalar_a, sizeof(scalar_sum));
        expect(purify_u256_try_add(scalar_sum, scalar_b) != 0, "small scalar addition stays in range");

        purify_curve_mul(&p, &curve1, &generator1, scalar_a);
        purify_curve_mul(&q, &curve1, &generator1, scalar_b);
        purify_curve_mul(&r, &curve1, &generator1, scalar_sum);
        purify_curve_add(&sum, &curve1, &p, &q);
        expect(jacobian_eq(&curve1, &sum, &r),
               "purify_curve_mul distributes over scalar addition");
        purify_curve_add(&sum, &curve1, &p, &q);
        purify_curve_add(&assoc_lhs, &curve1, &sum, &generator1);
        purify_curve_add(&sum, &curve1, &q, &p);
        expect(jacobian_eq(&curve1, &sum, &r),
               "purify_curve_add is commutative on subgroup points");
        purify_curve_mul(&r, &curve1, &generator1, scalar_c);
        purify_curve_add(&sum, &curve1, &p, &q);
        purify_curve_add(&assoc_lhs, &curve1, &sum, &r);
        purify_curve_add(&sum, &curve1, &q, &r);
        purify_curve_add(&assoc_rhs, &curve1, &p, &sum);
        expect(jacobian_eq(&curve1, &assoc_lhs, &assoc_rhs),
               "purify_curve_add is associative on subgroup points");

        expect(purify_curve_mul_secret_affine(&secret_affine, &curve1, &generator1, scalar_a) != 0,
               "purify_curve_mul_secret_affine succeeds in the property loop");
        purify_curve_affine(&affine1, &curve1, &p);
        expect(affine_eq(&secret_affine, &affine1),
               "purify_curve_mul_secret_affine matches affine(purify_curve_mul) in the property loop");

        purify_curve_affine(&affine1, &curve1, &p);
        purify_curve_affine(&affine2, &curve2, &generator2);
        purify_fe_get_u256(unpacked_x1, &affine1.x);
        purify_fe_get_u256(unpacked_x2, &affine2.x);
        purify_curve_pack_public(packed_x, unpacked_x1, unpacked_x2);
        expect(purify_curve_unpack_public(unpacked1, unpacked2, packed_x) != 0,
               "purify_curve_unpack_public succeeds on packed affine x-coordinates");
        expect(u256_eq(unpacked1, unpacked_x1) && u256_eq(unpacked2, unpacked_x2),
               "purify_curve_unpack_public round-trips purify_curve_pack_public");
        expect(purify_curve_is_valid_public_key(packed_x) != 0,
               "purify_curve_is_valid_public_key accepts packed affine x-coordinates");

        purify_u256_set_u64(z1, 1u + (splitmix64_next(&rng) % 64u));
        purify_u256_set_u64(z2, 1u + (splitmix64_next(&rng) % 64u));
        encode_secret_value(secret_words, z1, z2);
        expect(purify_curve_unpack_secret(unpacked1, unpacked2, secret_words) != 0,
               "purify_curve_unpack_secret succeeds on encoded mixed-radix secrets");
        expect(u256_eq(unpacked1, z1) && u256_eq(unpacked2, z2),
               "purify_curve_unpack_secret inverts the mixed-radix encoding");
        expect(purify_curve_is_valid_secret_key(secret_words) != 0,
               "purify_curve_is_valid_secret_key accepts encoded mixed-radix secrets");

        purify_curve_combine(&combine_direct, &affine1.x, &affine2.x);
        compute_combine_formula(&combine_formula, &affine1.x, &affine2.x);
        expect(purify_fe_eq(&combine_direct, &combine_formula) != 0,
               "purify_curve_combine matches the direct field formula");

        purify_u256_set_u64(small_max, 1000u);
        purify_u256_set_u64(value_u256, 1u + (splitmix64_next(&rng) % 1000u));
        out_len = purify_u256_bit_length(small_max);
        expect(purify_curve_key_to_bits(bits, out_len, value_u256, small_max) != 0,
               "purify_curve_key_to_bits succeeds for in-range values");
        expect(decode_key_bits(decoded_u256, bits, out_len) != 0,
               "decode_key_bits inverts purify_curve_key_to_bits");
        expect(u256_eq(decoded_u256, value_u256),
               "purify_curve_key_to_bits round-trips through the signed-window decoder");
        expect(purify_curve_key_to_bits(NULL, out_len, value_u256, small_max) == 0,
               "purify_curve_key_to_bits rejects a null output buffer when bits are requested");
        purify_u256_set_zero(one_u256);
        expect(purify_curve_key_to_bits(bits, out_len, one_u256, small_max) == 0,
               "purify_curve_key_to_bits rejects zero");
        purify_u256_set_u64(one_u256, 1001u);
        expect(purify_curve_key_to_bits(bits, out_len, one_u256, small_max) == 0,
               "purify_curve_key_to_bits rejects values above max_value");
        expect(purify_curve_key_to_bits(bits, out_len - 1u, value_u256, small_max) == 0,
               "purify_curve_key_to_bits rejects output buffers that are too short");
    }

    purify_u256_set_u64(z1, 5u);
    purify_u256_set_u64(z2, 7u);
    encode_secret_value(packed_secret, z1, z2);
    expect(purify_curve_unpack_secret(unpacked1, unpacked2, packed_secret) != 0,
           "purify_curve_unpack_secret succeeds on a fixed sample");
    expect(u256_eq(unpacked1, z1) && u256_eq(unpacked2, z2),
           "purify_curve_unpack_secret round-trips a fixed sample");

    purify_curve_packed_secret_key_space_size(secret_space);
    expect(purify_curve_unpack_secret(unpacked1, unpacked2, secret_space) == 0,
           "purify_curve_unpack_secret rejects the exclusive upper bound");
    expect(purify_curve_is_valid_secret_key(secret_space) == 0,
           "purify_curve_is_valid_secret_key rejects the exclusive upper bound");

    memcpy(max_x, p_mod, sizeof(max_x));
    expect(purify_u256_try_sub(max_x, (const uint64_t[4]){UINT64_C(1), 0, 0, 0}) != 0,
           "max_x derivation subtracts one from the field modulus");
    purify_curve_pack_public(packed_public, max_x, max_x);
    purify_curve_packed_public_key_space_size(public_space);
    expect(purify_u512_try_sub(public_space, (const uint64_t[8]){UINT64_C(1), 0, 0, 0, 0, 0, 0, 0}) != 0,
           "largest public key derivation subtracts one from the public key space size");
    expect(u512_eq(packed_public, public_space),
           "purify_curve_pack_public reaches the largest valid packed public key at (p-1, p-1)");
    expect(purify_curve_unpack_public(unpacked1, unpacked2, packed_public) != 0,
           "purify_curve_unpack_public succeeds on the largest valid packed public key");
    expect(u256_eq(unpacked1, max_x) && u256_eq(unpacked2, max_x),
           "purify_curve_unpack_public decodes the largest valid packed public key");
    purify_curve_packed_public_key_space_size(public_space);
    expect(purify_curve_unpack_public(unpacked1, unpacked2, public_space) == 0,
           "purify_curve_unpack_public rejects the exclusive upper bound");
    expect(purify_curve_is_valid_public_key(public_space) == 0,
           "purify_curve_is_valid_public_key rejects the exclusive upper bound");
}

int main(void) {
    test_error_strings();
    test_secure_random();
    test_core_keygen();
    test_uint_core();
    test_secp_bridge();
    test_public_c_api();
    test_field_core();
    test_curve_core();

    if (failures != 0) {
        fprintf(stderr, "%d C test(s) failed\n", failures);
        return 1;
    }

    puts("all c api tests passed");
    return 0;
}
