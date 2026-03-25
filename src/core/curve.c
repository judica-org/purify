// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "curve.h"

#include <assert.h>
#include <string.h>

static const uint64_t kPurifyPrimeP[4] = {
#if defined(PURIFY_CBMC_MODEL_SMALL_FIELD)
    #include "verification/cbmc/model_small_field_constants.h"
    PURIFY_CBMC_MODEL_FIELD_PRIME_INIT
#else
    UINT64_C(0xBFD25E8CD0364141),
    UINT64_C(0xBAAEDCE6AF48A03B),
    UINT64_C(0xFFFFFFFFFFFFFFFE),
    UINT64_C(0xFFFFFFFFFFFFFFFF),
#endif
};

static const uint64_t kPurifyOrderN1[4] = {
#if defined(PURIFY_CBMC_MODEL_SMALL_FIELD)
    PURIFY_CBMC_MODEL_CURVE_ORDER_N1_INIT
#else
    UINT64_C(0x8A5A2A2C58E547E9),
    UINT64_C(0xA328F24405347212),
    UINT64_C(0xFFFFFFFFFFFFFFFF),
    UINT64_C(0xFFFFFFFFFFFFFFFF),
#endif
};

static const uint64_t kPurifyOrderN2[4] = {
#if defined(PURIFY_CBMC_MODEL_SMALL_FIELD)
    PURIFY_CBMC_MODEL_CURVE_ORDER_N2_INIT
#else
    UINT64_C(0xF54A92ED47873A9B),
    UINT64_C(0xD234C789595CCE64),
    UINT64_C(0xFFFFFFFFFFFFFFFD),
    UINT64_C(0xFFFFFFFFFFFFFFFF),
#endif
};

static const uint64_t kPurifyHalfN1[4] = {
#if defined(PURIFY_CBMC_MODEL_SMALL_FIELD)
    PURIFY_CBMC_MODEL_CURVE_HALF_N1_INIT
#else
    UINT64_C(0x452D15162C72A3F4),
    UINT64_C(0xD1947922029A3909),
    UINT64_C(0xFFFFFFFFFFFFFFFF),
    UINT64_C(0x7FFFFFFFFFFFFFFF),
#endif
};

static const uint64_t kPurifyHalfN2[4] = {
#if defined(PURIFY_CBMC_MODEL_SMALL_FIELD)
    PURIFY_CBMC_MODEL_CURVE_HALF_N2_INIT
#else
    UINT64_C(0x7AA54976A3C39D4D),
    UINT64_C(0xE91A63C4ACAE6732),
    UINT64_C(0xFFFFFFFFFFFFFFFE),
    UINT64_C(0x7FFFFFFFFFFFFFFF),
#endif
};

static const uint64_t kPurifyFieldDi[4] = {
#if defined(PURIFY_CBMC_MODEL_SMALL_FIELD)
    PURIFY_CBMC_MODEL_FIELD_DI_INIT
#else
    UINT64_C(0x4CBA8C385348E6E7),
    UINT64_C(0xE445F1F5DFB6A67E),
    UINT64_C(0x6666666666666665),
    UINT64_C(0x6666666666666666),
#endif
};

static const char kPurifyHashToCurveTag[] = "Purify/HashToCurve";

static void purify_curve_copy_u256(uint64_t out[4], const uint64_t value[4]) {
    memcpy(out, value, 4u * sizeof(uint64_t));
}

static void purify_curve_u64_to_be(unsigned char out[8], uint64_t value) {
    size_t i;
    for (i = 0; i < 8; ++i) {
        out[7u - i] = (unsigned char)(value & 0xffu);
        value >>= 8;
    }
}

static void purify_curve_tag_hash(unsigned char out[32]) {
    purify_sha256(out, (const unsigned char*)kPurifyHashToCurveTag, sizeof(kPurifyHashToCurveTag) - 1u);
}

static int purify_curve_hash_to_int_tagged_u320(uint64_t out[5],
                                                const unsigned char* data,
                                                size_t data_len,
                                                const uint64_t range[5],
                                                unsigned char info_byte) {
    unsigned char tag_hash[32];
    unsigned char derived[40];
    unsigned char digest[32];
    size_t bits = purify_u320_bit_length(range);
    size_t bytes_needed = (bits + 7u) / 8u;
    unsigned int attempt;

    purify_curve_tag_hash(tag_hash);
    for (attempt = 0; attempt < 256u; ++attempt) {
        size_t derived_len = 0;
        uint64_t block = 0;

        while (derived_len < bytes_needed) {
            unsigned char attempt_bytes[8];
            unsigned char block_bytes[8];
            const unsigned char* items[6];
            size_t item_lens[6];
            size_t copy_len;
            int ok;

            purify_curve_u64_to_be(attempt_bytes, (uint64_t)attempt);
            purify_curve_u64_to_be(block_bytes, block);
            items[0] = tag_hash;
            item_lens[0] = sizeof(tag_hash);
            items[1] = tag_hash;
            item_lens[1] = sizeof(tag_hash);
            items[2] = data;
            item_lens[2] = data_len;
            items[3] = &info_byte;
            item_lens[3] = 1u;
            items[4] = attempt_bytes;
            item_lens[4] = sizeof(attempt_bytes);
            items[5] = block_bytes;
            item_lens[5] = sizeof(block_bytes);
            ok = purify_sha256_many(digest, items, item_lens, 6u);
            assert(ok != 0);
            if (ok == 0) {
                return 0;
            }
            copy_len = sizeof(digest);
            if (copy_len > bytes_needed - derived_len) {
                copy_len = bytes_needed - derived_len;
            }
            memcpy(derived + derived_len, digest, copy_len);
            derived_len += copy_len;
            ++block;
        }

        purify_u320_from_bytes_be(out, derived, bytes_needed);
        purify_u320_mask_bits(out, bits);
        if (purify_u320_compare(out, range) < 0) {
            return 1;
        }
    }

    return 0;
}

#if PURIFY_USE_LEGACY_FIELD_HASHES
static int purify_curve_hash_to_int_hkdf_u320(uint64_t out[5],
                                              const unsigned char* data,
                                              size_t data_len,
                                              const uint64_t range[5],
                                              unsigned char info_byte) {
    unsigned char derived[40];
    unsigned char prk[32];
    unsigned char t[32];
    size_t bits = purify_u320_bit_length(range);
    size_t bytes_needed = (bits + 7u) / 8u;
    unsigned int salt_counter;

    for (salt_counter = 0; salt_counter < 256u; ++salt_counter) {
        unsigned char salt_byte = (unsigned char)salt_counter;
        size_t offset = 0;
        unsigned int block_index = 0;

        memset(prk, 0, sizeof(prk));
        memset(t, 0, sizeof(t));
        purify_hmac_sha256(prk, &salt_byte, 1u, data, data_len);

        while (offset < bytes_needed) {
            const size_t prev_len = block_index == 0 ? 0u : sizeof(t);
            const size_t input_len = prev_len + 2u;
            unsigned char input[34];
            size_t copy_len;

            if (prev_len != 0u) {
                memcpy(input, t, prev_len);
            }
            input[prev_len] = info_byte;
            input[prev_len + 1u] = (unsigned char)(block_index + 1u);
            purify_hmac_sha256(t, prk, sizeof(prk), input, input_len);
            copy_len = sizeof(t);
            if (copy_len > bytes_needed - offset) {
                copy_len = bytes_needed - offset;
            }
            memcpy(derived + offset, t, copy_len);
            offset += copy_len;
            ++block_index;
        }

        purify_u320_from_bytes_be(out, derived, bytes_needed);
        purify_u320_mask_bits(out, bits);
        if (purify_u320_compare(out, range) < 0) {
            return 1;
        }
    }

    return 0;
}
#endif

static purify_complete_projective_point purify_curve_complete_identity(void) {
    purify_complete_projective_point out;
    purify_fe_set_zero(&out.x);
    purify_fe_set_u64(&out.y, 1);
    purify_fe_set_zero(&out.z);
    return out;
}

static purify_complete_projective_point
purify_curve_secret_input_point(const purify_curve* curve, const purify_jacobian_point* point) {
    purify_complete_projective_point out;
    if (point->infinity != 0 || purify_fe_is_zero(&point->z) != 0) {
        return purify_curve_complete_identity();
    }
    if (purify_fe_is_one(&point->z) != 0) {
        out.x = point->x;
        out.y = point->y;
        out.z = point->z;
        return out;
    }
    {
        purify_affine_point normalized;
        purify_curve_affine(&normalized, curve, point);
        out.x = normalized.x;
        out.y = normalized.y;
        purify_fe_set_u64(&out.z, 1);
    }
    return out;
}

static void purify_curve_complete_assign(purify_complete_projective_point* dst,
                                         const purify_complete_projective_point* src,
                                         int flag) {
    purify_fe_cmov(&dst->x, &src->x, flag);
    purify_fe_cmov(&dst->y, &src->y, flag);
    purify_fe_cmov(&dst->z, &src->z, flag);
}

static void purify_curve_complete_swap(purify_complete_projective_point* lhs,
                                       purify_complete_projective_point* rhs,
                                       int flag) {
    purify_complete_projective_point tmp = *lhs;
    purify_curve_complete_assign(lhs, rhs, flag);
    purify_curve_complete_assign(rhs, &tmp, flag);
}

static purify_complete_projective_point
purify_curve_complete_add(const purify_curve* curve,
                          const purify_complete_projective_point* lhs,
                          const purify_complete_projective_point* rhs) {
    purify_complete_projective_point out;
    purify_fe b3;
    purify_fe t0;
    purify_fe t1;
    purify_fe t2;
    purify_fe t3;
    purify_fe t4;
    purify_fe t5;
    purify_fe x3;
    purify_fe y3;
    purify_fe z3;

    purify_fe_add(&b3, &curve->b, &curve->b);
    purify_fe_add(&b3, &b3, &curve->b);
    purify_fe_mul(&t0, &lhs->x, &rhs->x);
    purify_fe_mul(&t1, &lhs->y, &rhs->y);
    purify_fe_mul(&t2, &lhs->z, &rhs->z);
    purify_fe_add(&t3, &lhs->x, &lhs->y);
    purify_fe_add(&t4, &rhs->x, &rhs->y);
    purify_fe_mul(&t3, &t3, &t4);
    purify_fe_add(&t4, &t0, &t1);
    purify_fe_sub(&t3, &t3, &t4);
    purify_fe_add(&t4, &lhs->x, &lhs->z);
    purify_fe_add(&t5, &rhs->x, &rhs->z);
    purify_fe_mul(&t4, &t4, &t5);
    purify_fe_add(&t5, &t0, &t2);
    purify_fe_sub(&t4, &t4, &t5);
    purify_fe_add(&t5, &lhs->y, &lhs->z);
    purify_fe_add(&x3, &rhs->y, &rhs->z);
    purify_fe_mul(&t5, &t5, &x3);
    purify_fe_add(&x3, &t1, &t2);
    purify_fe_sub(&t5, &t5, &x3);
    purify_fe_mul(&z3, &curve->a, &t4);
    purify_fe_mul(&x3, &b3, &t2);
    purify_fe_add(&z3, &x3, &z3);
    purify_fe_sub(&x3, &t1, &z3);
    purify_fe_add(&z3, &t1, &z3);
    purify_fe_mul(&y3, &x3, &z3);
    purify_fe_add(&t1, &t0, &t0);
    purify_fe_add(&t1, &t1, &t0);
    purify_fe_mul(&t2, &curve->a, &t2);
    purify_fe_mul(&t4, &b3, &t4);
    purify_fe_add(&t1, &t1, &t2);
    purify_fe_sub(&t2, &t0, &t2);
    purify_fe_mul(&t2, &curve->a, &t2);
    purify_fe_add(&t4, &t4, &t2);
    purify_fe_mul(&t0, &t1, &t4);
    purify_fe_add(&y3, &y3, &t0);
    purify_fe_mul(&t0, &t5, &t4);
    purify_fe_mul(&x3, &t3, &x3);
    purify_fe_sub(&x3, &x3, &t0);
    purify_fe_mul(&t0, &t3, &t1);
    purify_fe_mul(&z3, &t5, &z3);
    purify_fe_add(&z3, &z3, &t0);

    out.x = x3;
    out.y = y3;
    out.z = z3;
    return out;
}

static purify_complete_projective_point
purify_curve_complete_double(const purify_curve* curve,
                             const purify_complete_projective_point* point) {
    purify_complete_projective_point out;
    purify_fe b3;
    purify_fe t0;
    purify_fe t1;
    purify_fe t2;
    purify_fe t3;
    purify_fe x3;
    purify_fe y3;
    purify_fe z3;

    purify_fe_add(&b3, &curve->b, &curve->b);
    purify_fe_add(&b3, &b3, &curve->b);
    purify_fe_mul(&t0, &point->x, &point->x);
    purify_fe_mul(&t1, &point->y, &point->y);
    purify_fe_mul(&t2, &point->z, &point->z);
    purify_fe_mul(&t3, &point->x, &point->y);
    purify_fe_add(&t3, &t3, &t3);
    purify_fe_mul(&z3, &point->x, &point->z);
    purify_fe_add(&z3, &z3, &z3);
    purify_fe_mul(&x3, &curve->a, &z3);
    purify_fe_mul(&y3, &b3, &t2);
    purify_fe_add(&y3, &x3, &y3);
    purify_fe_sub(&x3, &t1, &y3);
    purify_fe_add(&y3, &t1, &y3);
    purify_fe_mul(&y3, &x3, &y3);
    purify_fe_mul(&x3, &t3, &x3);
    purify_fe_mul(&z3, &b3, &z3);
    purify_fe_mul(&t2, &curve->a, &t2);
    purify_fe_sub(&t3, &t0, &t2);
    purify_fe_mul(&t3, &curve->a, &t3);
    purify_fe_add(&t3, &t3, &z3);
    purify_fe_add(&z3, &t0, &t0);
    purify_fe_add(&t0, &z3, &t0);
    purify_fe_add(&t0, &t0, &t2);
    purify_fe_mul(&t0, &t0, &t3);
    purify_fe_add(&y3, &y3, &t0);
    purify_fe_mul(&t2, &point->y, &point->z);
    purify_fe_add(&t2, &t2, &t2);
    purify_fe_mul(&t0, &t2, &t3);
    purify_fe_sub(&x3, &x3, &t0);
    purify_fe_mul(&z3, &t2, &t1);
    purify_fe_add(&z3, &z3, &z3);
    purify_fe_add(&z3, &z3, &z3);

    out.x = x3;
    out.y = y3;
    out.z = z3;
    return out;
}

void purify_curve_prime_p(uint64_t out[4]) {
    purify_curve_copy_u256(out, kPurifyPrimeP);
}

void purify_curve_order_n1(uint64_t out[4]) {
    purify_curve_copy_u256(out, kPurifyOrderN1);
}

void purify_curve_order_n2(uint64_t out[4]) {
    purify_curve_copy_u256(out, kPurifyOrderN2);
}

void purify_curve_half_n1(uint64_t out[4]) {
    purify_curve_copy_u256(out, kPurifyHalfN1);
}

void purify_curve_half_n2(uint64_t out[4]) {
    purify_curve_copy_u256(out, kPurifyHalfN2);
}

void purify_curve_packed_secret_key_space_size(uint64_t out[8]) {
    purify_u512_multiply_u256(out, kPurifyHalfN1, kPurifyHalfN2);
}

void purify_curve_packed_public_key_space_size(uint64_t out[8]) {
    purify_u512_multiply_u256(out, kPurifyPrimeP, kPurifyPrimeP);
}

void purify_curve_two_p(uint64_t out[5]) {
    purify_u320_widen_u256(out, kPurifyPrimeP);
    purify_u320_try_mul_small(out, 2);
}

void purify_curve_field_a(purify_fe* out) {
    purify_fe_set_u64(out, 118);
}

void purify_curve_field_b(purify_fe* out) {
    purify_fe_set_u64(out, 339);
}

void purify_curve_field_d(purify_fe* out) {
    purify_fe_set_u64(out, 5);
}

void purify_curve_field_di(purify_fe* out) {
    int ok = purify_fe_set_u256(out, kPurifyFieldDi);
    assert(ok != 0);
    (void)ok;
}

void purify_curve_jacobian_infinity(purify_jacobian_point* out) {
    purify_fe_set_zero(&out->x);
    purify_fe_set_u64(&out->y, 1);
    purify_fe_set_zero(&out->z);
    out->infinity = 1;
}

void purify_curve_affine(purify_affine_point* out, const purify_curve* curve, const purify_jacobian_point* point) {
    purify_fe inv;
    purify_fe inv2;
    purify_fe inv3;
    (void)curve;

    if (point->infinity != 0 || purify_fe_is_zero(&point->z) != 0) {
        purify_fe_set_zero(&out->x);
        purify_fe_set_zero(&out->y);
        out->infinity = 1;
        return;
    }

    purify_fe_inverse_var(&inv, &point->z);
    purify_fe_mul(&inv2, &inv, &inv);
    purify_fe_mul(&inv3, &inv2, &inv);
    purify_fe_mul(&out->x, &inv2, &point->x);
    purify_fe_mul(&out->y, &inv3, &point->y);
    out->infinity = 0;
}

void purify_curve_negate(purify_jacobian_point* out, const purify_jacobian_point* point) {
    if (point->infinity != 0) {
        *out = *point;
        return;
    }
    out->x = point->x;
    purify_fe_negate(&out->y, &point->y);
    out->z = point->z;
    out->infinity = 0;
}

int purify_curve_is_x_coord(const purify_curve* curve, const purify_fe* x) {
    purify_fe x2;
    purify_fe x3;
    purify_fe ax;
    purify_fe v;

    purify_fe_mul(&x2, x, x);
    purify_fe_mul(&x3, &x2, x);
    purify_fe_mul(&ax, &curve->a, x);
    purify_fe_add(&v, &x3, &ax);
    purify_fe_add(&v, &v, &curve->b);
    return purify_fe_legendre_symbol(&v) != -1;
}

int purify_curve_lift_x(purify_jacobian_point* out, const purify_curve* curve, const purify_fe* x) {
    purify_fe x2;
    purify_fe x3;
    purify_fe ax;
    purify_fe v;

    purify_fe_mul(&x2, x, x);
    purify_fe_mul(&x3, &x2, x);
    purify_fe_mul(&ax, &curve->a, x);
    purify_fe_add(&v, &x3, &ax);
    purify_fe_add(&v, &v, &curve->b);
    if (purify_fe_sqrt(&out->y, &v) == 0) {
        return 0;
    }

    out->x = *x;
    purify_fe_set_u64(&out->z, 1);
    out->infinity = 0;
    return 1;
}

void purify_curve_double(purify_jacobian_point* out, const purify_curve* curve, const purify_jacobian_point* point) {
    /* `purify_curve_mul()` doubles its accumulator in place, so preserve the input first. */
    purify_jacobian_point input = *point;
    purify_fe y1_2;
    purify_fe y1_4;
    purify_fe x1_2;
    purify_fe s;
    purify_fe m;
    purify_fe tmp;

    point = &input;

    if (point->infinity != 0 || purify_fe_is_zero(&point->z) != 0) {
        purify_curve_jacobian_infinity(out);
        return;
    }

    purify_fe_mul(&y1_2, &point->y, &point->y);
    purify_fe_mul(&y1_4, &y1_2, &y1_2);
    purify_fe_mul(&x1_2, &point->x, &point->x);
    purify_fe_set_u64(&tmp, 4);
    purify_fe_mul(&s, &tmp, &point->x);
    purify_fe_mul(&s, &s, &y1_2);
    purify_fe_set_u64(&tmp, 3);
    purify_fe_mul(&m, &tmp, &x1_2);
    if (purify_fe_is_zero(&curve->a) == 0) {
        purify_fe z1_2;
        purify_fe z1_4;
        purify_fe az;
        purify_fe_mul(&z1_2, &point->z, &point->z);
        purify_fe_mul(&z1_4, &z1_2, &z1_2);
        purify_fe_mul(&az, &curve->a, &z1_4);
        purify_fe_add(&m, &m, &az);
    }
    purify_fe_mul(&out->x, &m, &m);
    purify_fe_set_u64(&tmp, 2);
    purify_fe_mul(&tmp, &tmp, &s);
    purify_fe_sub(&out->x, &out->x, &tmp);
    purify_fe_sub(&out->y, &s, &out->x);
    purify_fe_mul(&out->y, &m, &out->y);
    purify_fe_set_u64(&tmp, 8);
    purify_fe_mul(&tmp, &tmp, &y1_4);
    purify_fe_sub(&out->y, &out->y, &tmp);
    purify_fe_set_u64(&tmp, 2);
    purify_fe_mul(&out->z, &tmp, &point->y);
    purify_fe_mul(&out->z, &out->z, &point->z);
    out->infinity = 0;
}

void purify_curve_add_mixed(purify_jacobian_point* out, const purify_curve* curve,
                            const purify_jacobian_point* lhs, const purify_affine_point* rhs) {
    purify_fe z1_2;
    purify_fe z1_3;
    purify_fe u2;
    purify_fe s2;
    purify_fe h;
    purify_fe r;
    purify_fe h_2;
    purify_fe h_3;
    purify_fe u1_h_2;
    purify_fe tmp;
    (void)curve;

    if (lhs->infinity != 0 || purify_fe_is_zero(&lhs->z) != 0) {
        out->x = rhs->x;
        out->y = rhs->y;
        purify_fe_set_u64(&out->z, 1);
        out->infinity = rhs->infinity;
        return;
    }

    purify_fe_mul(&z1_2, &lhs->z, &lhs->z);
    purify_fe_mul(&z1_3, &z1_2, &lhs->z);
    purify_fe_mul(&u2, &rhs->x, &z1_2);
    purify_fe_mul(&s2, &rhs->y, &z1_3);
    if (purify_fe_eq(&lhs->x, &u2) != 0) {
        if (purify_fe_eq(&lhs->y, &s2) == 0) {
            purify_curve_jacobian_infinity(out);
            return;
        }
        purify_curve_double(out, curve, lhs);
        return;
    }

    purify_fe_sub(&h, &u2, &lhs->x);
    purify_fe_sub(&r, &s2, &lhs->y);
    purify_fe_mul(&h_2, &h, &h);
    purify_fe_mul(&h_3, &h_2, &h);
    purify_fe_mul(&u1_h_2, &lhs->x, &h_2);
    purify_fe_mul(&out->x, &r, &r);
    purify_fe_sub(&out->x, &out->x, &h_3);
    purify_fe_set_u64(&tmp, 2);
    purify_fe_mul(&tmp, &tmp, &u1_h_2);
    purify_fe_sub(&out->x, &out->x, &tmp);
    purify_fe_sub(&out->y, &u1_h_2, &out->x);
    purify_fe_mul(&out->y, &r, &out->y);
    purify_fe_mul(&tmp, &lhs->y, &h_3);
    purify_fe_sub(&out->y, &out->y, &tmp);
    purify_fe_mul(&out->z, &h, &lhs->z);
    out->infinity = 0;
}

void purify_curve_add(purify_jacobian_point* out, const purify_curve* curve,
                      const purify_jacobian_point* lhs, const purify_jacobian_point* rhs) {
    purify_fe z1_2;
    purify_fe z1_3;
    purify_fe z2_2;
    purify_fe z2_3;
    purify_fe u1;
    purify_fe u2;
    purify_fe s1;
    purify_fe s2;
    purify_fe h;
    purify_fe r;
    purify_fe h_2;
    purify_fe h_3;
    purify_fe u1_h_2;
    purify_fe tmp;

    if (lhs->infinity != 0 || purify_fe_is_zero(&lhs->z) != 0) {
        *out = *rhs;
        return;
    }
    if (rhs->infinity != 0 || purify_fe_is_zero(&rhs->z) != 0) {
        *out = *lhs;
        return;
    }
    if (purify_fe_is_one(&rhs->z) != 0) {
        purify_affine_point rhs_affine;
        rhs_affine.x = rhs->x;
        rhs_affine.y = rhs->y;
        rhs_affine.infinity = 0;
        purify_curve_add_mixed(out, curve, lhs, &rhs_affine);
        return;
    }
    if (purify_fe_is_one(&lhs->z) != 0) {
        purify_affine_point lhs_affine;
        lhs_affine.x = lhs->x;
        lhs_affine.y = lhs->y;
        lhs_affine.infinity = 0;
        purify_curve_add_mixed(out, curve, rhs, &lhs_affine);
        return;
    }

    purify_fe_mul(&z1_2, &lhs->z, &lhs->z);
    purify_fe_mul(&z1_3, &z1_2, &lhs->z);
    purify_fe_mul(&z2_2, &rhs->z, &rhs->z);
    purify_fe_mul(&z2_3, &z2_2, &rhs->z);
    purify_fe_mul(&u1, &lhs->x, &z2_2);
    purify_fe_mul(&u2, &rhs->x, &z1_2);
    purify_fe_mul(&s1, &lhs->y, &z2_3);
    purify_fe_mul(&s2, &rhs->y, &z1_3);
    if (purify_fe_eq(&u1, &u2) != 0) {
        if (purify_fe_eq(&s1, &s2) == 0) {
            purify_curve_jacobian_infinity(out);
            return;
        }
        purify_curve_double(out, curve, lhs);
        return;
    }

    purify_fe_sub(&h, &u2, &u1);
    purify_fe_sub(&r, &s2, &s1);
    purify_fe_mul(&h_2, &h, &h);
    purify_fe_mul(&h_3, &h_2, &h);
    purify_fe_mul(&u1_h_2, &u1, &h_2);
    purify_fe_mul(&out->x, &r, &r);
    purify_fe_sub(&out->x, &out->x, &h_3);
    purify_fe_set_u64(&tmp, 2);
    purify_fe_mul(&tmp, &tmp, &u1_h_2);
    purify_fe_sub(&out->x, &out->x, &tmp);
    purify_fe_sub(&out->y, &u1_h_2, &out->x);
    purify_fe_mul(&out->y, &r, &out->y);
    purify_fe_mul(&tmp, &s1, &h_3);
    purify_fe_sub(&out->y, &out->y, &tmp);
    purify_fe_mul(&out->z, &h, &lhs->z);
    purify_fe_mul(&out->z, &out->z, &rhs->z);
    out->infinity = 0;
}

void purify_curve_mul(purify_jacobian_point* out, const purify_curve* curve,
                      const purify_jacobian_point* point, const uint64_t scalar[4]) {
    purify_jacobian_point result;
    size_t bits = purify_u256_bit_length(scalar);
    size_t i;

    purify_curve_jacobian_infinity(&result);
    for (i = bits; i-- > 0;) {
        purify_curve_double(&result, curve, &result);
        if (purify_u256_bit(scalar, i) != 0) {
            purify_jacobian_point sum;
            purify_curve_add(&sum, curve, &result, point);
            result = sum;
        }
    }
    *out = result;
}

static void purify_curve_mul_secret_ladder_core(purify_complete_projective_point* out, const purify_curve* curve,
                                                const purify_jacobian_point* point, const uint64_t scalar[4]) {
    purify_complete_projective_point r0 = purify_curve_complete_identity();
    purify_complete_projective_point r1 = purify_curve_secret_input_point(curve, point);
    unsigned int prev_bit = 0;
    size_t bits = purify_u256_bit_length(curve->n);
    size_t i;

    for (i = bits; i-- > 0;) {
        unsigned int bit = purify_u256_bit(scalar, i) != 0 ? 1u : 0u;
        purify_curve_complete_swap(&r0, &r1, (int)(bit ^ prev_bit));
        {
            purify_complete_projective_point sum = purify_curve_complete_add(curve, &r0, &r1);
            purify_complete_projective_point doubled = purify_curve_complete_double(curve, &r0);
            r1 = sum;
            r0 = doubled;
        }
        prev_bit = bit;
    }
    purify_curve_complete_swap(&r0, &r1, (int)prev_bit);
    *out = r0;
}

#if defined(PURIFY_VALGRIND_TESTING)
void purify_curve_mul_secret_ladder_only(purify_complete_projective_point* out, const purify_curve* curve,
                                         const purify_jacobian_point* point, const uint64_t scalar[4]) {
    purify_curve_mul_secret_ladder_core(out, curve, point, scalar);
}
#endif

int purify_curve_mul_secret_affine(purify_affine_point* out, const purify_curve* curve,
                                   const purify_jacobian_point* point, const uint64_t scalar[4]) {
    purify_complete_projective_point r0;

    purify_curve_mul_secret_ladder_core(&r0, curve, point, scalar);
    if (purify_fe_is_zero(&r0.z) != 0) {
        return 0;
    }

    {
        purify_fe inv;
        purify_fe_inverse(&inv, &r0.z);
        purify_fe_mul(&out->x, &r0.x, &inv);
        purify_fe_mul(&out->y, &r0.y, &inv);
        out->infinity = 0;
    }
    return 1;
}

int purify_curve_hash_to_curve(purify_jacobian_point* out, const purify_curve* curve,
                               const unsigned char* data, size_t data_len) {
    uint64_t range[5];
    int info_counter;

    if (out == NULL || curve == NULL || (data_len != 0u && data == NULL)) {
        return 0;
    }

    purify_curve_jacobian_infinity(out);
    purify_curve_two_p(range);
    for (info_counter = 0; info_counter < 256; ++info_counter) {
        uint64_t value[5];
        uint64_t x_candidate[5];
        uint64_t x_words[4];
        purify_fe x;
        int ok;

#if PURIFY_USE_LEGACY_FIELD_HASHES
        ok = purify_curve_hash_to_int_hkdf_u320(value, data, data_len, range, (unsigned char)info_counter);
#else
        ok = purify_curve_hash_to_int_tagged_u320(value, data, data_len, range, (unsigned char)info_counter);
#endif
        if (ok == 0) {
            continue;
        }

        purify_u320_shifted_right(x_candidate, value, 1u);
        ok = purify_u256_try_narrow_u320(x_words, x_candidate);
        assert(ok != 0);
        if (ok == 0) {
            return 0;
        }
        ok = purify_fe_set_u256(&x, x_words);
        assert(ok != 0);
        if (ok == 0) {
            return 0;
        }
        if (purify_curve_is_x_coord(curve, &x) == 0) {
            continue;
        }
        if (purify_curve_lift_x(out, curve, &x) == 0) {
            continue;
        }
        if (purify_u320_bit(value, 0u) != 0) {
            purify_curve_negate(out, out);
        }
        return 1;
    }

    return 0;
}

int purify_curve_is_valid_secret_key(const uint64_t value[8]) {
    uint64_t upper_bound[8];
    purify_curve_packed_secret_key_space_size(upper_bound);
    return purify_u512_compare(value, upper_bound) < 0;
}

int purify_curve_is_valid_public_key(const uint64_t value[8]) {
    uint64_t upper_bound[8];
    purify_curve_packed_public_key_space_size(upper_bound);
    return purify_u512_compare(value, upper_bound) < 0;
}

int purify_curve_unpack_secret(uint64_t first[4], uint64_t second[4], const uint64_t value[8]) {
    uint64_t denominator[8];
    uint64_t quotient[8];
    uint64_t remainder[8];

    if (purify_curve_is_valid_secret_key(value) == 0) {
        return 0;
    }

    purify_u512_widen_u256(denominator, kPurifyHalfN1);
    if (purify_u512_try_divmod_same(quotient, remainder, value, denominator) == 0) {
        return 0;
    }
    if (purify_u256_try_narrow_u512(first, remainder) == 0 || purify_u256_try_narrow_u512(second, quotient) == 0) {
        return 0;
    }
    purify_u256_try_add_small(first, 1);
    purify_u256_try_add_small(second, 1);
    return 1;
}

int purify_curve_unpack_public(uint64_t first[4], uint64_t second[4], const uint64_t value[8]) {
    uint64_t denominator[8];
    uint64_t quotient[8];
    uint64_t remainder[8];

    if (purify_curve_is_valid_public_key(value) == 0) {
        return 0;
    }

    purify_u512_widen_u256(denominator, kPurifyPrimeP);
    if (purify_u512_try_divmod_same(quotient, remainder, value, denominator) == 0) {
        return 0;
    }
    if (purify_u256_try_narrow_u512(first, remainder) == 0 || purify_u256_try_narrow_u512(second, quotient) == 0) {
        return 0;
    }
    return 1;
}

void purify_curve_pack_public(uint64_t out[8], const uint64_t x1[4], const uint64_t x2[4]) {
    uint64_t wide_x1[8];
    purify_u512_multiply_u256(out, kPurifyPrimeP, x2);
    purify_u512_widen_u256(wide_x1, x1);
    purify_u512_try_add(out, wide_x1);
}

void purify_curve_combine(purify_fe* out, const purify_fe* x1, const purify_fe* x2) {
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

int purify_curve_key_to_bits(int* out_bits, size_t out_len, const uint64_t value[4], const uint64_t max_value[4]) {
    uint64_t copy[4];
    size_t bits;
    size_t i;

    if ((out_len != 0 && out_bits == NULL) || purify_u256_is_zero(value) != 0 || purify_u256_compare(value, max_value) > 0) {
        return 0;
    }

    bits = purify_u256_bit_length(max_value);
    if (out_len < bits) {
        return 0;
    }

    purify_curve_copy_u256(copy, value);
    purify_u256_try_sub(copy, (const uint64_t[4]){UINT64_C(1), UINT64_C(0), UINT64_C(0), UINT64_C(0)});
    for (i = 0; i < bits; ++i) {
        out_bits[i] = purify_u256_bit(copy, i) != 0 ? 1 : 0;
    }
    for (i = 3; i < bits; i += 3) {
        int flip = 1 - out_bits[i];
        out_bits[i - 1] ^= flip;
        out_bits[i - 2] ^= flip;
        out_bits[i] ^= 1;
    }
    return 1;
}
