// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "purify_field.h"

#include <string.h>

static const uint64_t kPurifyFieldPrime[4] = {
    UINT64_C(0xBFD25E8CD0364141),
    UINT64_C(0xBAAEDCE6AF48A03B),
    UINT64_C(0xFFFFFFFFFFFFFFFE),
    UINT64_C(0xFFFFFFFFFFFFFFFF),
};

static const uint64_t kPurifyU256One[4] = {
    UINT64_C(1), UINT64_C(0), UINT64_C(0), UINT64_C(0),
};

void purify_fe_set_zero(purify_fe* out) {
    purify_scalar_set_int(&out->value, 0);
}

void purify_fe_set_u64(purify_fe* out, uint64_t value) {
    purify_scalar_set_u64(&out->value, value);
}

void purify_fe_set_i64(purify_fe* out, int64_t value) {
    if (value >= 0) {
        purify_fe_set_u64(out, (uint64_t)value);
        return;
    }

    purify_fe_set_u64(out, (uint64_t)(-(value + 1)) + 1u);
    purify_fe_negate(out, out);
}

int purify_fe_set_b32(purify_fe* out, const unsigned char input32[32]) {
    int overflow = 0;
    purify_scalar_set_b32(&out->value, input32, &overflow);
    return overflow == 0;
}

int purify_fe_set_u256(purify_fe* out, const uint64_t value[4]) {
    unsigned char bytes[32];
    purify_u256_to_bytes_be(bytes, value);
    return purify_fe_set_b32(out, bytes);
}

void purify_fe_get_b32(unsigned char output32[32], const purify_fe* value) {
    purify_scalar_get_b32(output32, &value->value);
}

void purify_fe_get_u256(uint64_t out[4], const purify_fe* value) {
    unsigned char bytes[32];
    purify_fe_get_b32(bytes, value);
    purify_u256_from_bytes_be(out, bytes, sizeof(bytes));
}

int purify_fe_is_zero(const purify_fe* value) {
    return purify_scalar_is_zero(&value->value);
}

int purify_fe_is_one(const purify_fe* value) {
    return purify_scalar_is_one(&value->value);
}

int purify_fe_is_odd(const purify_fe* value) {
    return purify_scalar_is_even(&value->value) == 0;
}

int purify_fe_eq(const purify_fe* lhs, const purify_fe* rhs) {
    return purify_scalar_eq(&lhs->value, &rhs->value);
}

void purify_fe_negate(purify_fe* out, const purify_fe* value) {
    purify_fe input = *value;
    purify_scalar_negate(&out->value, &input.value);
}

void purify_fe_cmov(purify_fe* dst, const purify_fe* src, int flag) {
    purify_scalar_cmov(&dst->value, &src->value, flag);
}

void purify_fe_inverse(purify_fe* out, const purify_fe* value) {
    purify_fe input = *value;
    purify_scalar_inverse(&out->value, &input.value);
}

void purify_fe_inverse_var(purify_fe* out, const purify_fe* value) {
    purify_fe input = *value;
    purify_scalar_inverse_var(&out->value, &input.value);
}

void purify_fe_add(purify_fe* out, const purify_fe* lhs, const purify_fe* rhs) {
    purify_fe left = *lhs;
    purify_fe right = *rhs;
    purify_scalar_add(&out->value, &left.value, &right.value);
}

void purify_fe_sub(purify_fe* out, const purify_fe* lhs, const purify_fe* rhs) {
    purify_fe negated;
    purify_fe_negate(&negated, rhs);
    purify_fe_add(out, lhs, &negated);
}

void purify_fe_mul(purify_fe* out, const purify_fe* lhs, const purify_fe* rhs) {
    purify_fe left = *lhs;
    purify_fe right = *rhs;
    purify_scalar_mul(&out->value, &left.value, &right.value);
}

void purify_fe_square(purify_fe* out, const purify_fe* value) {
    purify_fe_mul(out, value, value);
}

void purify_fe_pow(purify_fe* out, const purify_fe* value, const uint64_t exponent[4]) {
    purify_fe result;
    size_t bits;
    size_t i;

    purify_fe_set_u64(&result, 1);
    bits = purify_u256_bit_length(exponent);
    for (i = bits; i-- > 0;) {
        purify_fe_square(&result, &result);
        if (purify_u256_bit(exponent, i) != 0) {
            purify_fe_mul(&result, &result, value);
        }
    }
    *out = result;
}

int purify_fe_is_square(const purify_fe* value) {
    uint64_t exponent[4];
    purify_fe result;

    if (purify_fe_is_zero(value) != 0) {
        return 1;
    }

    memcpy(exponent, kPurifyFieldPrime, sizeof(exponent));
    purify_u256_try_sub(exponent, kPurifyU256One);
    purify_u256_shift_right_one(exponent);
    purify_fe_pow(&result, value, exponent);
    return purify_fe_is_one(&result);
}

int purify_fe_legendre_symbol(const purify_fe* value) {
    if (purify_fe_is_zero(value) != 0) {
        return 0;
    }
    return purify_fe_is_square(value) != 0 ? 1 : -1;
}

int purify_fe_sqrt(purify_fe* out, const purify_fe* value) {
    uint64_t q[4];
    unsigned int s = 0;
    purify_fe z;
    purify_fe c;
    purify_fe x;
    purify_fe t;
    purify_fe one;

    if (purify_fe_is_zero(value) != 0) {
        return 0;
    }
    if (purify_fe_is_square(value) == 0) {
        return 0;
    }

    memcpy(q, kPurifyFieldPrime, sizeof(q));
    purify_u256_try_sub(q, kPurifyU256One);
    while (purify_u256_bit(q, 0) == 0) {
        purify_u256_shift_right_one(q);
        ++s;
    }

    if (s == 1u) {
        uint64_t exponent[4];
        memcpy(exponent, q, sizeof(exponent));
        purify_u256_try_add_small(exponent, 1);
        purify_u256_shift_right_one(exponent);
        purify_fe_pow(out, value, exponent);
        return 1;
    }

    purify_fe_set_u64(&z, 2);
    while (purify_fe_legendre_symbol(&z) != -1) {
        purify_fe next_z;
        purify_fe_set_u64(&one, 1);
        purify_fe_add(&next_z, &z, &one);
        z = next_z;
    }

    purify_fe_pow(&c, &z, q);

    {
        uint64_t exponent[4];
        memcpy(exponent, q, sizeof(exponent));
        purify_u256_try_add_small(exponent, 1);
        purify_u256_shift_right_one(exponent);
        purify_fe_pow(&x, value, exponent);
    }

    purify_fe_pow(&t, value, q);
    purify_fe_set_u64(&one, 1);

    while (purify_fe_eq(&t, &one) == 0) {
        unsigned int i = 1;
        unsigned int m = s;
        purify_fe t2i;

        purify_fe_square(&t2i, &t);
        while (i < m && purify_fe_eq(&t2i, &one) == 0) {
            purify_fe_square(&t2i, &t2i);
            ++i;
        }
        if (i == m) {
            return 0;
        }

        {
            uint64_t b_exp[4];
            uint64_t shifted[4];
            purify_fe b;
            purify_fe b2;

            purify_u256_set_u64(b_exp, 1);
            purify_u256_shifted_left(shifted, b_exp, m - i - 1u);
            memcpy(b_exp, shifted, sizeof(b_exp));
            purify_fe_pow(&b, &c, b_exp);
            purify_fe_mul(&x, &x, &b);
            purify_fe_square(&b2, &b);
            purify_fe_mul(&t, &t, &b2);
            c = b2;
            s = i;
        }
    }

    *out = x;
    return 1;
}
