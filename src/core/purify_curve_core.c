// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "purify_curve_core.h"

#include <assert.h>
#include <string.h>

static const uint64_t kPurifyPrimeP[4] = {
    UINT64_C(0xBFD25E8CD0364141),
    UINT64_C(0xBAAEDCE6AF48A03B),
    UINT64_C(0xFFFFFFFFFFFFFFFE),
    UINT64_C(0xFFFFFFFFFFFFFFFF),
};

static const uint64_t kPurifyOrderN1[4] = {
    UINT64_C(0x8A5A2A2C58E547E9),
    UINT64_C(0xA328F24405347212),
    UINT64_C(0xFFFFFFFFFFFFFFFF),
    UINT64_C(0xFFFFFFFFFFFFFFFF),
};

static const uint64_t kPurifyOrderN2[4] = {
    UINT64_C(0xF54A92ED47873A9B),
    UINT64_C(0xD234C789595CCE64),
    UINT64_C(0xFFFFFFFFFFFFFFFD),
    UINT64_C(0xFFFFFFFFFFFFFFFF),
};

static const uint64_t kPurifyHalfN1[4] = {
    UINT64_C(0x452D15162C72A3F4),
    UINT64_C(0xD1947922029A3909),
    UINT64_C(0xFFFFFFFFFFFFFFFF),
    UINT64_C(0x7FFFFFFFFFFFFFFF),
};

static const uint64_t kPurifyHalfN2[4] = {
    UINT64_C(0x7AA54976A3C39D4D),
    UINT64_C(0xE91A63C4ACAE6732),
    UINT64_C(0xFFFFFFFFFFFFFFFE),
    UINT64_C(0x7FFFFFFFFFFFFFFF),
};

static const uint64_t kPurifyFieldDi[4] = {
    UINT64_C(0x4CBA8C385348E6E7),
    UINT64_C(0xE445F1F5DFB6A67E),
    UINT64_C(0x6666666666666665),
    UINT64_C(0x6666666666666666),
};

static void purify_curve_copy_u256(uint64_t out[4], const uint64_t value[4]) {
    memcpy(out, value, 4u * sizeof(uint64_t));
}

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

int purify_curve_mul_secret_affine(purify_affine_point* out, const purify_curve* curve,
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
