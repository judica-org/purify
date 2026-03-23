// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "field.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct purify_jacobian_point {
    purify_fe x;
    purify_fe y;
    purify_fe z;
    int infinity;
} purify_jacobian_point;

typedef struct purify_affine_point {
    purify_fe x;
    purify_fe y;
    int infinity;
} purify_affine_point;

typedef struct purify_complete_projective_point {
    purify_fe x;
    purify_fe y;
    purify_fe z;
} purify_complete_projective_point;

typedef struct purify_curve {
    purify_fe a;
    purify_fe b;
    uint64_t n[4];
} purify_curve;

void purify_curve_prime_p(uint64_t out[4]);
void purify_curve_order_n1(uint64_t out[4]);
void purify_curve_order_n2(uint64_t out[4]);
void purify_curve_half_n1(uint64_t out[4]);
void purify_curve_half_n2(uint64_t out[4]);
void purify_curve_packed_secret_key_space_size(uint64_t out[8]);
void purify_curve_packed_public_key_space_size(uint64_t out[8]);
void purify_curve_two_p(uint64_t out[5]);

void purify_curve_field_a(purify_fe* out);
void purify_curve_field_b(purify_fe* out);
void purify_curve_field_d(purify_fe* out);
void purify_curve_field_di(purify_fe* out);

void purify_curve_jacobian_infinity(purify_jacobian_point* out);
void purify_curve_affine(purify_affine_point* out, const purify_curve* curve, const purify_jacobian_point* point);
void purify_curve_negate(purify_jacobian_point* out, const purify_jacobian_point* point);
int purify_curve_is_x_coord(const purify_curve* curve, const purify_fe* x);
int purify_curve_lift_x(purify_jacobian_point* out, const purify_curve* curve, const purify_fe* x);
void purify_curve_double(purify_jacobian_point* out, const purify_curve* curve, const purify_jacobian_point* point);
void purify_curve_add_mixed(purify_jacobian_point* out, const purify_curve* curve,
                            const purify_jacobian_point* lhs, const purify_affine_point* rhs);
void purify_curve_add(purify_jacobian_point* out, const purify_curve* curve,
                      const purify_jacobian_point* lhs, const purify_jacobian_point* rhs);
void purify_curve_mul(purify_jacobian_point* out, const purify_curve* curve,
                      const purify_jacobian_point* point, const uint64_t scalar[4]);
int purify_curve_mul_secret_affine(purify_affine_point* out, const purify_curve* curve,
                                   const purify_jacobian_point* point, const uint64_t scalar[4]);
int purify_curve_hash_to_curve(purify_jacobian_point* out, const purify_curve* curve,
                               const unsigned char* data, size_t data_len);

int purify_curve_is_valid_secret_key(const uint64_t value[8]);
int purify_curve_is_valid_public_key(const uint64_t value[8]);
int purify_curve_unpack_secret(uint64_t first[4], uint64_t second[4], const uint64_t value[8]);
int purify_curve_unpack_public(uint64_t first[4], uint64_t second[4], const uint64_t value[8]);
void purify_curve_pack_public(uint64_t out[8], const uint64_t x1[4], const uint64_t x2[4]);
void purify_curve_combine(purify_fe* out, const purify_fe* x1, const purify_fe* x2);
int purify_curve_key_to_bits(int* out_bits, size_t out_len, const uint64_t value[4], const uint64_t max_value[4]);

#ifdef __cplusplus
}
#endif
