// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <assert.h>

#include "curve_encoding_helpers.h"
#include "curve_model_helpers.h"

void purify_curve_unpack_secret_unchecked(uint64_t first[4], uint64_t second[4], const uint64_t value[8]);
void purify_curve_mul_secret_affine_unchecked(purify_affine_point* out, const purify_curve* curve,
                                              const purify_jacobian_point* point, const uint64_t scalar[4]);

static void purify_cbmc_make_generator2_point(purify_jacobian_point* out) {
    purify_fe_set_u64(&out->x, 76u);
    purify_fe_set_u64(&out->y, 10u);
    purify_fe_set_u64(&out->z, 1u);
    out->infinity = 0;
}

int main(void) {
    purify_curve curve2;
    purify_jacobian_point generator2;
    uint64_t z1[4];
    uint64_t z2[4];
    uint64_t packed_secret[8];
    uint64_t unpacked1[4];
    uint64_t unpacked2[4];
    purify_jacobian_point semantic_public2_projective;
    purify_affine_point semantic_public2;
    purify_affine_point unchecked_public2;
    uint64_t semantic_x2[4];
    uint64_t unchecked_x2[4];

    purify_cbmc_make_curve2(&curve2);
    purify_cbmc_make_generator2_point(&generator2);

    assert(purify_cbmc_point_on_curve(&curve2, &generator2));

    purify_u256_set_u64(z1, 1u + (nondet_uint64_t() % 54u));
    purify_u256_set_u64(z2, 1u + (nondet_uint64_t() % 53u));
    purify_cbmc_encode_secret_value(packed_secret, z1, z2);

    assert(purify_curve_is_valid_secret_key(packed_secret) != 0);
    purify_curve_unpack_secret_unchecked(unpacked1, unpacked2, packed_secret);
    assert(purify_u256_compare(unpacked1, z1) == 0);
    assert(purify_u256_compare(unpacked2, z2) == 0);

    purify_curve_mul(&semantic_public2_projective, &curve2, &generator2, z2);
    purify_curve_affine(&semantic_public2, &curve2, &semantic_public2_projective);
    purify_curve_mul_secret_affine_unchecked(&unchecked_public2, &curve2, &generator2, unpacked2);

    assert(purify_cbmc_affine_eq(&semantic_public2, &unchecked_public2));
    purify_fe_get_u256(semantic_x2, &semantic_public2.x);
    purify_fe_get_u256(unchecked_x2, &unchecked_public2.x);
    assert(purify_u256_compare(semantic_x2, unchecked_x2) == 0);

    return 0;
}
