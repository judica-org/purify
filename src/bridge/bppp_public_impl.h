// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/*
 * Public multi-scalar multiplication, point validation and hash-to-point.
 *
 * Part of the Purify secp256k1 bridge translation unit. Include only from
 * bppp_bridge.c, after secp256k1.c and the parts listed before this one.
 */

#ifndef PURIFY_BRIDGE_BPPP_PUBLIC_IMPL_H
#define PURIFY_BRIDGE_BPPP_PUBLIC_IMPL_H

int purify_bppp_generators_to_points(purify_secp_context* context,
                                   const unsigned char* generators33, size_t generators_count,
                                   unsigned char* points_out33) {
    secp256k1_context* ctx = purify_context_handle(context);
    size_t bytes, i;

    if (ctx == NULL || generators33 == NULL || points_out33 == NULL || generators_count == 0 ||
        !purify_bridge_checked_mul_size(generators_count, 33u, &bytes)) {
        return 0;
    }
    for (i = 0; i < generators_count; ++i) {
        secp256k1_ge point;
        if (!purify_parse_generator_as_ge(ctx, generators33 + 33u * i, &point) ||
            !purify_serialize_point(points_out33 + 33u * i, &point)) {
            return 0;
        }
    }
    return 1;
}

typedef struct purify_bppp_public_msm_data {
    const unsigned char* points33;
    const unsigned char* scalars32;
} purify_bppp_public_msm_data;

static int purify_bppp_public_msm_cb(secp256k1_scalar* scalar, secp256k1_ge* point,
                                   size_t index, void* data_ptr) {
    const purify_bppp_public_msm_data* data = (const purify_bppp_public_msm_data*)data_ptr;
    return purify_parse_scalar(data->scalars32 + 32u * index, scalar, 0)
        && secp256k1_ge_parse_ext(point, data->points33 + 33u * index);
}

int purify_bppp_public_msm(purify_secp_context* context,
                         const unsigned char* points33, const unsigned char* scalars32,
                         size_t count, unsigned char out33[33]) {
    secp256k1_context* ctx = purify_context_handle(context);
    secp256k1_scratch_space* scratch = NULL;
    secp256k1_gej result_j;
    secp256k1_ge result;
    purify_bppp_public_msm_data data;
    size_t point_bytes, scalar_bytes;
    int ok;

    if (ctx == NULL || out33 == NULL || (count != 0 && (points33 == NULL || scalars32 == NULL)) ||
        !purify_bridge_checked_mul_size(count, 33u, &point_bytes) ||
        !purify_bridge_checked_mul_size(count, 32u, &scalar_bytes)) {
        return 0;
    }
    if (count == 0) {
        memset(out33, 0, 33);
        return 1;
    }
    memset(out33, 0, 33);
    data.points33 = points33;
    data.scalars32 = scalars32;
    if (count <= 8u) {
        ok = secp256k1_ecmult_multi_var(&ctx->error_callback, NULL,
                                       &result_j, NULL,
                                       purify_bppp_public_msm_cb, &data,
                                       count);
    } else {
        scratch = secp256k1_scratch_space_create(
            ctx, purify_bulletproof_msm_scratch_size);
        if (scratch == NULL) return 0;
        ok = secp256k1_ecmult_multi_var(
            &ctx->error_callback, scratch, &result_j, NULL,
            purify_bppp_public_msm_cb, &data, count);
    }
    if (ok) {
        secp256k1_ge_set_gej_var(&result, &result_j);
        secp256k1_ge_serialize_ext(out33, &result);
    }
    if (scratch != NULL) {
        secp256k1_scratch_space_destroy(ctx, scratch);
    }
    return ok;
}

int purify_bppp_public_point_validate(
    const unsigned char point33[33]) {
    secp256k1_ge point;
    unsigned char canonical[33];

    if (point33 == NULL ||
        !secp256k1_ge_parse_ext(&point, point33)) {
        return 0;
    }
    secp256k1_ge_serialize_ext(canonical, &point);
    return memcmp(point33, canonical, sizeof(canonical)) == 0;
}

int purify_bppp_public_hash_to_point(purify_secp_context* context,
                                   const unsigned char* input, size_t input_len,
                                   unsigned char out33[33]) {
    static const unsigned char tag[] = "Purify/BPPP/PublicHashToPointV1";
    secp256k1_context* ctx = purify_context_handle(context);
    secp256k1_sha256 transcript;
    secp256k1_generator generator;
    secp256k1_ge point;
    unsigned char seed[32];

    if (ctx == NULL || out33 == NULL || (input_len != 0 && input == NULL)) return 0;
    secp256k1_sha256_initialize_tagged(&transcript, tag, sizeof(tag) - 1);
    if (input_len != 0) secp256k1_sha256_write(&transcript, input, input_len);
    secp256k1_sha256_finalize(&transcript, seed);
    secp256k1_sha256_clear(&transcript);
    if (!secp256k1_generator_generate(ctx, &generator, seed)) return 0;
    secp256k1_generator_load(&point, &generator);
    return purify_serialize_point(out33, &point);
}

#endif /* PURIFY_BRIDGE_BPPP_PUBLIC_IMPL_H */
