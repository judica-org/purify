// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file purify_bppp_bridge.c
 * @brief C bridge that binds Purify's lightweight ABI to secp256k1-zkp internals and BPPP helpers.
 */

#define SECP256K1_BUILD
#define ENABLE_MODULE_GENERATOR 1
#define ENABLE_MODULE_BPPP 1

#include "purify_bppp_bridge.h"
#include "purify_secp_bridge.h"

#include <stdlib.h>
#include <string.h>

#include "third_party/secp256k1-zkp/src/secp256k1.c"
#include "third_party/secp256k1-zkp/src/precomputed_ecmult.c"
#include "third_party/secp256k1-zkp/src/precomputed_ecmult_gen.c"

_Static_assert(sizeof(purify_scalar) == sizeof(secp256k1_scalar), "purify_scalar size mismatch");
_Static_assert(_Alignof(purify_scalar) >= _Alignof(secp256k1_scalar), "purify_scalar alignment mismatch");

static secp256k1_context* purify_create_context(void) {
    return secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
}

static secp256k1_scalar* purify_scalar_cast(purify_scalar* scalar) {
    return (secp256k1_scalar*)scalar;
}

static const secp256k1_scalar* purify_scalar_cast_const(const purify_scalar* scalar) {
    return (const secp256k1_scalar*)scalar;
}

void purify_scalar_set_int(purify_scalar* out, unsigned int value) {
    secp256k1_scalar_set_int(purify_scalar_cast(out), value);
}

void purify_scalar_set_u64(purify_scalar* out, uint64_t value) {
    secp256k1_scalar_set_u64(purify_scalar_cast(out), value);
}

void purify_scalar_set_b32(purify_scalar* out, const unsigned char input32[32], int* overflow) {
    secp256k1_scalar_set_b32(purify_scalar_cast(out), input32, overflow);
}

void purify_scalar_get_b32(unsigned char output32[32], const purify_scalar* value) {
    secp256k1_scalar_get_b32(output32, purify_scalar_cast_const(value));
}

int purify_scalar_is_zero(const purify_scalar* value) {
    return secp256k1_scalar_is_zero(purify_scalar_cast_const(value));
}

int purify_scalar_is_one(const purify_scalar* value) {
    return secp256k1_scalar_is_one(purify_scalar_cast_const(value));
}

int purify_scalar_is_even(const purify_scalar* value) {
    return secp256k1_scalar_is_even(purify_scalar_cast_const(value));
}

int purify_scalar_eq(const purify_scalar* lhs, const purify_scalar* rhs) {
    return secp256k1_scalar_eq(purify_scalar_cast_const(lhs), purify_scalar_cast_const(rhs));
}

void purify_scalar_negate(purify_scalar* out, const purify_scalar* value) {
    secp256k1_scalar_negate(purify_scalar_cast(out), purify_scalar_cast_const(value));
}

void purify_scalar_inverse(purify_scalar* out, const purify_scalar* value) {
    secp256k1_scalar_inverse(purify_scalar_cast(out), purify_scalar_cast_const(value));
}

void purify_scalar_inverse_var(purify_scalar* out, const purify_scalar* value) {
    secp256k1_scalar_inverse_var(purify_scalar_cast(out), purify_scalar_cast_const(value));
}

int purify_scalar_add(purify_scalar* out, const purify_scalar* lhs, const purify_scalar* rhs) {
    return secp256k1_scalar_add(purify_scalar_cast(out), purify_scalar_cast_const(lhs), purify_scalar_cast_const(rhs));
}

void purify_scalar_mul(purify_scalar* out, const purify_scalar* lhs, const purify_scalar* rhs) {
    secp256k1_scalar_mul(purify_scalar_cast(out), purify_scalar_cast_const(lhs), purify_scalar_cast_const(rhs));
}

void purify_scalar_cmov(purify_scalar* dst, const purify_scalar* src, int flag) {
    secp256k1_scalar_cmov(purify_scalar_cast(dst), purify_scalar_cast_const(src), flag);
}

void purify_hmac_sha256(unsigned char output32[32],
                        const unsigned char* key, size_t key_len,
                        const unsigned char* data, size_t data_len) {
    static const unsigned char zero = 0;
    secp256k1_hmac_sha256 hmac;

    if (key == NULL && key_len == 0) {
        key = &zero;
    }
    if (data == NULL && data_len == 0) {
        data = &zero;
    }

    secp256k1_hmac_sha256_initialize(&hmac, key, key_len);
    if (data_len != 0) {
        secp256k1_hmac_sha256_write(&hmac, data, data_len);
    }
    secp256k1_hmac_sha256_finalize(&hmac, output32);
    secp256k1_hmac_sha256_clear(&hmac);
}

static int purify_parse_scalar(const unsigned char input32[32], secp256k1_scalar* scalar, int reject_zero) {
    int overflow = 0;
    secp256k1_scalar_set_b32(scalar, input32, &overflow);
    if (overflow) {
        return 0;
    }
    if (reject_zero && secp256k1_scalar_is_zero(scalar)) {
        return 0;
    }
    return 1;
}

static int purify_parse_scalar_array(const unsigned char* input32, size_t count, secp256k1_scalar* out) {
    size_t i;
    for (i = 0; i < count; ++i) {
        if (!purify_parse_scalar(input32 + 32 * i, &out[i], 0)) {
            return 0;
        }
    }
    return 1;
}

static int purify_serialize_point(unsigned char out33[33], secp256k1_ge* point) {
    secp256k1_fe_normalize_var(&point->x);
    secp256k1_fe_normalize_var(&point->y);
    return secp256k1_bppp_serialize_pt(out33, point);
}

static void purify_norm_arg_commit_initial_data(secp256k1_sha256* transcript, const secp256k1_scalar* rho,
                                                const secp256k1_bppp_generators* gens_vec, size_t g_len,
                                                const secp256k1_scalar* c_vec, size_t c_vec_len,
                                                const secp256k1_ge* commit) {
    unsigned char ser_commit[33], ser_scalar[32], ser_le64[8];
    size_t i;
    secp256k1_ge comm = *commit;

    secp256k1_bppp_sha256_tagged_commitment_init(transcript);
    purify_serialize_point(ser_commit, &comm);
    secp256k1_sha256_write(transcript, ser_commit, sizeof(ser_commit));
    secp256k1_scalar_get_b32(ser_scalar, rho);
    secp256k1_sha256_write(transcript, ser_scalar, sizeof(ser_scalar));
    secp256k1_bppp_le64(ser_le64, g_len);
    secp256k1_sha256_write(transcript, ser_le64, sizeof(ser_le64));
    secp256k1_bppp_le64(ser_le64, gens_vec->n);
    secp256k1_sha256_write(transcript, ser_le64, sizeof(ser_le64));
    for (i = 0; i < gens_vec->n; ++i) {
        secp256k1_ge gen = gens_vec->gens[i];
        purify_serialize_point(ser_commit, &gen);
        secp256k1_sha256_write(transcript, ser_commit, sizeof(ser_commit));
    }
    secp256k1_bppp_le64(ser_le64, c_vec_len);
    secp256k1_sha256_write(transcript, ser_le64, sizeof(ser_le64));
    for (i = 0; i < c_vec_len; ++i) {
        secp256k1_scalar_get_b32(ser_scalar, &c_vec[i]);
        secp256k1_sha256_write(transcript, ser_scalar, sizeof(ser_scalar));
    }
}

static int purify_copy_vectors_into_scratch(const secp256k1_context* ctx, secp256k1_scratch_space* scratch,
                                            secp256k1_scalar** ns, secp256k1_scalar** ls, secp256k1_scalar** cs,
                                            secp256k1_ge** gs, const secp256k1_scalar* n_vec,
                                            const secp256k1_scalar* l_vec, const secp256k1_scalar* c_vec,
                                            const secp256k1_ge* gens_vec, size_t g_len, size_t h_len) {
    *ns = (secp256k1_scalar*)secp256k1_scratch_alloc(&ctx->error_callback, scratch, g_len * sizeof(secp256k1_scalar));
    *ls = (secp256k1_scalar*)secp256k1_scratch_alloc(&ctx->error_callback, scratch, h_len * sizeof(secp256k1_scalar));
    *cs = (secp256k1_scalar*)secp256k1_scratch_alloc(&ctx->error_callback, scratch, h_len * sizeof(secp256k1_scalar));
    *gs = (secp256k1_ge*)secp256k1_scratch_alloc(&ctx->error_callback, scratch, (g_len + h_len) * sizeof(secp256k1_ge));
    if (*ns == NULL || *ls == NULL || *cs == NULL || *gs == NULL) {
        return 0;
    }
    memcpy(*ns, n_vec, g_len * sizeof(secp256k1_scalar));
    memcpy(*ls, l_vec, h_len * sizeof(secp256k1_scalar));
    memcpy(*cs, c_vec, h_len * sizeof(secp256k1_scalar));
    memcpy(*gs, gens_vec, (g_len + h_len) * sizeof(secp256k1_ge));
    return 1;
}

static int purify_bppp_rangeproof_norm_product_prove_const(const secp256k1_context* ctx, secp256k1_scratch_space* scratch,
                                                           unsigned char* proof, size_t* proof_len,
                                                           secp256k1_sha256* transcript, const secp256k1_scalar* rho,
                                                           const secp256k1_ge* g_vec, size_t g_vec_len,
                                                           const secp256k1_scalar* n_vec, size_t n_vec_len,
                                                           const secp256k1_scalar* l_vec, size_t l_vec_len,
                                                           const secp256k1_scalar* c_vec, size_t c_vec_len) {
    secp256k1_scalar *ns = NULL, *ls = NULL, *cs = NULL;
    secp256k1_ge *gs = NULL;
    size_t checkpoint = secp256k1_scratch_checkpoint(&ctx->error_callback, scratch);
    int result = 0;

    if (purify_copy_vectors_into_scratch(ctx, scratch, &ns, &ls, &cs, &gs, n_vec, l_vec, c_vec, g_vec, n_vec_len, l_vec_len)) {
        result = secp256k1_bppp_rangeproof_norm_product_prove(ctx, scratch, proof, proof_len, transcript, rho,
                                                              gs, g_vec_len, ns, n_vec_len, ls, l_vec_len, cs, c_vec_len);
    }
    secp256k1_scratch_apply_checkpoint(&ctx->error_callback, scratch, checkpoint);
    return result;
}

size_t purify_bppp_required_proof_size(size_t n_vec_len, size_t c_vec_len) {
    size_t log_g_len, log_h_len;
    if (n_vec_len == 0 || c_vec_len == 0) {
        return 0;
    }
    log_g_len = secp256k1_bppp_log2(n_vec_len);
    log_h_len = secp256k1_bppp_log2(c_vec_len);
    return 65 * (log_g_len > log_h_len ? log_g_len : log_h_len) + 64;
}

int purify_bppp_base_generator(unsigned char out33[33]) {
    secp256k1_context* ctx = purify_create_context();
    secp256k1_generator generator;
    secp256k1_ge ge = secp256k1_ge_const_g;
    int ok;

    if (ctx == NULL || out33 == NULL) {
        if (ctx != NULL) secp256k1_context_destroy(ctx);
        return 0;
    }
    secp256k1_generator_save(&generator, &ge);
    ok = secp256k1_generator_serialize(ctx, out33, &generator);
    secp256k1_context_destroy(ctx);
    return ok;
}

int purify_bppp_value_generator_h(unsigned char out33[33]) {
    secp256k1_context* ctx = purify_create_context();
    int ok;

    if (ctx == NULL || out33 == NULL) {
        if (ctx != NULL) secp256k1_context_destroy(ctx);
        return 0;
    }
    ok = secp256k1_generator_serialize(ctx, out33, secp256k1_generator_h);
    secp256k1_context_destroy(ctx);
    return ok;
}

int purify_bppp_create_generators(size_t count, unsigned char* out, size_t* out_len) {
    secp256k1_context* ctx = purify_create_context();
    secp256k1_bppp_generators* gens = NULL;
    size_t required = count * 33;
    int ok = 0;

    if (ctx == NULL || out_len == NULL) {
        if (ctx != NULL) secp256k1_context_destroy(ctx);
        return 0;
    }
    if (*out_len < required || out == NULL) {
        *out_len = required;
        secp256k1_context_destroy(ctx);
        return 0;
    }
    gens = secp256k1_bppp_generators_create(ctx, count);
    if (gens == NULL) {
        secp256k1_context_destroy(ctx);
        return 0;
    }
    ok = secp256k1_bppp_generators_serialize(ctx, gens, out, out_len);
    secp256k1_bppp_generators_destroy(ctx, gens);
    secp256k1_context_destroy(ctx);
    return ok;
}

int purify_pedersen_commit_char(const unsigned char blind32[32], const unsigned char value32[32],
                                const unsigned char value_gen33[33], const unsigned char blind_gen33[33],
                                unsigned char commitment_out33[33]) {
    secp256k1_context* ctx = purify_create_context();
    secp256k1_scalar blind_scalar, value_scalar;
    secp256k1_generator value_generator, blind_generator;
    secp256k1_ge value_ge, blind_ge, commit_ge;
    secp256k1_gej blind_part, value_part, total;
    int ok = 0;

    if (ctx == NULL || blind32 == NULL || value32 == NULL || value_gen33 == NULL || blind_gen33 == NULL || commitment_out33 == NULL) {
        if (ctx != NULL) secp256k1_context_destroy(ctx);
        return 0;
    }
    if (!purify_parse_scalar(blind32, &blind_scalar, 0) || !purify_parse_scalar(value32, &value_scalar, 0)) {
        secp256k1_context_destroy(ctx);
        return 0;
    }
    if (!secp256k1_generator_parse(ctx, &value_generator, value_gen33) || !secp256k1_generator_parse(ctx, &blind_generator, blind_gen33)) {
        secp256k1_context_destroy(ctx);
        return 0;
    }
    secp256k1_generator_load(&value_ge, &value_generator);
    secp256k1_generator_load(&blind_ge, &blind_generator);
    secp256k1_ecmult_const(&blind_part, &blind_ge, &blind_scalar);
    secp256k1_ecmult_const(&value_part, &value_ge, &value_scalar);
    secp256k1_gej_add_var(&total, &blind_part, &value_part, NULL);
    if (!secp256k1_gej_is_infinity(&total)) {
        secp256k1_ge_set_gej(&commit_ge, &total);
        ok = purify_serialize_point(commitment_out33, &commit_ge);
    }
    secp256k1_context_destroy(ctx);
    return ok;
}

int purify_bppp_prove_norm_arg(const unsigned char rho32[32], const unsigned char* generators33, size_t generators_count,
                               const unsigned char* n_vec32, size_t n_vec_len, const unsigned char* l_vec32,
                               size_t l_vec_len, const unsigned char* c_vec32, size_t c_vec_len,
                               unsigned char commitment_out33[33], unsigned char* proof_out, size_t* proof_len) {
    secp256k1_context* ctx = purify_create_context();
    secp256k1_scratch_space* scratch = NULL;
    secp256k1_bppp_generators* gens = NULL;
    secp256k1_scalar rho, mu;
    secp256k1_scalar *n_vec = NULL, *l_vec = NULL, *c_vec = NULL;
    secp256k1_ge commit;
    secp256k1_sha256 transcript;
    size_t required = purify_bppp_required_proof_size(n_vec_len, c_vec_len);
    int ok = 0;

    if (ctx == NULL || rho32 == NULL || generators33 == NULL || n_vec32 == NULL || l_vec32 == NULL || c_vec32 == NULL ||
        commitment_out33 == NULL || proof_out == NULL || proof_len == NULL) {
        if (ctx != NULL) secp256k1_context_destroy(ctx);
        return 0;
    }
    if (n_vec_len == 0 || l_vec_len == 0 || c_vec_len == 0 || l_vec_len != c_vec_len) {
        secp256k1_context_destroy(ctx);
        return 0;
    }
    if (!secp256k1_is_power_of_two(n_vec_len) || !secp256k1_is_power_of_two(c_vec_len) || generators_count != n_vec_len + l_vec_len) {
        secp256k1_context_destroy(ctx);
        return 0;
    }
    if (*proof_len < required) {
        *proof_len = required;
        secp256k1_context_destroy(ctx);
        return 0;
    }
    if (!purify_parse_scalar(rho32, &rho, 1)) {
        secp256k1_context_destroy(ctx);
        return 0;
    }
    scratch = secp256k1_scratch_space_create(ctx, 1u << 20);
    gens = secp256k1_bppp_generators_parse(ctx, generators33, generators_count * 33);
    n_vec = (secp256k1_scalar*)malloc(n_vec_len * sizeof(*n_vec));
    l_vec = (secp256k1_scalar*)malloc(l_vec_len * sizeof(*l_vec));
    c_vec = (secp256k1_scalar*)malloc(c_vec_len * sizeof(*c_vec));
    if (scratch == NULL || gens == NULL || n_vec == NULL || l_vec == NULL || c_vec == NULL) {
        goto cleanup;
    }
    if (!purify_parse_scalar_array(n_vec32, n_vec_len, n_vec) ||
        !purify_parse_scalar_array(l_vec32, l_vec_len, l_vec) ||
        !purify_parse_scalar_array(c_vec32, c_vec_len, c_vec)) {
        goto cleanup;
    }
    secp256k1_scalar_sqr(&mu, &rho);
    if (!secp256k1_bppp_commit(ctx, scratch, &commit, gens, n_vec, n_vec_len, l_vec, l_vec_len, c_vec, c_vec_len, &mu)) {
        goto cleanup;
    }
    if (!purify_serialize_point(commitment_out33, &commit)) {
        goto cleanup;
    }
    purify_norm_arg_commit_initial_data(&transcript, &rho, gens, n_vec_len, c_vec, c_vec_len, &commit);
    ok = purify_bppp_rangeproof_norm_product_prove_const(ctx, scratch, proof_out, proof_len, &transcript, &rho,
                                                         gens->gens, gens->n, n_vec, n_vec_len, l_vec, l_vec_len, c_vec, c_vec_len);

cleanup:
    if (n_vec != NULL) free(n_vec);
    if (l_vec != NULL) free(l_vec);
    if (c_vec != NULL) free(c_vec);
    if (gens != NULL) secp256k1_bppp_generators_destroy(ctx, gens);
    if (scratch != NULL) secp256k1_scratch_space_destroy(ctx, scratch);
    secp256k1_context_destroy(ctx);
    return ok;
}

int purify_bppp_verify_norm_arg(const unsigned char rho32[32], const unsigned char* generators33, size_t generators_count,
                                const unsigned char* c_vec32, size_t c_vec_len, size_t n_vec_len,
                                const unsigned char commitment33[33], const unsigned char* proof, size_t proof_len) {
    secp256k1_context* ctx = purify_create_context();
    secp256k1_scratch_space* scratch = NULL;
    secp256k1_bppp_generators* gens = NULL;
    secp256k1_scalar rho, *c_vec = NULL;
    secp256k1_ge commit;
    secp256k1_sha256 transcript;
    int ok = 0;

    if (ctx == NULL || rho32 == NULL || generators33 == NULL || c_vec32 == NULL || commitment33 == NULL || proof == NULL) {
        if (ctx != NULL) secp256k1_context_destroy(ctx);
        return 0;
    }
    if (n_vec_len == 0 || c_vec_len == 0 || generators_count != n_vec_len + c_vec_len) {
        secp256k1_context_destroy(ctx);
        return 0;
    }
    if (!secp256k1_is_power_of_two(n_vec_len) || !secp256k1_is_power_of_two(c_vec_len)) {
        secp256k1_context_destroy(ctx);
        return 0;
    }
    if (!purify_parse_scalar(rho32, &rho, 1) || !secp256k1_ge_parse_ext(&commit, commitment33)) {
        secp256k1_context_destroy(ctx);
        return 0;
    }
    scratch = secp256k1_scratch_space_create(ctx, 1u << 20);
    gens = secp256k1_bppp_generators_parse(ctx, generators33, generators_count * 33);
    c_vec = (secp256k1_scalar*)malloc(c_vec_len * sizeof(*c_vec));
    if (scratch == NULL || gens == NULL || c_vec == NULL) {
        goto cleanup;
    }
    if (!purify_parse_scalar_array(c_vec32, c_vec_len, c_vec)) {
        goto cleanup;
    }
    purify_norm_arg_commit_initial_data(&transcript, &rho, gens, n_vec_len, c_vec, c_vec_len, &commit);
    ok = secp256k1_bppp_rangeproof_norm_product_verify(ctx, scratch, proof, proof_len, &transcript, &rho,
                                                       gens, n_vec_len, c_vec, c_vec_len, &commit);

cleanup:
    if (c_vec != NULL) free(c_vec);
    if (gens != NULL) secp256k1_bppp_generators_destroy(ctx, gens);
    if (scratch != NULL) secp256k1_scratch_space_destroy(ctx, scratch);
    secp256k1_context_destroy(ctx);
    return ok;
}
