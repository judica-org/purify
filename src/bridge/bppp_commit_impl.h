// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/*
 * BPPP generators, Pedersen and norm-argument commitments, and public point arithmetic.
 *
 * Part of the Purify secp256k1 bridge translation unit. Include only from
 * bppp_bridge.c, after secp256k1.c and the parts listed before this one.
 */

#ifndef PURIFY_BRIDGE_BPPP_COMMIT_IMPL_H
#define PURIFY_BRIDGE_BPPP_COMMIT_IMPL_H

size_t purify_bppp_required_proof_size(size_t n_vec_len, size_t c_vec_len) {
    size_t log_g_len, log_h_len, max_log_len, proof_size = 0;
    if (n_vec_len == 0 || c_vec_len == 0 || n_vec_len < c_vec_len) {
        return 0;
    }
    log_g_len = secp256k1_bppp_log2(n_vec_len);
    log_h_len = secp256k1_bppp_log2(c_vec_len);
    max_log_len = log_g_len > log_h_len ? log_g_len : log_h_len;
    if (!purify_bridge_checked_mul_size(65u, max_log_len, &proof_size) ||
        !purify_bridge_checked_add_size(proof_size, 64u, &proof_size)) {
        return 0;
    }
    return proof_size;
}

int purify_bppp_base_generator(purify_secp_context* context, unsigned char out33[33]) {
    secp256k1_context* ctx = purify_context_handle(context);
    secp256k1_generator generator;
    secp256k1_ge ge = secp256k1_ge_const_g;
    int ok;

    if (ctx == NULL || out33 == NULL) {
        return 0;
    }
    secp256k1_generator_save(&generator, &ge);
    ok = secp256k1_generator_serialize(ctx, out33, &generator);
    return ok;
}

int purify_bppp_value_generator_h(purify_secp_context* context, unsigned char out33[33]) {
    secp256k1_context* ctx = purify_context_handle(context);
    int ok;

    if (ctx == NULL || out33 == NULL) {
        return 0;
    }
    ok = secp256k1_generator_serialize(ctx, out33, secp256k1_generator_h);
    return ok;
}

int purify_bppp_create_generators(purify_secp_context* context, size_t count, unsigned char* out, size_t* out_len) {
    secp256k1_context* ctx = purify_context_handle(context);
    secp256k1_bppp_generators* gens = NULL;
    size_t required = 0;
    int ok = 0;

    if (ctx == NULL || out_len == NULL) {
        return 0;
    }
    if (!purify_bridge_checked_mul_size(count, 33u, &required)) {
        *out_len = 0;
        return 0;
    }
    if (*out_len < required || out == NULL) {
        *out_len = required;
        return 0;
    }
    gens = secp256k1_bppp_generators_create(ctx, count);
    if (gens == NULL) {
        return 0;
    }
    ok = secp256k1_bppp_generators_serialize(ctx, gens, out, out_len);
    secp256k1_bppp_generators_destroy(ctx, gens);
    return ok;
}

/* Scale a serialized BPPP generator without changing its wire encoding. */
int purify_bppp_scale_generator(purify_secp_context* context,
                                const unsigned char generator33[33],
                                const unsigned char scalar32[32],
                                unsigned char out33[33]) {
    secp256k1_context* ctx = purify_context_handle(context);
    secp256k1_generator generator = {{0}}, result_generator = {{0}};
    secp256k1_scalar scalar = {0};
    secp256k1_ge generator_ge = {0}, result_ge = {0};
    secp256k1_gej result_j = {0};
    int ok = 0;

    if (ctx == NULL || generator33 == NULL || scalar32 == NULL || out33 == NULL) {
        goto cleanup;
    }
    if (!secp256k1_generator_parse(ctx, &generator, generator33) ||
        !purify_parse_scalar(scalar32, &scalar, 0)) {
        goto cleanup;
    }
    secp256k1_generator_load(&generator_ge, &generator);
    secp256k1_ecmult_const(&result_j, &generator_ge, &scalar);
    if (secp256k1_gej_is_infinity(&result_j)) {
        goto cleanup;
    }
    secp256k1_ge_set_gej(&result_ge, &result_j);
    secp256k1_generator_save(&result_generator, &result_ge);
    ok = secp256k1_generator_serialize(ctx, out33, &result_generator);

cleanup:
    if (!ok && out33 != NULL) {
        memset(out33, 0, 33);
    }
    secp256k1_scalar_clear(&scalar);
    secp256k1_ge_clear(&generator_ge);
    secp256k1_ge_clear(&result_ge);
    secp256k1_gej_clear(&result_j);
    secp256k1_memclear_explicit(&generator, sizeof(generator));
    secp256k1_memclear_explicit(&result_generator,
                                sizeof(result_generator));
    return ok;
}

int purify_bppp_generator_to_point(purify_secp_context* context,
                                   const unsigned char generator33[33],
                                   unsigned char out33[33]) {
    secp256k1_context* ctx = purify_context_handle(context);
    secp256k1_generator generator;
    secp256k1_ge generator_ge;

    if (ctx == NULL || generator33 == NULL || out33 == NULL) {
        return 0;
    }
    if (!secp256k1_generator_parse(ctx, &generator, generator33)) {
        return 0;
    }
    secp256k1_generator_load(&generator_ge, &generator);
    return purify_serialize_point(out33, &generator_ge);
}

int purify_pedersen_commit_char(purify_secp_context* context,
                                const unsigned char blind32[32], const unsigned char value32[32],
                                const unsigned char value_gen33[33], const unsigned char blind_gen33[33],
                                unsigned char commitment_out33[33]) {
    secp256k1_context* ctx = purify_context_handle(context);
    secp256k1_scalar blind_scalar = {0}, value_scalar = {0};
    secp256k1_generator value_generator, blind_generator;
    secp256k1_ge value_ge, blind_ge, commit_ge;
    secp256k1_gej total;
    int ok = 0;

    if (ctx == NULL || blind32 == NULL || value32 == NULL || value_gen33 == NULL || blind_gen33 == NULL || commitment_out33 == NULL) {
        return 0;
    }
    purify_bridge_secure_clear(commitment_out33, 33);
    if (!purify_parse_scalar(blind32, &blind_scalar, 0) || !purify_parse_scalar(value32, &value_scalar, 0)) {
        goto cleanup;
    }
    if (!secp256k1_generator_parse(ctx, &value_generator, value_gen33) || !secp256k1_generator_parse(ctx, &blind_generator, blind_gen33)) {
        goto cleanup;
    }
    secp256k1_generator_load(&value_ge, &value_generator);
    secp256k1_generator_load(&blind_ge, &blind_generator);
    secp256k1_gej_set_infinity(&total);
    purify_gej_add_secret_scalar_term(&total, &blind_ge, &blind_scalar);
    purify_gej_add_secret_scalar_term(&total, &value_ge, &value_scalar);
    secp256k1_ge_set_gej(&commit_ge, &total);
    PURIFY_BRIDGE_DECLASSIFY(&commit_ge, sizeof(commit_ge));
    if (!commit_ge.infinity) {
        ok = purify_serialize_point(commitment_out33, &commit_ge);
    }

cleanup:
    secp256k1_scalar_clear(&blind_scalar);
    secp256k1_scalar_clear(&value_scalar);
    purify_bridge_secure_clear(&value_ge, sizeof(value_ge));
    purify_bridge_secure_clear(&blind_ge, sizeof(blind_ge));
    purify_bridge_secure_clear(&commit_ge, sizeof(commit_ge));
    purify_bridge_secure_clear(&total, sizeof(total));
    return ok;
}

static int purify_bppp_commit_norm_arg_impl(purify_secp_context* context,
                                            purify_bppp_backend_resources* resources,
                                            const unsigned char rho32[32], const unsigned char* generators33,
                                            size_t generators_count, const unsigned char* n_vec32, size_t n_vec_len,
                                            const unsigned char* l_vec32, size_t l_vec_len,
                                            const unsigned char* c_vec32, size_t c_vec_len,
                                            unsigned char commitment_out33[33]) {
    secp256k1_context* ctx = resources != NULL ? resources->ctx : purify_context_handle(context);
    secp256k1_scratch_space* scratch = resources != NULL ? resources->scratch : NULL;
    secp256k1_bppp_generators* gens = resources != NULL ? resources->gens : NULL;
    secp256k1_scalar rho = {0}, mu = {0};
    secp256k1_scalar *n_vec = NULL, *l_vec = NULL, *c_vec = NULL;
    secp256k1_ge commit;
    size_t expected_generators = 0;
    size_t serialized_generators_len = 0;
    size_t scratch_checkpoint = 0;
    int ok = 0;
    int scratch_contains_secrets = 0;

    if (ctx == NULL || rho32 == NULL || (resources == NULL && generators33 == NULL) || n_vec32 == NULL || l_vec32 == NULL || c_vec32 == NULL ||
        commitment_out33 == NULL) {
        return 0;
    }
    if (n_vec_len == 0 || l_vec_len == 0 || c_vec_len == 0 || l_vec_len != c_vec_len) {
        return 0;
    }
    if (!secp256k1_is_power_of_two(n_vec_len) || !secp256k1_is_power_of_two(c_vec_len) ||
        !purify_bridge_checked_add_size(n_vec_len, l_vec_len, &expected_generators) ||
        generators_count != expected_generators ||
        !purify_bridge_checked_mul_size(generators_count, 33u, &serialized_generators_len)) {
        return 0;
    }
    if (resources != NULL && resources->generators_count != generators_count) {
        return 0;
    }
    if (!purify_parse_scalar(rho32, &rho, 1)) {
        goto cleanup;
    }
    if (resources == NULL) {
        scratch = purify_bppp_create_scratch(ctx, generators_count);
        gens = secp256k1_bppp_generators_parse(ctx, generators33, serialized_generators_len);
    }
    n_vec = (secp256k1_scalar*)purify_malloc_array(n_vec_len, sizeof(*n_vec));
    l_vec = (secp256k1_scalar*)purify_malloc_array(l_vec_len, sizeof(*l_vec));
    c_vec = (secp256k1_scalar*)purify_malloc_array(c_vec_len, sizeof(*c_vec));
    if (scratch == NULL || gens == NULL || n_vec == NULL || l_vec == NULL || c_vec == NULL) {
        goto cleanup;
    }
    if (!purify_parse_scalar_array(n_vec32, n_vec_len, n_vec) ||
        !purify_parse_scalar_array(l_vec32, l_vec_len, l_vec) ||
        !purify_parse_scalar_array(c_vec32, c_vec_len, c_vec)) {
        goto cleanup;
    }
    scratch_checkpoint = secp256k1_scratch_checkpoint(&ctx->error_callback, scratch);
    scratch_contains_secrets = 1;
    secp256k1_scalar_sqr(&mu, &rho);
    if (!purify_bppp_commit_secret(ctx, &commit, gens, n_vec, n_vec_len,
                                  l_vec, l_vec_len, c_vec, c_vec_len, &mu)) {
        goto cleanup;
    }
    ok = purify_serialize_point(commitment_out33, &commit);

cleanup:
    purify_bridge_secure_free_array(n_vec, n_vec_len, sizeof(*n_vec));
    purify_bridge_secure_free_array(l_vec, l_vec_len, sizeof(*l_vec));
    purify_bridge_secure_free_array(c_vec, c_vec_len, sizeof(*c_vec));
    if (scratch_contains_secrets) {
        purify_bridge_secure_clear_scratch_tail(scratch, scratch_checkpoint);
    }
    secp256k1_scalar_clear(&rho);
    secp256k1_scalar_clear(&mu);
    purify_bridge_secure_clear(&commit, sizeof(commit));
    if (resources == NULL) {
        if (gens != NULL) secp256k1_bppp_generators_destroy(ctx, gens);
        if (scratch != NULL) secp256k1_scratch_space_destroy(ctx, scratch);
    }
    return ok;
}

int purify_bppp_commit_norm_arg(purify_secp_context* context,
                                const unsigned char rho32[32], const unsigned char* generators33, size_t generators_count,
                                const unsigned char* n_vec32, size_t n_vec_len, const unsigned char* l_vec32,
                                size_t l_vec_len, const unsigned char* c_vec32, size_t c_vec_len,
                                unsigned char commitment_out33[33]) {
    return purify_bppp_commit_norm_arg_impl(context, NULL, rho32, generators33, generators_count, n_vec32, n_vec_len,
                                            l_vec32, l_vec_len, c_vec32, c_vec_len, commitment_out33);
}

int purify_bppp_commit_norm_arg_with_resources(purify_bppp_backend_resources* resources,
                                               const unsigned char rho32[32],
                                               const unsigned char* n_vec32, size_t n_vec_len,
                                               const unsigned char* l_vec32, size_t l_vec_len,
                                               const unsigned char* c_vec32, size_t c_vec_len,
                                               unsigned char commitment_out33[33]) {
    return purify_bppp_commit_norm_arg_impl(NULL, resources, rho32, NULL,
                                            resources != NULL ? resources->generators_count : 0,
                                            n_vec32, n_vec_len, l_vec32, l_vec_len, c_vec32, c_vec_len,
                                            commitment_out33);
}

static int purify_bppp_commit_witness_only_impl(purify_secp_context* context,
                                                purify_bppp_backend_resources* resources,
                                                const unsigned char* generators33, size_t generators_count,
                                                const unsigned char* n_vec32, size_t n_vec_len,
                                                const unsigned char* l_vec32, size_t l_vec_len,
                                                unsigned char commitment_out33[33]) {
    secp256k1_context* ctx = resources != NULL ? resources->ctx : purify_context_handle(context);
    secp256k1_scratch_space* scratch = resources != NULL ? resources->scratch : NULL;
    secp256k1_bppp_generators* gens = resources != NULL ? resources->gens : NULL;
    secp256k1_scalar zero = {0};
    secp256k1_scalar *n_vec = NULL, *l_vec = NULL;
    secp256k1_ge commit;
    secp256k1_gej commitj;
    ecmult_bp_commit_cb_data data;
    size_t expected_generators = 0;
    size_t serialized_generators_len = 0;
    size_t scratch_checkpoint = 0;
    int ok = 0;
    int scratch_contains_secrets = 0;

    if (ctx == NULL || (resources == NULL && generators33 == NULL) || n_vec32 == NULL || l_vec32 == NULL || commitment_out33 == NULL) {
        return 0;
    }
    if (n_vec_len == 0 || l_vec_len == 0 ||
        !purify_bridge_checked_add_size(n_vec_len, l_vec_len, &expected_generators) ||
        generators_count != expected_generators ||
        !purify_bridge_checked_mul_size(generators_count, 33u, &serialized_generators_len)) {
        return 0;
    }
    if (resources != NULL && resources->generators_count != generators_count) {
        return 0;
    }

    if (resources == NULL) {
        scratch = purify_bppp_create_scratch(ctx, generators_count);
        gens = secp256k1_bppp_generators_parse(ctx, generators33, serialized_generators_len);
    }
    n_vec = (secp256k1_scalar*)purify_malloc_array(n_vec_len, sizeof(*n_vec));
    l_vec = (secp256k1_scalar*)purify_malloc_array(l_vec_len, sizeof(*l_vec));
    if (scratch == NULL || gens == NULL || n_vec == NULL || l_vec == NULL) {
        goto cleanup;
    }
    if (!purify_parse_scalar_array(n_vec32, n_vec_len, n_vec) ||
        !purify_parse_scalar_array(l_vec32, l_vec_len, l_vec)) {
        goto cleanup;
    }

    scratch_checkpoint = secp256k1_scratch_checkpoint(&ctx->error_callback, scratch);
    scratch_contains_secrets = 1;
    secp256k1_scalar_set_int(&zero, 0);
    data.g = gens->gens;
    data.n = n_vec;
    data.l = l_vec;
    data.g_len = n_vec_len;
    if (!purify_ecmult_multi_secret(ctx, &commitj, &zero,
                                    ecmult_bp_commit_cb, &data,
                                    expected_generators)) {
        goto cleanup;
    }
    PURIFY_BRIDGE_DECLASSIFY(&commitj.infinity,
                             sizeof(commitj.infinity));
    if (secp256k1_gej_is_infinity(&commitj)) {
        goto cleanup;
    }
    secp256k1_ge_set_gej(&commit, &commitj);
    PURIFY_BRIDGE_DECLASSIFY(&commit, sizeof(commit));
    ok = purify_serialize_point(commitment_out33, &commit);

cleanup:
    purify_bridge_secure_free_array(n_vec, n_vec_len, sizeof(*n_vec));
    purify_bridge_secure_free_array(l_vec, l_vec_len, sizeof(*l_vec));
    if (scratch_contains_secrets) {
        purify_bridge_secure_clear_scratch_tail(scratch, scratch_checkpoint);
    }
    secp256k1_scalar_clear(&zero);
    purify_bridge_secure_clear(&data, sizeof(data));
    purify_bridge_secure_clear(&commit, sizeof(commit));
    purify_bridge_secure_clear(&commitj, sizeof(commitj));
    if (resources == NULL) {
        if (gens != NULL) secp256k1_bppp_generators_destroy(ctx, gens);
        if (scratch != NULL) secp256k1_scratch_space_destroy(ctx, scratch);
    }
    return ok;
}

int purify_bppp_commit_witness_only(purify_secp_context* context,
                                    const unsigned char* generators33, size_t generators_count,
                                    const unsigned char* n_vec32, size_t n_vec_len, const unsigned char* l_vec32,
                                    size_t l_vec_len, unsigned char commitment_out33[33]) {
    return purify_bppp_commit_witness_only_impl(context, NULL, generators33, generators_count,
                                                n_vec32, n_vec_len, l_vec32, l_vec_len, commitment_out33);
}

int purify_bppp_commit_witness_only_with_resources(purify_bppp_backend_resources* resources,
                                                   const unsigned char* n_vec32, size_t n_vec_len,
                                                   const unsigned char* l_vec32, size_t l_vec_len,
                                                   unsigned char commitment_out33[33]) {
    return purify_bppp_commit_witness_only_impl(NULL, resources, NULL,
                                                resources != NULL ? resources->generators_count : 0,
                                                n_vec32, n_vec_len, l_vec32, l_vec_len, commitment_out33);
}

int purify_bppp_offset_commitment(purify_secp_context* context,
                                  const unsigned char commitment33[33], const unsigned char scalar32[32],
                                  unsigned char commitment_out33[33]) {
    secp256k1_context* ctx = purify_context_handle(context);
    secp256k1_scalar scalar = {0};
    secp256k1_ge commitment_ge, result_ge;
    secp256k1_gej result_j;
    int ok = 0;

    if (ctx == NULL || commitment33 == NULL || scalar32 == NULL || commitment_out33 == NULL) {
        return 0;
    }
    purify_bridge_secure_clear(commitment_out33, 33);
    if (!purify_parse_point_as_ge(commitment33, &commitment_ge) ||
        !purify_parse_scalar(scalar32, &scalar, 0)) {
        goto cleanup;
    }

    secp256k1_gej_set_ge(&result_j, &commitment_ge);
    purify_gej_add_secret_scalar_term(
        &result_j, &secp256k1_ge_const_g, &scalar);
    secp256k1_ge_set_gej(&result_ge, &result_j);
    PURIFY_BRIDGE_DECLASSIFY(&result_ge, sizeof(result_ge));
    if (!result_ge.infinity) {
        ok = purify_serialize_point(commitment_out33, &result_ge);
    }

cleanup:
    secp256k1_scalar_clear(&scalar);
    purify_bridge_secure_clear(&commitment_ge, sizeof(commitment_ge));
    purify_bridge_secure_clear(&result_ge, sizeof(result_ge));
    purify_bridge_secure_clear(&result_j, sizeof(result_j));
    return ok;
}

int purify_point_scale(purify_secp_context* context,
                       const unsigned char point33[33], const unsigned char scalar32[32],
                       unsigned char out33[33]) {
    secp256k1_context* ctx = purify_context_handle(context);
    secp256k1_scalar scalar = {0};
    secp256k1_ge point_ge, result_ge;
    secp256k1_gej result_j;
    int ok = 0;

    if (ctx == NULL || point33 == NULL || scalar32 == NULL || out33 == NULL) {
        return 0;
    }
    purify_bridge_secure_clear(out33, 33);
    if (!purify_parse_point_as_ge(point33, &point_ge) ||
        !purify_parse_scalar(scalar32, &scalar, 0)) {
        goto cleanup;
    }

    secp256k1_ecmult_const(&result_j, &point_ge, &scalar);
    secp256k1_ge_set_gej(&result_ge, &result_j);
    PURIFY_BRIDGE_DECLASSIFY(&result_ge, sizeof(result_ge));
    if (!result_ge.infinity) {
        ok = purify_serialize_point(out33, &result_ge);
    }

cleanup:
    secp256k1_scalar_clear(&scalar);
    purify_bridge_secure_clear(&point_ge, sizeof(point_ge));
    purify_bridge_secure_clear(&result_ge, sizeof(result_ge));
    purify_bridge_secure_clear(&result_j, sizeof(result_j));
    return ok;
}

int purify_point_add(purify_secp_context* context,
                     const unsigned char lhs33[33], const unsigned char rhs33[33],
                     unsigned char out33[33]) {
    secp256k1_context* ctx = purify_context_handle(context);
    secp256k1_ge lhs_ge, rhs_ge, result_ge;
    secp256k1_gej lhs_j, result_j;
    int ok = 0;

    if (ctx == NULL || lhs33 == NULL || rhs33 == NULL || out33 == NULL) {
        return 0;
    }
    if (!purify_parse_point_as_ge(lhs33, &lhs_ge) ||
        !purify_parse_point_as_ge(rhs33, &rhs_ge)) {
        return 0;
    }

    secp256k1_gej_set_ge(&lhs_j, &lhs_ge);
    secp256k1_gej_add_ge_var(&result_j, &lhs_j, &rhs_ge, NULL);
    if (!secp256k1_gej_is_infinity(&result_j)) {
        secp256k1_ge_set_gej(&result_ge, &result_j);
        ok = purify_serialize_point(out33, &result_ge);
    }
    return ok;
}

int purify_point_add_allow_infinity(
    purify_secp_context* context, const unsigned char lhs33[33],
    const unsigned char rhs33[33], unsigned char out33[33]) {
    secp256k1_context* ctx = purify_context_handle(context);
    secp256k1_ge lhs_ge, rhs_ge, result_ge;
    secp256k1_gej lhs_j, rhs_j, result_j;
    static const unsigned char infinity33[33] = {0};
    int lhs_infinity;
    int rhs_infinity;
    int ok = 0;

    if (ctx == NULL || lhs33 == NULL || rhs33 == NULL || out33 == NULL) {
        return 0;
    }
    purify_bridge_secure_clear(out33, 33);
    lhs_infinity = purify_bridge_memeq_const(lhs33, infinity33, 33);
    rhs_infinity = purify_bridge_memeq_const(rhs33, infinity33, 33);
    if ((!lhs_infinity && !purify_parse_point_as_ge(lhs33, &lhs_ge)) ||
        (!rhs_infinity && !purify_parse_point_as_ge(rhs33, &rhs_ge))) {
        goto cleanup;
    }
    if (lhs_infinity) {
        secp256k1_gej_set_infinity(&lhs_j);
    } else {
        secp256k1_gej_set_ge(&lhs_j, &lhs_ge);
    }
    if (rhs_infinity) {
        secp256k1_gej_set_infinity(&rhs_j);
    } else {
        secp256k1_gej_set_ge(&rhs_j, &rhs_ge);
    }
    secp256k1_gej_add_var(&result_j, &lhs_j, &rhs_j, NULL);
    if (secp256k1_gej_is_infinity(&result_j)) {
        ok = 1;
    } else {
        secp256k1_ge_set_gej(&result_ge, &result_j);
        ok = purify_serialize_point(out33, &result_ge);
    }

cleanup:
    purify_bridge_secure_clear(&lhs_ge, sizeof(lhs_ge));
    purify_bridge_secure_clear(&rhs_ge, sizeof(rhs_ge));
    purify_bridge_secure_clear(&result_ge, sizeof(result_ge));
    purify_bridge_secure_clear(&lhs_j, sizeof(lhs_j));
    purify_bridge_secure_clear(&rhs_j, sizeof(rhs_j));
    purify_bridge_secure_clear(&result_j, sizeof(result_j));
    return ok;
}

int purify_point_subtract_allow_infinity(
    purify_secp_context* context, const unsigned char lhs33[33],
    const unsigned char rhs33[33], unsigned char out33[33]) {
    secp256k1_context* ctx = purify_context_handle(context);
    secp256k1_ge lhs_ge, rhs_ge, result_ge;
    secp256k1_gej lhs_j, result_j;
    int ok = 0;

    if (ctx == NULL || lhs33 == NULL || rhs33 == NULL || out33 == NULL) {
        return 0;
    }
    purify_bridge_secure_clear(out33, 33);
    if (!purify_parse_point_as_ge(lhs33, &lhs_ge) ||
        !purify_parse_point_as_ge(rhs33, &rhs_ge)) {
        goto cleanup;
    }

    secp256k1_ge_neg(&rhs_ge, &rhs_ge);
    secp256k1_gej_set_ge(&lhs_j, &lhs_ge);
    secp256k1_gej_add_ge_var(&result_j, &lhs_j, &rhs_ge, NULL);
    if (secp256k1_gej_is_infinity(&result_j)) {
        ok = 1;
    } else {
        secp256k1_ge_set_gej(&result_ge, &result_j);
        ok = purify_serialize_point(out33, &result_ge);
    }

cleanup:
    purify_bridge_secure_clear(&lhs_ge, sizeof(lhs_ge));
    purify_bridge_secure_clear(&rhs_ge, sizeof(rhs_ge));
    purify_bridge_secure_clear(&result_ge, sizeof(result_ge));
    purify_bridge_secure_clear(&lhs_j, sizeof(lhs_j));
    purify_bridge_secure_clear(&result_j, sizeof(result_j));
    return ok;
}

#endif /* PURIFY_BRIDGE_BPPP_COMMIT_IMPL_H */
