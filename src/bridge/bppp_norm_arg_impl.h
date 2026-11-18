// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/*
 * BPPP norm-argument proving, verification and claim preparation.
 *
 * Part of the Purify secp256k1 bridge translation unit. Include only from
 * bppp_bridge.c, after secp256k1.c and the parts listed before this one.
 */

#ifndef PURIFY_BRIDGE_BPPP_NORM_ARG_IMPL_H
#define PURIFY_BRIDGE_BPPP_NORM_ARG_IMPL_H

static int purify_bppp_prove_norm_arg_impl(purify_secp_context* context,
                                           purify_bppp_backend_resources* resources,
                                           const unsigned char rho32[32], const unsigned char* generators33,
                                           size_t generators_count, const unsigned char* n_vec32, size_t n_vec_len,
                                           const unsigned char* l_vec32, size_t l_vec_len,
                                           const unsigned char* c_vec32, size_t c_vec_len,
                                           unsigned char commitment_out33[33], unsigned char* proof_out,
                                           size_t* proof_len) {
    secp256k1_context* ctx = resources != NULL ? resources->ctx : purify_context_handle(context);
    secp256k1_scratch_space* scratch = resources != NULL ? resources->scratch : NULL;
    secp256k1_bppp_generators* gens = NULL;
    secp256k1_scalar rho = {0}, mu = {0};
    secp256k1_scalar *n_vec = NULL, *l_vec = NULL, *c_vec = NULL;
    secp256k1_ge commit;
    secp256k1_sha256 transcript;
    size_t required = purify_bppp_required_proof_size(n_vec_len, c_vec_len);
    size_t expected_generators = 0;
    size_t serialized_generators_len = 0;
    size_t scratch_checkpoint = 0;
    int ok = 0;
    int scratch_contains_secrets = 0;
    int scratch_tail_cleared = 0;
    purify_bppp_mutable_generators_guard gens_guard = {0};

    if (ctx == NULL || rho32 == NULL || (resources == NULL && generators33 == NULL) || n_vec32 == NULL || l_vec32 == NULL || c_vec32 == NULL ||
        commitment_out33 == NULL || proof_out == NULL || proof_len == NULL) {
        return 0;
    }
    if (n_vec_len == 0 || l_vec_len == 0 || c_vec_len == 0 || l_vec_len != c_vec_len ||
        n_vec_len < c_vec_len) {
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
    if (*proof_len < required) {
        *proof_len = required;
        return 0;
    }
    if (!purify_parse_scalar(rho32, &rho, 1)) {
        goto cleanup;
    }
    if (resources != NULL) {
        gens = purify_bppp_backend_resources_acquire_scratch_gens(resources, &gens_guard);
        if (gens == NULL) {
            goto cleanup;
        }
    } else {
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
    if (!purify_serialize_point(commitment_out33, &commit)) {
        goto cleanup;
    }
    if (!purify_norm_arg_commit_initial_data(&transcript, &rho, gens, n_vec_len, c_vec, c_vec_len, &commit)) {
        goto cleanup;
    }
    ok = purify_bppp_rangeproof_norm_product_prove_with_copied_inputs(
        ctx, scratch, proof_out, proof_len, &transcript, &rho, gens->gens,
        gens->n, n_vec, n_vec_len, l_vec, l_vec_len, c_vec, c_vec_len,
        scratch_checkpoint, NULL, NULL);
    scratch_tail_cleared = 1;

cleanup:
    purify_bridge_secure_free_array(n_vec, n_vec_len, sizeof(*n_vec));
    purify_bridge_secure_free_array(l_vec, l_vec_len, sizeof(*l_vec));
    purify_bridge_secure_free_array(c_vec, c_vec_len, sizeof(*c_vec));
    if (scratch_contains_secrets && !scratch_tail_cleared) {
        purify_bridge_secure_clear_scratch_tail(scratch, scratch_checkpoint);
    }
    secp256k1_scalar_clear(&rho);
    secp256k1_scalar_clear(&mu);
    purify_bridge_secure_clear(&commit, sizeof(commit));
    purify_bridge_secure_clear(&transcript, sizeof(transcript));
    purify_bppp_backend_resources_release_scratch_gens(&gens_guard);
    if (resources == NULL) {
        if (gens != NULL) secp256k1_bppp_generators_destroy(ctx, gens);
        if (scratch != NULL) secp256k1_scratch_space_destroy(ctx, scratch);
    }
    return ok;
}

int purify_bppp_prove_norm_arg(purify_secp_context* context,
                               const unsigned char rho32[32], const unsigned char* generators33, size_t generators_count,
                               const unsigned char* n_vec32, size_t n_vec_len, const unsigned char* l_vec32,
                               size_t l_vec_len, const unsigned char* c_vec32, size_t c_vec_len,
                               unsigned char commitment_out33[33], unsigned char* proof_out, size_t* proof_len) {
    return purify_bppp_prove_norm_arg_impl(context, NULL, rho32, generators33, generators_count, n_vec32, n_vec_len,
                                           l_vec32, l_vec_len, c_vec32, c_vec_len, commitment_out33,
                                           proof_out, proof_len);
}

int purify_bppp_prove_norm_arg_with_resources(purify_bppp_backend_resources* resources,
                                              const unsigned char rho32[32],
                                              const unsigned char* n_vec32, size_t n_vec_len,
                                              const unsigned char* l_vec32, size_t l_vec_len,
                                              const unsigned char* c_vec32, size_t c_vec_len,
                                              unsigned char commitment_out33[33], unsigned char* proof_out,
                                              size_t* proof_len) {
    return purify_bppp_prove_norm_arg_impl(NULL, resources, rho32, NULL,
                                           resources != NULL ? resources->generators_count : 0,
                                           n_vec32, n_vec_len, l_vec32, l_vec_len, c_vec32, c_vec_len,
                                           commitment_out33, proof_out, proof_len);
}

static int purify_bppp_prove_norm_arg_to_commitment_impl(purify_secp_context* context,
                                                         purify_bppp_backend_resources* resources,
                                                         const unsigned char rho32[32], const unsigned char* generators33,
                                                         size_t generators_count, const unsigned char* n_vec32,
                                                         size_t n_vec_len, const unsigned char* l_vec32,
                                                         size_t l_vec_len, const unsigned char* c_vec32,
                                                         size_t c_vec_len, const unsigned char commitment33[33],
                                                         unsigned char* proof_out, size_t* proof_len,
                                                         purify_bppp_round_challenge_callback challenge_callback,
                                                         void* callback_data) {
    secp256k1_context* ctx = resources != NULL ? resources->ctx : purify_context_handle(context);
    secp256k1_scratch_space* scratch = resources != NULL ? resources->scratch : NULL;
    secp256k1_bppp_generators* gens = NULL;
    secp256k1_scalar rho = {0}, mu = {0};
    secp256k1_scalar *n_vec = NULL, *l_vec = NULL, *c_vec = NULL;
    secp256k1_ge expected_commit, commitment_ge;
    secp256k1_sha256 transcript;
    unsigned char expected_commitment33[33];
    size_t required = purify_bppp_required_proof_size(n_vec_len, c_vec_len);
    size_t expected_generators = 0;
    size_t serialized_generators_len = 0;
    size_t scratch_checkpoint = 0;
    int ok = 0;
    int scratch_contains_secrets = 0;
    int scratch_tail_cleared = 0;
    purify_bppp_mutable_generators_guard gens_guard = {0};

    memset(expected_commitment33, 0, sizeof(expected_commitment33));
    if (ctx == NULL || rho32 == NULL || (resources == NULL && generators33 == NULL) || n_vec32 == NULL || l_vec32 == NULL || c_vec32 == NULL ||
        commitment33 == NULL || proof_out == NULL || proof_len == NULL) {
        return 0;
    }
    if (n_vec_len == 0 || l_vec_len == 0 || c_vec_len == 0 || l_vec_len != c_vec_len ||
        n_vec_len < c_vec_len) {
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
    if (*proof_len < required) {
        *proof_len = required;
        return 0;
    }
    if (!purify_parse_scalar(rho32, &rho, 1) || !purify_parse_point_as_ge(commitment33, &commitment_ge)) {
        goto cleanup;
    }
    if (resources != NULL) {
        gens = purify_bppp_backend_resources_acquire_scratch_gens(resources, &gens_guard);
        if (gens == NULL) {
            goto cleanup;
        }
    } else {
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
    if (!purify_bppp_commit_secret(ctx, &expected_commit, gens, n_vec,
                                  n_vec_len, l_vec, l_vec_len, c_vec,
                                  c_vec_len, &mu)) {
        goto cleanup;
    }
    if (!purify_serialize_point(expected_commitment33, &expected_commit)) {
        goto cleanup;
    }
    if (!purify_bridge_memeq_const(expected_commitment33, commitment33,
                                   sizeof(expected_commitment33))) {
        goto cleanup;
    }
    if (!purify_norm_arg_commit_initial_data(&transcript, &rho, gens, n_vec_len, c_vec, c_vec_len, &commitment_ge)) {
        goto cleanup;
    }
    ok = purify_bppp_rangeproof_norm_product_prove_with_copied_inputs(
        ctx, scratch, proof_out, proof_len, &transcript, &rho, gens->gens,
        gens->n, n_vec, n_vec_len, l_vec, l_vec_len, c_vec, c_vec_len,
        scratch_checkpoint, challenge_callback, callback_data);
    scratch_tail_cleared = 1;

cleanup:
    purify_bridge_secure_free_array(n_vec, n_vec_len, sizeof(*n_vec));
    purify_bridge_secure_free_array(l_vec, l_vec_len, sizeof(*l_vec));
    purify_bridge_secure_free_array(c_vec, c_vec_len, sizeof(*c_vec));
    if (scratch_contains_secrets && !scratch_tail_cleared) {
        purify_bridge_secure_clear_scratch_tail(scratch, scratch_checkpoint);
    }
    secp256k1_scalar_clear(&rho);
    secp256k1_scalar_clear(&mu);
    purify_bridge_secure_clear(&expected_commit, sizeof(expected_commit));
    purify_bridge_secure_clear(&commitment_ge, sizeof(commitment_ge));
    purify_bridge_secure_clear(expected_commitment33,
                               sizeof(expected_commitment33));
    purify_bridge_secure_clear(&transcript, sizeof(transcript));
    purify_bppp_backend_resources_release_scratch_gens(&gens_guard);
    if (resources == NULL) {
        if (gens != NULL) secp256k1_bppp_generators_destroy(ctx, gens);
        if (scratch != NULL) secp256k1_scratch_space_destroy(ctx, scratch);
    }
    return ok;
}

int purify_bppp_prove_norm_arg_to_commitment(purify_secp_context* context,
                                             const unsigned char rho32[32], const unsigned char* generators33, size_t generators_count,
                                             const unsigned char* n_vec32, size_t n_vec_len, const unsigned char* l_vec32,
                                             size_t l_vec_len, const unsigned char* c_vec32, size_t c_vec_len,
                                             const unsigned char commitment33[33], unsigned char* proof_out, size_t* proof_len) {
    return purify_bppp_prove_norm_arg_to_commitment_impl(context, NULL, rho32, generators33, generators_count,
                                                         n_vec32, n_vec_len, l_vec32, l_vec_len, c_vec32, c_vec_len,
                                                         commitment33, proof_out, proof_len, NULL, NULL);
}

int purify_bppp_prove_norm_arg_to_commitment_with_resources(purify_bppp_backend_resources* resources,
                                                            const unsigned char rho32[32],
                                                            const unsigned char* n_vec32, size_t n_vec_len,
                                                            const unsigned char* l_vec32, size_t l_vec_len,
                                                            const unsigned char* c_vec32, size_t c_vec_len,
                                                            const unsigned char commitment33[33],
                                                            unsigned char* proof_out, size_t* proof_len) {
    return purify_bppp_prove_norm_arg_to_commitment_impl(NULL, resources, rho32, NULL,
                                                         resources != NULL ? resources->generators_count : 0,
                                                         n_vec32, n_vec_len, l_vec32, l_vec_len, c_vec32, c_vec_len,
                                                         commitment33, proof_out, proof_len, NULL, NULL);
}

int purify_bppp_prove_norm_arg_to_commitment_with_callback(
    purify_secp_context* context,
    const unsigned char rho32[32],
    const unsigned char* generators33,
    size_t generators_count,
    const unsigned char* n_vec32,
    size_t n_vec_len,
    const unsigned char* l_vec32,
    size_t l_vec_len,
    const unsigned char* c_vec32,
    size_t c_vec_len,
    const unsigned char commitment33[33],
    purify_bppp_round_challenge_callback challenge_callback,
    void* callback_data,
    unsigned char* proof_out,
    size_t* proof_len) {
    if (challenge_callback == NULL) {
        return 0;
    }
    return purify_bppp_prove_norm_arg_to_commitment_impl(
        context, NULL, rho32, generators33, generators_count,
        n_vec32, n_vec_len, l_vec32, l_vec_len, c_vec32, c_vec_len,
        commitment33, proof_out, proof_len, challenge_callback,
        callback_data);
}

static int purify_bppp_rangeproof_norm_product_verify_challenges(
    const secp256k1_context* ctx,
    secp256k1_scratch_space* scratch,
    const unsigned char* proof,
    size_t proof_len,
    const secp256k1_scalar* rho,
    const secp256k1_bppp_generators* g_vec,
    size_t g_len,
    const secp256k1_scalar* c_vec,
    size_t c_vec_len,
    const secp256k1_ge* commit,
    const secp256k1_scalar* gammas,
    size_t gamma_count) {
    secp256k1_scalar rho_f, mu_f, v, n, l, rho_inv, h_c;
    secp256k1_scalar *s_g, *s_h, *rho_inv_pows;
    secp256k1_gej res1, res2;
    size_t i = 0, scratch_checkpoint;
    int overflow;
    size_t log_g_len, log_h_len, n_rounds;
    size_t h_len = c_vec_len;
    int ok = 0;

    if (g_len == 0 || c_vec_len == 0) {
        return 0;
    }
    log_g_len = secp256k1_bppp_log2(g_len);
    log_h_len = secp256k1_bppp_log2(c_vec_len);
    n_rounds = log_g_len > log_h_len ? log_g_len : log_h_len;
    if (g_vec->n != h_len + g_len ||
        proof_len != 65u * n_rounds + 64u ||
        gamma_count != n_rounds ||
        (gamma_count != 0 && gammas == NULL) ||
        !secp256k1_is_power_of_two(g_len) ||
        !secp256k1_is_power_of_two(h_len)) {
        return 0;
    }

    secp256k1_scalar_set_b32(&n, &proof[n_rounds * 65u], &overflow);
    if (overflow) {
        return 0;
    }
    secp256k1_scalar_set_b32(&l, &proof[n_rounds * 65u + 32u], &overflow);
    if (overflow || secp256k1_scalar_is_zero(rho)) {
        return 0;
    }

    scratch_checkpoint =
        secp256k1_scratch_checkpoint(&ctx->error_callback, scratch);
    s_g = (secp256k1_scalar*)secp256k1_scratch_alloc(
        &ctx->error_callback, scratch, g_len * sizeof(*s_g));
    s_h = (secp256k1_scalar*)secp256k1_scratch_alloc(
        &ctx->error_callback, scratch, h_len * sizeof(*s_h));
    rho_inv_pows = (secp256k1_scalar*)secp256k1_scratch_alloc(
        &ctx->error_callback, scratch,
        log_g_len * sizeof(*rho_inv_pows));
    if (s_g == NULL || s_h == NULL || rho_inv_pows == NULL) {
        goto cleanup;
    }

    secp256k1_scalar_inverse_var(&rho_inv, rho);
    secp256k1_bppp_powers_of_rho(rho_inv_pows, &rho_inv, log_g_len);
    rho_f = *rho;
    for (i = 0; i < log_g_len; ++i) {
        secp256k1_scalar_sqr(&rho_f, &rho_f);
    }

    secp256k1_scalar_mul(&s_g[0], &n, &rho_f);
    secp256k1_scalar_mul(&s_g[0], &s_g[0], &rho_inv);
    for (i = 1; i < g_len; ++i) {
        const size_t log_i = secp256k1_bppp_log2(i);
        const size_t nearest_pow_of_two = (size_t)1 << log_i;
        secp256k1_scalar_mul(&s_g[i],
                            &s_g[i - nearest_pow_of_two],
                            &gammas[log_i]);
        secp256k1_scalar_mul(&s_g[i], &s_g[i], &rho_inv_pows[log_i]);
    }
    s_h[0] = l;
    secp256k1_scalar_set_int(&h_c, 0);
    for (i = 1; i < h_len; ++i) {
        const size_t log_i = secp256k1_bppp_log2(i);
        const size_t nearest_pow_of_two = (size_t)1 << log_i;
        secp256k1_scalar_mul(&s_h[i],
                            &s_h[i - nearest_pow_of_two],
                            &gammas[log_i]);
    }
    secp256k1_scalar_inner_product(&h_c, c_vec, 0, s_h, 0, 1, h_len);
    secp256k1_scalar_sqr(&mu_f, &rho_f);
    secp256k1_scalar_mul(&v, &n, &n);
    secp256k1_scalar_mul(&v, &v, &mu_f);
    secp256k1_scalar_add(&v, &v, &h_c);

    {
        ec_mult_verify_cb_data1 data;
        data.proof = proof;
        data.commit = commit;
        data.gammas = gammas;
        if (!secp256k1_ecmult_multi_var(
                &ctx->error_callback, scratch, &res1, NULL,
                ec_mult_verify_cb1, &data, 2u * n_rounds + 1u)) {
            goto cleanup;
        }
    }
    {
        ec_mult_verify_cb_data2 data;
        data.g_vec = g_vec->gens;
        data.g_vec_len = g_len;
        data.s_g = s_g;
        data.s_h = s_h;
        if (!secp256k1_ecmult_multi_var(
                &ctx->error_callback, scratch, &res2, &v,
                ec_mult_verify_cb2, &data, g_len + h_len)) {
            goto cleanup;
        }
    }
    ok = secp256k1_gej_eq_var(&res1, &res2);

cleanup:
    secp256k1_scratch_apply_checkpoint(
        &ctx->error_callback, scratch, scratch_checkpoint);
    return ok;
}

static int purify_bppp_verify_norm_arg_impl(purify_secp_context* context,
                                            purify_bppp_backend_resources* resources,
                                            const unsigned char rho32[32], const unsigned char* generators33,
                                            size_t generators_count, const unsigned char* c_vec32, size_t c_vec_len,
                                            size_t n_vec_len, const unsigned char commitment33[33],
                                            const unsigned char* proof, size_t proof_len,
                                            const unsigned char* gammas32,
                                            size_t gamma_count) {
    secp256k1_context* ctx = resources != NULL ? resources->ctx : purify_context_handle(context);
    secp256k1_scratch_space* scratch = resources != NULL ? resources->scratch : NULL;
    secp256k1_bppp_generators* gens = resources != NULL ? resources->gens : NULL;
    secp256k1_scalar rho, *c_vec = NULL, *gammas = NULL;
    secp256k1_ge commit;
    secp256k1_sha256 transcript;
    size_t expected_generators = 0;
    size_t serialized_generators_len = 0;
    int ok = 0;

    if (ctx == NULL || rho32 == NULL || (resources == NULL && generators33 == NULL) || c_vec32 == NULL || commitment33 == NULL || proof == NULL) {
        return 0;
    }
    /* Four-fork norm extraction requires a paired norm coordinate in every
     * nonterminal round. A linear-only tail does not preserve that relation. */
    if (n_vec_len == 0 || c_vec_len == 0 || n_vec_len < c_vec_len ||
        !purify_bridge_checked_add_size(n_vec_len, c_vec_len, &expected_generators) ||
        generators_count != expected_generators ||
        !purify_bridge_checked_mul_size(generators_count, 33u, &serialized_generators_len)) {
        return 0;
    }
    if (!secp256k1_is_power_of_two(n_vec_len) || !secp256k1_is_power_of_two(c_vec_len)) {
        return 0;
    }
    if (resources != NULL && resources->generators_count != generators_count) {
        return 0;
    }
    if (!purify_parse_scalar(rho32, &rho, 1) || !secp256k1_ge_parse_ext(&commit, commitment33)) {
        return 0;
    }
    if (resources == NULL) {
        scratch = purify_bppp_create_scratch(ctx, generators_count);
        gens = secp256k1_bppp_generators_parse(ctx, generators33, serialized_generators_len);
    }
    c_vec = (secp256k1_scalar*)purify_malloc_array(c_vec_len, sizeof(*c_vec));
    if (scratch == NULL || gens == NULL || c_vec == NULL) {
        goto cleanup;
    }
    if (!purify_parse_scalar_array(c_vec32, c_vec_len, c_vec)) {
        goto cleanup;
    }
    if (gammas32 != NULL) {
        const size_t rounds = secp256k1_bppp_log2(n_vec_len);
        if (gamma_count != rounds) {
            goto cleanup;
        }
        gammas = (secp256k1_scalar*)purify_malloc_array(
            gamma_count, sizeof(*gammas));
        if ((gamma_count != 0 && gammas == NULL) ||
            !purify_parse_scalar_array(gammas32, gamma_count, gammas)) {
            goto cleanup;
        }
        for (size_t i = 0; i < gamma_count; ++i) {
            if (secp256k1_scalar_is_zero(&gammas[i])) {
                goto cleanup;
            }
        }
        ok = purify_bppp_rangeproof_norm_product_verify_challenges(
            ctx, scratch, proof, proof_len, &rho, gens, n_vec_len,
            c_vec, c_vec_len, &commit, gammas, gamma_count);
    } else {
        if (gamma_count != 0 ||
            !purify_norm_arg_commit_initial_data(
                &transcript, &rho, gens, n_vec_len, c_vec, c_vec_len,
                &commit)) {
            goto cleanup;
        }
        ok = secp256k1_bppp_rangeproof_norm_product_verify(
            ctx, scratch, proof, proof_len, &transcript, &rho,
            gens, n_vec_len, c_vec, c_vec_len, &commit);
    }

cleanup:
    free(gammas);
    if (c_vec != NULL) free(c_vec);
    if (resources == NULL) {
        if (gens != NULL) secp256k1_bppp_generators_destroy(ctx, gens);
        if (scratch != NULL) secp256k1_scratch_space_destroy(ctx, scratch);
    }
    return ok;
}

int purify_bppp_verify_norm_arg(purify_secp_context* context,
                                const unsigned char rho32[32], const unsigned char* generators33, size_t generators_count,
                                const unsigned char* c_vec32, size_t c_vec_len, size_t n_vec_len,
                                const unsigned char commitment33[33], const unsigned char* proof, size_t proof_len) {
    return purify_bppp_verify_norm_arg_impl(context, NULL, rho32, generators33, generators_count,
                                            c_vec32, c_vec_len, n_vec_len, commitment33, proof, proof_len,
                                            NULL, 0);
}

int purify_bppp_verify_norm_arg_with_resources(purify_bppp_backend_resources* resources,
                                               const unsigned char rho32[32],
                                               const unsigned char* c_vec32, size_t c_vec_len, size_t n_vec_len,
                                               const unsigned char commitment33[33], const unsigned char* proof,
                                               size_t proof_len) {
    return purify_bppp_verify_norm_arg_impl(NULL, resources, rho32, NULL,
                                            resources != NULL ? resources->generators_count : 0,
                                            c_vec32, c_vec_len, n_vec_len, commitment33, proof, proof_len,
                                            NULL, 0);
}

int purify_bppp_verify_norm_arg_with_challenges(
    purify_secp_context* context,
    const unsigned char rho32[32],
    const unsigned char* generators33,
    size_t generators_count,
    const unsigned char* c_vec32,
    size_t c_vec_len,
    size_t n_vec_len,
    const unsigned char commitment33[33],
    const unsigned char* proof,
    size_t proof_len,
    const unsigned char* gammas32,
    size_t gamma_count) {
    if (gammas32 == NULL) {
        return 0;
    }
    return purify_bppp_verify_norm_arg_impl(
        context, NULL, rho32, generators33, generators_count,
        c_vec32, c_vec_len, n_vec_len, commitment33, proof, proof_len,
        gammas32, gamma_count);
}

static int purify_bppp_prepare_norm_arg_claim_impl(
    purify_secp_context* context,
    const unsigned char rho32[32],
    const unsigned char* generators33,
    size_t generators_count,
    const unsigned char* c_vec32,
    size_t c_vec_len,
    size_t n_vec_len,
    const unsigned char commitment33[33],
    const unsigned char* proof,
    size_t proof_len,
    const unsigned char* supplied_gammas32,
    unsigned char* derived_gammas32,
    size_t gamma_count,
    unsigned char terminal_n32[32],
    unsigned char terminal_l32[32],
    unsigned char residual33[33]) {
    secp256k1_context* ctx = purify_context_handle(context);
    secp256k1_scratch_space* scratch = NULL;
    secp256k1_bppp_generators* gens = NULL;
    secp256k1_scalar rho, n, l, norm, *c_vec = NULL, *gammas = NULL;
    secp256k1_ge commit, residual;
    secp256k1_gej residual_j;
    secp256k1_sha256 transcript;
    ec_mult_verify_cb_data1 equation;
    size_t expected_generators, generator_bytes, rounds, i;
    int ok = 0;

    if (ctx == NULL || rho32 == NULL || generators33 == NULL || c_vec32 == NULL ||
        commitment33 == NULL || proof == NULL || terminal_n32 == NULL ||
        terminal_l32 == NULL || residual33 == NULL ||
        (gamma_count != 0 && supplied_gammas32 == NULL &&
         derived_gammas32 == NULL)) {
        return 0;
    }
    /* Preserve the standalone norm verifier's supported relation exactly. */
    if (!secp256k1_is_power_of_two(n_vec_len) || !secp256k1_is_power_of_two(c_vec_len) ||
        n_vec_len < c_vec_len ||
        !purify_bridge_checked_add_size(n_vec_len, c_vec_len, &expected_generators) ||
        generators_count != expected_generators ||
        !purify_bridge_checked_mul_size(generators_count, 33u, &generator_bytes)) {
        return 0;
    }
    rounds = secp256k1_bppp_log2(n_vec_len);
    if (gamma_count != rounds || proof_len != 65u * rounds + 64u ||
        !purify_parse_scalar(rho32, &rho, 1) ||
        !purify_parse_scalar(proof + 65u * rounds, &n, 0) ||
        !purify_parse_scalar(proof + 65u * rounds + 32u, &l, 0) ||
        !purify_parse_point_as_ge(commitment33, &commit)) {
        return 0;
    }
    scratch = purify_bppp_create_scratch(ctx, generators_count);
    gens = secp256k1_bppp_generators_parse(ctx, generators33, generator_bytes);
    c_vec = (secp256k1_scalar*)purify_malloc_array(c_vec_len, sizeof(*c_vec));
    if (rounds != 0) {
        gammas = (secp256k1_scalar*)purify_malloc_array(rounds, sizeof(*gammas));
    }
    if (scratch == NULL || gens == NULL || c_vec == NULL ||
        (rounds != 0 && gammas == NULL) ||
        !purify_parse_scalar_array(c_vec32, c_vec_len, c_vec)) {
        goto cleanup;
    }
    if (supplied_gammas32 != NULL) {
        if (!purify_parse_scalar_array(
                supplied_gammas32, rounds, gammas)) {
            goto cleanup;
        }
        for (i = 0; i < rounds; ++i) {
            if (secp256k1_scalar_is_zero(&gammas[i])) {
                goto cleanup;
            }
        }
    } else {
        if (!purify_norm_arg_commit_initial_data(
                &transcript, &rho, gens, n_vec_len, c_vec, c_vec_len,
                &commit)) {
            goto cleanup;
        }
        for (i = 0; i < rounds; ++i) {
            secp256k1_sha256_write(&transcript, proof + 65u * i, 65u);
            secp256k1_bppp_challenge_scalar(&gammas[i], &transcript, 0);
        }
        secp256k1_sha256_clear(&transcript);
    }

    /* Remove only the weighted-norm base-generator contribution. This
     * computes the short side of the verification equation:
     * T = C + sum(gamma*X + (gamma^2-1)*R) - n^2*rho^(2*g)*G.
     * The linear contribution l*<c,w_gamma>*G still needs an authenticated
     * coefficient opening; equality to the fixed-basis MSM remains deferred.
     */
    norm = rho;
    for (i = 0; i <= rounds; ++i) {
        secp256k1_scalar_sqr(&norm, &norm);
    }
    secp256k1_scalar_mul(&norm, &norm, &n);
    secp256k1_scalar_mul(&norm, &norm, &n);
    secp256k1_scalar_negate(&norm, &norm);
    equation.proof = proof;
    equation.commit = &commit;
    equation.gammas = gammas;
    if (!secp256k1_ecmult_multi_var(&ctx->error_callback, scratch, &residual_j, &norm,
                                  ec_mult_verify_cb1, &equation, 2u * rounds + 1u)) {
        goto cleanup;
    }
    secp256k1_ge_set_gej_var(&residual, &residual_j);
    secp256k1_ge_serialize_ext(residual33, &residual);
    secp256k1_scalar_get_b32(terminal_n32, &n);
    secp256k1_scalar_get_b32(terminal_l32, &l);
    for (i = 0; derived_gammas32 != NULL && i < rounds; ++i) {
        secp256k1_scalar_get_b32(
            derived_gammas32 + 32u * i, &gammas[i]);
    }
    ok = 1;

cleanup:
    free(gammas);
    free(c_vec);
    if (gens != NULL) secp256k1_bppp_generators_destroy(ctx, gens);
    if (scratch != NULL) secp256k1_scratch_space_destroy(ctx, scratch);
    return ok;
}

int purify_bppp_prepare_norm_arg_claim(purify_secp_context* context,
                                     const unsigned char rho32[32],
                                     const unsigned char* generators33, size_t generators_count,
                                     const unsigned char* c_vec32, size_t c_vec_len, size_t n_vec_len,
                                     const unsigned char commitment33[33],
                                     const unsigned char* proof, size_t proof_len,
                                     unsigned char terminal_n32[32], unsigned char terminal_l32[32],
                                     unsigned char* gammas32, size_t gamma_count,
                                     unsigned char residual33[33]) {
    return purify_bppp_prepare_norm_arg_claim_impl(
        context, rho32, generators33, generators_count, c_vec32,
        c_vec_len, n_vec_len, commitment33, proof, proof_len, NULL,
        gammas32, gamma_count, terminal_n32, terminal_l32, residual33);
}

int purify_bppp_prepare_norm_arg_claim_with_challenges(
    purify_secp_context* context,
    const unsigned char rho32[32],
    const unsigned char* generators33,
    size_t generators_count,
    const unsigned char* c_vec32,
    size_t c_vec_len,
    size_t n_vec_len,
    const unsigned char commitment33[33],
    const unsigned char* proof,
    size_t proof_len,
    const unsigned char* gammas32,
    size_t gamma_count,
    unsigned char terminal_n32[32],
    unsigned char terminal_l32[32],
    unsigned char residual33[33]) {
    if (gammas32 == NULL) {
        return 0;
    }
    return purify_bppp_prepare_norm_arg_claim_impl(
        context, rho32, generators33, generators_count, c_vec32,
        c_vec_len, n_vec_len, commitment33, proof, proof_len,
        gammas32, NULL, gamma_count, terminal_n32, terminal_l32,
        residual33);
}

#endif /* PURIFY_BRIDGE_BPPP_NORM_ARG_IMPL_H */
