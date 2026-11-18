// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/*
 * Constant-time witness commitments and the secret-input BPPP norm-product prover.
 *
 * Part of the Purify secp256k1 bridge translation unit. Include only from
 * bppp_bridge.c, after secp256k1.c and the parts listed before this one.
 */

#ifndef PURIFY_BRIDGE_BPPP_SECRET_PROVER_IMPL_H
#define PURIFY_BRIDGE_BPPP_SECRET_PROVER_IMPL_H

static int purify_norm_arg_public_digest(unsigned char digest[32], const secp256k1_scalar* rho,
                                          const secp256k1_bppp_generators* gens_vec, size_t g_len,
                                          const secp256k1_scalar* c_vec, size_t c_vec_len) {
    static const unsigned char tag[] = "Purify/BPPP/NormArg/PublicDataV1";
    unsigned char ser_point[33], ser_scalar[32], ser_le64[8];
    secp256k1_sha256 public_data;
    size_t i;

    secp256k1_sha256_initialize_tagged(&public_data, tag, sizeof(tag) - 1);
    secp256k1_scalar_get_b32(ser_scalar, rho);
    secp256k1_sha256_write(&public_data, ser_scalar, sizeof(ser_scalar));
    secp256k1_bppp_le64(ser_le64, g_len);
    secp256k1_sha256_write(&public_data, ser_le64, sizeof(ser_le64));
    secp256k1_bppp_le64(ser_le64, gens_vec->n);
    secp256k1_sha256_write(&public_data, ser_le64, sizeof(ser_le64));
    for (i = 0; i < gens_vec->n; ++i) {
        secp256k1_ge gen = gens_vec->gens[i];
        if (!purify_serialize_point(ser_point, &gen)) {
            secp256k1_sha256_clear(&public_data);
            return 0;
        }
        secp256k1_sha256_write(&public_data, ser_point, sizeof(ser_point));
    }
    secp256k1_bppp_le64(ser_le64, c_vec_len);
    secp256k1_sha256_write(&public_data, ser_le64, sizeof(ser_le64));
    for (i = 0; i < c_vec_len; ++i) {
        secp256k1_scalar_get_b32(ser_scalar, &c_vec[i]);
        secp256k1_sha256_write(&public_data, ser_scalar, sizeof(ser_scalar));
    }
    secp256k1_sha256_finalize(&public_data, digest);
    secp256k1_sha256_clear(&public_data);
    return 1;
}

static int purify_norm_arg_commit_initial_data(secp256k1_sha256* transcript, const secp256k1_scalar* rho,
                                                const secp256k1_bppp_generators* gens_vec, size_t g_len,
                                                const secp256k1_scalar* c_vec, size_t c_vec_len,
                                                const secp256k1_ge* commit) {
    static const unsigned char tag[] = "Purify/BPPP/NormArg/TranscriptV1";
    unsigned char public_digest[32], ser_commit[33];
    secp256k1_ge comm = *commit;

    /* Recompute the digest from the checked public statement; never accept a
     * caller-supplied digest as a replacement. A future parent verifier can
     * compute this public work outside its circuit and bind the digest inside.
     * Distinct tags separate this transcript from the old direct serialization.
     */
    if (!purify_serialize_point(ser_commit, &comm)
        || !purify_norm_arg_public_digest(public_digest, rho, gens_vec, g_len, c_vec, c_vec_len)) {
        return 0;
    }
    secp256k1_sha256_initialize_tagged(transcript, tag, sizeof(tag) - 1);
    secp256k1_sha256_write(transcript, public_digest, sizeof(public_digest));
    secp256k1_sha256_write(transcript, ser_commit, sizeof(ser_commit));
    return 1;
}

static int purify_copy_vectors_into_scratch(const secp256k1_context* ctx, secp256k1_scratch_space* scratch,
                                            secp256k1_scalar** ns, secp256k1_scalar** ls, secp256k1_scalar** cs,
                                            secp256k1_ge** gs, const secp256k1_scalar* n_vec,
                                            const secp256k1_scalar* l_vec, const secp256k1_scalar* c_vec,
                                            const secp256k1_ge* gens_vec, size_t g_len, size_t h_len) {
    size_t scalar_g_bytes = 0;
    size_t scalar_h_bytes = 0;
    size_t ge_count = 0;
    size_t ge_bytes = 0;

    if (!purify_bridge_checked_mul_size(g_len, sizeof(secp256k1_scalar), &scalar_g_bytes) ||
        !purify_bridge_checked_mul_size(h_len, sizeof(secp256k1_scalar), &scalar_h_bytes) ||
        !purify_bridge_checked_add_size(g_len, h_len, &ge_count) ||
        !purify_bridge_checked_mul_size(ge_count, sizeof(secp256k1_ge), &ge_bytes)) {
        return 0;
    }

    *ns = (secp256k1_scalar*)secp256k1_scratch_alloc(&ctx->error_callback, scratch, scalar_g_bytes);
    *ls = (secp256k1_scalar*)secp256k1_scratch_alloc(&ctx->error_callback, scratch, scalar_h_bytes);
    *cs = (secp256k1_scalar*)secp256k1_scratch_alloc(&ctx->error_callback, scratch, scalar_h_bytes);
    *gs = (secp256k1_ge*)secp256k1_scratch_alloc(&ctx->error_callback, scratch, ge_bytes);
    if (*ns == NULL || *ls == NULL || *cs == NULL || *gs == NULL) {
        return 0;
    }
    memcpy(*ns, n_vec, scalar_g_bytes);
    memcpy(*ls, l_vec, scalar_h_bytes);
    memcpy(*cs, c_vec, scalar_h_bytes);
    memcpy(*gs, gens_vec, ge_bytes);
    return 1;
}

/*
 * Secret-scalar MSM for the circuit prover boundary.
 *
 * libsecp256k1's ecmult_multi_var is intentionally variable time and is only
 * suitable when every scalar is public.  Circuit witnesses are still secret
 * when their raw and norm commitments are formed, so use the constant-time
 * single-point and base-point multipliers here.  The point list and its length
 * are public.  A zero scalar produces infinity; replace that affine input with
 * G, perform the unified addition, then constant-time select the unchanged
 * accumulator.  This avoids branching on a witness scalar.
 *
 * The final point is intentionally declassified by serialization into the
 * proof.  Public verifier and accumulation MSMs remain variable time.
 */
static void purify_ge_cmov(secp256k1_ge* r, const secp256k1_ge* a, int flag) {
    secp256k1_fe_cmov(&r->x, &a->x, flag);
    secp256k1_fe_cmov(&r->y, &a->y, flag);
    r->infinity ^= (r->infinity ^ a->infinity) & flag;
}

static void purify_gej_add_secret_scalar_term(secp256k1_gej* accumulator,
                                               const secp256k1_ge* point,
                                               const secp256k1_scalar* scalar) {
    secp256k1_gej termj, candidate;
    secp256k1_ge term;
    int term_is_infinity;

    secp256k1_ecmult_const(&termj, point, scalar);
    secp256k1_ge_set_gej(&term, &termj);
    term_is_infinity = term.infinity;
    purify_ge_cmov(&term, &secp256k1_ge_const_g, term_is_infinity);
    candidate = *accumulator;
    secp256k1_gej_add_ge(&candidate, &candidate, &term);
    secp256k1_gej_cmov(accumulator, &candidate,
                       term_is_infinity ^ 1);

    purify_bridge_secure_clear(&termj, sizeof(termj));
    purify_bridge_secure_clear(&candidate, sizeof(candidate));
    purify_bridge_secure_clear(&term, sizeof(term));
}

static int purify_ecmult_multi_secret(const secp256k1_context* ctx,
                                      secp256k1_gej* result,
                                      const secp256k1_scalar* base_scalar,
                                      secp256k1_ecmult_multi_callback callback,
                                      void* callback_data,
                                      size_t point_count) {
    size_t i;

    if (base_scalar != NULL) {
        secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, result, base_scalar);
    } else {
        secp256k1_gej_set_infinity(result);
    }
    for (i = 0; i < point_count; ++i) {
        secp256k1_scalar scalar = {0};
        secp256k1_ge point = {0};
        int callback_ok = callback(&scalar, &point, i, callback_data);
        if (!callback_ok) {
            secp256k1_scalar_clear(&scalar);
            purify_bridge_secure_clear(&point, sizeof(point));
            purify_bridge_secure_clear(result, sizeof(*result));
            return 0;
        }
        purify_gej_add_secret_scalar_term(result, &point, &scalar);
        secp256k1_scalar_clear(&scalar);
        purify_bridge_secure_clear(&point, sizeof(point));
    }
    return 1;
}

static void purify_scalar_inner_product_secret(
    secp256k1_scalar* result,
    const secp256k1_scalar* lhs,
    size_t lhs_offset,
    const secp256k1_scalar* rhs,
    size_t rhs_offset,
    size_t step,
    size_t length) {
    size_t i;

    secp256k1_scalar_set_int(result, 0);
    for (i = 0; i < length; ++i) {
        secp256k1_scalar term;
        secp256k1_scalar_mul(
            &term, &lhs[lhs_offset + step * i],
            &rhs[rhs_offset + step * i]);
        secp256k1_scalar_add(result, result, &term);
        secp256k1_scalar_clear(&term);
    }
}

static void purify_weighted_scalar_inner_product_secret(
    secp256k1_scalar* result,
    const secp256k1_scalar* lhs,
    size_t lhs_offset,
    const secp256k1_scalar* rhs,
    size_t rhs_offset,
    size_t step,
    size_t length,
    const secp256k1_scalar* weight) {
    secp256k1_scalar weight_power = *weight;
    size_t i;

    secp256k1_scalar_set_int(result, 0);
    for (i = 0; i < length; ++i) {
        secp256k1_scalar term;
        secp256k1_scalar_mul(
            &term, &lhs[lhs_offset + step * i],
            &rhs[rhs_offset + step * i]);
        secp256k1_scalar_mul(&term, &term, &weight_power);
        secp256k1_scalar_mul(&weight_power, &weight_power, weight);
        secp256k1_scalar_add(result, result, &term);
        secp256k1_scalar_clear(&term);
    }
    secp256k1_scalar_clear(&weight_power);
}

static int purify_bppp_commit_secret(const secp256k1_context* ctx,
                                     secp256k1_ge* commit,
                                     const secp256k1_bppp_generators* generators,
                                     const secp256k1_scalar* n_vec,
                                     size_t n_vec_len,
                                     const secp256k1_scalar* l_vec,
                                     size_t l_vec_len,
                                     const secp256k1_scalar* c_vec,
                                     size_t c_vec_len,
                                     const secp256k1_scalar* mu) {
    secp256k1_scalar v, l_c;
    secp256k1_gej commitj;
    ecmult_bp_commit_cb_data data;
    int ok;

    (void)c_vec_len;
    VERIFY_CHECK(generators->n == n_vec_len + l_vec_len);
    VERIFY_CHECK(l_vec_len == c_vec_len);
    VERIFY_CHECK(secp256k1_is_power_of_two(n_vec_len));
    VERIFY_CHECK(secp256k1_is_power_of_two(c_vec_len));

    purify_weighted_scalar_inner_product_secret(
        &v, n_vec, 0, n_vec, 0, 1, n_vec_len, mu);
    purify_scalar_inner_product_secret(
        &l_c, l_vec, 0, c_vec, 0, 1, l_vec_len);
    secp256k1_scalar_add(&v, &v, &l_c);

    data.g = generators->gens;
    data.n = n_vec;
    data.l = l_vec;
    data.g_len = n_vec_len;
    ok = purify_ecmult_multi_secret(
        ctx, &commitj, &v, ecmult_bp_commit_cb, &data,
        n_vec_len + l_vec_len);
    if (ok) {
        secp256k1_ge_set_gej(commit, &commitj);
        PURIFY_BRIDGE_DECLASSIFY(commit, sizeof(*commit));
    }

    secp256k1_scalar_clear(&v);
    secp256k1_scalar_clear(&l_c);
    purify_bridge_secure_clear(&commitj, sizeof(commitj));
    purify_bridge_secure_clear(&data, sizeof(data));
    return ok;
}

/*
 * Constant-time adaptation of the upstream BPPP norm prover.  The transcript,
 * folding challenges, vector lengths, and generator folds are public, so their
 * existing variable-time operations are retained.  The X and R commitments
 * contain witness scalars and therefore use purify_ecmult_multi_secret.
 */
static int purify_bppp_rangeproof_norm_product_prove_secret(
    const secp256k1_context* ctx,
    unsigned char* proof,
    size_t* proof_len,
    secp256k1_sha256* transcript,
    const secp256k1_scalar* rho,
    secp256k1_ge* g_vec,
    size_t g_vec_len,
    secp256k1_scalar* n_vec,
    size_t n_vec_len,
    secp256k1_scalar* l_vec,
    size_t l_vec_len,
    secp256k1_scalar* c_vec,
    size_t c_vec_len,
    purify_bppp_round_challenge_callback challenge_callback,
    void* callback_data) {
    secp256k1_scalar mu_f, rho_f = *rho;
    size_t proof_idx = 0;
    ecmult_x_cb_data x_cb_data;
    ecmult_r_cb_data r_cb_data;
    size_t g_len = n_vec_len, h_len = l_vec_len;
    const size_t G_GENS_LEN = g_len;

#ifdef VERIFY
    {
        size_t log_g_len_ver, log_h_len_ver, num_rounds_ver;
        VERIFY_CHECK(g_len > 0 && h_len > 0);
        log_g_len_ver = secp256k1_bppp_log2(g_len);
        log_h_len_ver = secp256k1_bppp_log2(h_len);
        num_rounds_ver = log_g_len_ver > log_h_len_ver
            ? log_g_len_ver : log_h_len_ver;
        VERIFY_CHECK(*proof_len >= 65 * num_rounds_ver + 64);
        VERIFY_CHECK(g_vec_len == n_vec_len + l_vec_len);
        VERIFY_CHECK(l_vec_len == c_vec_len);
        VERIFY_CHECK(secp256k1_is_power_of_two(n_vec_len));
        VERIFY_CHECK(secp256k1_is_power_of_two(c_vec_len));
    }
#else
    (void)g_vec_len;
    (void)c_vec_len;
#endif

    x_cb_data.n = n_vec;
    x_cb_data.g = g_vec;
    x_cb_data.l = l_vec;
    x_cb_data.G_GENS_LEN = G_GENS_LEN;
    r_cb_data.n1 = n_vec;
    r_cb_data.g1 = g_vec;
    r_cb_data.l1 = l_vec;
    r_cb_data.G_GENS_LEN = G_GENS_LEN;
    secp256k1_scalar_sqr(&mu_f, &rho_f);

    while (g_len > 1 || h_len > 1) {
        size_t i, num_points;
        secp256k1_scalar mu_sq, rho_inv, c0_l1, c1_l0;
        secp256k1_scalar x_v, c1_l1, r_v, gamma;
        secp256k1_gej rj, xj;
        secp256k1_ge r_ge, x_ge;
        int ok;

        /* rho_f is transcript-derived public data. */
        secp256k1_scalar_inverse_var(&rho_inv, &rho_f);
        secp256k1_scalar_sqr(&mu_sq, &mu_f);
        purify_scalar_inner_product_secret(
            &c0_l1, c_vec, 0, l_vec, 1, 2, h_len / 2);
        purify_scalar_inner_product_secret(
            &c1_l0, c_vec, 1, l_vec, 0, 2, h_len / 2);
        purify_weighted_scalar_inner_product_secret(
            &x_v, n_vec, 0, n_vec, 1, 2, g_len / 2, &mu_sq);
        secp256k1_scalar_mul(&x_v, &x_v, &rho_inv);
        secp256k1_scalar_add(&x_v, &x_v, &x_v);
        secp256k1_scalar_add(&x_v, &x_v, &c0_l1);
        secp256k1_scalar_add(&x_v, &x_v, &c1_l0);

        x_cb_data.rho = &rho_f;
        x_cb_data.rho_inv = &rho_inv;
        x_cb_data.n_len = g_len >= 2 ? g_len : 0;
        num_points = x_cb_data.n_len + (h_len >= 2 ? h_len : 0);
        ok = purify_ecmult_multi_secret(
            ctx, &xj, &x_v, ecmult_x_cb, &x_cb_data, num_points);
        if (!ok) {
            goto round_failure;
        }

        purify_weighted_scalar_inner_product_secret(
            &r_v, n_vec, 1, n_vec, 1, 2, g_len / 2, &mu_sq);
        purify_scalar_inner_product_secret(
            &c1_l1, c_vec, 1, l_vec, 1, 2, h_len / 2);
        secp256k1_scalar_add(&r_v, &r_v, &c1_l1);

        r_cb_data.n_len = g_len / 2;
        num_points = r_cb_data.n_len + h_len / 2;
        ok = purify_ecmult_multi_secret(
            ctx, &rj, &r_v, ecmult_r_cb, &r_cb_data, num_points);
        if (!ok) {
            goto round_failure;
        }

        /* These points become public proof bytes at this line. */
        secp256k1_ge_set_gej(&x_ge, &xj);
        secp256k1_ge_set_gej(&r_ge, &rj);
        secp256k1_fe_normalize(&x_ge.x);
        secp256k1_fe_normalize(&x_ge.y);
        secp256k1_fe_normalize(&r_ge.x);
        secp256k1_fe_normalize(&r_ge.y);
        PURIFY_BRIDGE_DECLASSIFY(&x_ge, sizeof(x_ge));
        PURIFY_BRIDGE_DECLASSIFY(&r_ge, sizeof(r_ge));
        secp256k1_bppp_serialize_points(
            &proof[proof_idx], &x_ge, &r_ge);
        proof_idx += 65;
        if (challenge_callback != NULL) {
            unsigned char challenge32[32] = {0};
            const size_t round = proof_idx / 65u - 1u;
            ok = challenge_callback(callback_data, &proof[proof_idx - 65],
                                    round, challenge32);
            if (!ok || !purify_parse_scalar(challenge32, &gamma, 1)) {
                purify_bridge_secure_clear(challenge32,
                                           sizeof(challenge32));
                goto round_failure;
            }
            purify_bridge_secure_clear(challenge32, sizeof(challenge32));
        } else {
            secp256k1_sha256_write(
                transcript, &proof[proof_idx - 65], 65);
            secp256k1_bppp_challenge_scalar(&gamma, transcript, 0);
        }

        if (g_len > 1) {
            for (i = 0; i < g_len; i += 2) {
                secp256k1_scalar nl, nr;
                secp256k1_gej gl, gr;
                secp256k1_scalar_mul(&nl, &n_vec[i], &rho_inv);
                secp256k1_scalar_mul(&nr, &n_vec[i + 1], &gamma);
                secp256k1_scalar_add(&n_vec[i / 2], &nl, &nr);

                /* rho_f and gamma are public folding challenges. */
                secp256k1_gej_set_ge(&gl, &g_vec[i]);
                secp256k1_ecmult(&gl, &gl, &rho_f, NULL);
                secp256k1_gej_set_ge(&gr, &g_vec[i + 1]);
                secp256k1_ecmult(&gr, &gr, &gamma, NULL);
                secp256k1_gej_add_var(&gl, &gl, &gr, NULL);
                secp256k1_ge_set_gej_var(&g_vec[i / 2], &gl);

                secp256k1_scalar_clear(&nl);
                secp256k1_scalar_clear(&nr);
                purify_bridge_secure_clear(&gl, sizeof(gl));
                purify_bridge_secure_clear(&gr, sizeof(gr));
            }
        }
        if (h_len > 1) {
            for (i = 0; i < h_len; i += 2) {
                secp256k1_scalar temporary;
                secp256k1_gej folded_generator;
                secp256k1_scalar_mul(
                    &temporary, &c_vec[i + 1], &gamma);
                secp256k1_scalar_add(
                    &c_vec[i / 2], &c_vec[i], &temporary);
                secp256k1_scalar_mul(
                    &temporary, &l_vec[i + 1], &gamma);
                secp256k1_scalar_add(
                    &l_vec[i / 2], &l_vec[i], &temporary);

                secp256k1_gej_set_ge(
                    &folded_generator, &g_vec[G_GENS_LEN + i + 1]);
                secp256k1_ecmult(
                    &folded_generator, &folded_generator, &gamma, NULL);
                secp256k1_gej_add_ge_var(
                    &folded_generator, &folded_generator,
                    &g_vec[G_GENS_LEN + i], NULL);
                secp256k1_ge_set_gej_var(
                    &g_vec[G_GENS_LEN + i / 2], &folded_generator);

                secp256k1_scalar_clear(&temporary);
                purify_bridge_secure_clear(
                    &folded_generator, sizeof(folded_generator));
            }
        }
        g_len /= 2;
        h_len /= 2;
        rho_f = mu_f;
        mu_f = mu_sq;

        secp256k1_scalar_clear(&mu_sq);
        secp256k1_scalar_clear(&rho_inv);
        secp256k1_scalar_clear(&c0_l1);
        secp256k1_scalar_clear(&c1_l0);
        secp256k1_scalar_clear(&x_v);
        secp256k1_scalar_clear(&c1_l1);
        secp256k1_scalar_clear(&r_v);
        secp256k1_scalar_clear(&gamma);
        purify_bridge_secure_clear(&rj, sizeof(rj));
        purify_bridge_secure_clear(&xj, sizeof(xj));
        purify_bridge_secure_clear(&r_ge, sizeof(r_ge));
        purify_bridge_secure_clear(&x_ge, sizeof(x_ge));
        continue;

round_failure:
        secp256k1_scalar_clear(&mu_sq);
        secp256k1_scalar_clear(&rho_inv);
        secp256k1_scalar_clear(&c0_l1);
        secp256k1_scalar_clear(&c1_l0);
        secp256k1_scalar_clear(&x_v);
        secp256k1_scalar_clear(&c1_l1);
        secp256k1_scalar_clear(&r_v);
        secp256k1_scalar_clear(&gamma);
        purify_bridge_secure_clear(&rj, sizeof(rj));
        purify_bridge_secure_clear(&xj, sizeof(xj));
        purify_bridge_secure_clear(&r_ge, sizeof(r_ge));
        purify_bridge_secure_clear(&x_ge, sizeof(x_ge));
        secp256k1_scalar_clear(&mu_f);
        secp256k1_scalar_clear(&rho_f);
        purify_bridge_secure_clear(&x_cb_data, sizeof(x_cb_data));
        purify_bridge_secure_clear(&r_cb_data, sizeof(r_cb_data));
        return 0;
    }

    secp256k1_scalar_get_b32(&proof[proof_idx], &n_vec[0]);
    secp256k1_scalar_get_b32(&proof[proof_idx + 32], &l_vec[0]);
    PURIFY_BRIDGE_DECLASSIFY(&proof[proof_idx], 64);
    proof_idx += 64;
    *proof_len = proof_idx;
    secp256k1_scalar_clear(&mu_f);
    secp256k1_scalar_clear(&rho_f);
    purify_bridge_secure_clear(&x_cb_data, sizeof(x_cb_data));
    purify_bridge_secure_clear(&r_cb_data, sizeof(r_cb_data));
    return 1;
}

static int purify_bppp_rangeproof_norm_product_prove_with_copied_inputs(
    const secp256k1_context* ctx, secp256k1_scratch_space* scratch,
    unsigned char* proof, size_t* proof_len,
    secp256k1_sha256* transcript, const secp256k1_scalar* rho,
    const secp256k1_ge* g_vec, size_t g_vec_len,
    const secp256k1_scalar* n_vec, size_t n_vec_len,
    const secp256k1_scalar* l_vec, size_t l_vec_len,
    const secp256k1_scalar* c_vec, size_t c_vec_len,
    size_t secure_clear_checkpoint,
    purify_bppp_round_challenge_callback challenge_callback,
    void* callback_data) {
    secp256k1_scalar *ns = NULL, *ls = NULL, *cs = NULL;
    secp256k1_ge *gs = NULL;
    size_t checkpoint = secp256k1_scratch_checkpoint(&ctx->error_callback, scratch);
    int result = 0;

    if (purify_copy_vectors_into_scratch(ctx, scratch, &ns, &ls, &cs, &gs, n_vec, l_vec, c_vec, g_vec, n_vec_len, l_vec_len)) {
        result = purify_bppp_rangeproof_norm_product_prove_secret(
            ctx, proof, proof_len, transcript, rho, gs, g_vec_len,
            ns, n_vec_len, ls, l_vec_len, cs, c_vec_len,
            challenge_callback, callback_data);
    }
    /* The imported prover rewinds its private scratch frames before returning.
     * Clear the entire tail so those secret intermediates do not survive along
     * with the bridge-owned witness copies in a reusable scratch allocation.
     */
    purify_bridge_secure_clear_scratch_tail(scratch, secure_clear_checkpoint);
    secp256k1_scratch_apply_checkpoint(&ctx->error_callback, scratch, checkpoint);
    return result;
}

#endif /* PURIFY_BRIDGE_BPPP_SECRET_PROVER_IMPL_H */
