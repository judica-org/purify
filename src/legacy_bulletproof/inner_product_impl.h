/**********************************************************************
 * Copyright (c) 2018 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_BULLETPROOF_INNER_PRODUCT_IMPL
#define SECP256K1_MODULE_BULLETPROOF_INNER_PRODUCT_IMPL

#include "third_party/secp256k1-zkp/src/group.h"
#include "third_party/secp256k1-zkp/src/scalar.h"

#include "src/legacy_bulletproof/core.h"
#include "src/legacy_bulletproof/util.h"

#define POPCOUNT(x) (secp256k1_popcount_size_t((size_t)(x)))
#define CTZ(x) (secp256k1_ctz_size_t((size_t)(x)))

#define IP_AB_SCALARS	4

typedef int (secp256k1_bulletproof_vfy_callback)(secp256k1_scalar *sc, secp256k1_ge *pt, secp256k1_scalar *randomizer, size_t idx, void *data);

/* used by callers to wrap a proof with surrounding context */
typedef struct {
    const unsigned char *proof;
    secp256k1_scalar p_offs;
    secp256k1_scalar yinv;
    unsigned char commit[32];
    secp256k1_bulletproof_vfy_callback *rangeproof_cb;
    void *rangeproof_cb_data;
    size_t n_extra_rangeproof_points;
} secp256k1_bulletproof_innerproduct_context;

/* used internally: parsed inner-product proof state. We keep decoded a/b
 * scalars, decoded L/R points, and explicit challenge powers here so the
 * verifier derives Fiat-Shamir from validated points and rebuilds multiexp
 * coefficients directly from parsed proof data.
 */
typedef struct {
    const secp256k1_bulletproof_innerproduct_context *proof;
    secp256k1_scalar a[IP_AB_SCALARS / 2];
    secp256k1_scalar b[IP_AB_SCALARS / 2];
    secp256k1_scalar x[SECP256K1_BULLETPROOF_MAX_DEPTH + 1];
    secp256k1_scalar xinv[SECP256K1_BULLETPROOF_MAX_DEPTH + 1];
    secp256k1_scalar xsq[SECP256K1_BULLETPROOF_MAX_DEPTH + 1];
    secp256k1_scalar xsqinv[SECP256K1_BULLETPROOF_MAX_DEPTH + 1];
    secp256k1_scalar yinvpow2[SECP256K1_BULLETPROOF_MAX_DEPTH + 1];
    secp256k1_ge lr[2 * SECP256K1_BULLETPROOF_MAX_DEPTH];
    size_t final_grouping;
    size_t block_size;
} secp256k1_bulletproof_innerproduct_vfy_data;

/* used by callers to modify the multiexp */
typedef struct {
    size_t n_proofs;
    secp256k1_scalar p_offs;
    const secp256k1_ge *g;
    const secp256k1_ge *geng;
    const secp256k1_ge *genh;
    size_t vec_len;
    size_t lg_vec_len;
    int shared_g;
    secp256k1_scalar *randomizer;
    secp256k1_bulletproof_innerproduct_vfy_data *proof;
} secp256k1_bulletproof_innerproduct_vfy_ecmult_context;

size_t secp256k1_bulletproof_innerproduct_proof_length(size_t n) {
    if (n < IP_AB_SCALARS / 2) {
        return 32 * (1 + 2 * n);
    } else {
        size_t bit_count = POPCOUNT(n);
        size_t log = secp256k1_floor_lg(2 * n / IP_AB_SCALARS);
        return 32 * (1 + 2 * (bit_count - 1 + log) + IP_AB_SCALARS) + (2*log + 7) / 8;
    }
}

/* Bulletproof rangeproof verification comes down to a single multiexponentiation of the form
 *
 *   P + (c-a*b)*x*G - sum_{i=1}^n [a*s'_i*G_i + b*s_i*H_i] + sum_{i=1}^log2(n) [x_i^-2 L_i + x_i^2 R_i
 *
 * which will equal infinity if the rangeproof is correct. Here
 *   - `G_i` and `H_i` are standard NUMS generators. `G` is the standard secp256k1 generator.
 *   - `P` and `c` are inputs to the proof, which claims that there exist `a_i` and `b_i`, `i` ranging
 *     from 0 to `n-1`, such that `P = sum_i [a_i G_i + b_i H_i]` and that `<{a_i}, {b_i}> = c`.
 *   - `a`, `b`, `L_i` and `R_i`are auxillary components of the proof, where `i` ranges from 0 to `log2(n)-1`.
 *   - `x_i = H(x_{i-1} || L_i || R_i)`, where `x_{-1}` is passed through the `commit` variable and
 *     must be a commitment to `P` and `c`.
 *   - `x` is a hash of `commit` and is used to rerandomize `c`. See Protocol 2 vs Protocol 1 in the paper.
 *   - `s_i` and `s'_i` are computed as follows.
 *
 * For each `i` between 0 and `n-1` inclusive, let `b_{ij}` be -1 (1) if the `j`th bit of `i` is zero (one).
 * Here `j` ranges from 0 to `log2(n)-1`. Then for each such `i` we define
 *   - `s_i = prod_j x_j^{b_{ij}}`
 *   - `s'_i = 1/s_i`
 *
 * Alternately we can define `s_i` and `s'_i` recursively as follows:
 *   - `s_0 = s`_{n - 1} = 1 / prod_j x_j`
 *   - `s_i = s'_{n - 1 - i} = s_{i - 2^j} * x_j^2` where `j = i & (i - 1)` is `i` with its least significant 1 set to 0.
 *
 * Our ecmult_multi function takes `(c - a*b)*x` directly and multiplies this by `G`. For every other
 * (scalar, point) pair it calls the following callback function, which takes an index and outputs a
 * pair. The function therefore has three regimes:
 *
 * For the first `2n` invocations, it returns the generator terms for the G and
 * H halves of the proof. Earlier versions built these coefficients incrementally
 * inside the callback via caches and inverse tricks. We now preparse the final
 * `a`/`b` scalars, challenges `x_j`, and powers of `y^-1` during verifier
 * setup, then reconstruct each generator coefficient directly from that parsed
 * state.
 *
 * For the next `2*log2(n)` invocations it returns the parsed `L_i`/`R_i`
 * points with scalars `x_i^2` and `x_i^-2`.
 *
 * For the remaining invocations it passes through to another callback, `rangeproof_cb_data` which
 * computes `P`. The reason for this is that in practice `P` is usually defined by another multiexp
 * rather than being a known point, and it is more efficient to compute one exponentiation.
 *
 */

/* Rebuild the x_j product for a specific generator index directly from the
 * parsed challenges. This keeps verification coupled to decoded proof state.
 */
static void secp256k1_bulletproof_innerproduct_vfy_xproduct(
    secp256k1_scalar *out,
    const secp256k1_bulletproof_innerproduct_vfy_data *proof,
    size_t idx,
    size_t lg_vec_len,
    int invert
) {
    size_t i;
    secp256k1_scalar_set_int(out, 1);
    for (i = 0; i < lg_vec_len; i++) {
        if (idx & ((size_t)1 << i)) {
            secp256k1_scalar_mul(out, out, invert ? &proof->xinv[i] : &proof->x[i]);
        } else {
            secp256k1_scalar_mul(out, out, invert ? &proof->x[i] : &proof->xinv[i]);
        }
    }
}

/* Recover y^(-idx) from powers of two so H coefficients can be rebuilt
 * without making any assumptions about the final a/b values.
 */
static void secp256k1_bulletproof_innerproduct_vfy_yinvpow(
    secp256k1_scalar *out,
    const secp256k1_bulletproof_innerproduct_vfy_data *proof,
    size_t idx,
    size_t lg_vec_len
) {
    size_t i;
    secp256k1_scalar_set_int(out, 1);
    for (i = 0; i <= lg_vec_len; i++) {
        if (idx & ((size_t)1 << i)) {
            secp256k1_scalar_mul(out, out, &proof->yinvpow2[i]);
        }
    }
}

/* Derive the final G/H coefficient directly from parsed a/b and challenges.
 * Zero a or b is valid, so only malformed encodings are rejected during parse.
 */
static void secp256k1_bulletproof_innerproduct_vfy_generator_term(
    secp256k1_scalar *term,
    const secp256k1_bulletproof_innerproduct_vfy_ecmult_context *ctx,
    const secp256k1_bulletproof_innerproduct_vfy_data *proof,
    const secp256k1_scalar *randomizer,
    size_t idx
) {
    const int use_h = idx >= ctx->vec_len;
    const size_t proof_idx = use_h ? idx - ctx->vec_len : idx;
    const size_t scalar_idx = proof_idx / proof->block_size;
    const size_t local_idx = proof_idx % proof->block_size;
    secp256k1_scalar factor;

    VERIFY_CHECK(proof->final_grouping != 0);
    VERIFY_CHECK(proof->block_size != 0);
    VERIFY_CHECK(scalar_idx < proof->final_grouping);

    secp256k1_bulletproof_innerproduct_vfy_xproduct(&factor, proof, local_idx, ctx->lg_vec_len, use_h);
    if (use_h) {
        secp256k1_scalar yfactor;
        secp256k1_bulletproof_innerproduct_vfy_yinvpow(&yfactor, proof, proof_idx, ctx->lg_vec_len);
        secp256k1_scalar_mul(&factor, &factor, &yfactor);
        secp256k1_scalar_mul(&factor, &factor, &proof->b[scalar_idx]);
    } else {
        secp256k1_scalar_mul(&factor, &factor, &proof->a[scalar_idx]);
    }
    secp256k1_scalar_mul(&factor, &factor, randomizer);
    secp256k1_scalar_negate(term, &factor);
}

static int secp256k1_bulletproof_innerproduct_vfy_ecmult_callback(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *data) {
    secp256k1_bulletproof_innerproduct_vfy_ecmult_context *ctx = (secp256k1_bulletproof_innerproduct_vfy_ecmult_context *) data;

    if (idx < 2 * ctx->vec_len) {
        size_t i;
        if (idx < ctx->vec_len) {
            *pt = ctx->geng[idx];
        } else {
            *pt = ctx->genh[idx - ctx->vec_len];
        }

        secp256k1_scalar_clear(sc);
        for (i = 0; i < ctx->n_proofs; i++) {
            secp256k1_scalar term;
            secp256k1_bulletproof_innerproduct_vfy_generator_term(&term, ctx, &ctx->proof[i], &ctx->randomizer[i], idx);
            if (ctx->proof[i].proof->rangeproof_cb != NULL) {
                secp256k1_scalar rangeproof_offset;
                if ((ctx->proof[i].proof->rangeproof_cb)(&rangeproof_offset, NULL, &ctx->randomizer[i], idx, ctx->proof[i].proof->rangeproof_cb_data) == 0) {
                    return 0;
                }
                secp256k1_scalar_add(&term, &term, &rangeproof_offset);
            }
            secp256k1_scalar_add(sc, sc, &term);
        }
    } else if (idx < 2 * (ctx->vec_len + ctx->lg_vec_len * ctx->n_proofs)) {
        size_t real_idx = idx - 2 * ctx->vec_len;
        const size_t proof_idx = real_idx / (2 * ctx->lg_vec_len);
        real_idx = real_idx % (2 * ctx->lg_vec_len);
        *pt = ctx->proof[proof_idx].lr[real_idx];
        if (idx % 2 == 0) {
            *sc = ctx->proof[proof_idx].xsq[real_idx / 2];
        } else {
            *sc = ctx->proof[proof_idx].xsqinv[real_idx / 2];
        }
        secp256k1_scalar_mul(sc, sc, &ctx->randomizer[proof_idx]);
    } else if (idx == 2 * (ctx->vec_len + ctx->lg_vec_len * ctx->n_proofs)) {
        *sc = ctx->p_offs;
        *pt = *ctx->g;
    } else if (ctx->shared_g && idx == 2 * (ctx->vec_len + ctx->lg_vec_len * ctx->n_proofs) + 1) {
        size_t i;
        secp256k1_scalar_clear(sc);
        for (i = 0; i < ctx->n_proofs; i++) {
            secp256k1_scalar term;
            if ((ctx->proof[i].proof->rangeproof_cb)(&term, pt, &ctx->randomizer[i], 2 * (ctx->vec_len + ctx->lg_vec_len), ctx->proof[i].proof->rangeproof_cb_data) == 0) {
                return 0;
            }
            secp256k1_scalar_add(sc, sc, &term);
        }
    } else {
        size_t proof_idx = 0;
        size_t real_idx = idx - 2 * (ctx->vec_len + ctx->lg_vec_len * ctx->n_proofs) - 1 - !!ctx->shared_g;
        while (real_idx >= ctx->proof[proof_idx].proof->n_extra_rangeproof_points - !!ctx->shared_g) {
            real_idx -= ctx->proof[proof_idx].proof->n_extra_rangeproof_points - !!ctx->shared_g;
            proof_idx++;
            VERIFY_CHECK(proof_idx < ctx->n_proofs);
        }
        if ((ctx->proof[proof_idx].proof->rangeproof_cb)(sc, pt, &ctx->randomizer[proof_idx], 2 * (ctx->vec_len + ctx->lg_vec_len), ctx->proof[proof_idx].proof->rangeproof_cb_data) == 0) {
            return 0;
        }
    }

    return 1;
}

/* nb For security it is essential that `commit_inp` already commit to all data
 *    needed to compute `P`. We do not hash it in during verification since `P`
 *    may be specified indirectly as a bunch of scalar offsets.
 */
static int secp256k1_bulletproof_inner_product_verify_impl(const secp256k1_ecmult_context *ecmult_ctx, secp256k1_scratch *scratch, const secp256k1_bulletproof_generators *gens, size_t vec_len, const secp256k1_bulletproof_innerproduct_context *proof, size_t n_proofs, size_t plen, int shared_g) {
    secp256k1_sha256 sha256;
    secp256k1_bulletproof_innerproduct_vfy_ecmult_context ecmult_data;
    unsigned char commit[32];
    size_t total_n_points = 2 * vec_len + !!shared_g + 1; /* +1 for shared G (value_gen), +1 for H (blinding_gen) */
    secp256k1_gej r;
    secp256k1_scalar zero;
    size_t i;

    if (plen != secp256k1_bulletproof_innerproduct_proof_length(vec_len)) {
        return 0;
    }

    if (n_proofs == 0) {
        return 1;
    }

    if (!secp256k1_scratch_allocate_frame(scratch, n_proofs * (sizeof(*ecmult_data.randomizer) + sizeof(*ecmult_data.proof)), 2)) {
        return 0;
    }

    secp256k1_scalar_clear(&zero);
    ecmult_data.n_proofs = n_proofs;
    ecmult_data.g = gens->blinding_gen;
    ecmult_data.geng = gens->gens;
    ecmult_data.genh = gens->gens + gens->n / 2;
    ecmult_data.vec_len = vec_len;
    ecmult_data.lg_vec_len = secp256k1_floor_lg(2 * vec_len / IP_AB_SCALARS);
    ecmult_data.shared_g = shared_g;
    ecmult_data.randomizer = (secp256k1_scalar *)secp256k1_scratch_alloc(scratch, n_proofs * sizeof(*ecmult_data.randomizer));
    ecmult_data.proof = (secp256k1_bulletproof_innerproduct_vfy_data *)secp256k1_scratch_alloc(scratch, n_proofs * sizeof(*ecmult_data.proof));
    /* Seed RNG for per-proof randomizers */
    secp256k1_sha256_initialize(&sha256);
    for (i = 0; i < n_proofs; i++) {
        secp256k1_sha256_write(&sha256, proof[i].proof, plen);
        secp256k1_sha256_write(&sha256, proof[i].commit, 32);
        secp256k1_scalar_get_b32(commit, &proof[i].p_offs);
        secp256k1_sha256_write(&sha256, commit, 32);
    }
    secp256k1_sha256_finalize(&sha256, commit);

    secp256k1_scalar_clear(&ecmult_data.p_offs);
    for (i = 0; i < n_proofs; i++) {
        const unsigned char *serproof = proof[i].proof;
        unsigned char proof_commit[32];
        secp256k1_scalar dot;
        secp256k1_scalar ab[IP_AB_SCALARS];
        secp256k1_scalar negprod;
        secp256k1_scalar x;
        int overflow;
        size_t j;
        const size_t n_ab = 2 * vec_len < IP_AB_SCALARS ? 2 * vec_len : IP_AB_SCALARS;

        total_n_points += 2 * ecmult_data.lg_vec_len + proof[i].n_extra_rangeproof_points - !!shared_g; /* -1 for shared G */

        /* Extract dot product, will always be the first 32 bytes */
        secp256k1_scalar_set_b32(&dot, serproof, &overflow);
        if (overflow) {
            secp256k1_scratch_deallocate_frame(scratch);
            return 0;
        }
        /* Commit to dot product */
        secp256k1_sha256_initialize(&sha256);
        secp256k1_sha256_write(&sha256, proof[i].commit, 32);
        secp256k1_sha256_write(&sha256, serproof, 32);
        secp256k1_sha256_finalize(&sha256, proof_commit);
        serproof += 32;

        /* Extract a, b */
        for (j = 0; j < n_ab; j++) {
            /* Zero a/b scalars are valid; only non-canonical encodings fail. */
            secp256k1_scalar_set_b32(&ab[j], serproof, &overflow);
            if (overflow) {
                secp256k1_scratch_deallocate_frame(scratch);
                return 0;
            }
            serproof += 32;
        }
        secp256k1_scalar_dot_product(&negprod, &ab[0], &ab[n_ab / 2], n_ab / 2);

        ecmult_data.proof[i].proof = &proof[i];
        ecmult_data.proof[i].final_grouping = n_ab / 2;
        ecmult_data.proof[i].block_size = ecmult_data.proof[i].final_grouping == 0 ? 0 : vec_len / ecmult_data.proof[i].final_grouping;
        for (j = 0; j < ecmult_data.proof[i].final_grouping; j++) {
            ecmult_data.proof[i].a[j] = ab[j];
            ecmult_data.proof[i].b[j] = ab[j + ecmult_data.proof[i].final_grouping];
        }
        /* set per-proof randomizer */
        secp256k1_sha256_initialize(&sha256);
        secp256k1_sha256_write(&sha256, commit, 32);
        secp256k1_sha256_finalize(&sha256, commit);
        secp256k1_scalar_set_b32(&ecmult_data.randomizer[i], commit, &overflow);
        if (overflow || secp256k1_scalar_is_zero(&ecmult_data.randomizer[i])) {
            /* cryptographically unreachable */
            secp256k1_scratch_deallocate_frame(scratch);
            return 0;
        }

        /* Compute x*(dot - a*b) for each proof; add it and p_offs to the p_offs accumulator */
        secp256k1_scalar_set_b32(&x, proof_commit, &overflow);
        if (overflow || secp256k1_scalar_is_zero(&x)) {
            secp256k1_scratch_deallocate_frame(scratch);
            return 0;
        }
        secp256k1_scalar_negate(&negprod, &negprod);
        secp256k1_scalar_add(&negprod, &negprod, &dot);
        secp256k1_scalar_mul(&x, &x, &negprod);
        secp256k1_scalar_add(&x, &x, &proof[i].p_offs);

        secp256k1_scalar_mul(&x, &x, &ecmult_data.randomizer[i]);
        secp256k1_scalar_add(&ecmult_data.p_offs, &ecmult_data.p_offs, &x);

        /* Special-case: trivial proofs are valid iff the explicitly revealed scalars
         *               dot to the explicitly revealed dot product. */
        if (2 * vec_len <= IP_AB_SCALARS) {
            if (!secp256k1_scalar_is_zero(&negprod)) {
                secp256k1_scratch_deallocate_frame(scratch);
                return 0;
            }
            /* remaining data does not (and cannot) be computed for proofs with no a's or b's. */
            if (vec_len == 0) {
                continue;
            }
        }

        /* Store y^(-2^j) so y^(-idx) can be reconstructed by bit decomposition. */
        ecmult_data.proof[i].yinvpow2[0] = proof[i].yinv;
        for (j = 1; j <= ecmult_data.lg_vec_len; j++) {
            secp256k1_scalar_sqr(&ecmult_data.proof[i].yinvpow2[j], &ecmult_data.proof[i].yinvpow2[j - 1]);
        }

        for (j = 0; j < ecmult_data.lg_vec_len; j++) {
            const size_t lidx = 2 * j;
            const size_t ridx = 2 * j + 1;
            /* Parse and validate each round point before deriving x_j so the
             * transcript hash and the later multiexp see the same curve points.
             */
            if (!secp256k1_bulletproof_deserialize_point(&ecmult_data.proof[i].lr[lidx], serproof, lidx, 2 * ecmult_data.lg_vec_len) ||
                !secp256k1_bulletproof_deserialize_point(&ecmult_data.proof[i].lr[ridx], serproof, ridx, 2 * ecmult_data.lg_vec_len)) {
                secp256k1_scratch_deallocate_frame(scratch);
                return 0;
            }
            secp256k1_bulletproof_update_commit(proof_commit, &ecmult_data.proof[i].lr[lidx], &ecmult_data.proof[i].lr[ridx]);
            secp256k1_scalar_set_b32(&ecmult_data.proof[i].x[j], proof_commit, &overflow);
            if (overflow || secp256k1_scalar_is_zero(&ecmult_data.proof[i].x[j])) {
                secp256k1_scratch_deallocate_frame(scratch);
                return 0;
            }
            secp256k1_scalar_inverse_var(&ecmult_data.proof[i].xinv[j], &ecmult_data.proof[i].x[j]);
            secp256k1_scalar_sqr(&ecmult_data.proof[i].xsq[j], &ecmult_data.proof[i].x[j]);
            secp256k1_scalar_sqr(&ecmult_data.proof[i].xsqinv[j], &ecmult_data.proof[i].xinv[j]);
        }
    }

    /* Do the multiexp */
    if (secp256k1_ecmult_multi_var(ecmult_ctx, scratch, &r, &zero, secp256k1_bulletproof_innerproduct_vfy_ecmult_callback, (void *) &ecmult_data, total_n_points) != 1) {
        secp256k1_scratch_deallocate_frame(scratch);
        return 0;
    }
    secp256k1_scratch_deallocate_frame(scratch);
    return secp256k1_gej_is_infinity(&r);
}

typedef struct {
    secp256k1_scalar x[SECP256K1_BULLETPROOF_MAX_DEPTH];
    secp256k1_scalar xinv[SECP256K1_BULLETPROOF_MAX_DEPTH];
    secp256k1_scalar yinv;
    secp256k1_scalar yinvn;
    const secp256k1_ge *geng;
    const secp256k1_ge *genh;
    const secp256k1_ge *g;
    const secp256k1_scalar *a;
    const secp256k1_scalar *b;
    secp256k1_scalar g_sc;
    size_t grouping;
    size_t n;
} secp256k1_bulletproof_innerproduct_pf_ecmult_context;

/* At each level i of recursion (i from 0 upto lg(vector size) - 1)
 *   L = a_even . G_odd + b_odd . H_even (18)
 * which, by expanding the generators into the original G's and H's
 * and setting n = (1 << i), can be computed as follows:
 *
 * For j from 1 to [vector size],
 *    1. Use H[j] or G[j] as generator, starting with H and switching
 *       every n.
 *    2. Start with b1 with H and a0 with G, and increment by 2 each switch.
 *    3. For k = 1, 2, 4, ..., n/2, use the same algorithm to choose
 *       between a and b to choose between x and x^-1, except using
 *       k in place of n. With H's choose x then x^-1, with G's choose
 *       x^-1 then x.
 *
 * For R everything is the same except swap G/H and a/b and x/x^-1.
 */
static int secp256k1_bulletproof_innerproduct_pf_ecmult_callback_l(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *data) {
    secp256k1_bulletproof_innerproduct_pf_ecmult_context *ctx = (secp256k1_bulletproof_innerproduct_pf_ecmult_context *) data;
    const size_t ab_idx = (idx / ctx->grouping) ^ 1;
    size_t i;

    /* Special-case the primary generator */
    if (idx == ctx->n) {
        *pt = *ctx->g;
        *sc = ctx->g_sc;
        return 1;
    }

    /* steps 1/2 */
    if ((idx / ctx->grouping) % 2 == 0) {
        *pt = ctx->genh[idx];
        *sc = ctx->b[ab_idx];
        /* Map h -> h' (eqn 59) */
        secp256k1_scalar_mul(sc, sc, &ctx->yinvn);
    } else {
        *pt = ctx->geng[idx];
        *sc = ctx->a[ab_idx];
    }

    /* step 3 */
    for (i = 0; (1u << i) < ctx->grouping; i++) {
        size_t grouping = (1u << i);
        if ((((idx / grouping) % 2) ^ ((idx / ctx->grouping) % 2)) == 0) {
            secp256k1_scalar_mul(sc, sc, &ctx->x[i]);
        } else {
            secp256k1_scalar_mul(sc, sc, &ctx->xinv[i]);
        }
    }

    secp256k1_scalar_mul(&ctx->yinvn, &ctx->yinvn, &ctx->yinv);
    return 1;
}

/* Identical code except `== 0` changed to `== 1` twice, and the
 * `+ 1` from Step 1/2 was moved to the other if branch. */
static int secp256k1_bulletproof_innerproduct_pf_ecmult_callback_r(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *data) {
    secp256k1_bulletproof_innerproduct_pf_ecmult_context *ctx = (secp256k1_bulletproof_innerproduct_pf_ecmult_context *) data;
    const size_t ab_idx = (idx / ctx->grouping) ^ 1;
    size_t i;

    /* Special-case the primary generator */
    if (idx == ctx->n) {
        *pt = *ctx->g;
        *sc = ctx->g_sc;
        return 1;
    }

    /* steps 1/2 */
    if ((idx / ctx->grouping) % 2 == 1) {
        *pt = ctx->genh[idx];
        *sc = ctx->b[ab_idx];
        /* Map h -> h' (eqn 59) */
        secp256k1_scalar_mul(sc, sc, &ctx->yinvn);
    } else {
        *pt = ctx->geng[idx];
        *sc = ctx->a[ab_idx];
    }

    /* step 3 */
    for (i = 0; (1u << i) < ctx->grouping; i++) {
        size_t grouping = (1u << i);
        if ((((idx / grouping) % 2) ^ ((idx / ctx->grouping) % 2)) == 1) {
            secp256k1_scalar_mul(sc, sc, &ctx->x[i]);
        } else {
            secp256k1_scalar_mul(sc, sc, &ctx->xinv[i]);
        }
    }

    secp256k1_scalar_mul(&ctx->yinvn, &ctx->yinvn, &ctx->yinv);
    return 1;
}

static int secp256k1_bulletproof_innerproduct_pf_ecmult_callback_g(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *data) {
    secp256k1_bulletproof_innerproduct_pf_ecmult_context *ctx = (secp256k1_bulletproof_innerproduct_pf_ecmult_context *) data;
    size_t i;

    *pt = ctx->geng[idx];
    secp256k1_scalar_set_int(sc, 1);
    for (i = 0; (1u << i) <= ctx->grouping; i++) {
        if (idx & (1u << i)) {
            secp256k1_scalar_mul(sc, sc, &ctx->x[i]);
        } else {
            secp256k1_scalar_mul(sc, sc, &ctx->xinv[i]);
        }
    }
    return 1;
}

static int secp256k1_bulletproof_innerproduct_pf_ecmult_callback_h(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *data) {
    secp256k1_bulletproof_innerproduct_pf_ecmult_context *ctx = (secp256k1_bulletproof_innerproduct_pf_ecmult_context *) data;
    size_t i;

    *pt = ctx->genh[idx];
    secp256k1_scalar_set_int(sc, 1);
    for (i = 0; (1u << i) <= ctx->grouping; i++) {
        if (idx & (1u << i)) {
            secp256k1_scalar_mul(sc, sc, &ctx->xinv[i]);
        } else {
            secp256k1_scalar_mul(sc, sc, &ctx->x[i]);
        }
    }
    secp256k1_scalar_mul(sc, sc, &ctx->yinvn);
    secp256k1_scalar_mul(&ctx->yinvn, &ctx->yinvn, &ctx->yinv);
    return 1;
}

/* These proofs are not zero-knowledge. There is no need to worry about constant timeness.
 * `commit_inp` must contain 256 bits of randomness, it is used immediately as a randomizer.
 */
static int secp256k1_bulletproof_inner_product_real_prove_impl(const secp256k1_ecmult_context *ecmult_ctx, secp256k1_scratch *scratch, secp256k1_ge *out_pt, size_t *pt_idx, const secp256k1_ge *g, secp256k1_ge *geng, secp256k1_ge *genh, secp256k1_scalar *a_arr, secp256k1_scalar *b_arr, const secp256k1_scalar *yinv, const secp256k1_scalar *ux, const size_t n, unsigned char *commit) {
    size_t i;
    size_t halfwidth;
    secp256k1_scalar zero;

    secp256k1_bulletproof_innerproduct_pf_ecmult_context pfdata;
    pfdata.yinv = *yinv;
    pfdata.g = g;
    pfdata.geng = geng;
    pfdata.genh = genh;
    pfdata.a = a_arr;
    pfdata.b = b_arr;
    pfdata.n = n;

    secp256k1_scalar_clear(&zero);

    /* Protocol 1: Iterate, halving vector size until it is 1 */
    for (halfwidth = n / 2, i = 0; halfwidth > IP_AB_SCALARS / 4; halfwidth /= 2, i++) {
        secp256k1_gej tmplj, tmprj;
        size_t j;
        int overflow;

        pfdata.grouping = 1u << i;

        /* L */
        secp256k1_scalar_clear(&pfdata.g_sc);
        for (j = 0; j < halfwidth; j++) {
            secp256k1_scalar prod;
            secp256k1_scalar_mul(&prod, &a_arr[2*j], &b_arr[2*j + 1]);
            secp256k1_scalar_add(&pfdata.g_sc, &pfdata.g_sc, &prod);
        }
        secp256k1_scalar_mul(&pfdata.g_sc, &pfdata.g_sc, ux);

        secp256k1_scalar_set_int(&pfdata.yinvn, 1);
        secp256k1_ecmult_multi_var(ecmult_ctx, scratch, &tmplj, &zero, &secp256k1_bulletproof_innerproduct_pf_ecmult_callback_l, (void *) &pfdata, n + 1);
        secp256k1_ge_set_gej(&out_pt[(*pt_idx)++], &tmplj);

        /* R */
        secp256k1_scalar_clear(&pfdata.g_sc);
        for (j = 0; j < halfwidth; j++) {
            secp256k1_scalar prod;
            secp256k1_scalar_mul(&prod, &a_arr[2*j + 1], &b_arr[2*j]);
            secp256k1_scalar_add(&pfdata.g_sc, &pfdata.g_sc, &prod);
        }
        secp256k1_scalar_mul(&pfdata.g_sc, &pfdata.g_sc, ux);

        secp256k1_scalar_set_int(&pfdata.yinvn, 1);
        secp256k1_ecmult_multi_var(ecmult_ctx, scratch, &tmprj, &zero, &secp256k1_bulletproof_innerproduct_pf_ecmult_callback_r, (void *) &pfdata, n + 1);
        secp256k1_ge_set_gej(&out_pt[(*pt_idx)++], &tmprj);

        /* x, x^2, x^-1, x^-2 */
        secp256k1_bulletproof_update_commit(commit, &out_pt[*pt_idx - 2], &out_pt[*pt_idx] - 1);
        secp256k1_scalar_set_b32(&pfdata.x[i], commit, &overflow);
        if (overflow || secp256k1_scalar_is_zero(&pfdata.x[i])) {
            return 0;
        }
        secp256k1_scalar_inverse_var(&pfdata.xinv[i], &pfdata.x[i]);

        /* update scalar array */
        for (j = 0; j < halfwidth; j++) {
            secp256k1_scalar tmps;
            secp256k1_scalar_mul(&a_arr[2*j], &a_arr[2*j], &pfdata.x[i]);
            secp256k1_scalar_mul(&tmps, &a_arr[2*j + 1], &pfdata.xinv[i]);
            secp256k1_scalar_add(&a_arr[j], &a_arr[2*j], &tmps);

            secp256k1_scalar_mul(&b_arr[2*j], &b_arr[2*j], &pfdata.xinv[i]);
            secp256k1_scalar_mul(&tmps, &b_arr[2*j + 1], &pfdata.x[i]);
            secp256k1_scalar_add(&b_arr[j], &b_arr[2*j], &tmps);

        }

        /* Combine G generators and recurse, if that would be more optimal */
        if ((n > 2048 && i == 3) || (n > 128 && i == 2) || (n > 32 && i == 1)) {
            secp256k1_scalar yinv2;

            for (j = 0; j < halfwidth; j++) {
                secp256k1_gej rj;
                secp256k1_ecmult_multi_var(ecmult_ctx, scratch, &rj, &zero, &secp256k1_bulletproof_innerproduct_pf_ecmult_callback_g, (void *) &pfdata, 2u << i);
                pfdata.geng += 2u << i;
                secp256k1_ge_set_gej(&geng[j], &rj);
                secp256k1_scalar_set_int(&pfdata.yinvn, 1);
                secp256k1_ecmult_multi_var(ecmult_ctx, scratch, &rj, &zero, &secp256k1_bulletproof_innerproduct_pf_ecmult_callback_h, (void *) &pfdata, 2u << i);
                pfdata.genh += 2u << i;
                secp256k1_ge_set_gej(&genh[j], &rj);
            }

            secp256k1_scalar_sqr(&yinv2, yinv);
            for (j = 0; j < i; j++) {
                secp256k1_scalar_sqr(&yinv2, &yinv2);
            }
            if (!secp256k1_bulletproof_inner_product_real_prove_impl(ecmult_ctx, scratch, out_pt, pt_idx, g, geng, genh, a_arr, b_arr, &yinv2, ux, halfwidth, commit)) {
                return 0;
            }
            break;
        }
    }
    return 1;
}

static int secp256k1_bulletproof_inner_product_prove_impl(const secp256k1_ecmult_context *ecmult_ctx, secp256k1_scratch *scratch, unsigned char *proof, size_t *proof_len, const secp256k1_bulletproof_generators *gens, const secp256k1_scalar *yinv, const size_t n, secp256k1_ecmult_multi_callback *cb, void *cb_data, const unsigned char *commit_inp) {
    secp256k1_sha256 sha256;
    size_t i;
    unsigned char commit[32];
    secp256k1_scalar *a_arr;
    secp256k1_scalar *b_arr;
    secp256k1_ge *out_pt;
    secp256k1_ge *geng;
    secp256k1_ge *genh;
    secp256k1_scalar ux;
    int overflow;
    size_t pt_idx = 0;
    secp256k1_scalar dot;
    size_t half_n_ab = n < IP_AB_SCALARS / 2 ? n : IP_AB_SCALARS / 2;

    if (*proof_len < secp256k1_bulletproof_innerproduct_proof_length(n)) {
        return 0;
    }
    *proof_len = secp256k1_bulletproof_innerproduct_proof_length(n);

    /* Special-case lengths 0 and 1 whose proofs are just expliict lists of scalars */
    if (n <= IP_AB_SCALARS / 2) {
        secp256k1_scalar a[IP_AB_SCALARS / 2];
        secp256k1_scalar b[IP_AB_SCALARS / 2];

        for (i = 0; i < n; i++) {
            cb(&a[i], NULL, 2*i, cb_data);
            cb(&b[i], NULL, 2*i+1, cb_data);
        }

        secp256k1_scalar_dot_product(&dot, a, b, n);
        secp256k1_scalar_get_b32(proof, &dot);

        for (i = 0; i < n; i++) {
            secp256k1_scalar_get_b32(&proof[32 * (i + 1)], &a[i]);
            secp256k1_scalar_get_b32(&proof[32 * (i + n + 1)], &b[i]);
        }
        VERIFY_CHECK(*proof_len == 32 * (2 * n + 1));
        return 1;
    }

    /* setup for nontrivial proofs */
    if (!secp256k1_scratch_allocate_frame(scratch, 2 * n * (sizeof(secp256k1_scalar) + sizeof(secp256k1_ge)) + 2 * secp256k1_floor_lg(n) * sizeof(secp256k1_ge), 5)) {
        return 0;
    }

    a_arr = (secp256k1_scalar*)secp256k1_scratch_alloc(scratch, n * sizeof(secp256k1_scalar));
    b_arr = (secp256k1_scalar*)secp256k1_scratch_alloc(scratch, n * sizeof(secp256k1_scalar));
    geng = (secp256k1_ge*)secp256k1_scratch_alloc(scratch, n * sizeof(secp256k1_ge));
    genh = (secp256k1_ge*)secp256k1_scratch_alloc(scratch, n * sizeof(secp256k1_ge));
    out_pt = (secp256k1_ge*)secp256k1_scratch_alloc(scratch, 2 * secp256k1_floor_lg(n) * sizeof(secp256k1_ge));
    VERIFY_CHECK(a_arr != NULL);
    VERIFY_CHECK(b_arr != NULL);
    VERIFY_CHECK(gens != NULL);

    for (i = 0; i < n; i++) {
        cb(&a_arr[i], NULL, 2*i, cb_data);
        cb(&b_arr[i], NULL, 2*i+1, cb_data);
        geng[i] = gens->gens[i];
        genh[i] = gens->gens[i + gens->n/2];
    }

    /* Record final dot product */
    secp256k1_scalar_dot_product(&dot, a_arr, b_arr, n);
    secp256k1_scalar_get_b32(proof, &dot);

    /* Protocol 2: hash dot product to obtain G-randomizer */
    secp256k1_sha256_initialize(&sha256);
    secp256k1_sha256_write(&sha256, commit_inp, 32);
    secp256k1_sha256_write(&sha256, proof, 32);
    secp256k1_sha256_finalize(&sha256, commit);

    proof += 32;

    secp256k1_scalar_set_b32(&ux, commit, &overflow);
    if (overflow || secp256k1_scalar_is_zero(&ux)) {
        /* cryptographically unreachable */
        secp256k1_scratch_deallocate_frame(scratch);
        return 0;
    }

    if (!secp256k1_bulletproof_inner_product_real_prove_impl(ecmult_ctx, scratch, out_pt, &pt_idx, gens->blinding_gen, geng, genh, a_arr, b_arr, yinv, &ux, n, commit)) {
        secp256k1_scratch_deallocate_frame(scratch);
        return 0;
    }

    /* Final a/b values */
    for (i = 0; i < half_n_ab; i++) {
        secp256k1_scalar_get_b32(&proof[32 * i], &a_arr[i]);
        secp256k1_scalar_get_b32(&proof[32 * (i + half_n_ab)], &b_arr[i]);
    }
    proof += 64 * half_n_ab;
    secp256k1_bulletproof_serialize_points(proof, out_pt, pt_idx);

    secp256k1_scratch_deallocate_frame(scratch);
    return 1;
}

#undef IP_AB_SCALARS

#endif
