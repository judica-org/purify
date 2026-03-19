/*
 * Legacy Bulletproof circuit core compatibility shim.
 *
 * This header is intentionally internal and assumes it is included only from
 * the Purify secp256k1 bridge translation unit after `secp256k1.c`.
 */

#ifndef PURIFY_LEGACY_BULLETPROOF_CORE_H
#define PURIFY_LEGACY_BULLETPROOF_CORE_H

#include <string.h>

#define SECP256K1_BULLETPROOF_MAX_DEPTH 60
#define SECP256K1_BULLETPROOF_MAX_PROOF (160 + 66 * 32 + 7)

typedef secp256k1_callback secp256k1_ecmult_context;

typedef struct {
    secp256k1_scratch *scratch;
    size_t depth;
    size_t checkpoints[32];
} purify_bulletproof_scratch_frames;

static purify_bulletproof_scratch_frames *purify_bulletproof_scratch_frames_for(secp256k1_scratch *scratch) {
    static purify_bulletproof_scratch_frames slots[8];
    size_t i;

    for (i = 0; i < sizeof(slots) / sizeof(slots[0]); ++i) {
        if (slots[i].scratch == scratch) {
            return &slots[i];
        }
    }
    for (i = 0; i < sizeof(slots) / sizeof(slots[0]); ++i) {
        if (slots[i].scratch == NULL) {
            slots[i].scratch = scratch;
            slots[i].depth = 0;
            return &slots[i];
        }
    }
    return NULL;
}

static int secp256k1_scratch_allocate_frame(secp256k1_scratch *scratch, size_t n, size_t objects) {
    purify_bulletproof_scratch_frames *frames;
    if (scratch == NULL) {
        return 0;
    }
    frames = purify_bulletproof_scratch_frames_for(scratch);
    if (frames == NULL || frames->depth >= sizeof(frames->checkpoints) / sizeof(frames->checkpoints[0])) {
        return 0;
    }
    if (n > secp256k1_scratch_max_allocation(&default_error_callback, scratch, objects)) {
        return 0;
    }
    frames->checkpoints[frames->depth++] = secp256k1_scratch_checkpoint(&default_error_callback, scratch);
    return 1;
}

static void secp256k1_scratch_deallocate_frame(secp256k1_scratch *scratch) {
    purify_bulletproof_scratch_frames *frames;
    VERIFY_CHECK(scratch != NULL);
    frames = purify_bulletproof_scratch_frames_for(scratch);
    VERIFY_CHECK(frames != NULL && frames->depth > 0);
    secp256k1_scratch_apply_checkpoint(&default_error_callback, scratch, frames->checkpoints[--frames->depth]);
    if (frames->depth == 0) {
        frames->scratch = NULL;
    }
}

#define secp256k1_scratch_alloc(scratch, size) secp256k1_scratch_alloc(&default_error_callback, scratch, size)

typedef struct {
    int special;
    secp256k1_scalar scal;
} secp256k1_fast_scalar;

typedef struct secp256k1_bulletproof_circuit secp256k1_bulletproof_circuit;
typedef struct secp256k1_bulletproof_circuit_assignment secp256k1_bulletproof_circuit_assignment;
typedef struct secp256k1_bulletproof_generators secp256k1_bulletproof_generators;

typedef struct {
    size_t idx;
    secp256k1_fast_scalar scal;
} secp256k1_bulletproof_wmatrix_entry;

typedef struct {
    size_t size;
    secp256k1_bulletproof_wmatrix_entry *entry;
} secp256k1_bulletproof_wmatrix_row;

struct secp256k1_bulletproof_circuit {
    size_t n_gates;
    size_t n_commits;
    size_t n_constraints;
    size_t n_bits;
    secp256k1_bulletproof_wmatrix_row *wl;
    secp256k1_bulletproof_wmatrix_row *wr;
    secp256k1_bulletproof_wmatrix_row *wo;
    secp256k1_bulletproof_wmatrix_row *wv;
    secp256k1_fast_scalar *c;
    secp256k1_bulletproof_wmatrix_entry *entries;
};

struct secp256k1_bulletproof_circuit_assignment {
    size_t n_gates;
    size_t n_commits;
    secp256k1_scalar *al;
    secp256k1_scalar *ar;
    secp256k1_scalar *ao;
    secp256k1_scalar *v;
};

struct secp256k1_bulletproof_generators {
    size_t n;
    secp256k1_ge *gens;
    secp256k1_ge *blinding_gen;
};

static secp256k1_bulletproof_generators *secp256k1_bulletproof_generators_create(
    const secp256k1_context *ctx,
    const secp256k1_generator *blinding_gen,
    size_t n,
    size_t precomp_n
) {
    secp256k1_bulletproof_generators *ret;
    secp256k1_rfc6979_hmac_sha256 rng;
    unsigned char seed[64];
    secp256k1_gej precompj;
    size_t i;

    VERIFY_CHECK(ctx != NULL);
    VERIFY_CHECK(blinding_gen != NULL);
    VERIFY_CHECK(precomp_n >= 1);

    ret = (secp256k1_bulletproof_generators *)checked_malloc(&ctx->error_callback, sizeof(*ret));
    if (ret == NULL) {
        return NULL;
    }
    ret->gens = (secp256k1_ge *)checked_malloc(&ctx->error_callback, (precomp_n * (n + 1)) * sizeof(*ret->gens));
    if (ret->gens == NULL) {
        free(ret);
        return NULL;
    }
    ret->blinding_gen = &ret->gens[precomp_n * n];
    ret->n = n;

    secp256k1_fe_get_b32(&seed[0], &secp256k1_ge_const_g.x);
    secp256k1_fe_get_b32(&seed[32], &secp256k1_ge_const_g.y);

    secp256k1_rfc6979_hmac_sha256_initialize(&rng, seed, sizeof(seed));
    for (i = 0; i < n; ++i) {
        size_t j;
        unsigned char tmp[32] = {0};
        secp256k1_generator gen;
        secp256k1_rfc6979_hmac_sha256_generate(&rng, tmp, sizeof(tmp));
        CHECK(secp256k1_generator_generate(ctx, &gen, tmp));
        secp256k1_generator_load(&ret->gens[i], &gen);

        secp256k1_gej_set_ge(&precompj, &ret->gens[i]);
        for (j = 1; j < precomp_n; ++j) {
            size_t k;
            for (k = 0; k < 256 / precomp_n; ++k) {
                secp256k1_gej_double_var(&precompj, &precompj, NULL);
            }
            secp256k1_ge_set_gej(&ret->gens[i + n * j], &precompj);
        }
    }

    secp256k1_generator_load(&ret->blinding_gen[0], blinding_gen);
    secp256k1_gej_set_ge(&precompj, &ret->blinding_gen[0]);
    for (i = 1; i < precomp_n; ++i) {
        size_t k;
        for (k = 0; k < 256 / precomp_n; ++k) {
            secp256k1_gej_double_var(&precompj, &precompj, NULL);
        }
        secp256k1_ge_set_gej(&ret->blinding_gen[i], &precompj);
    }
    secp256k1_rfc6979_hmac_sha256_finalize(&rng);
    return ret;
}

static void secp256k1_bulletproof_generators_destroy(
    const secp256k1_context *ctx,
    secp256k1_bulletproof_generators *gen
) {
    (void)ctx;
    if (gen == NULL) {
        return;
    }
    free(gen->gens);
    free(gen);
}

static void secp256k1_scalar_chacha20(
    secp256k1_scalar *r1,
    secp256k1_scalar *r2,
    const unsigned char *seed,
    size_t idx
) {
    static const unsigned char domain[] = "Purify/Bulletproof/ScalarExpand";
    unsigned char digest[32];
    unsigned char idx_bytes[9];
    secp256k1_sha256 sha256;
    int overflow = 0;
    size_t shift;

    VERIFY_CHECK(seed != NULL);
    for (shift = 0; shift < 8; ++shift) {
        idx_bytes[shift] = (unsigned char)(idx >> (8 * (7 - shift)));
    }

    idx_bytes[8] = 0;
    secp256k1_sha256_initialize(&sha256);
    secp256k1_sha256_write(&sha256, domain, sizeof(domain) - 1);
    secp256k1_sha256_write(&sha256, seed, 32);
    secp256k1_sha256_write(&sha256, idx_bytes, sizeof(idx_bytes));
    secp256k1_sha256_finalize(&sha256, digest);
    secp256k1_scalar_set_b32(r1, digest, &overflow);
    VERIFY_CHECK(!overflow);

    idx_bytes[8] = 1;
    secp256k1_sha256_initialize(&sha256);
    secp256k1_sha256_write(&sha256, domain, sizeof(domain) - 1);
    secp256k1_sha256_write(&sha256, seed, 32);
    secp256k1_sha256_write(&sha256, idx_bytes, sizeof(idx_bytes));
    secp256k1_sha256_finalize(&sha256, digest);
    secp256k1_scalar_set_b32(r2, digest, &overflow);
    VERIFY_CHECK(!overflow);

    secp256k1_memczero(digest, sizeof(digest), 1);
}

SECP256K1_INLINE static void secp256k1_pedersen_ecmult_scalar(
    secp256k1_gej *rj,
    const secp256k1_scalar *sec,
    const secp256k1_scalar *value,
    const secp256k1_ge *value_gen,
    const secp256k1_ge *blind_gen
) {
    secp256k1_gej bj;
    secp256k1_ge bp;

    secp256k1_ecmult_const(rj, value_gen, value);
    secp256k1_ecmult_const(&bj, blind_gen, sec);
    if (!secp256k1_gej_is_infinity(&bj)) {
        secp256k1_ge_set_gej(&bp, &bj);
        secp256k1_gej_add_ge(rj, rj, &bp);
    }
    secp256k1_gej_clear(&bj);
    secp256k1_ge_clear(&bp);
}

#endif
