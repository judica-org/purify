/**********************************************************************
 * Copyright (c) 2018 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_BULLETPROOF_UTIL
#define SECP256K1_MODULE_BULLETPROOF_UTIL

#include <limits.h>
#include <stdint.h>

#if defined(_MSC_VER)
#include <intrin.h>
#endif

SECP256K1_INLINE static size_t secp256k1_popcount_size_t(size_t n) {
#if defined(__GNUC__) || defined(__clang__)
#if SIZE_MAX <= UINT_MAX
    return (size_t)__builtin_popcount((unsigned int)n);
#elif SIZE_MAX <= ULONG_MAX
    return (size_t)__builtin_popcountl((unsigned long)n);
#elif SIZE_MAX <= ULLONG_MAX
    return (size_t)__builtin_popcountll((unsigned long long)n);
#else
#error "size_t wider than unsigned long long is unsupported"
#endif
#elif defined(_MSC_VER)
#if SIZE_MAX > UINT_MAX
    return (size_t)__popcnt64((unsigned __int64)n);
#else
    return (size_t)__popcnt((unsigned int)n);
#endif
#else
    size_t count = 0;
    while (n != 0) {
        count += n & 1u;
        n >>= 1;
    }
    return count;
#endif
}

SECP256K1_INLINE static size_t secp256k1_ctz_size_t(size_t n) {
    if (n == 0) {
        return sizeof(size_t) * CHAR_BIT;
    }
#if defined(__GNUC__) || defined(__clang__)
#if SIZE_MAX <= UINT_MAX
    return (size_t)__builtin_ctz((unsigned int)n);
#elif SIZE_MAX <= ULONG_MAX
    return (size_t)__builtin_ctzl((unsigned long)n);
#elif SIZE_MAX <= ULLONG_MAX
    return (size_t)__builtin_ctzll((unsigned long long)n);
#else
#error "size_t wider than unsigned long long is unsupported"
#endif
#elif defined(_MSC_VER)
    {
        unsigned long index;
#if SIZE_MAX > UINT_MAX
        if (_BitScanForward64(&index, (unsigned __int64)n) != 0) {
            return (size_t)index;
        }
#else
        if (_BitScanForward(&index, (unsigned long)n) != 0) {
            return (size_t)index;
        }
#endif
    }
    return sizeof(size_t) * CHAR_BIT;
#else
    {
        size_t count = 0;
        while ((n & 1u) == 0) {
            ++count;
            n >>= 1;
        }
        return count;
    }
#endif
}

/* floor(log2(n)) which returns 0 for 0, since this is used to estimate proof sizes */
SECP256K1_INLINE static size_t secp256k1_floor_lg(size_t n) {
    if (n == 0) {
        return 0;
    }
#if defined(__GNUC__) || defined(__clang__)
#if SIZE_MAX <= UINT_MAX
    return (sizeof(unsigned int) * CHAR_BIT - 1u) - (size_t)__builtin_clz((unsigned int)n);
#elif SIZE_MAX <= ULONG_MAX
    return (sizeof(unsigned long) * CHAR_BIT - 1u) - (size_t)__builtin_clzl((unsigned long)n);
#elif SIZE_MAX <= ULLONG_MAX
    return (sizeof(unsigned long long) * CHAR_BIT - 1u) - (size_t)__builtin_clzll((unsigned long long)n);
#else
#error "size_t wider than unsigned long long is unsupported"
#endif
#elif defined(_MSC_VER)
    {
        unsigned long index;
#if SIZE_MAX > UINT_MAX
        if (_BitScanReverse64(&index, (unsigned __int64)n) != 0) {
            return (size_t)index;
        }
#else
        if (_BitScanReverse(&index, (unsigned long)n) != 0) {
            return (size_t)index;
        }
#endif
    }
    return 0;
#else
    size_t i = 0;
    while (n >>= 1) {
        ++i;
    }
    return i;
#endif
}

static void secp256k1_scalar_dot_product(secp256k1_scalar *r, const secp256k1_scalar *a, const secp256k1_scalar *b, size_t n) {
    secp256k1_scalar_clear(r);
    while(n--) {
        secp256k1_scalar term;
        secp256k1_scalar_mul(&term, &a[n], &b[n]);
        secp256k1_scalar_add(r, r, &term);
    }
}

static void secp256k1_scalar_inverse_all_var(secp256k1_scalar *r, const secp256k1_scalar *a, size_t len) {
    secp256k1_scalar u;
    size_t i;
    if (len < 1) {
        return;
    }

    VERIFY_CHECK((r + len <= a) || (a + len <= r));

    r[0] = a[0];

    i = 0;
    while (++i < len) {
        secp256k1_scalar_mul(&r[i], &r[i - 1], &a[i]);
    }

    secp256k1_scalar_inverse_var(&u, &r[--i]);

    while (i > 0) {
        size_t j = i--;
        secp256k1_scalar_mul(&r[j], &r[i], &u);
        secp256k1_scalar_mul(&u, &u, &a[j]);
    }

    r[0] = u;
}

SECP256K1_INLINE static void secp256k1_bulletproof_serialize_points(unsigned char *out, secp256k1_ge *pt, size_t n) {
    const size_t bitveclen = (n + 7) / 8;
    size_t i;

    memset(out, 0, bitveclen);
    for (i = 0; i < n; i++) {
        secp256k1_fe pointx;
        pointx = pt[i].x;
        secp256k1_fe_normalize(&pointx);
        secp256k1_fe_get_b32(&out[bitveclen + i*32], &pointx);
        if (!secp256k1_fe_is_square_var(&pt[i].y)) {
            out[i/8] |= (1ull << (i % 8));
        }
    }
}

/* Fail closed on malformed encodings. The verifier later hashes parsed points
 * into Fiat-Shamir, so it cannot safely accept bytes that do not decode to a
 * unique curve point.
 */
SECP256K1_INLINE static int secp256k1_bulletproof_deserialize_point(secp256k1_ge *pt, const unsigned char *data, size_t i, size_t n) {
    const size_t bitveclen = (n + 7) / 8;
    const size_t offset = bitveclen + i*32;
    secp256k1_fe fe;

    if (!secp256k1_fe_set_b32_limit(&fe, &data[offset])) {
        secp256k1_ge_clear(pt);
        return 0;
    }
    if (!secp256k1_ge_set_xquad(pt, &fe)) {
        secp256k1_ge_clear(pt);
        return 0;
    }
    if (data[i / 8] & (1 << (i % 8))) {
        secp256k1_ge_neg(pt, pt);
    }
    return 1;
}

static void secp256k1_bulletproof_update_commit(unsigned char *commit, const secp256k1_ge *lpt, const secp256k1_ge *rpt) {
    secp256k1_fe pointx;
    secp256k1_sha256 sha256;
    unsigned char lrparity;
    lrparity = (!secp256k1_fe_is_square_var(&lpt->y) << 1) + !secp256k1_fe_is_square_var(&rpt->y);
    secp256k1_sha256_initialize(&sha256);
    secp256k1_sha256_write(&sha256, commit, 32);
    secp256k1_sha256_write(&sha256, &lrparity, 1);
    pointx = lpt->x;
    secp256k1_fe_normalize(&pointx);
    secp256k1_fe_get_b32(commit, &pointx);
    secp256k1_sha256_write(&sha256, commit, 32);
    pointx = rpt->x;
    secp256k1_fe_normalize(&pointx);
    secp256k1_fe_get_b32(commit, &pointx);
    secp256k1_sha256_write(&sha256, commit, 32);
    secp256k1_sha256_finalize(&sha256, commit);
}

static void secp256k1_bulletproof_update_commit_n(unsigned char *commit, const secp256k1_ge *pt, size_t n) {
    secp256k1_sha256 sha256;
    unsigned char lrparity = 0;
    size_t i;

    VERIFY_CHECK(n < 8);

    for (i = 0; i < n; i++) {
        lrparity |= secp256k1_fe_is_square_var(&pt[i].y) << i;
    }

    secp256k1_sha256_initialize(&sha256);
    secp256k1_sha256_write(&sha256, commit, 32);
    secp256k1_sha256_write(&sha256, &lrparity, 1);
    for (i = 0; i < n; i++) {
        secp256k1_fe pointx;
        pointx = pt[i].x;
        secp256k1_fe_normalize(&pointx);
        secp256k1_fe_get_b32(commit, &pointx);
        secp256k1_sha256_write(&sha256, commit, 32);
    }
    secp256k1_sha256_finalize(&sha256, commit);
}

/* Hash primitive values in a stable byte format so prover and verifier commit
 * to the exact same circuit structure and coefficients.
 */
static void secp256k1_bulletproof_sha256_write_size(secp256k1_sha256 *sha256, size_t n) {
    unsigned char ser[8];
    size_t i;
    for (i = 0; i < sizeof(ser); i++) {
        ser[i] = (unsigned char)(n & 0xffu);
        n >>= 8;
    }
    secp256k1_sha256_write(sha256, ser, sizeof(ser));
}

static void secp256k1_bulletproof_sha256_write_fast_scalar(secp256k1_sha256 *sha256, const secp256k1_fast_scalar *scal) {
    unsigned char ser[32];
    secp256k1_scalar_get_b32(ser, &scal->scal);
    secp256k1_sha256_write(sha256, ser, sizeof(ser));
}

static void secp256k1_bulletproof_sha256_write_row_family(secp256k1_sha256 *sha256, const secp256k1_bulletproof_wmatrix_row *rows, size_t n_rows) {
    size_t i;
    secp256k1_bulletproof_sha256_write_size(sha256, n_rows);
    for (i = 0; i < n_rows; i++) {
        size_t j;
        secp256k1_bulletproof_sha256_write_size(sha256, rows[i].size);
        for (j = 0; j < rows[i].size; j++) {
            secp256k1_bulletproof_sha256_write_size(sha256, rows[i].entry[j].idx);
            secp256k1_bulletproof_sha256_write_fast_scalar(sha256, &rows[i].entry[j].scal);
        }
    }
}

/* Bind the full circuit into the legacy transcript. extra_commit still layers
 * on top, but callers should not need to supply circuit bytes just to make the
 * base protocol sound.
 */
static void secp256k1_bulletproof_update_commit_circuit(unsigned char *commit, const secp256k1_bulletproof_circuit *circ) {
    secp256k1_sha256 sha256;
    size_t i;

    secp256k1_sha256_initialize(&sha256);
    secp256k1_sha256_write(&sha256, commit, 32);
    secp256k1_bulletproof_sha256_write_size(&sha256, circ->n_gates);
    secp256k1_bulletproof_sha256_write_size(&sha256, circ->n_commits);
    secp256k1_bulletproof_sha256_write_size(&sha256, circ->n_constraints);
    secp256k1_bulletproof_sha256_write_size(&sha256, circ->n_bits);
    secp256k1_bulletproof_sha256_write_row_family(&sha256, circ->wl, circ->n_gates);
    secp256k1_bulletproof_sha256_write_row_family(&sha256, circ->wr, circ->n_gates);
    secp256k1_bulletproof_sha256_write_row_family(&sha256, circ->wo, circ->n_gates);
    secp256k1_bulletproof_sha256_write_row_family(&sha256, circ->wv, circ->n_commits);
    secp256k1_bulletproof_sha256_write_size(&sha256, circ->n_constraints);
    for (i = 0; i < circ->n_constraints; i++) {
        secp256k1_bulletproof_sha256_write_fast_scalar(&sha256, &circ->c[i]);
    }
    secp256k1_sha256_finalize(&sha256, commit);
}

/* Convenience function to compute blind*G + sum_i (s[i] * gen[i])
 * If G is passed as NULL, use the standard generator. While in the
 * standard-generator case we could use ecmult_gen rather than
 * ecmult_const, we don't. This function is only used during proof
 * generation so performance is not critical.
 *
 * If `blind` is NULL it is treated as zero.
 *
 * This function is not constant-time with respect to the NULLness
 * of its inputs. NULLness should never be correlated with secret data.
 */
static void secp256k1_bulletproof_vector_commit(secp256k1_gej *r, const secp256k1_scalar *s, const secp256k1_ge *gen, size_t n, const secp256k1_scalar *blind, const secp256k1_ge *g) {
    secp256k1_scalar zero;
    secp256k1_ge rge;

    if (g == NULL) {
        g = &secp256k1_ge_const_g;
    }
    if (blind == NULL) {
        secp256k1_scalar_clear(&zero);
        blind = &zero;
    }

    /* Multiply by blinding factor */
    secp256k1_ecmult_const(r, g, blind);

    /* Do the non-blind sum, going through contortions to avoid adding infinities */
    while (n--) {
        int inf;
        secp256k1_ge tmpge;
        secp256k1_ge negg;
        secp256k1_gej tmpj;

        /* Add G, undoing it if this causes rge == infinity */
        secp256k1_ge_set_gej(&tmpge, r);
        secp256k1_gej_add_ge(r, r, g);
        secp256k1_ge_set_gej(&rge, r);

        inf = secp256k1_ge_is_infinity(&rge);
        secp256k1_fe_cmov(&rge.x, &tmpge.x, inf);
        secp256k1_fe_cmov(&rge.y, &tmpge.y, inf);
        rge.infinity = 0;

        /* Add the next term to our now-guaranteed-noninfinite R */
        secp256k1_ecmult_const(&tmpj, &gen[n], &s[n]);
        secp256k1_gej_add_ge(r, &tmpj, &rge); /* here tmpj may be infinite but tmpge won't be */

        /* Subtract G, undoing it if we undid the addition above */
        secp256k1_ge_neg(&negg, g);
        secp256k1_ge_set_gej(&tmpge, r);
        secp256k1_gej_add_ge(r, r, &negg);
        secp256k1_ge_set_gej(&rge, r);

        secp256k1_fe_cmov(&rge.x, &tmpge.x, inf);
        secp256k1_fe_cmov(&rge.y, &tmpge.y, inf);
        rge.infinity = rge.infinity * (1 - inf) + tmpge.infinity * inf;
    }
}

#endif
