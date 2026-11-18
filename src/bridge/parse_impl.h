// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/*
 * Parsing and serialization of scalars, points and generators at the bridge boundary.
 *
 * Part of the Purify secp256k1 bridge translation unit. Include only from
 * bppp_bridge.c, after secp256k1.c and the parts listed before this one.
 */

#ifndef PURIFY_BRIDGE_PARSE_IMPL_H
#define PURIFY_BRIDGE_PARSE_IMPL_H

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
    /* This helper also serializes prover commitments derived from secret
     * witnesses. Keep normalization constant-time; serialization is the
     * deliberate declassification boundary. */
    secp256k1_fe_normalize(&point->x);
    secp256k1_fe_normalize(&point->y);
    return secp256k1_bppp_serialize_pt(out33, point);
}

static int purify_bridge_memeq_const(const unsigned char* lhs,
                                     const unsigned char* rhs,
                                     size_t size) {
    volatile unsigned char difference = 0;
    size_t i;

    for (i = 0; i < size; ++i) {
        difference |= lhs[i] ^ rhs[i];
    }
    return difference == 0;
}

static int purify_parse_fast_scalar(const unsigned char input32[32], secp256k1_fast_scalar* scalar) {
    secp256k1_scalar one, two, neg_one, neg_two;

    if (!purify_parse_scalar(input32, &scalar->scal, 0)) {
        return 0;
    }

    secp256k1_scalar_set_int(&one, 1);
    secp256k1_scalar_set_int(&two, 2);
    secp256k1_scalar_negate(&neg_one, &one);
    secp256k1_scalar_negate(&neg_two, &two);

    scalar->special = 3;
    if (secp256k1_scalar_is_zero(&scalar->scal)) {
        scalar->special = 0;
    } else if (secp256k1_scalar_eq(&scalar->scal, &one)) {
        scalar->special = 1;
    } else if (secp256k1_scalar_eq(&scalar->scal, &two)) {
        scalar->special = 2;
    } else if (secp256k1_scalar_eq(&scalar->scal, &neg_one)) {
        scalar->special = -1;
    } else if (secp256k1_scalar_eq(&scalar->scal, &neg_two)) {
        scalar->special = -2;
    }
    return 1;
}

static int purify_parse_generator_as_ge(const secp256k1_context* ctx, const unsigned char generator33[33], secp256k1_ge* out) {
    secp256k1_generator generator;
    if (ctx == NULL || generator33 == NULL || out == NULL) {
        return 0;
    }
    if (!secp256k1_generator_parse(ctx, &generator, generator33)) {
        return 0;
    }
    secp256k1_generator_load(out, &generator);
    return 1;
}

static int purify_parse_point_as_ge(const unsigned char point33[33], secp256k1_ge* out) {
    if (point33 == NULL || out == NULL) {
        return 0;
    }
    return secp256k1_eckey_pubkey_parse(out, point33, 33);
}

#endif /* PURIFY_BRIDGE_PARSE_IMPL_H */
