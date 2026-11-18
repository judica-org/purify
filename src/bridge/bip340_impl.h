// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/*
 * BIP340 key, nonce and signature helpers.
 *
 * Part of the Purify secp256k1 bridge translation unit. Include only from
 * bppp_bridge.c, after secp256k1.c and the parts listed before this one.
 */

#ifndef PURIFY_BRIDGE_BIP340_IMPL_H
#define PURIFY_BRIDGE_BIP340_IMPL_H

static int purify_bip340_canonicalize_scalar(
    const secp256k1_context* ctx, unsigned char scalar32[32],
    unsigned char xonly_pubkey32[32]) {
    secp256k1_scalar scalar = {0};
    secp256k1_ge point;
    secp256k1_gej pointj;
    int overflow = 0;
    int ok = 0;

    secp256k1_scalar_set_b32(&scalar, scalar32, &overflow);
    if (overflow || secp256k1_scalar_is_zero(&scalar)) {
        goto cleanup;
    }
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &pointj, &scalar);
    secp256k1_ge_set_gej(&point, &pointj);
    secp256k1_fe_normalize(&point.x);
    secp256k1_fe_normalize(&point.y);
    secp256k1_scalar_cond_negate(
        &scalar, secp256k1_fe_is_odd(&point.y));
    secp256k1_scalar_get_b32(scalar32, &scalar);
    secp256k1_fe_get_b32(xonly_pubkey32, &point.x);
    ok = 1;

cleanup:
    secp256k1_scalar_clear(&scalar);
    purify_bridge_secure_clear(&point, sizeof(point));
    purify_bridge_secure_clear(&pointj, sizeof(pointj));
    return ok;
}

int purify_bip340_key_from_seckey(purify_secp_context* context,
                                  unsigned char seckey32[32],
                                  unsigned char xonly_pubkey32[32]) {
    secp256k1_context* ctx = purify_context_handle(context);
    int ok = 0;

    if (xonly_pubkey32 != NULL) {
        memset(xonly_pubkey32, 0, 32);
    }

    if (ctx == NULL || seckey32 == NULL || xonly_pubkey32 == NULL) {
        return 0;
    }

    ok = purify_bip340_canonicalize_scalar(
        ctx, seckey32, xonly_pubkey32);
    if (!ok) {
        purify_bridge_secure_clear(seckey32, 32);
        memset(xonly_pubkey32, 0, 32);
    }
    return ok;
}

int purify_bip340_nonce_from_scalar(purify_secp_context* context,
                                    unsigned char scalar32[32],
                                    unsigned char xonly_nonce32[32]) {
    secp256k1_context* ctx = purify_context_handle(context);
    int ok = 0;

    if (xonly_nonce32 != NULL) {
        memset(xonly_nonce32, 0, 32);
    }

    if (ctx == NULL || scalar32 == NULL || xonly_nonce32 == NULL) {
        return 0;
    }

    ok = purify_bip340_canonicalize_scalar(
        ctx, scalar32, xonly_nonce32);
    if (!ok) {
        purify_bridge_secure_clear(scalar32, 32);
        memset(xonly_nonce32, 0, 32);
    }
    return ok;
}

int purify_bip340_xonly_from_point(purify_secp_context* context,
                                   const unsigned char point33[33],
                                   unsigned char xonly32[32],
                                   int* parity_out) {
    secp256k1_context* ctx = purify_context_handle(context);
    secp256k1_pubkey pubkey;
    secp256k1_xonly_pubkey xonly;
    int parity = 0;
    int ok = 0;

    memset(&pubkey, 0, sizeof(pubkey));
    memset(&xonly, 0, sizeof(xonly));
    if (xonly32 != NULL) {
        memset(xonly32, 0, 32);
    }
    if (parity_out != NULL) {
        *parity_out = 0;
    }

    if (ctx == NULL || point33 == NULL || xonly32 == NULL) {
        return 0;
    }

    ok = secp256k1_ec_pubkey_parse(ctx, &pubkey, point33, 33);
    if (ok) {
        ok = secp256k1_xonly_pubkey_from_pubkey(ctx, &xonly, &parity, &pubkey);
    }
    if (ok) {
        ok = secp256k1_xonly_pubkey_serialize(ctx, xonly32, &xonly);
    }
    if (ok && parity_out != NULL) {
        *parity_out = parity;
    }
    if (!ok) {
        memset(xonly32, 0, 32);
    }

    purify_bridge_secure_clear(&pubkey, sizeof(pubkey));
    purify_bridge_secure_clear(&xonly, sizeof(xonly));
    return ok;
}

int purify_bip340_validate_xonly_pubkey(purify_secp_context* context,
                                        const unsigned char xonly_pubkey32[32]) {
    secp256k1_context* ctx = purify_context_handle(context);
    secp256k1_xonly_pubkey xonly;
    int ok = 0;

    memset(&xonly, 0, sizeof(xonly));
    if (ctx == NULL || xonly_pubkey32 == NULL) {
        return 0;
    }

    ok = secp256k1_xonly_pubkey_parse(ctx, &xonly, xonly_pubkey32);

    purify_bridge_secure_clear(&xonly, sizeof(xonly));
    return ok;
}

int purify_bip340_validate_signature(purify_secp_context* context,
                                     const unsigned char sig64[64]) {
    secp256k1_context* ctx = purify_context_handle(context);
    secp256k1_xonly_pubkey rxonly;
    secp256k1_scalar s;
    int overflow = 0;
    int ok = 0;

    purify_bridge_secure_clear(&rxonly, sizeof(rxonly));
    purify_bridge_secure_clear(&s, sizeof(s));
    if (ctx == NULL || sig64 == NULL) {
        return 0;
    }

    ok = secp256k1_xonly_pubkey_parse(ctx, &rxonly, sig64);
    if (ok) {
        secp256k1_scalar_set_b32(&s, sig64 + 32, &overflow);
        ok = !overflow;
    }

    purify_bridge_secure_clear(&rxonly, sizeof(rxonly));
    secp256k1_scalar_clear(&s);
    return ok;
}

static int purify_fixed_nonce_function(unsigned char *nonce32,
                                       const unsigned char *msg, size_t msglen,
                                       const unsigned char *key32,
                                       const unsigned char *xonly_pk32,
                                       const unsigned char *algo, size_t algolen,
                                       void *data) {
    (void)msg;
    (void)msglen;
    (void)key32;
    (void)xonly_pk32;
    (void)algo;
    (void)algolen;

    if (nonce32 == NULL || data == NULL) {
        return 0;
    }
    memcpy(nonce32, data, 32);
    return 1;
}

int purify_bip340_sign_with_fixed_nonce(purify_secp_context* context,
                                        unsigned char sig64[64],
                                        const unsigned char* msg, size_t msglen,
                                        const unsigned char seckey32[32],
                                        const unsigned char nonce32[32]) {
    secp256k1_context* ctx = purify_context_handle(context);
    secp256k1_keypair keypair;
    secp256k1_scalar nonce_scalar;
    secp256k1_schnorrsig_extraparams extraparams = SECP256K1_SCHNORRSIG_EXTRAPARAMS_INIT;
    unsigned char canonical_nonce32[32];
    unsigned char xonly_nonce32[32];
    int ok = 0;
    int overflow = 0;

    purify_bridge_secure_clear(&keypair, sizeof(keypair));
    purify_bridge_secure_clear(&nonce_scalar, sizeof(nonce_scalar));
    purify_bridge_secure_clear(canonical_nonce32, sizeof(canonical_nonce32));
    purify_bridge_secure_clear(xonly_nonce32, sizeof(xonly_nonce32));
    if (sig64 != NULL) {
        memset(sig64, 0, 64);
    }

    if (ctx == NULL || sig64 == NULL || seckey32 == NULL || nonce32 == NULL || (msg == NULL && msglen != 0)) {
        return 0;
    }

    memcpy(canonical_nonce32, nonce32, 32);
    ok = purify_bip340_nonce_from_scalar(context, canonical_nonce32, xonly_nonce32);
    if (ok) {
        ok = purify_bridge_memeq_const(
            canonical_nonce32, nonce32, sizeof(canonical_nonce32));
    }
    secp256k1_scalar_set_b32(&nonce_scalar, nonce32, &overflow);
    if (ok && !overflow && !secp256k1_scalar_is_zero(&nonce_scalar)) {
        ok = secp256k1_keypair_create(ctx, &keypair, seckey32);
        if (ok) {
            extraparams.noncefp = purify_fixed_nonce_function;
            extraparams.ndata = (void*)nonce32;
            ok = secp256k1_schnorrsig_sign_custom(ctx, sig64, msg, msglen, &keypair, &extraparams);
        }
    }

    purify_bridge_secure_clear(&keypair, sizeof(keypair));
    secp256k1_scalar_clear(&nonce_scalar);
    purify_bridge_secure_clear(canonical_nonce32, sizeof(canonical_nonce32));
    purify_bridge_secure_clear(xonly_nonce32, sizeof(xonly_nonce32));
    if (!ok) {
        memset(sig64, 0, 64);
    }
    return ok;
}

int purify_bip340_verify(purify_secp_context* context,
                         const unsigned char sig64[64],
                         const unsigned char* msg, size_t msglen,
                         const unsigned char xonly_pubkey32[32]) {
    secp256k1_context* ctx = purify_context_handle(context);
    secp256k1_xonly_pubkey pubkey;
    int ok = 0;

    memset(&pubkey, 0, sizeof(pubkey));
    if (ctx == NULL || sig64 == NULL || xonly_pubkey32 == NULL || (msg == NULL && msglen != 0)) {
        return 0;
    }

    ok = secp256k1_xonly_pubkey_parse(ctx, &pubkey, xonly_pubkey32);
    if (ok) {
        ok = secp256k1_schnorrsig_verify(ctx, sig64, msg, msglen, &pubkey);
    }

    memset(&pubkey, 0, sizeof(pubkey));
    return ok;
}

#endif /* PURIFY_BRIDGE_BIP340_IMPL_H */
