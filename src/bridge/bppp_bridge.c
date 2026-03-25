// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file bppp_bridge.c
 * @brief C bridge that binds Purify's lightweight ABI to secp256k1-zkp internals and BPPP helpers.
 */

#define SECP256K1_BUILD
#define ENABLE_MODULE_GENERATOR 1
#define ENABLE_MODULE_BPPP 1
#define ENABLE_MODULE_EXTRAKEYS 1
#define ENABLE_MODULE_SCHNORRSIG 1

#include "bppp_bridge.h"
#include "purify/secp_bridge.h"

#include <stdlib.h>
#include <string.h>

#include "third_party/secp256k1-zkp/include/secp256k1_extrakeys.h"
#include "third_party/secp256k1-zkp/include/secp256k1_schnorrsig.h"
#include "third_party/secp256k1-zkp/src/secp256k1.c"
#include "third_party/secp256k1-zkp/src/precomputed_ecmult.c"
#include "third_party/secp256k1-zkp/src/precomputed_ecmult_gen.c"
#include "src/legacy_bulletproof/circuit_impl.h"

#undef secp256k1_scratch_alloc

_Static_assert(sizeof(purify_scalar) == sizeof(secp256k1_scalar), "purify_scalar size mismatch");
_Static_assert(_Alignof(purify_scalar) >= _Alignof(secp256k1_scalar), "purify_scalar alignment mismatch");

static secp256k1_context* purify_create_context(void) {
    return secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
}

static void purify_bridge_secure_clear(void* data, size_t size) {
    if (data != NULL && size != 0u) {
        secp256k1_memclear_explicit(data, size);
    }
}

struct purify_bulletproof_backend_resources {
    size_t n_gates;
    secp256k1_context* ctx;
    secp256k1_scratch_space* scratch;
    secp256k1_bulletproof_generators* gens;
};

struct purify_bppp_backend_resources {
    size_t generators_count;
    secp256k1_context* ctx;
    secp256k1_scratch_space* scratch;
    secp256k1_bppp_generators* gens;
};

purify_bulletproof_backend_resources* purify_bulletproof_backend_resources_create(size_t n_gates) {
    purify_bulletproof_backend_resources* resources;

    if (n_gates == 0 || !secp256k1_is_power_of_two(n_gates)) {
        return NULL;
    }

    resources = (purify_bulletproof_backend_resources*)calloc(1, sizeof(*resources));
    if (resources == NULL) {
        return NULL;
    }

    resources->ctx = purify_create_context();
    if (resources->ctx == NULL) {
        purify_bulletproof_backend_resources_destroy(resources);
        return NULL;
    }

    resources->scratch = secp256k1_scratch_space_create(resources->ctx, 1u << 24);
    if (resources->scratch == NULL) {
        purify_bulletproof_backend_resources_destroy(resources);
        return NULL;
    }

    resources->gens = secp256k1_bulletproof_generators_create(resources->ctx, secp256k1_generator_h, 2 * n_gates, 1);
    if (resources->gens == NULL || resources->gens->n < 2 * n_gates) {
        purify_bulletproof_backend_resources_destroy(resources);
        return NULL;
    }

    resources->n_gates = n_gates;
    return resources;
}

void purify_bulletproof_backend_resources_destroy(purify_bulletproof_backend_resources* resources) {
    if (resources == NULL) {
        return;
    }
    if (resources->gens != NULL && resources->ctx != NULL) {
        secp256k1_bulletproof_generators_destroy(resources->ctx, resources->gens);
    }
    if (resources->scratch != NULL && resources->ctx != NULL) {
        secp256k1_scratch_space_destroy(resources->ctx, resources->scratch);
    }
    if (resources->ctx != NULL) {
        secp256k1_context_destroy(resources->ctx);
    }
    free(resources);
}

purify_bppp_backend_resources* purify_bppp_backend_resources_create(const unsigned char* generators33,
                                                                    size_t generators_count) {
    purify_bppp_backend_resources* resources;

    if (generators33 == NULL || generators_count == 0) {
        return NULL;
    }

    resources = (purify_bppp_backend_resources*)calloc(1, sizeof(*resources));
    if (resources == NULL) {
        return NULL;
    }

    resources->ctx = purify_create_context();
    if (resources->ctx == NULL) {
        purify_bppp_backend_resources_destroy(resources);
        return NULL;
    }

    resources->scratch = secp256k1_scratch_space_create(resources->ctx, 1u << 24);
    if (resources->scratch == NULL) {
        purify_bppp_backend_resources_destroy(resources);
        return NULL;
    }

    resources->gens = secp256k1_bppp_generators_parse(resources->ctx, generators33, generators_count * 33);
    if (resources->gens == NULL || resources->gens->n != generators_count) {
        purify_bppp_backend_resources_destroy(resources);
        return NULL;
    }

    resources->generators_count = generators_count;
    return resources;
}

void purify_bppp_backend_resources_destroy(purify_bppp_backend_resources* resources) {
    if (resources == NULL) {
        return;
    }
    if (resources->gens != NULL && resources->ctx != NULL) {
        secp256k1_bppp_generators_destroy(resources->ctx, resources->gens);
    }
    if (resources->scratch != NULL && resources->ctx != NULL) {
        secp256k1_scratch_space_destroy(resources->ctx, resources->scratch);
    }
    if (resources->ctx != NULL) {
        secp256k1_context_destroy(resources->ctx);
    }
    free(resources);
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

void purify_sha256(unsigned char output32[32], const unsigned char *data,
                   size_t data_len) {
  static const unsigned char zero = 0;
  secp256k1_sha256 sha256;

  if (data == NULL && data_len == 0) {
    data = &zero;
  }

  secp256k1_sha256_initialize(&sha256);
  if (data_len != 0) {
    secp256k1_sha256_write(&sha256, data, data_len);
  }
  secp256k1_sha256_finalize(&sha256, output32);
  secp256k1_sha256_clear(&sha256);
}

int purify_sha256_many(unsigned char output32[32],
                       const unsigned char *const *items,
                       const size_t *item_lens,
                       size_t items_count) {
  secp256k1_sha256 sha256;
  if (output32 == NULL) {
    return 0;
  }
  if (items_count != 0 && (items == NULL || item_lens == NULL)) {
    memset(output32, 0, 32);
    return 0;
  }
  secp256k1_sha256_initialize(&sha256);
  for (size_t i = 0; i < items_count; ++i) {
    const unsigned char *item = items[i];
    size_t item_len = item_lens[i];
    if (item == NULL) {
      if (item_len != 0) {
        secp256k1_sha256_clear(&sha256);
        memset(output32, 0, 32);
        return 0;
      }
      continue;
    }
    if (item_len != 0) {
      secp256k1_sha256_write(&sha256, item, item_len);
    }
  }
  secp256k1_sha256_finalize(&sha256, output32);
  secp256k1_sha256_clear(&sha256);
  return 1;
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

int purify_bip340_key_from_seckey(unsigned char seckey32[32], unsigned char xonly_pubkey32[32]) {
    secp256k1_context* ctx = purify_create_context();
    secp256k1_keypair keypair;
    secp256k1_xonly_pubkey xonly;
    int parity = 0;
    int ok = 0;

    memset(&keypair, 0, sizeof(keypair));
    memset(&xonly, 0, sizeof(xonly));
    if (xonly_pubkey32 != NULL) {
        memset(xonly_pubkey32, 0, 32);
    }

    if (ctx == NULL || seckey32 == NULL || xonly_pubkey32 == NULL) {
        if (ctx != NULL) {
            secp256k1_context_destroy(ctx);
        }
        return 0;
    }

    ok = secp256k1_keypair_create(ctx, &keypair, seckey32);
    if (ok) {
        ok = secp256k1_keypair_xonly_pub(ctx, &xonly, &parity, &keypair);
    }
    if (ok) {
        ok = secp256k1_xonly_pubkey_serialize(ctx, xonly_pubkey32, &xonly);
    }
    if (ok && parity != 0) {
        ok = secp256k1_ec_seckey_negate(ctx, seckey32);
    }
    if (!ok) {
        purify_bridge_secure_clear(seckey32, 32);
        memset(xonly_pubkey32, 0, 32);
    }

    purify_bridge_secure_clear(&keypair, sizeof(keypair));
    purify_bridge_secure_clear(&xonly, sizeof(xonly));
    secp256k1_context_destroy(ctx);
    return ok;
}

int purify_bip340_nonce_from_scalar(unsigned char scalar32[32], unsigned char xonly_nonce32[32]) {
    secp256k1_context* ctx = purify_create_context();
    secp256k1_pubkey pubkey;
    secp256k1_xonly_pubkey xonly;
    int parity = 0;
    int ok = 0;

    memset(&pubkey, 0, sizeof(pubkey));
    memset(&xonly, 0, sizeof(xonly));
    if (xonly_nonce32 != NULL) {
        memset(xonly_nonce32, 0, 32);
    }

    if (ctx == NULL || scalar32 == NULL || xonly_nonce32 == NULL) {
        if (ctx != NULL) {
            secp256k1_context_destroy(ctx);
        }
        return 0;
    }

    ok = secp256k1_ec_pubkey_create(ctx, &pubkey, scalar32);
    if (ok) {
        ok = secp256k1_xonly_pubkey_from_pubkey(ctx, &xonly, &parity, &pubkey);
    }
    if (ok) {
        ok = secp256k1_xonly_pubkey_serialize(ctx, xonly_nonce32, &xonly);
    }
    if (ok && parity != 0) {
        ok = secp256k1_ec_seckey_negate(ctx, scalar32);
    }
    if (!ok) {
        purify_bridge_secure_clear(scalar32, 32);
        memset(xonly_nonce32, 0, 32);
    }

    purify_bridge_secure_clear(&pubkey, sizeof(pubkey));
    purify_bridge_secure_clear(&xonly, sizeof(xonly));
    secp256k1_context_destroy(ctx);
    return ok;
}

int purify_bip340_xonly_from_point(const unsigned char point33[33], unsigned char xonly32[32], int* parity_out) {
    secp256k1_context* ctx = purify_create_context();
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
        if (ctx != NULL) {
            secp256k1_context_destroy(ctx);
        }
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
    secp256k1_context_destroy(ctx);
    return ok;
}

int purify_bip340_validate_xonly_pubkey(const unsigned char xonly_pubkey32[32]) {
    secp256k1_context* ctx = purify_create_context();
    secp256k1_xonly_pubkey xonly;
    int ok = 0;

    memset(&xonly, 0, sizeof(xonly));
    if (ctx == NULL || xonly_pubkey32 == NULL) {
        if (ctx != NULL) {
            secp256k1_context_destroy(ctx);
        }
        return 0;
    }

    ok = secp256k1_xonly_pubkey_parse(ctx, &xonly, xonly_pubkey32);

    purify_bridge_secure_clear(&xonly, sizeof(xonly));
    secp256k1_context_destroy(ctx);
    return ok;
}

int purify_bip340_validate_signature(const unsigned char sig64[64]) {
    secp256k1_context* ctx = purify_create_context();
    secp256k1_xonly_pubkey rxonly;
    secp256k1_scalar s;
    int overflow = 0;
    int ok = 0;

    purify_bridge_secure_clear(&rxonly, sizeof(rxonly));
    purify_bridge_secure_clear(&s, sizeof(s));
    if (ctx == NULL || sig64 == NULL) {
        if (ctx != NULL) {
            secp256k1_context_destroy(ctx);
        }
        return 0;
    }

    ok = secp256k1_xonly_pubkey_parse(ctx, &rxonly, sig64);
    if (ok) {
        secp256k1_scalar_set_b32(&s, sig64 + 32, &overflow);
        ok = !overflow;
    }

    purify_bridge_secure_clear(&rxonly, sizeof(rxonly));
    secp256k1_scalar_clear(&s);
    secp256k1_context_destroy(ctx);
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

int purify_bip340_sign_with_fixed_nonce(unsigned char sig64[64],
                                        const unsigned char* msg, size_t msglen,
                                        const unsigned char seckey32[32],
                                        const unsigned char nonce32[32]) {
    secp256k1_context* ctx = purify_create_context();
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
        if (ctx != NULL) {
            secp256k1_context_destroy(ctx);
        }
        return 0;
    }

    memcpy(canonical_nonce32, nonce32, 32);
    ok = purify_bip340_nonce_from_scalar(canonical_nonce32, xonly_nonce32);
    if (ok) {
        ok = secp256k1_memcmp_var(canonical_nonce32, nonce32, 32) == 0;
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
    secp256k1_context_destroy(ctx);
    return ok;
}

int purify_bip340_verify(const unsigned char sig64[64],
                         const unsigned char* msg, size_t msglen,
                         const unsigned char xonly_pubkey32[32]) {
    secp256k1_context* ctx = purify_create_context();
    secp256k1_xonly_pubkey pubkey;
    int ok = 0;

    memset(&pubkey, 0, sizeof(pubkey));
    if (ctx == NULL || sig64 == NULL || xonly_pubkey32 == NULL || (msg == NULL && msglen != 0)) {
        if (ctx != NULL) {
            secp256k1_context_destroy(ctx);
        }
        return 0;
    }

    ok = secp256k1_xonly_pubkey_parse(ctx, &pubkey, xonly_pubkey32);
    if (ok) {
        ok = secp256k1_schnorrsig_verify(ctx, sig64, msg, msglen, &pubkey);
    }

    memset(&pubkey, 0, sizeof(pubkey));
    secp256k1_context_destroy(ctx);
    return ok;
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

static void purify_free_bulletproof_circuit(secp256k1_bulletproof_circuit* circuit) {
    if (circuit == NULL) {
        return;
    }
    free(circuit->wl);
    free(circuit->wr);
    free(circuit->wo);
    free(circuit->wv);
    free(circuit->c);
    free(circuit->entries);
    memset(circuit, 0, sizeof(*circuit));
}

static void purify_free_bulletproof_assignment(secp256k1_bulletproof_circuit_assignment* assignment) {
    if (assignment == NULL) {
        return;
    }
    free(assignment->al);
    free(assignment->ar);
    free(assignment->ao);
    free(assignment->v);
    memset(assignment, 0, sizeof(*assignment));
}

static size_t purify_total_row_entries(const purify_bulletproof_row_view* rows, size_t count, int* ok) {
    size_t total = 0;
    size_t i;

    if (ok != NULL) {
        *ok = 0;
    }
    if (count == 0) {
        if (ok != NULL) {
            *ok = 1;
        }
        return 0;
    }
    if (rows == NULL) {
        return 0;
    }
    for (i = 0; i < count; ++i) {
        if (rows[i].size != 0 && (rows[i].indices == NULL || rows[i].scalars32 == NULL)) {
            return 0;
        }
        total += rows[i].size;
    }
    if (ok != NULL) {
        *ok = 1;
    }
    return total;
}

static int purify_build_row_family(secp256k1_bulletproof_wmatrix_row* out_rows,
                                   size_t row_count,
                                   const purify_bulletproof_row_view* in_rows,
                                   size_t n_constraints,
                                   secp256k1_bulletproof_wmatrix_entry* entries,
                                   size_t* offset) {
    size_t i;
    for (i = 0; i < row_count; ++i) {
        size_t j;
        out_rows[i].size = in_rows[i].size;
        out_rows[i].entry = in_rows[i].size == 0 ? NULL : entries + *offset;
        for (j = 0; j < in_rows[i].size; ++j) {
            size_t entry_idx = *offset + j;
            if (in_rows[i].indices[j] >= n_constraints) {
                return 0;
            }
            out_rows[i].entry[j].idx = in_rows[i].indices[j];
            if (!purify_parse_fast_scalar(in_rows[i].scalars32 + 32 * j, &out_rows[i].entry[j].scal)) {
                return 0;
            }
            entries[entry_idx] = out_rows[i].entry[j];
        }
        *offset += in_rows[i].size;
    }
    return 1;
}

static void purify_bulletproof_circuit_evaluate_sum_row(secp256k1_scalar* acc,
                                                         const secp256k1_bulletproof_wmatrix_row* row,
                                                         const secp256k1_scalar* assn) {
    size_t j;
    for (j = 0; j < row->size; ++j) {
        secp256k1_scalar term;
        secp256k1_fast_scalar_mul(&term, &row->entry[j].scal, assn);
        secp256k1_scalar_add(&acc[row->entry[j].idx], &acc[row->entry[j].idx], &term);
    }
}

static int purify_bulletproof_circuit_evaluate(const secp256k1_bulletproof_circuit* circuit,
                                               const secp256k1_bulletproof_circuit_assignment* assignment) {
    secp256k1_scalar* acc = NULL;
    size_t i;
    int ok = 0;

    if (circuit == NULL || assignment == NULL) {
        return 0;
    }
    if (assignment->n_gates != circuit->n_gates || assignment->n_commits != circuit->n_commits) {
        return 0;
    }

    acc = circuit->n_constraints == 0 ? NULL : (secp256k1_scalar*)calloc(circuit->n_constraints, sizeof(*acc));
    if (circuit->n_constraints != 0 && acc == NULL) {
        return 0;
    }

    for (i = 0; i < assignment->n_gates; ++i) {
        secp256k1_scalar product;
        secp256k1_scalar_mul(&product, &assignment->al[i], &assignment->ar[i]);
        if (!secp256k1_scalar_eq(&product, &assignment->ao[i])) {
            goto done;
        }
    }

    for (i = 0; i < circuit->n_constraints; ++i) {
        secp256k1_scalar_clear(&acc[i]);
    }

    for (i = 0; i < circuit->n_gates; ++i) {
        purify_bulletproof_circuit_evaluate_sum_row(acc, &circuit->wl[i], &assignment->al[i]);
        purify_bulletproof_circuit_evaluate_sum_row(acc, &circuit->wr[i], &assignment->ar[i]);
        purify_bulletproof_circuit_evaluate_sum_row(acc, &circuit->wo[i], &assignment->ao[i]);
    }
    for (i = 0; i < circuit->n_commits; ++i) {
        secp256k1_scalar negated_v;
        secp256k1_scalar_negate(&negated_v, &assignment->v[i]);
        purify_bulletproof_circuit_evaluate_sum_row(acc, &circuit->wv[i], &negated_v);
    }
    for (i = 0; i < circuit->n_constraints; ++i) {
        secp256k1_scalar constant_term;
        secp256k1_scalar one;
        secp256k1_scalar_set_int(&one, 1);
        secp256k1_fast_scalar_mul(&constant_term, &circuit->c[i], &one);
        if (!secp256k1_scalar_eq(&acc[i], &constant_term)) {
            goto done;
        }
    }
    ok = 1;

done:
    free(acc);
    return ok;
}

static int purify_build_bulletproof_circuit(const purify_bulletproof_circuit_view* view,
                                            secp256k1_bulletproof_circuit* out) {
    int ok = 0;
    size_t total_entries = 0;
    size_t offset = 0;
    size_t i;

    /* Bit/range-style circuits can have no explicit constraint rows, so the
     * constant vector is optional when n_constraints == 0.
     */
    if (view == NULL || out == NULL || (view->n_constraints != 0 && view->c32 == NULL)) {
        return 0;
    }
    if (!secp256k1_is_power_of_two(view->n_gates) || view->n_commits > 1) {
        return 0;
    }
    memset(out, 0, sizeof(*out));

    total_entries += purify_total_row_entries(view->wl, view->n_gates, &ok);
    if (!ok) return 0;
    total_entries += purify_total_row_entries(view->wr, view->n_gates, &ok);
    if (!ok) return 0;
    total_entries += purify_total_row_entries(view->wo, view->n_gates, &ok);
    if (!ok) return 0;
    total_entries += purify_total_row_entries(view->wv, view->n_commits, &ok);
    if (!ok) return 0;

    out->n_gates = view->n_gates;
    out->n_commits = view->n_commits;
    out->n_bits = view->n_bits;
    out->n_constraints = view->n_constraints;
    out->wl = view->n_gates == 0 ? NULL : (secp256k1_bulletproof_wmatrix_row*)calloc(view->n_gates, sizeof(*out->wl));
    out->wr = view->n_gates == 0 ? NULL : (secp256k1_bulletproof_wmatrix_row*)calloc(view->n_gates, sizeof(*out->wr));
    out->wo = view->n_gates == 0 ? NULL : (secp256k1_bulletproof_wmatrix_row*)calloc(view->n_gates, sizeof(*out->wo));
    out->wv = view->n_commits == 0 ? NULL : (secp256k1_bulletproof_wmatrix_row*)calloc(view->n_commits, sizeof(*out->wv));
    /* Mirror the legacy circuit representation: no explicit constraints means
     * no c vector allocation either.
     */
    out->c = view->n_constraints == 0 ? NULL : (secp256k1_fast_scalar*)malloc(view->n_constraints * sizeof(*out->c));
    out->entries = total_entries == 0 ? NULL : (secp256k1_bulletproof_wmatrix_entry*)malloc(total_entries * sizeof(*out->entries));
    if ((view->n_gates != 0 && (out->wl == NULL || out->wr == NULL || out->wo == NULL)) ||
        (view->n_commits != 0 && out->wv == NULL) ||
        (view->n_constraints != 0 && out->c == NULL) ||
        (total_entries != 0 && out->entries == NULL)) {
        purify_free_bulletproof_circuit(out);
        return 0;
    }

    if (!purify_build_row_family(out->wl, view->n_gates, view->wl, view->n_constraints, out->entries, &offset) ||
        !purify_build_row_family(out->wr, view->n_gates, view->wr, view->n_constraints, out->entries, &offset) ||
        !purify_build_row_family(out->wo, view->n_gates, view->wo, view->n_constraints, out->entries, &offset) ||
        !purify_build_row_family(out->wv, view->n_commits, view->wv, view->n_constraints, out->entries, &offset)) {
        purify_free_bulletproof_circuit(out);
        return 0;
    }
    for (i = 0; i < view->n_constraints; ++i) {
        if (!purify_parse_fast_scalar(view->c32 + 32 * i, &out->c[i])) {
            purify_free_bulletproof_circuit(out);
            return 0;
        }
    }
    return 1;
}

static int purify_build_bulletproof_assignment(const purify_bulletproof_assignment_view* view,
                                               secp256k1_bulletproof_circuit_assignment* out) {
    if (view == NULL || out == NULL) {
        return 0;
    }
    if ((view->n_gates != 0 && (view->al32 == NULL || view->ar32 == NULL || view->ao32 == NULL)) ||
        (view->n_commits != 0 && view->v32 == NULL) ||
        view->n_commits > 1) {
        return 0;
    }
    memset(out, 0, sizeof(*out));
    out->n_gates = view->n_gates;
    out->n_commits = view->n_commits;
    out->al = view->n_gates == 0 ? NULL : (secp256k1_scalar*)malloc(view->n_gates * sizeof(*out->al));
    out->ar = view->n_gates == 0 ? NULL : (secp256k1_scalar*)malloc(view->n_gates * sizeof(*out->ar));
    out->ao = view->n_gates == 0 ? NULL : (secp256k1_scalar*)malloc(view->n_gates * sizeof(*out->ao));
    out->v = view->n_commits == 0 ? NULL : (secp256k1_scalar*)malloc(view->n_commits * sizeof(*out->v));
    if ((view->n_gates != 0 && (out->al == NULL || out->ar == NULL || out->ao == NULL)) ||
        (view->n_commits != 0 && out->v == NULL)) {
        purify_free_bulletproof_assignment(out);
        return 0;
    }
    if (!purify_parse_scalar_array(view->al32, view->n_gates, out->al) ||
        !purify_parse_scalar_array(view->ar32, view->n_gates, out->ar) ||
        !purify_parse_scalar_array(view->ao32, view->n_gates, out->ao) ||
        !purify_parse_scalar_array(view->v32, view->n_commits, out->v)) {
        purify_free_bulletproof_assignment(out);
        return 0;
    }
    return 1;
}

size_t purify_bulletproof_required_proof_size(size_t n_gates) {
    if (n_gates == 0) {
        return 0;
    }
    return 64 + 256 + 1 + secp256k1_bulletproof_innerproduct_proof_length(n_gates);
}

static int purify_bulletproof_prove_circuit_impl(const purify_bulletproof_circuit_view* circuit,
                                                 const purify_bulletproof_assignment_view* assignment,
                                                 const unsigned char* blind32,
                                                 const unsigned char value_gen33[33],
                                                 const unsigned char nonce32[32],
                                                 const unsigned char* extra_commit,
                                                 size_t extra_commit_len,
                                                 unsigned char commitment_out33[33],
                                                 unsigned char* proof_out,
                                                 size_t* proof_len,
                                                 int require_valid_assignment,
                                                 purify_bulletproof_backend_resources* resources) {
    secp256k1_context* ctx = NULL;
    secp256k1_scratch_space* scratch = NULL;
    secp256k1_bulletproof_generators* gens = NULL;
    secp256k1_bulletproof_circuit bp_circuit;
    secp256k1_bulletproof_circuit_assignment bp_assignment;
    secp256k1_ge value_gen;
    secp256k1_ge commit_points[1];
    secp256k1_scalar blinds[1];
    size_t n_commits = 0;
    int ok = 0;
    int owns_resources = 0;

    memset(&bp_circuit, 0, sizeof(bp_circuit));
    memset(&bp_assignment, 0, sizeof(bp_assignment));
    memset(commit_points, 0, sizeof(commit_points));
    memset(blinds, 0, sizeof(blinds));
    if (commitment_out33 != NULL) {
        memset(commitment_out33, 0, 33);
    }

    if (circuit == NULL || assignment == NULL || value_gen33 == NULL || nonce32 == NULL || proof_out == NULL || proof_len == NULL) {
        return 0;
    }
    if (extra_commit == NULL && extra_commit_len != 0) {
        return 0;
    }
    if (!purify_build_bulletproof_circuit(circuit, &bp_circuit) ||
        !purify_build_bulletproof_assignment(assignment, &bp_assignment)) {
        goto done;
    }
    if (require_valid_assignment && !purify_bulletproof_circuit_evaluate(&bp_circuit, &bp_assignment)) {
        goto done;
    }
    if (resources == NULL) {
        resources = purify_bulletproof_backend_resources_create(bp_circuit.n_gates);
        if (resources == NULL) {
            goto done;
        }
        owns_resources = 1;
    }
    if (resources->n_gates < bp_circuit.n_gates || resources->ctx == NULL || resources->scratch == NULL || resources->gens == NULL) {
        goto done;
    }
    ctx = resources->ctx;
    scratch = resources->scratch;
    gens = resources->gens;
    if (gens->n < 2 * bp_circuit.n_gates) {
        goto done;
    }
    if (!purify_parse_generator_as_ge(ctx, value_gen33, &value_gen)) {
        goto done;
    }

    n_commits = bp_circuit.n_commits;
    if (n_commits == 1) {
        secp256k1_gej commitj;
        if (commitment_out33 == NULL) {
            goto done;
        }
        if (blind32 == NULL) {
            secp256k1_scalar_clear(&blinds[0]);
        } else if (!purify_parse_scalar(blind32, &blinds[0], 0)) {
            goto done;
        }
        secp256k1_pedersen_ecmult_scalar(&commitj, &blinds[0], &bp_assignment.v[0], &value_gen, gens->blinding_gen);
        if (secp256k1_gej_is_infinity(&commitj)) {
            goto done;
        }
        secp256k1_ge_set_gej(&commit_points[0], &commitj);
        if (!purify_serialize_point(commitment_out33, &commit_points[0])) {
            goto done;
        }
    } else if (n_commits > 1) {
        goto done;
    }

    ok = secp256k1_bulletproof_relation66_prove_impl(
        &ctx->error_callback,
        scratch,
        proof_out,
        proof_len,
        &bp_assignment,
        n_commits == 0 ? NULL : commit_points,
        n_commits == 0 ? NULL : blinds,
        n_commits,
        &value_gen,
        &bp_circuit,
        gens,
        nonce32,
        extra_commit,
        extra_commit_len
    );

done:
    purify_free_bulletproof_assignment(&bp_assignment);
    purify_free_bulletproof_circuit(&bp_circuit);
    if (owns_resources) {
        purify_bulletproof_backend_resources_destroy(resources);
    }
    return ok;
}

int purify_bulletproof_prove_circuit(const purify_bulletproof_circuit_view* circuit,
                                     const purify_bulletproof_assignment_view* assignment,
                                     const unsigned char* blind32,
                                     const unsigned char value_gen33[33],
                                     const unsigned char nonce32[32],
                                     const unsigned char* extra_commit,
                                     size_t extra_commit_len,
                                     unsigned char commitment_out33[33],
                                     unsigned char* proof_out,
                                     size_t* proof_len) {
    return purify_bulletproof_prove_circuit_impl(circuit, assignment, blind32, value_gen33, nonce32,
                                                 extra_commit, extra_commit_len, commitment_out33,
                                                 proof_out, proof_len, 1, NULL);
}

int purify_bulletproof_prove_circuit_with_resources(purify_bulletproof_backend_resources* resources,
                                                    const purify_bulletproof_circuit_view* circuit,
                                                    const purify_bulletproof_assignment_view* assignment,
                                                    const unsigned char* blind32,
                                                    const unsigned char value_gen33[33],
                                                    const unsigned char nonce32[32],
                                                    const unsigned char* extra_commit,
                                                    size_t extra_commit_len,
                                                    unsigned char commitment_out33[33],
                                                    unsigned char* proof_out,
                                                    size_t* proof_len) {
    return purify_bulletproof_prove_circuit_impl(circuit, assignment, blind32, value_gen33, nonce32,
                                                 extra_commit, extra_commit_len, commitment_out33,
                                                 proof_out, proof_len, 1, resources);
}

int purify_bulletproof_prove_circuit_assume_valid(const purify_bulletproof_circuit_view* circuit,
                                                  const purify_bulletproof_assignment_view* assignment,
                                                  const unsigned char* blind32,
                                                  const unsigned char value_gen33[33],
                                                  const unsigned char nonce32[32],
                                                  const unsigned char* extra_commit,
                                                  size_t extra_commit_len,
                                                  unsigned char commitment_out33[33],
                                                  unsigned char* proof_out,
                                                  size_t* proof_len) {
    return purify_bulletproof_prove_circuit_impl(circuit, assignment, blind32, value_gen33, nonce32,
                                                 extra_commit, extra_commit_len, commitment_out33,
                                                 proof_out, proof_len, 0, NULL);
}

int purify_bulletproof_prove_circuit_assume_valid_with_resources(purify_bulletproof_backend_resources* resources,
                                                                 const purify_bulletproof_circuit_view* circuit,
                                                                 const purify_bulletproof_assignment_view* assignment,
                                                                 const unsigned char* blind32,
                                                                 const unsigned char value_gen33[33],
                                                                 const unsigned char nonce32[32],
                                                                 const unsigned char* extra_commit,
                                                                 size_t extra_commit_len,
                                                                 unsigned char commitment_out33[33],
                                                                 unsigned char* proof_out,
                                                                 size_t* proof_len) {
    return purify_bulletproof_prove_circuit_impl(circuit, assignment, blind32, value_gen33, nonce32,
                                                 extra_commit, extra_commit_len, commitment_out33,
                                                 proof_out, proof_len, 0, resources);
}

int purify_bulletproof_verify_circuit(const purify_bulletproof_circuit_view* circuit,
                                      const unsigned char commitment33[33],
                                      const unsigned char value_gen33[33],
                                      const unsigned char* extra_commit,
                                      size_t extra_commit_len,
                                      const unsigned char* proof,
                                      size_t proof_len) {
    return purify_bulletproof_verify_circuit_with_resources(NULL, circuit, commitment33, value_gen33,
                                                            extra_commit, extra_commit_len, proof, proof_len);
}

int purify_bulletproof_verify_circuit_with_resources(purify_bulletproof_backend_resources* resources,
                                                     const purify_bulletproof_circuit_view* circuit,
                                                     const unsigned char commitment33[33],
                                                     const unsigned char value_gen33[33],
                                                     const unsigned char* extra_commit,
                                                     size_t extra_commit_len,
                                                     const unsigned char* proof,
                                                     size_t proof_len) {
    secp256k1_context* ctx = NULL;
    secp256k1_scratch_space* scratch = NULL;
    secp256k1_bulletproof_generators* gens = NULL;
    secp256k1_bulletproof_circuit bp_circuit;
    secp256k1_ge value_gen;
    secp256k1_ge commit_points[1];
    const secp256k1_ge* commit_ptr = NULL;
    const secp256k1_bulletproof_circuit* circuit_ptr = NULL;
    const unsigned char* proof_ptr = NULL;
    const unsigned char* extra_commit_ptr = NULL;
    size_t n_commits = 0;
    int ok = 0;
    int owns_resources = 0;

    memset(&bp_circuit, 0, sizeof(bp_circuit));
    memset(commit_points, 0, sizeof(commit_points));
    if (circuit == NULL || value_gen33 == NULL || proof == NULL) {
        return 0;
    }
    if (extra_commit == NULL && extra_commit_len != 0) {
        return 0;
    }
    if (!purify_build_bulletproof_circuit(circuit, &bp_circuit)) {
        goto done;
    }
    if (resources == NULL) {
        resources = purify_bulletproof_backend_resources_create(bp_circuit.n_gates);
        if (resources == NULL) {
            goto done;
        }
        owns_resources = 1;
    }
    if (resources->n_gates < bp_circuit.n_gates || resources->ctx == NULL || resources->scratch == NULL || resources->gens == NULL) {
        goto done;
    }
    ctx = resources->ctx;
    scratch = resources->scratch;
    gens = resources->gens;
    if (gens->n < 2 * bp_circuit.n_gates) {
        goto done;
    }
    if (!purify_parse_generator_as_ge(ctx, value_gen33, &value_gen)) {
        goto done;
    }

    n_commits = bp_circuit.n_commits;
    if (n_commits == 1) {
        if (commitment33 == NULL || !purify_parse_point_as_ge(commitment33, &commit_points[0])) {
            goto done;
        }
        commit_ptr = commit_points;
    } else if (n_commits > 1) {
        goto done;
    }

    circuit_ptr = &bp_circuit;
    proof_ptr = proof;
    extra_commit_ptr = extra_commit;
    ok = secp256k1_bulletproof_relation66_verify_impl(
        &ctx->error_callback,
        scratch,
        &proof_ptr,
        1,
        proof_len,
        n_commits == 0 ? NULL : &commit_ptr,
        n_commits == 0 ? NULL : &n_commits,
        &value_gen,
        &circuit_ptr,
        gens,
        &extra_commit_ptr,
        &extra_commit_len
    );

done:
    purify_free_bulletproof_circuit(&bp_circuit);
    if (owns_resources) {
        purify_bulletproof_backend_resources_destroy(resources);
    }
    return ok;
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

static int purify_bppp_commit_norm_arg_impl(purify_bppp_backend_resources* resources,
                                            const unsigned char rho32[32], const unsigned char* generators33,
                                            size_t generators_count, const unsigned char* n_vec32, size_t n_vec_len,
                                            const unsigned char* l_vec32, size_t l_vec_len,
                                            const unsigned char* c_vec32, size_t c_vec_len,
                                            unsigned char commitment_out33[33]) {
    secp256k1_context* ctx = resources != NULL ? resources->ctx : purify_create_context();
    secp256k1_scratch_space* scratch = resources != NULL ? resources->scratch : NULL;
    secp256k1_bppp_generators* gens = resources != NULL ? resources->gens : NULL;
    secp256k1_scalar rho, mu;
    secp256k1_scalar *n_vec = NULL, *l_vec = NULL, *c_vec = NULL;
    secp256k1_ge commit;
    int ok = 0;

    if (ctx == NULL || rho32 == NULL || (resources == NULL && generators33 == NULL) || n_vec32 == NULL || l_vec32 == NULL || c_vec32 == NULL ||
        commitment_out33 == NULL) {
        if (resources == NULL && ctx != NULL) secp256k1_context_destroy(ctx);
        return 0;
    }
    if (n_vec_len == 0 || l_vec_len == 0 || c_vec_len == 0 || l_vec_len != c_vec_len) {
        if (resources == NULL) secp256k1_context_destroy(ctx);
        return 0;
    }
    if (!secp256k1_is_power_of_two(n_vec_len) || !secp256k1_is_power_of_two(c_vec_len) || generators_count != n_vec_len + l_vec_len) {
        if (resources == NULL) secp256k1_context_destroy(ctx);
        return 0;
    }
    if (resources != NULL && resources->generators_count != generators_count) {
        return 0;
    }
    if (!purify_parse_scalar(rho32, &rho, 1)) {
        if (resources == NULL) secp256k1_context_destroy(ctx);
        return 0;
    }
    if (resources == NULL) {
        scratch = secp256k1_scratch_space_create(ctx, 1u << 24);
        gens = secp256k1_bppp_generators_parse(ctx, generators33, generators_count * 33);
    }
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
    ok = purify_serialize_point(commitment_out33, &commit);

cleanup:
    if (n_vec != NULL) free(n_vec);
    if (l_vec != NULL) free(l_vec);
    if (c_vec != NULL) free(c_vec);
    if (resources == NULL) {
        if (gens != NULL) secp256k1_bppp_generators_destroy(ctx, gens);
        if (scratch != NULL) secp256k1_scratch_space_destroy(ctx, scratch);
        secp256k1_context_destroy(ctx);
    }
    return ok;
}

int purify_bppp_commit_norm_arg(const unsigned char rho32[32], const unsigned char* generators33, size_t generators_count,
                                const unsigned char* n_vec32, size_t n_vec_len, const unsigned char* l_vec32,
                                size_t l_vec_len, const unsigned char* c_vec32, size_t c_vec_len,
                                unsigned char commitment_out33[33]) {
    return purify_bppp_commit_norm_arg_impl(NULL, rho32, generators33, generators_count, n_vec32, n_vec_len,
                                            l_vec32, l_vec_len, c_vec32, c_vec_len, commitment_out33);
}

int purify_bppp_commit_norm_arg_with_resources(purify_bppp_backend_resources* resources,
                                               const unsigned char rho32[32],
                                               const unsigned char* n_vec32, size_t n_vec_len,
                                               const unsigned char* l_vec32, size_t l_vec_len,
                                               const unsigned char* c_vec32, size_t c_vec_len,
                                               unsigned char commitment_out33[33]) {
    return purify_bppp_commit_norm_arg_impl(resources, rho32, NULL, resources != NULL ? resources->generators_count : 0,
                                            n_vec32, n_vec_len, l_vec32, l_vec_len, c_vec32, c_vec_len,
                                            commitment_out33);
}

static int purify_bppp_commit_witness_only_impl(purify_bppp_backend_resources* resources,
                                                const unsigned char* generators33, size_t generators_count,
                                                const unsigned char* n_vec32, size_t n_vec_len,
                                                const unsigned char* l_vec32, size_t l_vec_len,
                                                unsigned char commitment_out33[33]) {
    secp256k1_context* ctx = resources != NULL ? resources->ctx : purify_create_context();
    secp256k1_scratch_space* scratch = resources != NULL ? resources->scratch : NULL;
    secp256k1_bppp_generators* gens = resources != NULL ? resources->gens : NULL;
    secp256k1_scalar zero;
    secp256k1_scalar *n_vec = NULL, *l_vec = NULL;
    secp256k1_ge commit;
    secp256k1_gej commitj;
    ecmult_bp_commit_cb_data data;
    int ok = 0;

    if (ctx == NULL || (resources == NULL && generators33 == NULL) || n_vec32 == NULL || l_vec32 == NULL || commitment_out33 == NULL) {
        if (resources == NULL && ctx != NULL) secp256k1_context_destroy(ctx);
        return 0;
    }
    if (n_vec_len == 0 || l_vec_len == 0 || generators_count != n_vec_len + l_vec_len) {
        if (resources == NULL) secp256k1_context_destroy(ctx);
        return 0;
    }
    if (resources != NULL && resources->generators_count != generators_count) {
        return 0;
    }

    if (resources == NULL) {
        scratch = secp256k1_scratch_space_create(ctx, 1u << 24);
        gens = secp256k1_bppp_generators_parse(ctx, generators33, generators_count * 33);
    }
    n_vec = (secp256k1_scalar*)malloc(n_vec_len * sizeof(*n_vec));
    l_vec = (secp256k1_scalar*)malloc(l_vec_len * sizeof(*l_vec));
    if (scratch == NULL || gens == NULL || n_vec == NULL || l_vec == NULL) {
        goto cleanup;
    }
    if (!purify_parse_scalar_array(n_vec32, n_vec_len, n_vec) ||
        !purify_parse_scalar_array(l_vec32, l_vec_len, l_vec)) {
        goto cleanup;
    }

    secp256k1_scalar_set_int(&zero, 0);
    data.g = gens->gens;
    data.n = n_vec;
    data.l = l_vec;
    data.g_len = n_vec_len;
    if (!secp256k1_ecmult_multi_var(&ctx->error_callback, scratch, &commitj, &zero, ecmult_bp_commit_cb,
                                    (void*)&data, n_vec_len + l_vec_len)) {
        goto cleanup;
    }
    if (secp256k1_gej_is_infinity(&commitj)) {
        goto cleanup;
    }
    secp256k1_ge_set_gej_var(&commit, &commitj);
    ok = purify_serialize_point(commitment_out33, &commit);

cleanup:
    if (n_vec != NULL) free(n_vec);
    if (l_vec != NULL) free(l_vec);
    if (resources == NULL) {
        if (gens != NULL) secp256k1_bppp_generators_destroy(ctx, gens);
        if (scratch != NULL) secp256k1_scratch_space_destroy(ctx, scratch);
        secp256k1_context_destroy(ctx);
    }
    return ok;
}

int purify_bppp_commit_witness_only(const unsigned char* generators33, size_t generators_count,
                                    const unsigned char* n_vec32, size_t n_vec_len, const unsigned char* l_vec32,
                                    size_t l_vec_len, unsigned char commitment_out33[33]) {
    return purify_bppp_commit_witness_only_impl(NULL, generators33, generators_count,
                                                n_vec32, n_vec_len, l_vec32, l_vec_len, commitment_out33);
}

int purify_bppp_commit_witness_only_with_resources(purify_bppp_backend_resources* resources,
                                                   const unsigned char* n_vec32, size_t n_vec_len,
                                                   const unsigned char* l_vec32, size_t l_vec_len,
                                                   unsigned char commitment_out33[33]) {
    return purify_bppp_commit_witness_only_impl(resources, NULL,
                                                resources != NULL ? resources->generators_count : 0,
                                                n_vec32, n_vec_len, l_vec32, l_vec_len, commitment_out33);
}

int purify_bppp_offset_commitment(const unsigned char commitment33[33], const unsigned char scalar32[32],
                                  unsigned char commitment_out33[33]) {
    secp256k1_context* ctx = purify_create_context();
    secp256k1_scalar scalar;
    secp256k1_ge commitment_ge, result_ge;
    secp256k1_gej commitment_j, offset_j, result_j;
    int ok = 0;

    if (ctx == NULL || commitment33 == NULL || scalar32 == NULL || commitment_out33 == NULL) {
        if (ctx != NULL) secp256k1_context_destroy(ctx);
        return 0;
    }
    if (!purify_parse_point_as_ge(commitment33, &commitment_ge) ||
        !purify_parse_scalar(scalar32, &scalar, 0)) {
        secp256k1_context_destroy(ctx);
        return 0;
    }

    secp256k1_gej_set_ge(&commitment_j, &commitment_ge);
    secp256k1_ecmult_const(&offset_j, &secp256k1_ge_const_g, &scalar);
    secp256k1_gej_add_var(&result_j, &commitment_j, &offset_j, NULL);
    if (!secp256k1_gej_is_infinity(&result_j)) {
        secp256k1_ge_set_gej(&result_ge, &result_j);
        ok = purify_serialize_point(commitment_out33, &result_ge);
    }
    secp256k1_context_destroy(ctx);
    return ok;
}

int purify_point_scale(const unsigned char point33[33], const unsigned char scalar32[32],
                       unsigned char out33[33]) {
    secp256k1_context* ctx = purify_create_context();
    secp256k1_scalar scalar;
    secp256k1_ge point_ge, result_ge;
    secp256k1_gej result_j;
    int ok = 0;

    if (ctx == NULL || point33 == NULL || scalar32 == NULL || out33 == NULL) {
        if (ctx != NULL) secp256k1_context_destroy(ctx);
        return 0;
    }
    if (!purify_parse_point_as_ge(point33, &point_ge) ||
        !purify_parse_scalar(scalar32, &scalar, 0)) {
        secp256k1_context_destroy(ctx);
        return 0;
    }

    secp256k1_ecmult_const(&result_j, &point_ge, &scalar);
    if (!secp256k1_gej_is_infinity(&result_j)) {
        secp256k1_ge_set_gej(&result_ge, &result_j);
        ok = purify_serialize_point(out33, &result_ge);
    }
    secp256k1_context_destroy(ctx);
    return ok;
}

int purify_point_add(const unsigned char lhs33[33], const unsigned char rhs33[33],
                     unsigned char out33[33]) {
    secp256k1_context* ctx = purify_create_context();
    secp256k1_ge lhs_ge, rhs_ge, result_ge;
    secp256k1_gej lhs_j, result_j;
    int ok = 0;

    if (ctx == NULL || lhs33 == NULL || rhs33 == NULL || out33 == NULL) {
        if (ctx != NULL) secp256k1_context_destroy(ctx);
        return 0;
    }
    if (!purify_parse_point_as_ge(lhs33, &lhs_ge) ||
        !purify_parse_point_as_ge(rhs33, &rhs_ge)) {
        secp256k1_context_destroy(ctx);
        return 0;
    }

    secp256k1_gej_set_ge(&lhs_j, &lhs_ge);
    secp256k1_gej_add_ge_var(&result_j, &lhs_j, &rhs_ge, NULL);
    if (!secp256k1_gej_is_infinity(&result_j)) {
        secp256k1_ge_set_gej(&result_ge, &result_j);
        ok = purify_serialize_point(out33, &result_ge);
    }
    secp256k1_context_destroy(ctx);
    return ok;
}

static int purify_bppp_prove_norm_arg_impl(purify_bppp_backend_resources* resources,
                                           const unsigned char rho32[32], const unsigned char* generators33,
                                           size_t generators_count, const unsigned char* n_vec32, size_t n_vec_len,
                                           const unsigned char* l_vec32, size_t l_vec_len,
                                           const unsigned char* c_vec32, size_t c_vec_len,
                                           unsigned char commitment_out33[33], unsigned char* proof_out,
                                           size_t* proof_len) {
    secp256k1_context* ctx = resources != NULL ? resources->ctx : purify_create_context();
    secp256k1_scratch_space* scratch = resources != NULL ? resources->scratch : NULL;
    secp256k1_bppp_generators* gens = resources != NULL ? resources->gens : NULL;
    secp256k1_scalar rho, mu;
    secp256k1_scalar *n_vec = NULL, *l_vec = NULL, *c_vec = NULL;
    secp256k1_ge commit;
    secp256k1_sha256 transcript;
    size_t required = purify_bppp_required_proof_size(n_vec_len, c_vec_len);
    int ok = 0;

    if (ctx == NULL || rho32 == NULL || (resources == NULL && generators33 == NULL) || n_vec32 == NULL || l_vec32 == NULL || c_vec32 == NULL ||
        commitment_out33 == NULL || proof_out == NULL || proof_len == NULL) {
        if (resources == NULL && ctx != NULL) secp256k1_context_destroy(ctx);
        return 0;
    }
    if (n_vec_len == 0 || l_vec_len == 0 || c_vec_len == 0 || l_vec_len != c_vec_len) {
        if (resources == NULL) secp256k1_context_destroy(ctx);
        return 0;
    }
    if (!secp256k1_is_power_of_two(n_vec_len) || !secp256k1_is_power_of_two(c_vec_len) || generators_count != n_vec_len + l_vec_len) {
        if (resources == NULL) secp256k1_context_destroy(ctx);
        return 0;
    }
    if (resources != NULL && resources->generators_count != generators_count) {
        return 0;
    }
    if (*proof_len < required) {
        *proof_len = required;
        if (resources == NULL) secp256k1_context_destroy(ctx);
        return 0;
    }
    if (!purify_parse_scalar(rho32, &rho, 1)) {
        if (resources == NULL) secp256k1_context_destroy(ctx);
        return 0;
    }
    if (resources == NULL) {
        scratch = secp256k1_scratch_space_create(ctx, 1u << 24);
        gens = secp256k1_bppp_generators_parse(ctx, generators33, generators_count * 33);
    }
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
    if (resources == NULL) {
        if (gens != NULL) secp256k1_bppp_generators_destroy(ctx, gens);
        if (scratch != NULL) secp256k1_scratch_space_destroy(ctx, scratch);
        secp256k1_context_destroy(ctx);
    }
    return ok;
}

int purify_bppp_prove_norm_arg(const unsigned char rho32[32], const unsigned char* generators33, size_t generators_count,
                               const unsigned char* n_vec32, size_t n_vec_len, const unsigned char* l_vec32,
                               size_t l_vec_len, const unsigned char* c_vec32, size_t c_vec_len,
                               unsigned char commitment_out33[33], unsigned char* proof_out, size_t* proof_len) {
    return purify_bppp_prove_norm_arg_impl(NULL, rho32, generators33, generators_count, n_vec32, n_vec_len,
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
    return purify_bppp_prove_norm_arg_impl(resources, rho32, NULL,
                                           resources != NULL ? resources->generators_count : 0,
                                           n_vec32, n_vec_len, l_vec32, l_vec_len, c_vec32, c_vec_len,
                                           commitment_out33, proof_out, proof_len);
}

static int purify_bppp_prove_norm_arg_to_commitment_impl(purify_bppp_backend_resources* resources,
                                                         const unsigned char rho32[32], const unsigned char* generators33,
                                                         size_t generators_count, const unsigned char* n_vec32,
                                                         size_t n_vec_len, const unsigned char* l_vec32,
                                                         size_t l_vec_len, const unsigned char* c_vec32,
                                                         size_t c_vec_len, const unsigned char commitment33[33],
                                                         unsigned char* proof_out, size_t* proof_len) {
    secp256k1_context* ctx = resources != NULL ? resources->ctx : purify_create_context();
    secp256k1_scratch_space* scratch = resources != NULL ? resources->scratch : NULL;
    secp256k1_bppp_generators* gens = resources != NULL ? resources->gens : NULL;
    secp256k1_scalar rho, mu;
    secp256k1_scalar *n_vec = NULL, *l_vec = NULL, *c_vec = NULL;
    secp256k1_ge expected_commit, commitment_ge;
    secp256k1_sha256 transcript;
    unsigned char expected_commitment33[33];
    size_t required = purify_bppp_required_proof_size(n_vec_len, c_vec_len);
    int ok = 0;

    memset(expected_commitment33, 0, sizeof(expected_commitment33));
    if (ctx == NULL || rho32 == NULL || (resources == NULL && generators33 == NULL) || n_vec32 == NULL || l_vec32 == NULL || c_vec32 == NULL ||
        commitment33 == NULL || proof_out == NULL || proof_len == NULL) {
        if (resources == NULL && ctx != NULL) secp256k1_context_destroy(ctx);
        return 0;
    }
    if (n_vec_len == 0 || l_vec_len == 0 || c_vec_len == 0 || l_vec_len != c_vec_len) {
        if (resources == NULL) secp256k1_context_destroy(ctx);
        return 0;
    }
    if (!secp256k1_is_power_of_two(n_vec_len) || !secp256k1_is_power_of_two(c_vec_len) || generators_count != n_vec_len + l_vec_len) {
        if (resources == NULL) secp256k1_context_destroy(ctx);
        return 0;
    }
    if (resources != NULL && resources->generators_count != generators_count) {
        return 0;
    }
    if (*proof_len < required) {
        *proof_len = required;
        if (resources == NULL) secp256k1_context_destroy(ctx);
        return 0;
    }
    if (!purify_parse_scalar(rho32, &rho, 1) || !purify_parse_point_as_ge(commitment33, &commitment_ge)) {
        if (resources == NULL) secp256k1_context_destroy(ctx);
        return 0;
    }
    if (resources == NULL) {
        scratch = secp256k1_scratch_space_create(ctx, 1u << 24);
        gens = secp256k1_bppp_generators_parse(ctx, generators33, generators_count * 33);
    }
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
    if (!secp256k1_bppp_commit(ctx, scratch, &expected_commit, gens, n_vec, n_vec_len, l_vec, l_vec_len, c_vec, c_vec_len, &mu)) {
        goto cleanup;
    }
    if (!purify_serialize_point(expected_commitment33, &expected_commit)) {
        goto cleanup;
    }
    if (secp256k1_memcmp_var(expected_commitment33, commitment33, sizeof(expected_commitment33)) != 0) {
        goto cleanup;
    }
    purify_norm_arg_commit_initial_data(&transcript, &rho, gens, n_vec_len, c_vec, c_vec_len, &commitment_ge);
    ok = purify_bppp_rangeproof_norm_product_prove_const(ctx, scratch, proof_out, proof_len, &transcript, &rho,
                                                         gens->gens, gens->n, n_vec, n_vec_len, l_vec, l_vec_len, c_vec, c_vec_len);

cleanup:
    if (n_vec != NULL) free(n_vec);
    if (l_vec != NULL) free(l_vec);
    if (c_vec != NULL) free(c_vec);
    if (resources == NULL) {
        if (gens != NULL) secp256k1_bppp_generators_destroy(ctx, gens);
        if (scratch != NULL) secp256k1_scratch_space_destroy(ctx, scratch);
        secp256k1_context_destroy(ctx);
    }
    return ok;
}

int purify_bppp_prove_norm_arg_to_commitment(const unsigned char rho32[32], const unsigned char* generators33, size_t generators_count,
                                             const unsigned char* n_vec32, size_t n_vec_len, const unsigned char* l_vec32,
                                             size_t l_vec_len, const unsigned char* c_vec32, size_t c_vec_len,
                                             const unsigned char commitment33[33], unsigned char* proof_out, size_t* proof_len) {
    return purify_bppp_prove_norm_arg_to_commitment_impl(NULL, rho32, generators33, generators_count,
                                                         n_vec32, n_vec_len, l_vec32, l_vec_len, c_vec32, c_vec_len,
                                                         commitment33, proof_out, proof_len);
}

int purify_bppp_prove_norm_arg_to_commitment_with_resources(purify_bppp_backend_resources* resources,
                                                            const unsigned char rho32[32],
                                                            const unsigned char* n_vec32, size_t n_vec_len,
                                                            const unsigned char* l_vec32, size_t l_vec_len,
                                                            const unsigned char* c_vec32, size_t c_vec_len,
                                                            const unsigned char commitment33[33],
                                                            unsigned char* proof_out, size_t* proof_len) {
    return purify_bppp_prove_norm_arg_to_commitment_impl(resources, rho32, NULL,
                                                         resources != NULL ? resources->generators_count : 0,
                                                         n_vec32, n_vec_len, l_vec32, l_vec_len, c_vec32, c_vec_len,
                                                         commitment33, proof_out, proof_len);
}

static int purify_bppp_verify_norm_arg_impl(purify_bppp_backend_resources* resources,
                                            const unsigned char rho32[32], const unsigned char* generators33,
                                            size_t generators_count, const unsigned char* c_vec32, size_t c_vec_len,
                                            size_t n_vec_len, const unsigned char commitment33[33],
                                            const unsigned char* proof, size_t proof_len) {
    secp256k1_context* ctx = resources != NULL ? resources->ctx : purify_create_context();
    secp256k1_scratch_space* scratch = resources != NULL ? resources->scratch : NULL;
    secp256k1_bppp_generators* gens = resources != NULL ? resources->gens : NULL;
    secp256k1_scalar rho, *c_vec = NULL;
    secp256k1_ge commit;
    secp256k1_sha256 transcript;
    int ok = 0;

    if (ctx == NULL || rho32 == NULL || (resources == NULL && generators33 == NULL) || c_vec32 == NULL || commitment33 == NULL || proof == NULL) {
        if (resources == NULL && ctx != NULL) secp256k1_context_destroy(ctx);
        return 0;
    }
    if (n_vec_len == 0 || c_vec_len == 0 || generators_count != n_vec_len + c_vec_len) {
        if (resources == NULL) secp256k1_context_destroy(ctx);
        return 0;
    }
    if (!secp256k1_is_power_of_two(n_vec_len) || !secp256k1_is_power_of_two(c_vec_len)) {
        if (resources == NULL) secp256k1_context_destroy(ctx);
        return 0;
    }
    if (resources != NULL && resources->generators_count != generators_count) {
        return 0;
    }
    if (!purify_parse_scalar(rho32, &rho, 1) || !secp256k1_ge_parse_ext(&commit, commitment33)) {
        if (resources == NULL) secp256k1_context_destroy(ctx);
        return 0;
    }
    if (resources == NULL) {
        scratch = secp256k1_scratch_space_create(ctx, 1u << 24);
        gens = secp256k1_bppp_generators_parse(ctx, generators33, generators_count * 33);
    }
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
    if (resources == NULL) {
        if (gens != NULL) secp256k1_bppp_generators_destroy(ctx, gens);
        if (scratch != NULL) secp256k1_scratch_space_destroy(ctx, scratch);
        secp256k1_context_destroy(ctx);
    }
    return ok;
}

int purify_bppp_verify_norm_arg(const unsigned char rho32[32], const unsigned char* generators33, size_t generators_count,
                                const unsigned char* c_vec32, size_t c_vec_len, size_t n_vec_len,
                                const unsigned char commitment33[33], const unsigned char* proof, size_t proof_len) {
    return purify_bppp_verify_norm_arg_impl(NULL, rho32, generators33, generators_count,
                                            c_vec32, c_vec_len, n_vec_len, commitment33, proof, proof_len);
}

int purify_bppp_verify_norm_arg_with_resources(purify_bppp_backend_resources* resources,
                                               const unsigned char rho32[32],
                                               const unsigned char* c_vec32, size_t c_vec_len, size_t n_vec_len,
                                               const unsigned char commitment33[33], const unsigned char* proof,
                                               size_t proof_len) {
    return purify_bppp_verify_norm_arg_impl(resources, rho32, NULL,
                                            resources != NULL ? resources->generators_count : 0,
                                            c_vec32, c_vec_len, n_vec_len, commitment33, proof, proof_len);
}
