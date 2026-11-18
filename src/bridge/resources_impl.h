// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/*
 * Context handles, secret erasure, checked sizes, scratch space and reusable backend resources.
 *
 * Part of the Purify secp256k1 bridge translation unit. Include only from
 * bppp_bridge.c, after secp256k1.c and the parts listed before this one.
 */

#ifndef PURIFY_BRIDGE_RESOURCES_IMPL_H
#define PURIFY_BRIDGE_RESOURCES_IMPL_H

_Static_assert(sizeof(purify_scalar) == sizeof(secp256k1_scalar), "purify_scalar size mismatch");
_Static_assert(_Alignof(purify_scalar) >= _Alignof(secp256k1_scalar), "purify_scalar alignment mismatch");

struct purify_secp_context {
    secp256k1_context* ctx;
};

static void purify_bridge_secure_clear(void* data, size_t size);
static int purify_bridge_memeq_const(const unsigned char* lhs,
                                     const unsigned char* rhs,
                                     size_t size);

static secp256k1_context* purify_context_handle(const purify_secp_context* context) {
    return context != NULL ? context->ctx : NULL;
}

purify_secp_context* purify_secp_context_create(void) {
    unsigned char seed32[32] = {0};
    purify_secp_context* context =
        (purify_secp_context*)calloc(1, sizeof(*context));
    if (context == NULL) {
        return NULL;
    }
    context->ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (context->ctx == NULL) {
        free(context);
        return NULL;
    }
    if (purify_fill_secure_random(seed32, sizeof(seed32)) != PURIFY_ERROR_OK
        || !secp256k1_context_randomize(context->ctx, seed32)) {
        purify_bridge_secure_clear(seed32, sizeof(seed32));
        secp256k1_context_destroy(context->ctx);
        free(context);
        return NULL;
    }
    purify_bridge_secure_clear(seed32, sizeof(seed32));
    return context;
}

void purify_secp_context_destroy(purify_secp_context* context) {
    if (context == NULL) {
        return;
    }
    if (context->ctx != NULL) {
        secp256k1_context_destroy(context->ctx);
    }
    free(context);
}

static void purify_bridge_secure_clear(void* data, size_t size) {
    if (data != NULL && size != 0u) {
        secp256k1_memclear_explicit(data, size);
    }
}

static void purify_bridge_secure_clear_scratch_tail(secp256k1_scratch_space* scratch,
                                                    size_t checkpoint) {
    if (scratch != NULL && scratch->data != NULL && checkpoint <= scratch->max_size) {
        purify_bridge_secure_clear((unsigned char*)scratch->data + checkpoint,
                                   scratch->max_size - checkpoint);
    }
}

struct purify_bulletproof_backend_resources {
    size_t n_gates;
    size_t scratch_capacity;
    secp256k1_context* ctx;
    secp256k1_scratch_space* scratch;
    secp256k1_bulletproof_generators* gens;
};

size_t purify_bulletproof_backend_resources_scratch_capacity(const purify_bulletproof_backend_resources* resources) {
    return resources != NULL && resources->scratch != NULL ? resources->scratch->max_size : 0;
}

struct purify_bppp_backend_resources {
    size_t generators_count;
    secp256k1_context* ctx;
    secp256k1_scratch_space* scratch;
    secp256k1_bppp_generators* gens;
    secp256k1_bppp_generators gens_scratch;
    int gens_scratch_in_use;
};

typedef struct purify_bppp_mutable_generators_guard {
    purify_bppp_backend_resources* resources;
} purify_bppp_mutable_generators_guard;

static int purify_bridge_checked_mul_size(size_t lhs, size_t rhs, size_t* out) {
    if (out == NULL) {
        return 0;
    }
    if (lhs != 0 && rhs > SIZE_MAX / lhs) {
        return 0;
    }
    *out = lhs * rhs;
    return 1;
}

static int purify_bridge_checked_add_size(size_t lhs, size_t rhs, size_t* out) {
    if (out == NULL) {
        return 0;
    }
    if (rhs > SIZE_MAX - lhs) {
        return 0;
    }
    *out = lhs + rhs;
    return 1;
}

static void purify_bridge_secure_free_array(void* data, size_t count, size_t elem_size) {
    size_t bytes = 0;

    if (data != NULL && purify_bridge_checked_mul_size(count, elem_size, &bytes)) {
        purify_bridge_secure_clear(data, bytes);
    }
    free(data);
}

/* Reserve this much work space for the batched multiscalar multiplication
 * after the imported circuit and inner-product frames have been allocated.
 */
static const size_t purify_bulletproof_msm_scratch_size = (size_t)1u << 24;

static int purify_bulletproof_add_scratch_frame(size_t* total, size_t bytes, size_t objects) {
    size_t padding;
    return purify_bridge_checked_mul_size(objects, ALIGNMENT - 1, &padding)
        && purify_bridge_checked_add_size(bytes, padding, &bytes)
        && purify_bridge_checked_add_size(*total, bytes, total);
}

static secp256k1_scratch_space* purify_bppp_create_scratch(
    const secp256k1_context* ctx, size_t generators_count) {
    size_t frame;
    size_t capacity = purify_bulletproof_msm_scratch_size;
    size_t allocation_size;

    /* The norm prover keeps copies of n, l, c and all generators alive during
     * its MSMs. With g = |n| and h = |l| = |c|, g + 2h <= 2(g + h).
     * The verifier's four scalar arrays also fit this bound: their total is
     * g + h + 2log2(g) <= 2(g + h) for the supported g >= h >= 1.
     * Reserve the live frame separately from the existing MSM work space.
     */
    if (generators_count == 0
        || !purify_bridge_checked_mul_size(generators_count,
            sizeof(secp256k1_ge) + 2 * sizeof(secp256k1_scalar), &frame)
        || !purify_bulletproof_add_scratch_frame(&capacity, frame, 4)
        || !purify_bridge_checked_add_size(capacity,
            ROUND_TO_ALIGN(sizeof(secp256k1_scratch)), &allocation_size)) {
        return NULL;
    }
    return secp256k1_scratch_space_create(ctx, capacity);
}

static int purify_bulletproof_circuit_scratch_size(
    const secp256k1_bulletproof_circuit* circuit, size_t* out) {
    size_t scalars;
    size_t bytes;
    size_t points;
    size_t prover = 0;
    size_t verifier = 0;
    size_t allocation_size;

    /* The prover's compressed circuit stays live throughout the nested
     * inner-product proof. Match both frames in the imported implementation.
     */
    if (!purify_bridge_checked_mul_size(5, circuit->n_gates, &scalars)
        || !purify_bridge_checked_add_size(scalars, circuit->n_constraints, &scalars)
        || !purify_bridge_checked_add_size(scalars, circuit->n_commits, &scalars)
        || !purify_bridge_checked_mul_size(scalars, sizeof(secp256k1_scalar), &bytes)
        || !purify_bridge_checked_add_size(bytes, sizeof(secp256k1_bulletproof_pf_compressed_circuit), &bytes)
        || !purify_bulletproof_add_scratch_frame(&prover, bytes, 2)) {
        return 0;
    }
    if (circuit->n_gates > 2) {
        if (!purify_bridge_checked_mul_size(2, circuit->n_gates, &scalars)
            || !purify_bridge_checked_mul_size(scalars, sizeof(secp256k1_scalar) + sizeof(secp256k1_ge), &bytes)
            || !purify_bridge_checked_mul_size(2, secp256k1_floor_lg(circuit->n_gates), &points)
            || !purify_bridge_checked_mul_size(points, sizeof(secp256k1_ge), &points)
            || !purify_bridge_checked_add_size(bytes, points, &bytes)
            || !purify_bulletproof_add_scratch_frame(&prover, bytes, 5)) {
            return 0;
        }
    }

    /* The bridge verifies one proof: outer verifier, compressed circuit, and
     * inner-product verifier frames are simultaneously live during the MSM.
     */
    if (!purify_bridge_checked_add_size(sizeof(secp256k1_bulletproof_circuit_vfy_ecmult_context),
                                        sizeof(secp256k1_bulletproof_innerproduct_context), &bytes)
        || !purify_bulletproof_add_scratch_frame(&verifier, bytes, 2)
        || !purify_bridge_checked_mul_size(2, circuit->n_gates, &scalars)
        || !purify_bridge_checked_add_size(scalars, circuit->n_constraints, &scalars)
        || !purify_bridge_checked_add_size(scalars, circuit->n_commits, &scalars)
        || !purify_bridge_checked_mul_size(scalars, sizeof(secp256k1_scalar), &bytes)
        || !purify_bridge_checked_add_size(bytes, sizeof(secp256k1_bulletproof_vfy_compressed_circuit), &bytes)
        || !purify_bulletproof_add_scratch_frame(&verifier, bytes, 2)
        || !purify_bridge_checked_add_size(sizeof(secp256k1_scalar),
                                          sizeof(secp256k1_bulletproof_innerproduct_vfy_data), &bytes)
        || !purify_bulletproof_add_scratch_frame(&verifier, bytes, 2)
        || !purify_bridge_checked_add_size(prover > verifier ? prover : verifier,
                                          purify_bulletproof_msm_scratch_size, out)
        || !purify_bridge_checked_add_size(*out, ROUND_TO_ALIGN(sizeof(secp256k1_scratch)), &allocation_size)) {
        return 0;
    }
    return 1;
}

static int purify_bulletproof_reserve_circuit_scratch(
    purify_bulletproof_backend_resources* resources,
    const secp256k1_bulletproof_circuit* circuit) {
    size_t required;
    secp256k1_scratch_space* replacement;

    if (!purify_bulletproof_circuit_scratch_size(circuit, &required)) {
        return 0;
    }
    if (required <= resources->scratch_capacity) {
        return 1;
    }
    replacement = secp256k1_scratch_space_create(resources->ctx, required);
    if (replacement == NULL) {
        return 0;
    }
    purify_bridge_secure_clear_scratch_tail(resources->scratch, 0);
    secp256k1_scratch_space_destroy(resources->ctx, resources->scratch);
    resources->scratch = replacement;
    resources->scratch_capacity = required;
    return 1;
}

static void* purify_malloc_array(size_t count, size_t elem_size) {
    size_t bytes = 0;

    if (count == 0) {
        return NULL;
    }
    if (!purify_bridge_checked_mul_size(count, elem_size, &bytes)) {
        return NULL;
    }
    return malloc(bytes);
}

static void* purify_calloc_array(size_t count, size_t elem_size) {
    size_t bytes = 0;

    if (count == 0) {
        return NULL;
    }
    if (!purify_bridge_checked_mul_size(count, elem_size, &bytes)) {
        return NULL;
    }
    return calloc(1, bytes);
}

static secp256k1_bppp_generators* purify_bppp_generators_clone(
    const secp256k1_bppp_generators* generators) {
    secp256k1_bppp_generators* clone;
    size_t generator_bytes = 0;

    if (generators == NULL || generators->gens == NULL || generators->n == 0 ||
        !purify_bridge_checked_mul_size(generators->n, sizeof(*generators->gens), &generator_bytes)) {
        return NULL;
    }

    clone = (secp256k1_bppp_generators*)calloc(1, sizeof(*clone));
    if (clone == NULL) {
        return NULL;
    }
    clone->n = generators->n;
    clone->gens = (secp256k1_ge*)purify_malloc_array(generators->n, sizeof(*clone->gens));
    if (clone->gens == NULL) {
        free(clone);
        return NULL;
    }
    memcpy(clone->gens, generators->gens, generator_bytes);
    return clone;
}

/* BPPP proving folds the generator table in place, so cached resources keep one
   pristine parsed copy and one resettable scratch copy for prove calls. */
static int purify_bppp_backend_resources_reset_scratch_gens(purify_bppp_backend_resources* resources) {
    size_t generator_bytes = 0;

    if (resources == NULL || resources->gens == NULL || resources->gens->gens == NULL ||
        resources->gens->n != resources->generators_count ||
        resources->gens_scratch.gens == NULL || resources->gens_scratch.n != resources->generators_count ||
        !purify_bridge_checked_mul_size(resources->generators_count, sizeof(*resources->gens->gens), &generator_bytes)) {
        return 0;
    }

    memcpy(resources->gens_scratch.gens, resources->gens->gens, generator_bytes);
    return 1;
}

static secp256k1_bppp_generators* purify_bppp_backend_resources_acquire_scratch_gens(
    purify_bppp_backend_resources* resources,
    purify_bppp_mutable_generators_guard* guard) {
    if (guard == NULL || resources == NULL || resources->gens_scratch_in_use) {
        return NULL;
    }
    if (!purify_bppp_backend_resources_reset_scratch_gens(resources)) {
        return NULL;
    }
    resources->gens_scratch_in_use = 1;
    guard->resources = resources;
    return &resources->gens_scratch;
}

static void purify_bppp_backend_resources_release_scratch_gens(
    purify_bppp_mutable_generators_guard* guard) {
    if (guard != NULL && guard->resources != NULL) {
        guard->resources->gens_scratch_in_use = 0;
        guard->resources = NULL;
    }
}

purify_bulletproof_backend_resources* purify_bulletproof_backend_resources_create(purify_secp_context* context,
                                                                                  size_t n_gates) {
    purify_bulletproof_backend_resources* resources;
    size_t generator_count = 0;
    secp256k1_context* ctx = purify_context_handle(context);

    if (ctx == NULL || n_gates == 0 || !secp256k1_is_power_of_two(n_gates)) {
        return NULL;
    }
    if (!purify_bridge_checked_mul_size(2u, n_gates, &generator_count)) {
        return NULL;
    }

    resources = (purify_bulletproof_backend_resources*)calloc(1, sizeof(*resources));
    if (resources == NULL) {
        return NULL;
    }

    resources->ctx = ctx;

    resources->scratch_capacity = purify_bulletproof_msm_scratch_size;
    resources->scratch = secp256k1_scratch_space_create(resources->ctx, resources->scratch_capacity);
    if (resources->scratch == NULL) {
        purify_bulletproof_backend_resources_destroy(resources);
        return NULL;
    }

    resources->gens = secp256k1_bulletproof_generators_create(resources->ctx, secp256k1_generator_h, generator_count, 1);
    if (resources->gens == NULL || resources->gens->n < generator_count) {
        purify_bulletproof_backend_resources_destroy(resources);
        return NULL;
    }

    resources->n_gates = n_gates;
    return resources;
}

purify_bulletproof_backend_resources* purify_bulletproof_backend_resources_clone(
    const purify_bulletproof_backend_resources* resources) {
    purify_bulletproof_backend_resources* clone;
    size_t generator_count = 0;

    if (resources == NULL || resources->ctx == NULL || resources->n_gates == 0 ||
        !purify_bridge_checked_mul_size(2u, resources->n_gates, &generator_count)) {
        return NULL;
    }

    clone = (purify_bulletproof_backend_resources*)calloc(1, sizeof(*clone));
    if (clone == NULL) {
        return NULL;
    }
    clone->ctx = resources->ctx;
    clone->n_gates = resources->n_gates;
    clone->scratch_capacity = resources->scratch_capacity;
    clone->scratch = secp256k1_scratch_space_create(clone->ctx, clone->scratch_capacity);
    if (clone->scratch == NULL) {
        purify_bulletproof_backend_resources_destroy(clone);
        return NULL;
    }
    clone->gens = secp256k1_bulletproof_generators_create(
        clone->ctx, secp256k1_generator_h, generator_count, 1);
    if (clone->gens == NULL || clone->gens->n < generator_count) {
        purify_bulletproof_backend_resources_destroy(clone);
        return NULL;
    }
    return clone;
}

void purify_bulletproof_backend_resources_destroy(purify_bulletproof_backend_resources* resources) {
    if (resources == NULL) {
        return;
    }
    if (resources->gens != NULL && resources->ctx != NULL) {
        secp256k1_bulletproof_generators_destroy(resources->ctx, resources->gens);
    }
    if (resources->scratch != NULL && resources->ctx != NULL) {
        purify_bridge_secure_clear_scratch_tail(resources->scratch, 0);
        secp256k1_scratch_space_destroy(resources->ctx, resources->scratch);
    }
    free(resources);
}

purify_bppp_backend_resources* purify_bppp_backend_resources_create(purify_secp_context* context,
                                                                    const unsigned char* generators33,
                                                                    size_t generators_count) {
    purify_bppp_backend_resources* resources;
    size_t serialized_len = 0;
    secp256k1_context* ctx = purify_context_handle(context);

    if (ctx == NULL || generators33 == NULL || generators_count == 0) {
        return NULL;
    }
    if (!purify_bridge_checked_mul_size(generators_count, 33u, &serialized_len)) {
        return NULL;
    }

    resources = (purify_bppp_backend_resources*)calloc(1, sizeof(*resources));
    if (resources == NULL) {
        return NULL;
    }

    resources->ctx = ctx;

    resources->scratch = purify_bppp_create_scratch(resources->ctx, generators_count);
    if (resources->scratch == NULL) {
        purify_bppp_backend_resources_destroy(resources);
        return NULL;
    }

    resources->gens = secp256k1_bppp_generators_parse(resources->ctx, generators33, serialized_len);
    if (resources->gens == NULL || resources->gens->n != generators_count) {
        purify_bppp_backend_resources_destroy(resources);
        return NULL;
    }
    resources->gens_scratch.n = generators_count;
    resources->gens_scratch.gens =
        (secp256k1_ge*)purify_malloc_array(generators_count, sizeof(*resources->gens_scratch.gens));
    if (resources->gens_scratch.gens == NULL) {
        purify_bppp_backend_resources_destroy(resources);
        return NULL;
    }

    resources->generators_count = generators_count;
    return resources;
}

purify_bppp_backend_resources* purify_bppp_backend_resources_clone(
    const purify_bppp_backend_resources* resources) {
    purify_bppp_backend_resources* clone;
    size_t generator_bytes = 0;

    if (resources == NULL || resources->ctx == NULL || resources->generators_count == 0 ||
        resources->gens == NULL || resources->gens->n != resources->generators_count ||
        !purify_bridge_checked_mul_size(resources->generators_count, sizeof(*resources->gens->gens), &generator_bytes)) {
        return NULL;
    }

    clone = (purify_bppp_backend_resources*)calloc(1, sizeof(*clone));
    if (clone == NULL) {
        return NULL;
    }
    clone->ctx = resources->ctx;
    clone->generators_count = resources->generators_count;
    clone->scratch = purify_bppp_create_scratch(clone->ctx, clone->generators_count);
    if (clone->scratch == NULL) {
        purify_bppp_backend_resources_destroy(clone);
        return NULL;
    }
    clone->gens = purify_bppp_generators_clone(resources->gens);
    if (clone->gens == NULL) {
        purify_bppp_backend_resources_destroy(clone);
        return NULL;
    }
    clone->gens_scratch.n = clone->generators_count;
    clone->gens_scratch.gens =
        (secp256k1_ge*)purify_malloc_array(clone->generators_count, sizeof(*clone->gens_scratch.gens));
    if (clone->gens_scratch.gens == NULL) {
        purify_bppp_backend_resources_destroy(clone);
        return NULL;
    }
    memcpy(clone->gens_scratch.gens, clone->gens->gens, generator_bytes);
    return clone;
}

void purify_bppp_backend_resources_destroy(purify_bppp_backend_resources* resources) {
    if (resources == NULL) {
        return;
    }
    if (resources->gens != NULL && resources->ctx != NULL) {
        secp256k1_bppp_generators_destroy(resources->ctx, resources->gens);
    }
    if (resources->gens_scratch.gens != NULL) {
        free(resources->gens_scratch.gens);
    }
    if (resources->scratch != NULL && resources->ctx != NULL) {
        purify_bridge_secure_clear_scratch_tail(resources->scratch, 0);
        secp256k1_scratch_space_destroy(resources->ctx, resources->scratch);
    }
    free(resources);
}

#endif /* PURIFY_BRIDGE_RESOURCES_IMPL_H */
