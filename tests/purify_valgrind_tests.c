// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if defined(__has_include)
#if __has_include(<valgrind/memcheck.h>)
#include <valgrind/memcheck.h>
#endif
#endif

#ifndef VALGRIND_MAKE_MEM_UNDEFINED
#define VALGRIND_MAKE_MEM_UNDEFINED(addr, len) ((void)(addr), (void)(len))
#define VALGRIND_MAKE_MEM_DEFINED(addr, len) ((void)(addr), (void)(len))
#endif

#include "../src/core/curve.h"
#include "../src/core/core.h"
#include "../src/core/field.h"
#include "../src/bridge/bppp_bridge.h"

void purify_curve_mul_secret_ladder_only(purify_complete_projective_point* out, const purify_curve* curve,
                                         const purify_jacobian_point* point, const uint64_t scalar[4]);
void purify_curve_mul_secret_affine_unchecked(purify_affine_point* out, const purify_curve* curve,
                                              const purify_jacobian_point* point, const uint64_t scalar[4]);
void purify_curve_unpack_secret_unchecked(uint64_t first[4], uint64_t second[4], const uint64_t value[8]);

static int failures = 0;

static void expect(int condition, const char* message) {
    if (!condition) {
        ++failures;
        fprintf(stderr, "FAIL: %s\n", message);
    }
}

static void make_curve1(purify_curve* out) {
    purify_curve_field_a(&out->a);
    purify_curve_field_b(&out->b);
    purify_curve_order_n1(out->n);
}

static void make_curve2(purify_curve* out) {
    purify_fe a;
    purify_fe b;
    purify_fe d;

    purify_curve_field_a(&a);
    purify_curve_field_b(&b);
    purify_curve_field_d(&d);
    purify_fe_mul(&out->a, &a, &d);
    purify_fe_mul(&out->a, &out->a, &d);
    purify_fe_mul(&out->b, &b, &d);
    purify_fe_mul(&out->b, &out->b, &d);
    purify_fe_mul(&out->b, &out->b, &d);
    purify_curve_order_n2(out->n);
}

static int make_generator(purify_jacobian_point* out, const purify_curve* curve, const char* label) {
    const unsigned char* data = (const unsigned char*)label;
    const size_t len = strlen(label);
    const int ok = purify_curve_hash_to_curve(out, curve, data, len);
    expect(ok != 0, "hash_to_curve derives a generator point");
    return ok;
}

static void test_secret_ladder_consttime(const purify_curve* curve, const char* label) {
    purify_jacobian_point generator;
    purify_complete_projective_point ladder;
    uint64_t scalar[4] = {UINT64_C(0x123456789ABCDEF1), 0, 0, 0};

    if (make_generator(&generator, curve, label) == 0) {
        return;
    }

    /* Mark the scalar undefined so Memcheck reports secret-dependent branches or table indices. */
    VALGRIND_MAKE_MEM_UNDEFINED(scalar, sizeof(scalar));
    purify_curve_mul_secret_ladder_only(&ladder, curve, &generator, scalar);
    VALGRIND_MAKE_MEM_DEFINED(scalar, sizeof(scalar));
    VALGRIND_MAKE_MEM_DEFINED(&ladder, sizeof(ladder));
}

static void test_divmod_secret_numerator_consttime(void) {
    uint64_t numerator[8] = {
        UINT64_C(0x123456789ABCDEF1), UINT64_C(0x0FEDCBA987654321), UINT64_C(0x1111222233334444), UINT64_C(0x5555666677778888),
        UINT64_C(0x9999AAAABBBBCCCC), UINT64_C(0xDDDDEEEEFFFF0000), UINT64_C(0x0123456789ABCDEF), UINT64_C(0x0011223344556677)};
    uint64_t half_n1[4];
    uint64_t denominator[8];
    uint64_t quotient[8];
    uint64_t remainder[8];

    purify_curve_half_n1(half_n1);
    purify_u512_widen_u256(denominator, half_n1);

    /* Mark only the numerator undefined so Memcheck reports secret-dependent branches or table indices. */
    VALGRIND_MAKE_MEM_UNDEFINED(numerator, sizeof(numerator));
    expect(purify_u512_try_divmod_same_consttime(quotient, remainder, numerator, denominator) != 0,
           "constant-time u512 divider accepts a fixed non-zero denominator");
    VALGRIND_MAKE_MEM_DEFINED(numerator, sizeof(numerator));
    VALGRIND_MAKE_MEM_DEFINED(quotient, sizeof(quotient));
    VALGRIND_MAKE_MEM_DEFINED(remainder, sizeof(remainder));
}

static void test_secret_affine_consttime(const purify_curve* curve, const char* label) {
    purify_jacobian_point generator;
    purify_affine_point affine;
    uint64_t scalar[4] = {1u, 0u, 0u, 0u};

    if (make_generator(&generator, curve, label) == 0) {
        return;
    }

    /* Keep the scalar non-zero while leaving the high 192 bits secret. */
    VALGRIND_MAKE_MEM_UNDEFINED(&scalar[1], 3u * sizeof(uint64_t));
    purify_curve_mul_secret_affine_unchecked(&affine, curve, &generator, scalar);
    VALGRIND_MAKE_MEM_DEFINED(&scalar[1], 3u * sizeof(uint64_t));
    VALGRIND_MAKE_MEM_DEFINED(&affine, sizeof(affine));
}

static void test_secret_inverse_consttime(void) {
    purify_fe value;
    purify_fe inverse;

    purify_fe_set_u64(&value, 1u);

    /* Keep the input non-zero while leaving the high 192 bits secret. */
    VALGRIND_MAKE_MEM_UNDEFINED(&value.value.words[1], 3u * sizeof(uint64_t));
    purify_fe_inverse(&inverse, &value);
    VALGRIND_MAKE_MEM_DEFINED(&value.value.words[1], 3u * sizeof(uint64_t));
    VALGRIND_MAKE_MEM_DEFINED(&inverse, sizeof(inverse));
}

static void test_valid_packed_secret_path_consttime(const purify_curve* curve1, const purify_curve* curve2) {
    purify_jacobian_point generator1;
    purify_jacobian_point generator2;
    purify_affine_point public1;
    purify_affine_point public2;
    uint64_t packed_secret[8] = {0};
    uint64_t secret1[4];
    uint64_t secret2[4];

    if (make_generator(&generator1, curve1, "Generator/1") == 0 ||
        make_generator(&generator2, curve2, "Generator/2") == 0) {
        return;
    }

    /*
     * Keep the top 128 bits zero so every concrete execution stays below the packed-secret space size,
     * while the low 384 bits remain secret.
     */
    VALGRIND_MAKE_MEM_UNDEFINED(packed_secret, 6u * sizeof(uint64_t));
    purify_curve_unpack_secret_unchecked(secret1, secret2, packed_secret);
    purify_curve_mul_secret_affine_unchecked(&public1, curve1, &generator1, secret1);
    purify_curve_mul_secret_affine_unchecked(&public2, curve2, &generator2, secret2);
    VALGRIND_MAKE_MEM_DEFINED(packed_secret, sizeof(packed_secret));
    VALGRIND_MAKE_MEM_DEFINED(secret1, sizeof(secret1));
    VALGRIND_MAKE_MEM_DEFINED(secret2, sizeof(secret2));
    VALGRIND_MAKE_MEM_DEFINED(&public1, sizeof(public1));
    VALGRIND_MAKE_MEM_DEFINED(&public2, sizeof(public2));
}

static void test_uint_helpers_consttime(void) {
    unsigned char bytes256[32];
    unsigned char bytes320[40];
    unsigned char bytes512[64];
    uint64_t value256[4] = {UINT64_C(0xffffffffffffffff),
                            UINT64_C(0x123456789abcdef0),
                            UINT64_C(0), UINT64_C(0)};
    uint64_t value320[5] = {UINT64_C(0xffffffffffffffff),
                            UINT64_C(0x123456789abcdef0),
                            UINT64_C(0), UINT64_C(0), UINT64_C(0)};
    uint64_t value512[8] = {UINT64_C(0xffffffffffffffff),
                            UINT64_C(0x123456789abcdef0),
                            UINT64_C(0), UINT64_C(0), UINT64_C(0),
                            UINT64_C(0), UINT64_C(0), UINT64_C(0)};
    uint64_t selected256[4] = {UINT64_C(42), 0, 0, 0};
    uint64_t selected320[5] = {UINT64_C(42), 0, 0, 0, 0};
    uint64_t selected512[8] = {UINT64_C(42), 0, 0, 0, 0, 0, 0, 0};
    int select = 1;
    int result;
    size_t i;

    for (i = 0; i < sizeof(bytes256); ++i) {
        bytes256[i] = (unsigned char)(i * 7u + 3u);
    }
    for (i = 0; i < sizeof(bytes320); ++i) {
        bytes320[i] = (unsigned char)(i * 11u + 5u);
    }
    for (i = 0; i < sizeof(bytes512); ++i) {
        bytes512[i] = (unsigned char)(i * 13u + 9u);
    }

    VALGRIND_MAKE_MEM_UNDEFINED(value256, sizeof(value256));
    result = purify_u256_is_zero(value256);
    VALGRIND_MAKE_MEM_DEFINED(value256, sizeof(value256));
    VALGRIND_MAKE_MEM_DEFINED(&result, sizeof(result));
    expect(result == 0, "u256 is_zero scans a secret value without branching");

    VALGRIND_MAKE_MEM_UNDEFINED(value320, sizeof(value320));
    result = purify_u320_is_zero(value320);
    VALGRIND_MAKE_MEM_DEFINED(value320, sizeof(value320));
    VALGRIND_MAKE_MEM_DEFINED(&result, sizeof(result));
    expect(result == 0, "u320 is_zero scans a secret value without branching");

    VALGRIND_MAKE_MEM_UNDEFINED(value512, sizeof(value512));
    result = purify_u512_is_zero(value512);
    VALGRIND_MAKE_MEM_DEFINED(value512, sizeof(value512));
    VALGRIND_MAKE_MEM_DEFINED(&result, sizeof(result));
    expect(result == 0, "u512 is_zero scans a secret value without branching");

    VALGRIND_MAKE_MEM_UNDEFINED(value256, sizeof(value256));
    result = purify_u256_try_add_small(value256, 1u);
    VALGRIND_MAKE_MEM_DEFINED(value256, sizeof(value256));
    VALGRIND_MAKE_MEM_DEFINED(&result, sizeof(result));
    expect(result != 0 && value256[0] == 0 &&
               value256[1] == UINT64_C(0x123456789abcdef1),
           "u256 add_small propagates a secret carry in fixed rounds");

    VALGRIND_MAKE_MEM_UNDEFINED(value320, sizeof(value320));
    result = purify_u320_try_add_small(value320, 1u);
    VALGRIND_MAKE_MEM_DEFINED(value320, sizeof(value320));
    VALGRIND_MAKE_MEM_DEFINED(&result, sizeof(result));
    expect(result != 0 && value320[0] == 0 &&
               value320[1] == UINT64_C(0x123456789abcdef1),
           "u320 add_small propagates a secret carry in fixed rounds");

    VALGRIND_MAKE_MEM_UNDEFINED(value512, sizeof(value512));
    result = purify_u512_try_add_small(value512, 1u);
    VALGRIND_MAKE_MEM_DEFINED(value512, sizeof(value512));
    VALGRIND_MAKE_MEM_DEFINED(&result, sizeof(result));
    expect(result != 0 && value512[0] == 0 &&
               value512[1] == UINT64_C(0x123456789abcdef1),
           "u512 add_small propagates a secret carry in fixed rounds");

    VALGRIND_MAKE_MEM_UNDEFINED(value256, sizeof(value256));
    VALGRIND_MAKE_MEM_UNDEFINED(selected256, sizeof(selected256));
    VALGRIND_MAKE_MEM_UNDEFINED(&select, sizeof(select));
    purify_u256_conditional_assign(value256, selected256, select);
    VALGRIND_MAKE_MEM_DEFINED(value256, sizeof(value256));
    VALGRIND_MAKE_MEM_DEFINED(selected256, sizeof(selected256));
    VALGRIND_MAKE_MEM_DEFINED(&select, sizeof(select));
    expect(value256[0] == 42,
           "u256 conditional assignment does not branch on secret inputs");

    VALGRIND_MAKE_MEM_UNDEFINED(value320, sizeof(value320));
    VALGRIND_MAKE_MEM_UNDEFINED(selected320, sizeof(selected320));
    VALGRIND_MAKE_MEM_UNDEFINED(&select, sizeof(select));
    purify_u320_conditional_assign(value320, selected320, select);
    VALGRIND_MAKE_MEM_DEFINED(value320, sizeof(value320));
    VALGRIND_MAKE_MEM_DEFINED(selected320, sizeof(selected320));
    VALGRIND_MAKE_MEM_DEFINED(&select, sizeof(select));
    expect(value320[0] == 42,
           "u320 conditional assignment does not branch on secret inputs");

    VALGRIND_MAKE_MEM_UNDEFINED(value512, sizeof(value512));
    VALGRIND_MAKE_MEM_UNDEFINED(selected512, sizeof(selected512));
    VALGRIND_MAKE_MEM_UNDEFINED(&select, sizeof(select));
    purify_u512_conditional_assign(value512, selected512, select);
    VALGRIND_MAKE_MEM_DEFINED(value512, sizeof(value512));
    VALGRIND_MAKE_MEM_DEFINED(selected512, sizeof(selected512));
    VALGRIND_MAKE_MEM_DEFINED(&select, sizeof(select));
    expect(value512[0] == 42,
           "u512 conditional assignment does not branch on secret inputs");

    VALGRIND_MAKE_MEM_UNDEFINED(bytes256, sizeof(bytes256));
    purify_u256_from_bytes_be(value256, bytes256, sizeof(bytes256));
    VALGRIND_MAKE_MEM_DEFINED(bytes256, sizeof(bytes256));
    VALGRIND_MAKE_MEM_DEFINED(value256, sizeof(value256));

    VALGRIND_MAKE_MEM_UNDEFINED(bytes320, sizeof(bytes320));
    purify_u320_from_bytes_be(value320, bytes320, sizeof(bytes320));
    VALGRIND_MAKE_MEM_DEFINED(bytes320, sizeof(bytes320));
    VALGRIND_MAKE_MEM_DEFINED(value320, sizeof(value320));

    VALGRIND_MAKE_MEM_UNDEFINED(bytes512, sizeof(bytes512));
    purify_u512_from_bytes_be(value512, bytes512, sizeof(bytes512));
    VALGRIND_MAKE_MEM_DEFINED(bytes512, sizeof(bytes512));
    VALGRIND_MAKE_MEM_DEFINED(value512, sizeof(value512));
}

static void test_secret_comparison_consttime(void) {
    unsigned char lhs[PURIFY_SECRET_KEY_BYTES];
    unsigned char rhs[PURIFY_SECRET_KEY_BYTES];
    int comparison;
    purify_error_code validation;

    memset(lhs, 0x19, sizeof(lhs));
    memset(rhs, 0xa7, sizeof(rhs));
    VALGRIND_MAKE_MEM_UNDEFINED(lhs, sizeof(lhs));
    VALGRIND_MAKE_MEM_UNDEFINED(rhs, sizeof(rhs));
    comparison = purify_core_compare_be_test(lhs, rhs, sizeof(lhs));
    VALGRIND_MAKE_MEM_DEFINED(lhs, sizeof(lhs));
    VALGRIND_MAKE_MEM_DEFINED(rhs, sizeof(rhs));
    VALGRIND_MAKE_MEM_DEFINED(&comparison, sizeof(comparison));
    expect(comparison < 0,
           "big-endian secret comparison scans every byte without branching");

    memset(lhs, 0, sizeof(lhs));
    VALGRIND_MAKE_MEM_UNDEFINED(lhs + 1, sizeof(lhs) - 1u);
    validation = purify_validate_secret_key(lhs);
    VALGRIND_MAKE_MEM_DEFINED(lhs + 1, sizeof(lhs) - 1u);
    VALGRIND_MAKE_MEM_DEFINED(&validation, sizeof(validation));
    expect(validation == PURIFY_ERROR_OK,
           "secret-key validation does not branch on trailing secret bytes");
}

static void set_bppp_secret_scalar(unsigned char out[32],
                                   unsigned char high_byte,
                                   unsigned char tail_seed) {
    size_t i;

    memset(out, 0, 32);
    /* Canonicality and nonzeroness stay public; only value bits are tainted. */
    out[24] = high_byte;
    for (i = 25; i < 32; ++i) {
        out[i] = (unsigned char)(tail_seed + i);
    }
}

static void mark_bppp_scalar_tails_undefined(unsigned char* scalars,
                                              size_t count) {
    size_t i;
    for (i = 0; i < count; ++i) {
        VALGRIND_MAKE_MEM_UNDEFINED(scalars + 32 * i + 25, 7);
    }
}

static void test_bppp_secret_point_paths_consttime(void) {
    purify_secp_context* context = purify_secp_context_create();
    unsigned char base_generator[33];
    unsigned char value_generator[33];
    unsigned char base_point[33];
    unsigned char scalar_a[32];
    unsigned char scalar_b[32];
    unsigned char output[33];
    int ok;

    expect(context != NULL, "BPPP secret point context creates");
    if (context == NULL) {
        return;
    }
    expect(purify_bppp_base_generator(context, base_generator) != 0,
           "BPPP base generator serializes");
    expect(purify_bppp_value_generator_h(context, value_generator) != 0,
           "BPPP value generator serializes");
    expect(purify_bppp_generators_to_points(
               context, base_generator, 1, base_point) != 0,
           "BPPP base generator converts to a point");

    set_bppp_secret_scalar(scalar_a, 1, 0x21);
    set_bppp_secret_scalar(scalar_b, 2, 0x43);
    mark_bppp_scalar_tails_undefined(scalar_a, 1);
    mark_bppp_scalar_tails_undefined(scalar_b, 1);
    ok = purify_pedersen_commit_char(
        context, scalar_a, scalar_b, value_generator, base_generator, output);
    VALGRIND_MAKE_MEM_DEFINED(scalar_a, sizeof(scalar_a));
    VALGRIND_MAKE_MEM_DEFINED(scalar_b, sizeof(scalar_b));
    VALGRIND_MAKE_MEM_DEFINED(output, sizeof(output));
    VALGRIND_MAKE_MEM_DEFINED(&ok, sizeof(ok));
    expect(ok != 0, "BPPP Pedersen commitment accepts secret scalars");

    mark_bppp_scalar_tails_undefined(scalar_a, 1);
    ok = purify_bppp_offset_commitment(
        context, base_point, scalar_a, output);
    VALGRIND_MAKE_MEM_DEFINED(scalar_a, sizeof(scalar_a));
    VALGRIND_MAKE_MEM_DEFINED(output, sizeof(output));
    VALGRIND_MAKE_MEM_DEFINED(&ok, sizeof(ok));
    expect(ok != 0, "BPPP commitment offset accepts a secret scalar");

    mark_bppp_scalar_tails_undefined(scalar_b, 1);
    ok = purify_point_scale(context, base_point, scalar_b, output);
    VALGRIND_MAKE_MEM_DEFINED(scalar_b, sizeof(scalar_b));
    VALGRIND_MAKE_MEM_DEFINED(output, sizeof(output));
    VALGRIND_MAKE_MEM_DEFINED(&ok, sizeof(ok));
    expect(ok != 0, "BPPP point scaling accepts a secret scalar");

    purify_secp_context_destroy(context);
}

static void test_bppp_secret_norm_prover_consttime(void) {
    enum {
        N_VEC_LEN = 2,
        L_VEC_LEN = 2,
        GENERATOR_COUNT = N_VEC_LEN + L_VEC_LEN,
        MAX_PROOF_SIZE = 256
    };
    purify_secp_context* context = purify_secp_context_create();
    unsigned char generators[GENERATOR_COUNT * 33];
    unsigned char n_vec[N_VEC_LEN * 32];
    unsigned char l_vec[L_VEC_LEN * 32];
    unsigned char c_vec[L_VEC_LEN * 32];
    unsigned char rho[32] = {0};
    unsigned char commitment[33];
    unsigned char proof[MAX_PROOF_SIZE];
    size_t generators_len = sizeof(generators);
    size_t proof_len = sizeof(proof);
    size_t required_proof_size;
    size_t i;
    int ok;

    expect(context != NULL, "BPPP secret norm context creates");
    if (context == NULL) {
        return;
    }
    expect(purify_bppp_create_generators(
               context, GENERATOR_COUNT, generators,
               &generators_len) != 0 &&
               generators_len == sizeof(generators),
           "BPPP secret norm generators create");
    for (i = 0; i < N_VEC_LEN; ++i) {
        set_bppp_secret_scalar(n_vec + 32 * i,
                               (unsigned char)(i + 1),
                               (unsigned char)(0x11 + 13 * i));
    }
    for (i = 0; i < L_VEC_LEN; ++i) {
        set_bppp_secret_scalar(l_vec + 32 * i,
                               (unsigned char)(i + 3),
                               (unsigned char)(0x37 + 17 * i));
        memset(c_vec + 32 * i, 0, 32);
        c_vec[32 * i + 31] = (unsigned char)(i + 5);
    }
    rho[31] = 3;

    mark_bppp_scalar_tails_undefined(n_vec, N_VEC_LEN);
    mark_bppp_scalar_tails_undefined(l_vec, L_VEC_LEN);
    ok = purify_bppp_commit_witness_only(
        context, generators, GENERATOR_COUNT,
        n_vec, N_VEC_LEN, l_vec, L_VEC_LEN, commitment);
    VALGRIND_MAKE_MEM_DEFINED(n_vec, sizeof(n_vec));
    VALGRIND_MAKE_MEM_DEFINED(l_vec, sizeof(l_vec));
    VALGRIND_MAKE_MEM_DEFINED(commitment, sizeof(commitment));
    VALGRIND_MAKE_MEM_DEFINED(&ok, sizeof(ok));
    expect(ok != 0, "BPPP witness commitment accepts secret vectors");

    required_proof_size =
        purify_bppp_required_proof_size(N_VEC_LEN, L_VEC_LEN);
    expect(required_proof_size != 0 &&
               required_proof_size <= sizeof(proof),
           "BPPP secret norm proof buffer is sufficient");
    if (required_proof_size == 0 || required_proof_size > sizeof(proof)) {
        purify_secp_context_destroy(context);
        return;
    }
    proof_len = required_proof_size;
    mark_bppp_scalar_tails_undefined(n_vec, N_VEC_LEN);
    mark_bppp_scalar_tails_undefined(l_vec, L_VEC_LEN);
    ok = purify_bppp_prove_norm_arg(
        context, rho, generators, GENERATOR_COUNT,
        n_vec, N_VEC_LEN, l_vec, L_VEC_LEN,
        c_vec, L_VEC_LEN, commitment, proof, &proof_len);
    VALGRIND_MAKE_MEM_DEFINED(n_vec, sizeof(n_vec));
    VALGRIND_MAKE_MEM_DEFINED(l_vec, sizeof(l_vec));
    VALGRIND_MAKE_MEM_DEFINED(commitment, sizeof(commitment));
    VALGRIND_MAKE_MEM_DEFINED(proof, sizeof(proof));
    VALGRIND_MAKE_MEM_DEFINED(&proof_len, sizeof(proof_len));
    VALGRIND_MAKE_MEM_DEFINED(&ok, sizeof(ok));
    expect(ok != 0 && proof_len == required_proof_size,
           "BPPP norm prover accepts secret vectors");
    if (ok != 0) {
        expect(purify_bppp_verify_norm_arg(
                   context, rho, generators, GENERATOR_COUNT,
                   c_vec, L_VEC_LEN, N_VEC_LEN,
                   commitment, proof, proof_len) != 0,
               "BPPP secret norm proof verifies after declassification");
    }

    purify_secp_context_destroy(context);
}

static void run_bppp_tests(void) {
    test_bppp_secret_point_paths_consttime();
    test_bppp_secret_norm_prover_consttime();
}

static void run_divmod_tests(void) {
    test_divmod_secret_numerator_consttime();
}

static void run_ladder_tests(const purify_curve* curve1, const purify_curve* curve2) {
    test_secret_ladder_consttime(curve1, "Generator/1");
    test_secret_ladder_consttime(curve2, "Generator/2");
}

static void run_affine_tests(const purify_curve* curve1, const purify_curve* curve2) {
    test_secret_affine_consttime(curve1, "Generator/1");
    test_secret_affine_consttime(curve2, "Generator/2");
}

static void run_inverse_tests(void) {
    test_secret_inverse_consttime();
}

static void run_packed_secret_tests(const purify_curve* curve1, const purify_curve* curve2) {
    test_valid_packed_secret_path_consttime(curve1, curve2);
}

static void run_uint_tests(void) {
    test_uint_helpers_consttime();
    test_secret_comparison_consttime();
}

int main(int argc, char** argv) {
    purify_curve curve1;
    purify_curve curve2;

    make_curve1(&curve1);
    make_curve2(&curve2);

    if (argc <= 1 || strcmp(argv[1], "all") == 0) {
        run_divmod_tests();
        run_ladder_tests(&curve1, &curve2);
        run_affine_tests(&curve1, &curve2);
        run_inverse_tests();
        run_packed_secret_tests(&curve1, &curve2);
        run_uint_tests();
        run_bppp_tests();
    } else if (strcmp(argv[1], "divmod") == 0) {
        run_divmod_tests();
    } else if (strcmp(argv[1], "ladder") == 0) {
        run_ladder_tests(&curve1, &curve2);
    } else if (strcmp(argv[1], "affine") == 0) {
        run_affine_tests(&curve1, &curve2);
    } else if (strcmp(argv[1], "inverse") == 0) {
        run_inverse_tests();
    } else if (strcmp(argv[1], "packed_secret") == 0) {
        run_packed_secret_tests(&curve1, &curve2);
    } else if (strcmp(argv[1], "uint") == 0) {
        run_uint_tests();
    } else if (strcmp(argv[1], "bppp") == 0) {
        run_bppp_tests();
    } else {
        expect(0, "unknown valgrind test selector");
    }

    return failures == 0 ? 0 : 1;
}
