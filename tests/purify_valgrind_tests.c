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
#include "../src/core/field.h"

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
    } else {
        expect(0, "unknown valgrind test selector");
    }

    return failures == 0 ? 0 : 1;
}
