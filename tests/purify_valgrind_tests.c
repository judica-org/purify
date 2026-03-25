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

int main(void) {
    purify_curve curve1;
    purify_curve curve2;

    make_curve1(&curve1);
    make_curve2(&curve2);

    test_secret_ladder_consttime(&curve1, "Generator/1");
    test_secret_ladder_consttime(&curve2, "Generator/2");

    return failures == 0 ? 0 : 1;
}
