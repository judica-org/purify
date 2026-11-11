// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __CPROVER
#define PURIFY_CBMC_ASSUME(expr) __CPROVER_assume(expr)
extern uint64_t nondet_uint64_t(void);
extern unsigned char nondet_uchar(void);
extern size_t nondet_size_t(void);
#else
#define PURIFY_CBMC_ASSUME(expr) \
    do { \
        if (!(expr)) { \
            return 0; \
        } \
    } while (0)
static inline uint64_t nondet_uint64_t(void) {
    return 0;
}
static inline unsigned char nondet_uchar(void) {
    return 0;
}
static inline size_t nondet_size_t(void) {
    return 0;
}
#endif

static inline void purify_cbmc_nondet_words(uint64_t* out, size_t words) {
    size_t i;
    for (i = 0; i < words; ++i) {
        out[i] = nondet_uint64_t();
    }
}

static inline void purify_cbmc_nondet_bytes(unsigned char* out, size_t len) {
    size_t i;
    for (i = 0; i < len; ++i) {
        out[i] = nondet_uchar();
    }
}

static inline int purify_cbmc_words_eq(const uint64_t* lhs, const uint64_t* rhs, size_t words) {
    size_t i;
    for (i = 0; i < words; ++i) {
        if (lhs[i] != rhs[i]) {
            return 0;
        }
    }
    return 1;
}

static inline int purify_cbmc_bytes_eq(const unsigned char* lhs, const unsigned char* rhs, size_t len) {
    size_t i;
    for (i = 0; i < len; ++i) {
        if (lhs[i] != rhs[i]) {
            return 0;
        }
    }
    return 1;
}

static inline int purify_cbmc_u256_shift_left_is_lossless(const uint64_t value[4], size_t shift) {
    size_t i;

    if (shift >= 256u) {
        return 0;
    }

    for (i = 256u - shift; i < 256u; ++i) {
        const size_t word = i / 64u;
        const size_t bit = i % 64u;
        if (((value[word] >> bit) & UINT64_C(1)) != 0) {
            return 0;
        }
    }

    return 1;
}

static inline int purify_cbmc_any_high_words_nonzero(const uint64_t* value, size_t first_high_word, size_t words) {
    size_t i;
    for (i = first_high_word; i < words; ++i) {
        if (value[i] != 0) {
            return 1;
        }
    }
    return 0;
}
