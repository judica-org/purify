// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "purify/uint.h"

#include <assert.h>
#include <string.h>

static size_t purify_uint_bit_length_u64(uint64_t value) {
    if (value == 0) {
        return 0;
    }
#if defined(__GNUC__) || defined(__clang__)
    return 64u - (size_t)__builtin_clzll(value);
#else
    size_t bits = 0;
    while (value != 0) {
        value >>= 1;
        ++bits;
    }
    return bits;
#endif
}

static uint64_t purify_uint_mul_u64(uint64_t lhs, uint64_t rhs, uint64_t* hi) {
#if defined(__SIZEOF_INT128__) && !defined(_MSC_VER)
    unsigned __int128 value = (unsigned __int128)lhs * (unsigned __int128)rhs;
    *hi = (uint64_t)(value >> 64);
    return (uint64_t)value;
#else
    const uint64_t mask32 = 0xffffffffULL;
    uint64_t lhs_lo = lhs & mask32;
    uint64_t lhs_hi = lhs >> 32;
    uint64_t rhs_lo = rhs & mask32;
    uint64_t rhs_hi = rhs >> 32;
    uint64_t lo_lo = lhs_lo * rhs_lo;
    uint64_t hi_lo = lhs_hi * rhs_lo;
    uint64_t lo_hi = lhs_lo * rhs_hi;
    uint64_t hi_hi = lhs_hi * rhs_hi;
    uint64_t cross = (lo_lo >> 32) + (hi_lo & mask32) + (lo_hi & mask32);
    *hi = hi_hi + (hi_lo >> 32) + (lo_hi >> 32) + (cross >> 32);
    return (lo_lo & mask32) | (cross << 32);
#endif
}

static uint64_t purify_uint_add_u64_carry(uint64_t value, uint64_t addend, uint64_t* hi) {
#if defined(__SIZEOF_INT128__) && !defined(_MSC_VER)
    unsigned __int128 accum = (unsigned __int128)value + (unsigned __int128)addend + ((unsigned __int128)(*hi) << 64);
    *hi = (uint64_t)(accum >> 64);
    return (uint64_t)accum;
#else
    uint64_t out = value + addend;
    *hi += out < value ? 1u : 0u;
    return out;
#endif
}

static uint64_t purify_uint_mask_u64(int flag) {
    return (uint64_t)0 - (uint64_t)(flag != 0);
}

static int purify_u512_is_nonzero_ct(const uint64_t value[8]) {
    uint64_t acc = 0;
    size_t i;
    for (i = 0; i < 8u; ++i) {
        acc |= value[i];
    }
    return acc != 0;
}

static void purify_u512_shift_left_one_or_bit(uint64_t value[8], uint64_t bit) {
    uint64_t carry = bit & 1u;
    size_t i;
    for (i = 0; i < 8u; ++i) {
        uint64_t next = value[i] >> 63;
        value[i] = (value[i] << 1) | carry;
        carry = next;
    }
}

static uint64_t purify_u512_sub_with_borrow_ct(uint64_t out[8], const uint64_t lhs[8], const uint64_t rhs[8]) {
    uint64_t borrow = 0;
    size_t i;
    for (i = 0; i < 8u; ++i) {
        uint64_t rhs_word = rhs[i] + borrow;
        uint64_t rhs_overflow = rhs_word < rhs[i] ? 1u : 0u;
        uint64_t diff = lhs[i] - rhs_word;
        uint64_t needs_borrow = lhs[i] < rhs_word ? 1u : 0u;
        out[i] = diff;
        borrow = rhs_overflow | needs_borrow;
    }
    return borrow;
}

static void purify_u512_cmov_words(uint64_t dst[8], const uint64_t src[8], uint64_t mask) {
    size_t i;
    for (i = 0; i < 8u; ++i) {
        dst[i] ^= mask & (dst[i] ^ src[i]);
    }
}

static uint64_t purify_uint_divmod_u32(uint64_t hi, uint64_t lo, uint32_t divisor, uint32_t* rem_out) {
#if defined(__SIZEOF_INT128__) && !defined(_MSC_VER)
    unsigned __int128 value = ((unsigned __int128)hi << 64) | lo;
    uint64_t quotient = (uint64_t)(value / divisor);
    *rem_out = (uint32_t)(value % divisor);
    return quotient;
#else
    const uint64_t mask32 = 0xffffffffULL;
    uint64_t rem = hi;
    uint32_t q3;
    uint32_t q2;
    uint32_t q1;
    uint32_t q0;
    uint64_t cur;

    cur = (rem << 32) | (lo >> 32);
    q1 = (uint32_t)(cur / divisor);
    rem = cur % divisor;
    cur = (rem << 32) | (lo & mask32);
    q0 = (uint32_t)(cur / divisor);
    rem = cur % divisor;

    q3 = 0;
    q2 = (uint32_t)(hi & mask32);
    (void)q3;
    (void)q2;
    *rem_out = (uint32_t)rem;
    return ((uint64_t)q1 << 32) | q0;
#endif
}

#define PURIFY_UINT_FN(name) purify_u256_##name
#define PURIFY_UINT_WORDS 4
#include "uint_impl.h"
#undef PURIFY_UINT_WORDS
#undef PURIFY_UINT_FN

#define PURIFY_UINT_FN(name) purify_u320_##name
#define PURIFY_UINT_WORDS 5
#include "uint_impl.h"
#undef PURIFY_UINT_WORDS
#undef PURIFY_UINT_FN

#define PURIFY_UINT_FN(name) purify_u512_##name
#define PURIFY_UINT_WORDS 8
#include "uint_impl.h"
#undef PURIFY_UINT_WORDS
#undef PURIFY_UINT_FN

void purify_u320_widen_u256(uint64_t out[5], const uint64_t value[4]) {
    purify_u320_set_zero(out);
    memcpy(out, value, 4 * sizeof(uint64_t));
}

void purify_u512_widen_u256(uint64_t out[8], const uint64_t value[4]) {
    purify_u512_set_zero(out);
    memcpy(out, value, 4 * sizeof(uint64_t));
}

int purify_u256_try_narrow_u320(uint64_t out[4], const uint64_t value[5]) {
    if (value[4] != 0) {
        return 0;
    }
    memcpy(out, value, 4 * sizeof(uint64_t));
    return 1;
}

int purify_u256_try_narrow_u512(uint64_t out[4], const uint64_t value[8]) {
    size_t i;
    for (i = 4; i < 8; ++i) {
        if (value[i] != 0) {
            return 0;
        }
    }
    memcpy(out, value, 4 * sizeof(uint64_t));
    return 1;
}

int purify_u512_try_divmod_same(uint64_t quotient[8], uint64_t remainder[8],
                                const uint64_t numerator[8], const uint64_t denominator[8]) {
    size_t n_bits;
    size_t d_bits;
    size_t shift;
    uint64_t shifted[8];
    size_t i;

    if (purify_u512_is_zero(denominator)) {
        return 0;
    }

    memcpy(remainder, numerator, 8 * sizeof(uint64_t));
    purify_u512_set_zero(quotient);
    n_bits = purify_u512_bit_length(remainder);
    d_bits = purify_u512_bit_length(denominator);
    if (n_bits < d_bits) {
        return 1;
    }

    shift = n_bits - d_bits;
    purify_u512_shifted_left(shifted, denominator, shift);
    for (i = shift + 1u; i != 0; --i) {
        size_t idx = i - 1u;
        if (purify_u512_compare(remainder, shifted) >= 0) {
            int sub_ok = purify_u512_try_sub(remainder, shifted);
            int bit_ok = purify_u512_try_set_bit(quotient, idx);
            assert(sub_ok != 0);
            assert(bit_ok != 0);
            if (sub_ok == 0 || bit_ok == 0) {
                return 0;
            }
        }
        if (idx != 0) {
            purify_u512_shift_right_one(shifted);
        }
    }

    return 1;
}

int purify_u512_try_divmod_same_consttime(uint64_t quotient[8], uint64_t remainder[8],
                                          const uint64_t numerator[8], const uint64_t denominator[8]) {
    uint64_t candidate[8];
    const uint64_t denominator_mask = purify_uint_mask_u64(purify_u512_is_nonzero_ct(denominator));
    size_t bit_index;

    purify_u512_set_zero(quotient);
    purify_u512_set_zero(remainder);
    for (bit_index = 512u; bit_index != 0; --bit_index) {
        const size_t idx = bit_index - 1u;
        const size_t word = idx / 64u;
        const size_t shift = idx % 64u;
        const uint64_t quotient_bit = (uint64_t)1u << shift;
        const uint64_t next_bit = (numerator[word] >> shift) & 1u;
        uint64_t borrow;

        purify_u512_shift_left_one_or_bit(remainder, next_bit);
        borrow = purify_u512_sub_with_borrow_ct(candidate, remainder, denominator);
        {
            const uint64_t ge_mask = purify_uint_mask_u64(borrow == 0u);
            purify_u512_cmov_words(remainder, candidate, ge_mask);
            quotient[word] |= ge_mask & quotient_bit;
        }
    }

    return denominator_mask != 0;
}

void purify_u512_multiply_u256(uint64_t out[8], const uint64_t lhs[4], const uint64_t rhs[4]) {
    size_t i;
    purify_u512_set_zero(out);
    for (i = 0; i < 4; ++i) {
        uint64_t carry = 0;
        size_t j;
        for (j = 0; j < 4; ++j) {
            uint64_t hi = 0;
            uint64_t lo = purify_uint_mul_u64(lhs[i], rhs[j], &hi);
            lo = purify_uint_add_u64_carry(lo, out[i + j], &hi);
            lo = purify_uint_add_u64_carry(lo, carry, &hi);
            out[i + j] = lo;
            carry = hi;
        }
        out[i + 4] += carry;
    }
}
