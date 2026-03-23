// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file uint.h
 * @brief Fixed-width unsigned integer helpers implemented in C for Purify.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PURIFY_DECLARE_UINT_FUNCS(width, words) \
    void purify_u##width##_set_zero(uint64_t out[words]); \
    void purify_u##width##_set_u64(uint64_t out[words], uint64_t value); \
    void purify_u##width##_from_bytes_be(uint64_t out[words], const unsigned char* data, size_t size); \
    int purify_u##width##_is_zero(const uint64_t value[words]); \
    int purify_u##width##_compare(const uint64_t lhs[words], const uint64_t rhs[words]); \
    int purify_u##width##_try_add_small(uint64_t value[words], uint32_t addend); \
    int purify_u##width##_try_mul_small(uint64_t value[words], uint32_t factor); \
    int purify_u##width##_try_add(uint64_t value[words], const uint64_t addend[words]); \
    int purify_u##width##_try_sub(uint64_t value[words], const uint64_t subtrahend[words]); \
    size_t purify_u##width##_bit_length(const uint64_t value[words]); \
    int purify_u##width##_bit(const uint64_t value[words], size_t index); \
    int purify_u##width##_try_set_bit(uint64_t value[words], size_t index); \
    void purify_u##width##_shifted_left(uint64_t out[words], const uint64_t value[words], size_t shift_bits); \
    void purify_u##width##_shifted_right(uint64_t out[words], const uint64_t value[words], size_t shift_bits); \
    void purify_u##width##_shift_right_one(uint64_t value[words]); \
    void purify_u##width##_mask_bits(uint64_t value[words], size_t keep_bits); \
    uint32_t purify_u##width##_divmod_small(uint64_t value[words], uint32_t divisor); \
    void purify_u##width##_to_bytes_be(unsigned char out[words * 8], const uint64_t value[words])

PURIFY_DECLARE_UINT_FUNCS(256, 4);
PURIFY_DECLARE_UINT_FUNCS(320, 5);
PURIFY_DECLARE_UINT_FUNCS(512, 8);

#undef PURIFY_DECLARE_UINT_FUNCS

void purify_u320_widen_u256(uint64_t out[5], const uint64_t value[4]);
void purify_u512_widen_u256(uint64_t out[8], const uint64_t value[4]);
int purify_u256_try_narrow_u320(uint64_t out[4], const uint64_t value[5]);
int purify_u256_try_narrow_u512(uint64_t out[4], const uint64_t value[8]);
int purify_u512_try_divmod_same(uint64_t quotient[8], uint64_t remainder[8],
                                const uint64_t numerator[8], const uint64_t denominator[8]);
void purify_u512_multiply_u256(uint64_t out[8], const uint64_t lhs[4], const uint64_t rhs[4]);

#ifdef __cplusplus
}
#endif
