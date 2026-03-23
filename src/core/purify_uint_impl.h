// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef PURIFY_UINT_FN
#error "PURIFY_UINT_FN must be defined before including purify_uint_impl.h"
#endif

#ifndef PURIFY_UINT_WORDS
#error "PURIFY_UINT_WORDS must be defined before including purify_uint_impl.h"
#endif

int PURIFY_UINT_FN(try_add_small)(uint64_t value[PURIFY_UINT_WORDS], uint32_t addend);
int PURIFY_UINT_FN(try_mul_small)(uint64_t value[PURIFY_UINT_WORDS], uint32_t factor);

void PURIFY_UINT_FN(set_zero)(uint64_t out[PURIFY_UINT_WORDS]) {
    size_t i;
    for (i = 0; i < PURIFY_UINT_WORDS; ++i) {
        out[i] = 0;
    }
}

void PURIFY_UINT_FN(set_u64)(uint64_t out[PURIFY_UINT_WORDS], uint64_t value) {
    PURIFY_UINT_FN(set_zero)(out);
    out[0] = value;
}

void PURIFY_UINT_FN(from_bytes_be)(uint64_t out[PURIFY_UINT_WORDS], const unsigned char* data, size_t size) {
    size_t i;
    PURIFY_UINT_FN(set_zero)(out);
    for (i = 0; i < size; ++i) {
        int ok = PURIFY_UINT_FN(try_mul_small)(out, 256);
        ok = ok && PURIFY_UINT_FN(try_add_small)(out, data[i]);
        assert(ok != 0);
    }
}

int PURIFY_UINT_FN(is_zero)(const uint64_t value[PURIFY_UINT_WORDS]) {
    size_t i;
    for (i = 0; i < PURIFY_UINT_WORDS; ++i) {
        if (value[i] != 0) {
            return 0;
        }
    }
    return 1;
}

int PURIFY_UINT_FN(compare)(const uint64_t lhs[PURIFY_UINT_WORDS], const uint64_t rhs[PURIFY_UINT_WORDS]) {
    size_t i;
    for (i = PURIFY_UINT_WORDS; i-- > 0;) {
        if (lhs[i] < rhs[i]) {
            return -1;
        }
        if (lhs[i] > rhs[i]) {
            return 1;
        }
    }
    return 0;
}

int PURIFY_UINT_FN(try_add_small)(uint64_t value[PURIFY_UINT_WORDS], uint32_t addend) {
    uint64_t carry = addend;
    size_t i;
    for (i = 0; i < PURIFY_UINT_WORDS && carry != 0; ++i) {
        uint64_t sum = value[i] + carry;
        carry = sum < value[i] ? 1u : 0u;
        value[i] = sum;
    }
    return carry == 0;
}

int PURIFY_UINT_FN(try_mul_small)(uint64_t value[PURIFY_UINT_WORDS], uint32_t factor) {
    uint64_t carry = 0;
    size_t i;
    for (i = 0; i < PURIFY_UINT_WORDS; ++i) {
        uint64_t hi = 0;
        uint64_t lo = purify_uint_mul_u64(value[i], factor, &hi);
        lo = purify_uint_add_u64_carry(lo, carry, &hi);
        value[i] = lo;
        carry = hi;
    }
    return carry == 0;
}

int PURIFY_UINT_FN(try_add)(uint64_t value[PURIFY_UINT_WORDS], const uint64_t addend[PURIFY_UINT_WORDS]) {
    uint64_t carry = 0;
    size_t i;
    for (i = 0; i < PURIFY_UINT_WORDS; ++i) {
        uint64_t sum = value[i] + addend[i];
        uint64_t carry1 = sum < value[i] ? 1u : 0u;
        uint64_t next = sum + carry;
        uint64_t carry2 = next < sum ? 1u : 0u;
        value[i] = next;
        carry = carry1 | carry2;
    }
    return carry == 0;
}

int PURIFY_UINT_FN(try_sub)(uint64_t value[PURIFY_UINT_WORDS], const uint64_t subtrahend[PURIFY_UINT_WORDS]) {
    uint64_t borrow = 0;
    size_t i;
    for (i = 0; i < PURIFY_UINT_WORDS; ++i) {
        uint64_t rhs = subtrahend[i] + borrow;
        uint64_t rhs_overflow = rhs < subtrahend[i] ? 1u : 0u;
        uint64_t next = value[i] - rhs;
        uint64_t needs_borrow = value[i] < rhs ? 1u : 0u;
        value[i] = next;
        borrow = rhs_overflow | needs_borrow;
    }
    return borrow == 0;
}

size_t PURIFY_UINT_FN(bit_length)(const uint64_t value[PURIFY_UINT_WORDS]) {
    size_t i;
    for (i = PURIFY_UINT_WORDS; i-- > 0;) {
        if (value[i] != 0) {
            return i * 64u + purify_uint_bit_length_u64(value[i]);
        }
    }
    return 0;
}

int PURIFY_UINT_FN(bit)(const uint64_t value[PURIFY_UINT_WORDS], size_t index) {
    size_t word = index / 64u;
    size_t shift = index % 64u;
    if (word >= PURIFY_UINT_WORDS) {
        return 0;
    }
    return ((value[word] >> shift) & 1u) != 0;
}

int PURIFY_UINT_FN(try_set_bit)(uint64_t value[PURIFY_UINT_WORDS], size_t index) {
    size_t word = index / 64u;
    size_t shift = index % 64u;
    if (word >= PURIFY_UINT_WORDS) {
        return 0;
    }
    value[word] |= ((uint64_t)1u << shift);
    return 1;
}

void PURIFY_UINT_FN(shifted_left)(uint64_t out[PURIFY_UINT_WORDS], const uint64_t value[PURIFY_UINT_WORDS], size_t bits) {
    size_t word_shift = bits / 64u;
    size_t bit_shift = bits % 64u;
    size_t i;
    PURIFY_UINT_FN(set_zero)(out);
    for (i = PURIFY_UINT_WORDS; i-- > 0;) {
        size_t src;
        if (i < word_shift) {
            continue;
        }
        src = i - word_shift;
        out[i] |= value[src] << bit_shift;
        if (bit_shift != 0 && src > 0) {
            out[i] |= value[src - 1] >> (64u - bit_shift);
        }
    }
}

void PURIFY_UINT_FN(shifted_right)(uint64_t out[PURIFY_UINT_WORDS], const uint64_t value[PURIFY_UINT_WORDS], size_t bits) {
    size_t word_shift = bits / 64u;
    size_t bit_shift = bits % 64u;
    size_t i;
    PURIFY_UINT_FN(set_zero)(out);
    for (i = 0; i < PURIFY_UINT_WORDS; ++i) {
        size_t src = i + word_shift;
        if (src >= PURIFY_UINT_WORDS) {
            break;
        }
        out[i] |= value[src] >> bit_shift;
        if (bit_shift != 0 && src + 1 < PURIFY_UINT_WORDS) {
            out[i] |= value[src + 1] << (64u - bit_shift);
        }
    }
}

void PURIFY_UINT_FN(shift_right_one)(uint64_t value[PURIFY_UINT_WORDS]) {
    size_t i;
    for (i = 0; i < PURIFY_UINT_WORDS; ++i) {
        uint64_t next = i + 1 < PURIFY_UINT_WORDS ? value[i + 1] : 0;
        value[i] = (value[i] >> 1) | (next << 63);
    }
}

void PURIFY_UINT_FN(mask_bits)(uint64_t value[PURIFY_UINT_WORDS], size_t bits) {
    const size_t total_bits = PURIFY_UINT_WORDS * 64u;
    const size_t full_words = bits / 64u;
    const size_t extra_bits = bits % 64u;
    size_t i;
    if (bits >= total_bits) {
        return;
    }
    for (i = full_words + (extra_bits != 0 ? 1u : 0u); i < PURIFY_UINT_WORDS; ++i) {
        value[i] = 0;
    }
    if (extra_bits != 0 && full_words < PURIFY_UINT_WORDS) {
        uint64_t mask = ((uint64_t)1u << extra_bits) - 1u;
        value[full_words] &= mask;
    }
}

uint32_t PURIFY_UINT_FN(divmod_small)(uint64_t value[PURIFY_UINT_WORDS], uint32_t divisor) {
    uint64_t rem = 0;
    size_t i;
    assert(divisor != 0);
    for (i = PURIFY_UINT_WORDS; i-- > 0;) {
        uint32_t next_rem = 0;
        uint64_t quotient = purify_uint_divmod_u32(rem, value[i], divisor, &next_rem);
        value[i] = quotient;
        rem = next_rem;
    }
    return (uint32_t)rem;
}

void PURIFY_UINT_FN(to_bytes_be)(unsigned char out[PURIFY_UINT_WORDS * 8], const uint64_t value[PURIFY_UINT_WORDS]) {
    size_t i;
    for (i = 0; i < PURIFY_UINT_WORDS; ++i) {
        uint64_t limb = value[i];
        size_t j;
        for (j = 0; j < 8u; ++j) {
            out[PURIFY_UINT_WORDS * 8u - 1u - (i * 8u + j)] = (unsigned char)(limb & 0xffu);
            limb >>= 8;
        }
    }
}
