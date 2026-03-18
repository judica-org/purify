// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include "purify/common.hpp"

namespace purify {

template <std::size_t Words>
struct BigUInt {
    std::array<std::uint64_t, Words> limbs{};

    static BigUInt zero() {
        return {};
    }

    static BigUInt one() {
        BigUInt out;
        out.limbs[0] = 1;
        return out;
    }

    static BigUInt from_u64(std::uint64_t value) {
        BigUInt out;
        out.limbs[0] = value;
        return out;
    }

    static BigUInt from_bytes_be(const unsigned char* data, std::size_t size) {
        BigUInt out;
        for (std::size_t i = 0; i < size; ++i) {
            out.mul_small(256);
            out.add_small(data[i]);
        }
        return out;
    }

    static BigUInt from_hex(std::string_view hex) {
        BigUInt out;
        if (hex.size() >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) {
            hex.remove_prefix(2);
        }
        for (char ch : hex) {
            if (std::isspace(static_cast<unsigned char>(ch)) != 0) {
                continue;
            }
            unsigned value;
            if (ch >= '0' && ch <= '9') {
                value = static_cast<unsigned>(ch - '0');
            } else if (ch >= 'a' && ch <= 'f') {
                value = static_cast<unsigned>(10 + ch - 'a');
            } else if (ch >= 'A' && ch <= 'F') {
                value = static_cast<unsigned>(10 + ch - 'A');
            } else {
                throw std::runtime_error("Invalid hex character");
            }
            out.mul_small(16);
            out.add_small(value);
        }
        return out;
    }

    bool is_zero() const {
        for (std::uint64_t limb : limbs) {
            if (limb != 0) {
                return false;
            }
        }
        return true;
    }

    int compare(const BigUInt& other) const {
        for (std::size_t i = Words; i-- > 0;) {
            if (limbs[i] < other.limbs[i]) {
                return -1;
            }
            if (limbs[i] > other.limbs[i]) {
                return 1;
            }
        }
        return 0;
    }

    bool operator==(const BigUInt& other) const {
        return limbs == other.limbs;
    }

    bool operator!=(const BigUInt& other) const {
        return !(*this == other);
    }

    bool operator<(const BigUInt& other) const {
        return compare(other) < 0;
    }

    bool operator>=(const BigUInt& other) const {
        return compare(other) >= 0;
    }

    void add_small(std::uint32_t value) {
        unsigned __int128 carry = value;
        for (std::size_t i = 0; i < Words && carry != 0; ++i) {
            carry += limbs[i];
            limbs[i] = static_cast<std::uint64_t>(carry);
            carry >>= 64;
        }
        if (carry != 0) {
            throw std::runtime_error("BigUInt overflow");
        }
    }

    void mul_small(std::uint32_t value) {
        unsigned __int128 carry = 0;
        for (std::size_t i = 0; i < Words; ++i) {
            unsigned __int128 accum = static_cast<unsigned __int128>(limbs[i]) * value + carry;
            limbs[i] = static_cast<std::uint64_t>(accum);
            carry = accum >> 64;
        }
        if (carry != 0) {
            throw std::runtime_error("BigUInt overflow");
        }
    }

    void add_assign(const BigUInt& other) {
        unsigned __int128 carry = 0;
        for (std::size_t i = 0; i < Words; ++i) {
            unsigned __int128 accum = static_cast<unsigned __int128>(limbs[i]) + other.limbs[i] + carry;
            limbs[i] = static_cast<std::uint64_t>(accum);
            carry = accum >> 64;
        }
        if (carry != 0) {
            throw std::runtime_error("BigUInt overflow");
        }
    }

    void sub_assign(const BigUInt& other) {
        std::uint64_t borrow = 0;
        for (std::size_t i = 0; i < Words; ++i) {
            std::uint64_t rhs = other.limbs[i] + borrow;
            std::uint64_t next_borrow = borrow ? (rhs <= other.limbs[i] ? 1U : 0U) : 0U;
            if (limbs[i] < rhs) {
                limbs[i] = static_cast<std::uint64_t>((static_cast<unsigned __int128>(1) << 64) + limbs[i] - rhs);
                borrow = 1;
            } else {
                limbs[i] -= rhs;
                borrow = next_borrow;
            }
        }
        if (borrow != 0) {
            throw std::runtime_error("BigUInt underflow");
        }
    }

    std::size_t bit_length() const {
        for (std::size_t i = Words; i-- > 0;) {
            if (limbs[i] != 0) {
                return i * 64 + (64U - static_cast<std::size_t>(__builtin_clzll(limbs[i])));
            }
        }
        return 0;
    }

    bool bit(std::size_t index) const {
        std::size_t word = index / 64;
        std::size_t shift = index % 64;
        if (word >= Words) {
            return false;
        }
        return ((limbs[word] >> shift) & 1U) != 0;
    }

    void set_bit(std::size_t index) {
        std::size_t word = index / 64;
        std::size_t shift = index % 64;
        if (word >= Words) {
            throw std::runtime_error("Bit index out of range");
        }
        limbs[word] |= (static_cast<std::uint64_t>(1) << shift);
    }

    BigUInt shifted_left(std::size_t bits) const {
        BigUInt out;
        std::size_t word_shift = bits / 64;
        std::size_t bit_shift = bits % 64;
        for (std::size_t i = Words; i-- > 0;) {
            if (i < word_shift) {
                continue;
            }
            std::size_t src = i - word_shift;
            out.limbs[i] |= limbs[src] << bit_shift;
            if (bit_shift != 0 && src > 0) {
                out.limbs[i] |= limbs[src - 1] >> (64 - bit_shift);
            }
        }
        return out;
    }

    BigUInt shifted_right(std::size_t bits) const {
        BigUInt out;
        std::size_t word_shift = bits / 64;
        std::size_t bit_shift = bits % 64;
        for (std::size_t i = 0; i < Words; ++i) {
            std::size_t src = i + word_shift;
            if (src >= Words) {
                break;
            }
            out.limbs[i] |= limbs[src] >> bit_shift;
            if (bit_shift != 0 && src + 1 < Words) {
                out.limbs[i] |= limbs[src + 1] << (64 - bit_shift);
            }
        }
        return out;
    }

    void shift_right_one() {
        for (std::size_t i = 0; i < Words; ++i) {
            std::uint64_t next = (i + 1 < Words) ? limbs[i + 1] : 0;
            limbs[i] = (limbs[i] >> 1) | (next << 63);
        }
    }

    void mask_bits(std::size_t bits) {
        std::size_t full_words = bits / 64;
        std::size_t extra_bits = bits % 64;
        for (std::size_t i = full_words + (extra_bits != 0 ? 1 : 0); i < Words; ++i) {
            limbs[i] = 0;
        }
        if (extra_bits != 0 && full_words < Words) {
            std::uint64_t mask = (extra_bits == 64) ? ~static_cast<std::uint64_t>(0) : ((static_cast<std::uint64_t>(1) << extra_bits) - 1);
            limbs[full_words] &= mask;
        }
    }

    std::uint32_t divmod_small(std::uint32_t divisor) {
        unsigned __int128 rem = 0;
        for (std::size_t i = Words; i-- > 0;) {
            unsigned __int128 cur = (rem << 64) | limbs[i];
            limbs[i] = static_cast<std::uint64_t>(cur / divisor);
            rem = cur % divisor;
        }
        return static_cast<std::uint32_t>(rem);
    }

    std::array<unsigned char, Words * 8> to_bytes_be() const {
        std::array<unsigned char, Words * 8> out{};
        for (std::size_t i = 0; i < Words; ++i) {
            std::uint64_t limb = limbs[i];
            for (std::size_t j = 0; j < 8; ++j) {
                out[out.size() - 1 - (i * 8 + j)] = static_cast<unsigned char>(limb & 0xffU);
                limb >>= 8;
            }
        }
        return out;
    }

    std::string to_hex() const {
        auto bytes = to_bytes_be();
        std::ostringstream out;
        bool started = false;
        out << std::hex << std::nouppercase;
        for (unsigned char byte : bytes) {
            if (!started) {
                if (byte == 0) {
                    continue;
                }
                out << static_cast<unsigned>(byte);
                started = true;
            } else {
                out << std::setw(2) << std::setfill('0') << static_cast<unsigned>(byte);
            }
        }
        return started ? out.str() : "0";
    }

    std::string to_decimal() const {
        if (is_zero()) {
            return "0";
        }
        BigUInt copy = *this;
        std::vector<std::uint32_t> parts;
        while (!copy.is_zero()) {
            parts.push_back(copy.divmod_small(1000000000U));
        }
        std::ostringstream out;
        out << parts.back();
        for (std::size_t i = parts.size() - 1; i-- > 0;) {
            out << std::setw(9) << std::setfill('0') << parts[i];
        }
        return out.str();
    }
};

template <std::size_t OutWords, std::size_t InWords>
BigUInt<OutWords> widen(const BigUInt<InWords>& value) {
    static_assert(OutWords >= InWords, "Cannot narrow with widen");
    BigUInt<OutWords> out;
    for (std::size_t i = 0; i < InWords; ++i) {
        out.limbs[i] = value.limbs[i];
    }
    return out;
}

template <std::size_t OutWords, std::size_t InWords>
BigUInt<OutWords> narrow(const BigUInt<InWords>& value) {
    static_assert(OutWords <= InWords, "Cannot widen with narrow");
    BigUInt<OutWords> out;
    for (std::size_t i = 0; i < OutWords; ++i) {
        out.limbs[i] = value.limbs[i];
    }
    for (std::size_t i = OutWords; i < InWords; ++i) {
        if (value.limbs[i] != 0) {
            throw std::runtime_error("BigUInt narrowing overflow");
        }
    }
    return out;
}

template <std::size_t Words>
std::pair<BigUInt<Words>, BigUInt<Words>> divmod_same(const BigUInt<Words>& numerator, const BigUInt<Words>& denominator) {
    if (denominator.is_zero()) {
        throw std::runtime_error("Division by zero");
    }
    BigUInt<Words> quotient;
    BigUInt<Words> remainder = numerator;
    std::size_t n_bits = remainder.bit_length();
    std::size_t d_bits = denominator.bit_length();
    if (n_bits < d_bits) {
        return {quotient, remainder};
    }
    std::size_t shift = n_bits - d_bits;
    BigUInt<Words> shifted = denominator.shifted_left(shift);
    for (std::size_t i = shift + 1; i-- > 0;) {
        if (remainder.compare(shifted) >= 0) {
            remainder.sub_assign(shifted);
            quotient.set_bit(i);
        }
        if (i != 0) {
            shifted.shift_right_one();
        }
    }
    return {quotient, remainder};
}

template <std::size_t LeftWords, std::size_t RightWords>
BigUInt<LeftWords + RightWords> multiply(const BigUInt<LeftWords>& lhs, const BigUInt<RightWords>& rhs) {
    BigUInt<LeftWords + RightWords> out;
    for (std::size_t i = 0; i < LeftWords; ++i) {
        unsigned __int128 carry = 0;
        for (std::size_t j = 0; j < RightWords; ++j) {
            unsigned __int128 accum = static_cast<unsigned __int128>(lhs.limbs[i]) * rhs.limbs[j]
                + out.limbs[i + j] + carry;
            out.limbs[i + j] = static_cast<std::uint64_t>(accum);
            carry = accum >> 64;
        }
        out.limbs[i + RightWords] += static_cast<std::uint64_t>(carry);
    }
    return out;
}

using UInt256 = BigUInt<4>;
using UInt320 = BigUInt<5>;
using UInt512 = BigUInt<8>;

class FieldElement;

inline const UInt256& prime_p();
FieldElement square(const FieldElement& value);
int legendre_symbol(const FieldElement& value);

class FieldElement {
public:
    FieldElement() {
        purify_scalar_set_int(&value_, 0);
    }

    static FieldElement zero() {
        return FieldElement();
    }

    static FieldElement one() {
        return from_u64(1);
    }

    static FieldElement from_u64(std::uint64_t value) {
        FieldElement out;
        purify_scalar_set_u64(&out.value_, value);
        return out;
    }

    static FieldElement from_int(std::int64_t value) {
        if (value >= 0) {
            return from_u64(static_cast<std::uint64_t>(value));
        }
        return from_u64(static_cast<std::uint64_t>(-value)).negate();
    }

    static FieldElement from_bytes32(const std::array<unsigned char, 32>& bytes) {
        FieldElement out;
        int overflow = 0;
        purify_scalar_set_b32(&out.value_, bytes.data(), &overflow);
        return out;
    }

    static FieldElement from_uint256(const UInt256& value) {
        return from_bytes32(narrow<4>(widen<4>(value)).to_bytes_be());
    }

    UInt256 to_uint256() const {
        std::array<unsigned char, 32> bytes = to_bytes_be();
        return UInt256::from_bytes_be(bytes.data(), bytes.size());
    }

    std::array<unsigned char, 32> to_bytes_be() const {
        std::array<unsigned char, 32> bytes{};
        purify_scalar_get_b32(bytes.data(), &value_);
        return bytes;
    }

    std::array<unsigned char, 32> to_bytes_le() const {
        std::array<unsigned char, 32> bytes = to_bytes_be();
        std::reverse(bytes.begin(), bytes.end());
        return bytes;
    }

    std::string to_hex() const {
        return to_uint256().to_hex();
    }

    std::string to_decimal() const {
        return to_uint256().to_decimal();
    }

    bool is_zero() const {
        return purify_scalar_is_zero(&value_) != 0;
    }

    bool is_one() const {
        return purify_scalar_is_one(&value_) != 0;
    }

    bool is_odd() const {
        return purify_scalar_is_even(&value_) == 0;
    }

    bool is_square() const {
        if (is_zero()) {
            return true;
        }
        UInt256 exponent = prime_p();
        exponent.sub_assign(UInt256::one());
        exponent = exponent.shifted_right(1);
        FieldElement result = pow(exponent);
        return result.is_one();
    }

    FieldElement negate() const {
        FieldElement out;
        purify_scalar_negate(&out.value_, &value_);
        return out;
    }

    FieldElement inverse() const {
        FieldElement out;
        purify_scalar_inverse_var(&out.value_, &value_);
        return out;
    }

    std::optional<FieldElement> sqrt() const {
        if (is_zero()) {
            return std::nullopt;
        }
        if (!is_square()) {
            return std::nullopt;
        }
        UInt256 q = prime_p();
        q.sub_assign(UInt256::one());
        unsigned s = 0;
        while (!q.bit(0)) {
            q = q.shifted_right(1);
            ++s;
        }
        if (s == 1) {
            UInt256 exponent = q;
            exponent.add_small(1);
            exponent = exponent.shifted_right(1);
            return pow(exponent);
        }
        FieldElement z = FieldElement::from_u64(2);
        while (legendre_symbol(z) != -1) {
            z = z + FieldElement::one();
        }
        FieldElement c = z.pow(q);
        UInt256 exponent = q;
        exponent.add_small(1);
        exponent = exponent.shifted_right(1);
        FieldElement x = pow(exponent);
        FieldElement t = pow(q);
        unsigned m = s;
        while (t != FieldElement::one()) {
            unsigned i = 1;
            FieldElement t2i = square(t);
            while (i < m && t2i != FieldElement::one()) {
                t2i = square(t2i);
                ++i;
            }
            if (i == m) {
                return std::nullopt;
            }
            UInt256 b_exp = UInt256::one();
            b_exp = b_exp.shifted_left(m - i - 1);
            FieldElement b = c.pow(b_exp);
            x = x * b;
            FieldElement b2 = square(b);
            t = t * b2;
            c = b2;
            m = i;
        }
        return x;
    }

    FieldElement pow(const UInt256& exponent) const {
        FieldElement result = one();
        std::size_t bits = exponent.bit_length();
        for (std::size_t i = bits; i-- > 0;) {
            result = result * result;
            if (exponent.bit(i)) {
                result = result * *this;
            }
        }
        return result;
    }

    friend bool operator==(const FieldElement& lhs, const FieldElement& rhs) {
        return purify_scalar_eq(&lhs.value_, &rhs.value_) != 0;
    }

    friend bool operator!=(const FieldElement& lhs, const FieldElement& rhs) {
        return !(lhs == rhs);
    }

    friend FieldElement operator+(const FieldElement& lhs, const FieldElement& rhs) {
        FieldElement out;
        purify_scalar_add(&out.value_, &lhs.value_, &rhs.value_);
        return out;
    }

    friend FieldElement operator-(const FieldElement& lhs, const FieldElement& rhs) {
        return lhs + rhs.negate();
    }

    friend FieldElement operator*(const FieldElement& lhs, const FieldElement& rhs) {
        FieldElement out;
        purify_scalar_mul(&out.value_, &lhs.value_, &rhs.value_);
        return out;
    }

private:
    explicit FieldElement(const purify_scalar& raw) : value_(raw) {}

    purify_scalar value_{};
};

inline FieldElement square(const FieldElement& value) {
    return value * value;
}

inline int legendre_symbol(const FieldElement& value) {
    if (value.is_zero()) {
        return 0;
    }
    return value.is_square() ? 1 : -1;
}

}  // namespace purify
