// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file numeric.hpp
 * @brief Fixed-width integer and field arithmetic helpers used throughout Purify.
 */

#pragma once

#include "purify/common.hpp"

namespace purify {

/**
 * @brief Little-endian fixed-width unsigned integer with simple arithmetic utilities.
 *
 * @tparam Words Number of 64-bit limbs stored in the integer.
 */
template <std::size_t Words>
struct BigUInt {
    std::array<std::uint64_t, Words> limbs{};

    /** @brief Returns the additive identity. */
    static BigUInt zero() {
        return {};
    }

    /** @brief Returns the multiplicative identity. */
    static BigUInt one() {
        BigUInt out;
        out.limbs[0] = 1;
        return out;
    }

    /** @brief Constructs a value from a single 64-bit limb. */
    static BigUInt from_u64(std::uint64_t value) {
        BigUInt out;
        out.limbs[0] = value;
        return out;
    }

    /** @brief Parses a big-endian byte string into the fixed-width integer. */
    static BigUInt from_bytes_be(const unsigned char* data, std::size_t size) {
        BigUInt out;
        for (std::size_t i = 0; i < size; ++i) {
            out.mul_small(256);
            out.add_small(data[i]);
        }
        return out;
    }

    /** @brief Parses a hexadecimal string, ignoring optional `0x` and whitespace. */
    static Result<BigUInt> try_from_hex(std::string_view hex) {
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
                return unexpected_error(ErrorCode::InvalidHex, "BigUInt::try_from_hex:invalid_digit");
            }
            if (!out.try_mul_small(16) || !out.try_add_small(value)) {
                return unexpected_error(ErrorCode::Overflow, "BigUInt::try_from_hex:overflow");
            }
        }
        return out;
    }

    /**
     * @brief Parses a hexadecimal string with the precondition that the value fits exactly.
     *
     * Call `try_from_hex()` when the input may be user-controlled.
     */
    static BigUInt from_hex(std::string_view hex) {
        Result<BigUInt> out = try_from_hex(hex);
        assert(out.has_value() && "BigUInt::from_hex() requires valid in-range input");
        return std::move(*out);
    }

    /** @brief Returns true when all limbs are zero. */
    bool is_zero() const {
        for (std::uint64_t limb : limbs) {
            if (limb != 0) {
                return false;
            }
        }
        return true;
    }

    /** @brief Compares two fixed-width integers using unsigned ordering. */
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

    /** @brief Adds a small unsigned value in place when the result fits. */
    bool try_add_small(std::uint32_t value) {
        BigUInt out = *this;
        unsigned __int128 carry = value;
        for (std::size_t i = 0; i < Words && carry != 0; ++i) {
            carry += out.limbs[i];
            out.limbs[i] = static_cast<std::uint64_t>(carry);
            carry >>= 64;
        }
        if (carry != 0) {
            return false;
        }
        *this = out;
        return true;
    }

    /**
     * @brief Adds a small unsigned value in place.
     *
     * Precondition: the sum fits in the fixed-width representation.
     */
    void add_small(std::uint32_t value) {
        bool ok = try_add_small(value);
        assert(ok && "BigUInt::add_small() overflow");
        (void)ok;
    }

    /** @brief Multiplies by a small unsigned value in place when the result fits. */
    bool try_mul_small(std::uint32_t value) {
        BigUInt out = *this;
        unsigned __int128 carry = 0;
        for (std::size_t i = 0; i < Words; ++i) {
            unsigned __int128 accum = static_cast<unsigned __int128>(out.limbs[i]) * value + carry;
            out.limbs[i] = static_cast<std::uint64_t>(accum);
            carry = accum >> 64;
        }
        if (carry != 0) {
            return false;
        }
        *this = out;
        return true;
    }

    /**
     * @brief Multiplies by a small unsigned value in place.
     *
     * Precondition: the product fits in the fixed-width representation.
     */
    void mul_small(std::uint32_t value) {
        bool ok = try_mul_small(value);
        assert(ok && "BigUInt::mul_small() overflow");
        (void)ok;
    }

    /** @brief Adds another fixed-width integer when the result fits. */
    bool try_add_assign(const BigUInt& other) {
        BigUInt out = *this;
        unsigned __int128 carry = 0;
        for (std::size_t i = 0; i < Words; ++i) {
            unsigned __int128 accum = static_cast<unsigned __int128>(out.limbs[i]) + other.limbs[i] + carry;
            out.limbs[i] = static_cast<std::uint64_t>(accum);
            carry = accum >> 64;
        }
        if (carry != 0) {
            return false;
        }
        *this = out;
        return true;
    }

    /**
     * @brief Adds another fixed-width integer in place.
     *
     * Precondition: the sum fits in the fixed-width representation.
     */
    void add_assign(const BigUInt& other) {
        bool ok = try_add_assign(other);
        assert(ok && "BigUInt::add_assign() overflow");
        (void)ok;
    }

    /** @brief Subtracts another fixed-width integer when the minuend is large enough. */
    bool try_sub_assign(const BigUInt& other) {
        BigUInt out = *this;
        std::uint64_t borrow = 0;
        for (std::size_t i = 0; i < Words; ++i) {
            std::uint64_t rhs = other.limbs[i] + borrow;
            std::uint64_t next_borrow = borrow ? (rhs <= other.limbs[i] ? 1U : 0U) : 0U;
            if (out.limbs[i] < rhs) {
                out.limbs[i] = static_cast<std::uint64_t>((static_cast<unsigned __int128>(1) << 64) + out.limbs[i] - rhs);
                borrow = 1;
            } else {
                out.limbs[i] -= rhs;
                borrow = next_borrow;
            }
        }
        if (borrow != 0) {
            return false;
        }
        *this = out;
        return true;
    }

    /**
     * @brief Subtracts another fixed-width integer in place.
     *
     * Precondition: `*this >= other`.
     */
    void sub_assign(const BigUInt& other) {
        bool ok = try_sub_assign(other);
        assert(ok && "BigUInt::sub_assign() underflow");
        (void)ok;
    }

    /** @brief Returns the index of the highest set bit plus one. */
    std::size_t bit_length() const {
        for (std::size_t i = Words; i-- > 0;) {
            if (limbs[i] != 0) {
                return i * 64 + (64U - static_cast<std::size_t>(__builtin_clzll(limbs[i])));
            }
        }
        return 0;
    }

    /** @brief Returns the bit at the given little-endian bit index. */
    bool bit(std::size_t index) const {
        std::size_t word = index / 64;
        std::size_t shift = index % 64;
        if (word >= Words) {
            return false;
        }
        return ((limbs[word] >> shift) & 1U) != 0;
    }

    /** @brief Sets the bit at the given little-endian bit index when it is in range. */
    bool try_set_bit(std::size_t index) {
        std::size_t word = index / 64;
        std::size_t shift = index % 64;
        if (word >= Words) {
            return false;
        }
        limbs[word] |= (static_cast<std::uint64_t>(1) << shift);
        return true;
    }

    /**
     * @brief Sets the bit at the given little-endian bit index.
     *
     * Precondition: `index < Words * 64`.
     */
    void set_bit(std::size_t index) {
        bool ok = try_set_bit(index);
        assert(ok && "BigUInt::set_bit() index out of range");
        (void)ok;
    }

    /** @brief Returns a copy shifted left by the requested bit count. */
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

    /** @brief Returns a copy shifted right by the requested bit count. */
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

    /** @brief Shifts the value right by one bit in place. */
    void shift_right_one() {
        for (std::size_t i = 0; i < Words; ++i) {
            std::uint64_t next = (i + 1 < Words) ? limbs[i + 1] : 0;
            limbs[i] = (limbs[i] >> 1) | (next << 63);
        }
    }

    /** @brief Clears all bits above the requested width. */
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

    /** @brief Divides by a small unsigned value in place and returns the remainder. */
    std::uint32_t divmod_small(std::uint32_t divisor) {
        unsigned __int128 rem = 0;
        for (std::size_t i = Words; i-- > 0;) {
            unsigned __int128 cur = (rem << 64) | limbs[i];
            limbs[i] = static_cast<std::uint64_t>(cur / divisor);
            rem = cur % divisor;
        }
        return static_cast<std::uint32_t>(rem);
    }

    /** @brief Serializes the value to a fixed-width big-endian byte array. */
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

    /** @brief Formats the value as lowercase hexadecimal without leading zero padding. */
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

    /** @brief Formats the value as an unsigned decimal string. */
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

/** @brief Widens an integer to a larger limb count by zero-extending high limbs. */
template <std::size_t OutWords, std::size_t InWords>
BigUInt<OutWords> widen(const BigUInt<InWords>& value) {
    static_assert(OutWords >= InWords, "Cannot narrow with widen");
    BigUInt<OutWords> out;
    for (std::size_t i = 0; i < InWords; ++i) {
        out.limbs[i] = value.limbs[i];
    }
    return out;
}

/** @brief Narrows an integer to a smaller limb count, rejecting truncated high bits. */
template <std::size_t OutWords, std::size_t InWords>
Result<BigUInt<OutWords>> try_narrow(const BigUInt<InWords>& value) {
    static_assert(OutWords <= InWords, "Cannot widen with narrow");
    BigUInt<OutWords> out;
    for (std::size_t i = 0; i < OutWords; ++i) {
        out.limbs[i] = value.limbs[i];
    }
    for (std::size_t i = OutWords; i < InWords; ++i) {
        if (value.limbs[i] != 0) {
            return unexpected_error(ErrorCode::NarrowingOverflow, "try_narrow:high_bits_set");
        }
    }
    return out;
}

/** @brief Narrows an integer to a smaller limb count, requiring that no high bits are lost. */
template <std::size_t OutWords, std::size_t InWords>
BigUInt<OutWords> narrow(const BigUInt<InWords>& value) {
    Result<BigUInt<OutWords>> out = try_narrow<OutWords>(value);
    assert(out.has_value() && "narrow() requires the source value to fit");
    return std::move(*out);
}

/** @brief Performs long division where numerator and denominator have the same width. */
template <std::size_t Words>
Result<std::pair<BigUInt<Words>, BigUInt<Words>>> try_divmod_same(const BigUInt<Words>& numerator, const BigUInt<Words>& denominator) {
    if (denominator.is_zero()) {
        return unexpected_error(ErrorCode::DivisionByZero, "try_divmod_same:zero_denominator");
    }
    BigUInt<Words> quotient;
    BigUInt<Words> remainder = numerator;
    std::size_t n_bits = remainder.bit_length();
    std::size_t d_bits = denominator.bit_length();
    if (n_bits < d_bits) {
        return std::make_pair(quotient, remainder);
    }
    std::size_t shift = n_bits - d_bits;
    BigUInt<Words> shifted = denominator.shifted_left(shift);
    for (std::size_t i = shift + 1; i-- > 0;) {
        if (remainder.compare(shifted) >= 0) {
            bool sub_ok = remainder.try_sub_assign(shifted);
            bool bit_ok = quotient.try_set_bit(i);
            assert(sub_ok && "divmod_same() subtraction should stay in range");
            assert(bit_ok && "divmod_same() quotient bit index should stay in range");
            if (!sub_ok || !bit_ok) {
                return unexpected_error(ErrorCode::InternalMismatch, "try_divmod_same:internal_step");
            }
        }
        if (i != 0) {
            shifted.shift_right_one();
        }
    }
    return std::make_pair(quotient, remainder);
}

/** @brief Performs long division where numerator and denominator have the same width. */
template <std::size_t Words>
std::pair<BigUInt<Words>, BigUInt<Words>> divmod_same(const BigUInt<Words>& numerator, const BigUInt<Words>& denominator) {
    Result<std::pair<BigUInt<Words>, BigUInt<Words>>> out = try_divmod_same(numerator, denominator);
    assert(out.has_value() && "divmod_same() requires a non-zero denominator");
    return std::move(*out);
}

/** @brief Multiplies two fixed-width integers and returns the full-width product. */
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

/** @brief 256-bit unsigned integer used for field elements and curve orders. */
using UInt256 = BigUInt<4>;
/** @brief 320-bit unsigned integer used during hash-to-curve sampling. */
using UInt320 = BigUInt<5>;
/** @brief 512-bit unsigned integer used for private and packed public keys. */
using UInt512 = BigUInt<8>;

class FieldElement;

inline const UInt256& prime_p();
/** @brief Squares a field element. */
FieldElement square(const FieldElement& value);
/** @brief Returns the Legendre symbol of a field element. */
int legendre_symbol(const FieldElement& value);

/**
 * @brief Field element modulo the backend scalar field used by this implementation.
 *
 * The implementation delegates arithmetic to secp256k1-zkp scalar routines through
 * a thin C bridge so the C++ layer stays header-only.
 */
class FieldElement {
public:
    FieldElement() {
        purify_scalar_set_int(&value_, 0);
    }

    /** @brief Returns the additive identity of the scalar field. */
    static FieldElement zero() {
        return FieldElement();
    }

    /** @brief Returns the multiplicative identity of the scalar field. */
    static FieldElement one() {
        return from_u64(1);
    }

    /** @brief Constructs a field element from an unsigned 64-bit integer. */
    static FieldElement from_u64(std::uint64_t value) {
        FieldElement out;
        purify_scalar_set_u64(&out.value_, value);
        return out;
    }

    /** @brief Constructs a field element from a signed integer, reducing negatives modulo the field. */
    static FieldElement from_int(std::int64_t value) {
        if (value >= 0) {
            return from_u64(static_cast<std::uint64_t>(value));
        }
        return from_u64(static_cast<std::uint64_t>(-value)).negate();
    }

    /** @brief Decodes a canonical 32-byte big-endian field element. */
    static Result<FieldElement> try_from_bytes32(const std::array<unsigned char, 32>& bytes) {
        FieldElement out;
        int overflow = 0;
        purify_scalar_set_b32(&out.value_, bytes.data(), &overflow);
        if (overflow != 0) {
            return unexpected_error(ErrorCode::RangeViolation, "FieldElement::try_from_bytes32:out_of_range");
        }
        return out;
    }

    /**
     * @brief Decodes a 32-byte big-endian field element.
     *
     * Precondition: the input is canonical and strictly below the field modulus.
     */
    static FieldElement from_bytes32(const std::array<unsigned char, 32>& bytes) {
        Result<FieldElement> out = try_from_bytes32(bytes);
        assert(out.has_value() && "FieldElement::from_bytes32() requires a canonical field element");
        return std::move(*out);
    }

    /** @brief Converts a canonical 256-bit unsigned integer into the scalar field representation. */
    static Result<FieldElement> try_from_uint256(const UInt256& value) {
        return try_from_bytes32(value.to_bytes_be());
    }

    /**
     * @brief Converts a 256-bit unsigned integer into the scalar field representation.
     *
     * Precondition: the integer is strictly below the field modulus.
     */
    static FieldElement from_uint256(const UInt256& value) {
        Result<FieldElement> out = try_from_uint256(value);
        assert(out.has_value() && "FieldElement::from_uint256() requires a canonical field element");
        return std::move(*out);
    }

    /** @brief Exports the field element as a canonical 256-bit unsigned integer. */
    UInt256 to_uint256() const {
        std::array<unsigned char, 32> bytes = to_bytes_be();
        return UInt256::from_bytes_be(bytes.data(), bytes.size());
    }

    /** @brief Serializes the field element in big-endian form. */
    std::array<unsigned char, 32> to_bytes_be() const {
        std::array<unsigned char, 32> bytes{};
        purify_scalar_get_b32(bytes.data(), &value_);
        return bytes;
    }

    /** @brief Serializes the field element in little-endian form. */
    std::array<unsigned char, 32> to_bytes_le() const {
        std::array<unsigned char, 32> bytes = to_bytes_be();
        std::reverse(bytes.begin(), bytes.end());
        return bytes;
    }

    /** @brief Formats the field element as lowercase hexadecimal. */
    std::string to_hex() const {
        return to_uint256().to_hex();
    }

    /** @brief Formats the field element as an unsigned decimal string. */
    std::string to_decimal() const {
        return to_uint256().to_decimal();
    }

    /** @brief Returns true when the element is zero. */
    bool is_zero() const {
        return purify_scalar_is_zero(&value_) != 0;
    }

    /** @brief Returns true when the element is one. */
    bool is_one() const {
        return purify_scalar_is_one(&value_) != 0;
    }

    /** @brief Returns true when the canonical representative is odd. */
    bool is_odd() const {
        return purify_scalar_is_even(&value_) == 0;
    }

    /** @brief Returns true when the element is a quadratic residue in the field. */
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

    /** @brief Returns the additive inverse modulo the field prime. */
    FieldElement negate() const {
        FieldElement out;
        purify_scalar_negate(&out.value_, &value_);
        return out;
    }

    /** @brief Conditionally assigns `other` into `*this` when `flag` is true. */
    void conditional_assign(const FieldElement& other, bool flag) {
        purify_scalar_cmov(&value_, &other.value_, flag ? 1 : 0);
    }

    /** @brief Returns the multiplicative inverse modulo the field prime in constant time. */
    FieldElement inverse_consttime() const {
        FieldElement out;
        purify_scalar_inverse(&out.value_, &value_);
        return out;
    }

    /** @brief Returns the multiplicative inverse modulo the field prime using the faster variable-time backend. */
    FieldElement inverse() const {
        FieldElement out;
        purify_scalar_inverse_var(&out.value_, &value_);
        return out;
    }

    /** @brief Computes a square root when one exists, otherwise returns `std::nullopt`. */
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

    /** @brief Raises the element to an unsigned exponent via square-and-multiply. */
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

    /** @brief Compares two field elements for exact equality. */
    friend bool operator==(const FieldElement& lhs, const FieldElement& rhs) {
        return purify_scalar_eq(&lhs.value_, &rhs.value_) != 0;
    }

    /** @brief Compares two field elements for inequality. */
    friend bool operator!=(const FieldElement& lhs, const FieldElement& rhs) {
        return !(lhs == rhs);
    }

    /** @brief Adds two field elements modulo the field prime. */
    friend FieldElement operator+(const FieldElement& lhs, const FieldElement& rhs) {
        FieldElement out;
        purify_scalar_add(&out.value_, &lhs.value_, &rhs.value_);
        return out;
    }

    /** @brief Subtracts two field elements modulo the field prime. */
    friend FieldElement operator-(const FieldElement& lhs, const FieldElement& rhs) {
        return lhs + rhs.negate();
    }

    /** @brief Multiplies two field elements modulo the field prime. */
    friend FieldElement operator*(const FieldElement& lhs, const FieldElement& rhs) {
        FieldElement out;
        purify_scalar_mul(&out.value_, &lhs.value_, &rhs.value_);
        return out;
    }

private:
    explicit FieldElement(const purify_scalar& raw) : value_(raw) {}

    purify_scalar value_{};
};

/** @brief Squares a field element. */
inline FieldElement square(const FieldElement& value) {
    return value * value;
}

/** @brief Returns `0` for zero, `1` for quadratic residues, and `-1` for non-residues. */
inline int legendre_symbol(const FieldElement& value) {
    if (value.is_zero()) {
        return 0;
    }
    return value.is_square() ? 1 : -1;
}

}  // namespace purify
