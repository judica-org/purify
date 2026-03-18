#pragma once

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <cstdint>
#include <format>
#include <iomanip>
#include <map>
#include <optional>
#include <ostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "purify_secp_bridge.h"

namespace purify {

using Bytes = std::vector<unsigned char>;

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

struct JacobianPoint {
    FieldElement x;
    FieldElement y;
    FieldElement z;
    bool infinity = false;

    static JacobianPoint infinity_point() {
        return {FieldElement::zero(), FieldElement::one(), FieldElement::zero(), true};
    }
};

struct AffinePoint {
    FieldElement x;
    FieldElement y;
    bool infinity = false;
};

class EllipticCurve {
public:
    EllipticCurve(FieldElement a, FieldElement b, UInt256 n) : a_(std::move(a)), b_(std::move(b)), n_(std::move(n)) {}

    const UInt256& order() const {
        return n_;
    }

    AffinePoint affine(const JacobianPoint& point) const {
        if (point.infinity || point.z.is_zero()) {
            return {FieldElement::zero(), FieldElement::zero(), true};
        }
        FieldElement inv = point.z.inverse();
        FieldElement inv2 = inv * inv;
        FieldElement inv3 = inv2 * inv;
        return {inv2 * point.x, inv3 * point.y, false};
    }

    JacobianPoint negate(const JacobianPoint& point) const {
        if (point.infinity) {
            return point;
        }
        return {point.x, point.y.negate(), point.z, false};
    }

    bool is_x_coord(const FieldElement& x) const {
        FieldElement v = square(x) * x + a_ * x + b_;
        return legendre_symbol(v) != -1;
    }

    std::optional<JacobianPoint> lift_x(const FieldElement& x) const {
        FieldElement v = square(x) * x + a_ * x + b_;
        std::optional<FieldElement> y = v.sqrt();
        if (!y.has_value()) {
            return std::nullopt;
        }
        return JacobianPoint{x, *y, FieldElement::one(), false};
    }

    JacobianPoint double_point(const JacobianPoint& point) const {
        if (point.infinity || point.z.is_zero()) {
            return JacobianPoint::infinity_point();
        }
        FieldElement y1_2 = square(point.y);
        FieldElement y1_4 = square(y1_2);
        FieldElement x1_2 = square(point.x);
        FieldElement s = FieldElement::from_int(4) * point.x * y1_2;
        FieldElement m = FieldElement::from_int(3) * x1_2;
        if (!a_.is_zero()) {
            FieldElement z1_2 = square(point.z);
            FieldElement z1_4 = square(z1_2);
            m = m + a_ * z1_4;
        }
        FieldElement x3 = square(m) - FieldElement::from_int(2) * s;
        FieldElement y3 = m * (s - x3) - FieldElement::from_int(8) * y1_4;
        FieldElement z3 = FieldElement::from_int(2) * point.y * point.z;
        return {x3, y3, z3, false};
    }

    JacobianPoint add_mixed(const JacobianPoint& lhs, const AffinePoint& rhs) const {
        if (lhs.infinity || lhs.z.is_zero()) {
            return {rhs.x, rhs.y, FieldElement::one(), rhs.infinity};
        }
        FieldElement z1_2 = square(lhs.z);
        FieldElement z1_3 = z1_2 * lhs.z;
        FieldElement u2 = rhs.x * z1_2;
        FieldElement s2 = rhs.y * z1_3;
        if (lhs.x == u2) {
            if (lhs.y != s2) {
                return JacobianPoint::infinity_point();
            }
            return double_point(lhs);
        }
        FieldElement h = u2 - lhs.x;
        FieldElement r = s2 - lhs.y;
        FieldElement h_2 = square(h);
        FieldElement h_3 = h_2 * h;
        FieldElement u1_h_2 = lhs.x * h_2;
        FieldElement x3 = square(r) - h_3 - FieldElement::from_int(2) * u1_h_2;
        FieldElement y3 = r * (u1_h_2 - x3) - lhs.y * h_3;
        FieldElement z3 = h * lhs.z;
        return {x3, y3, z3, false};
    }

    JacobianPoint add(const JacobianPoint& lhs, const JacobianPoint& rhs) const {
        if (lhs.infinity || lhs.z.is_zero()) {
            return rhs;
        }
        if (rhs.infinity || rhs.z.is_zero()) {
            return lhs;
        }
        if (rhs.z.is_one()) {
            return add_mixed(lhs, {rhs.x, rhs.y, false});
        }
        if (lhs.z.is_one()) {
            return add_mixed(rhs, {lhs.x, lhs.y, false});
        }
        FieldElement z1_2 = square(lhs.z);
        FieldElement z1_3 = z1_2 * lhs.z;
        FieldElement z2_2 = square(rhs.z);
        FieldElement z2_3 = z2_2 * rhs.z;
        FieldElement u1 = lhs.x * z2_2;
        FieldElement u2 = rhs.x * z1_2;
        FieldElement s1 = lhs.y * z2_3;
        FieldElement s2 = rhs.y * z1_3;
        if (u1 == u2) {
            if (s1 != s2) {
                return JacobianPoint::infinity_point();
            }
            return double_point(lhs);
        }
        FieldElement h = u2 - u1;
        FieldElement r = s2 - s1;
        FieldElement h_2 = square(h);
        FieldElement h_3 = h_2 * h;
        FieldElement u1_h_2 = u1 * h_2;
        FieldElement x3 = square(r) - h_3 - FieldElement::from_int(2) * u1_h_2;
        FieldElement y3 = r * (u1_h_2 - x3) - s1 * h_3;
        FieldElement z3 = h * lhs.z * rhs.z;
        return {x3, y3, z3, false};
    }

    JacobianPoint mul(const JacobianPoint& point, const UInt256& scalar) const {
        JacobianPoint result = JacobianPoint::infinity_point();
        std::size_t bits = scalar.bit_length();
        for (std::size_t i = bits; i-- > 0;) {
            result = double_point(result);
            if (scalar.bit(i)) {
                result = add(result, point);
            }
        }
        return result;
    }

private:
    FieldElement a_;
    FieldElement b_;
    UInt256 n_;
};

inline Bytes bytes_from_ascii(std::string_view input) {
    return Bytes(input.begin(), input.end());
}

inline Bytes operator+(Bytes lhs, const Bytes& rhs) {
    lhs.insert(lhs.end(), rhs.begin(), rhs.end());
    return lhs;
}

inline std::uint64_t ceil_div(std::uint64_t lhs, std::uint64_t rhs) {
    return (lhs + rhs - 1) / rhs;
}

inline Bytes hmac_sha256(const Bytes& key, const Bytes& data) {
    Bytes out(32);
    purify_hmac_sha256(out.data(), key.data(), key.size(), data.data(), data.size());
    return out;
}

inline Bytes hkdf(std::size_t length, const Bytes& ikm, const Bytes& salt = {}, const Bytes& info = {}) {
    constexpr std::size_t hash_len = 32;
    Bytes zero_salt(hash_len, 0);
    Bytes prk = hmac_sha256(salt.empty() ? zero_salt : salt, ikm);
    Bytes t;
    Bytes okm;
    for (std::size_t i = 0; i < ceil_div(length, hash_len); ++i) {
        Bytes input = t;
        input.insert(input.end(), info.begin(), info.end());
        input.push_back(static_cast<unsigned char>(i + 1));
        t = hmac_sha256(prk, input);
        okm.insert(okm.end(), t.begin(), t.end());
    }
    okm.resize(length);
    return okm;
}

template <std::size_t Words>
std::optional<BigUInt<Words>> hash_to_int(const Bytes& data, const BigUInt<Words>& range, const Bytes& info = {}) {
    std::size_t bits = range.bit_length();
    for (int i = 0; i < 256; ++i) {
        Bytes salt{static_cast<unsigned char>(i)};
        Bytes derived = hkdf((bits + 7) / 8, data, salt, info);
        BigUInt<Words> value = BigUInt<Words>::from_bytes_be(derived.data(), derived.size());
        value.mask_bits(bits);
        if (value.compare(range) < 0) {
            return value;
        }
    }
    return std::nullopt;
}

inline const UInt256& prime_p() {
    static const UInt256 value = UInt256::from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    return value;
}

inline const UInt256& order_n1() {
    static const UInt256 value = UInt256::from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA328F244053472128A5A2A2C58E547E9");
    return value;
}

inline const UInt256& order_n2() {
    static const UInt256 value = UInt256::from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDD234C789595CCE64F54A92ED47873A9B");
    return value;
}

inline const UInt256& half_n1() {
    static const UInt256 value = UInt256::from_hex("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD1947922029A3909452D15162C72A3F4");
    return value;
}

inline const UInt256& half_n2() {
    static const UInt256 value = UInt256::from_hex("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEE91A63C4ACAE67327AA54976A3C39D4D");
    return value;
}

inline const UInt320& two_p() {
    static const UInt320 value = [] {
        UInt320 out = widen<5>(prime_p());
        out.mul_small(2);
        return out;
    }();
    return value;
}

inline FieldElement field_a() {
    return FieldElement::from_int(118);
}

inline FieldElement field_b() {
    return FieldElement::from_int(339);
}

inline FieldElement field_d() {
    return FieldElement::from_int(5);
}

inline FieldElement field_di() {
    static const FieldElement value = FieldElement::from_uint256(
        UInt256::from_hex("66666666666666666666666666666665E445F1F5DFB6A67E4CBA8C385348E6E7"));
    return value;
}

inline const EllipticCurve& curve1() {
    static const EllipticCurve curve(field_a(), field_b(), order_n1());
    return curve;
}

inline const EllipticCurve& curve2() {
    static const EllipticCurve curve(field_a() * field_d() * field_d(),
                                     field_b() * field_d() * field_d() * field_d(),
                                     order_n2());
    return curve;
}

inline JacobianPoint hash_to_curve(const Bytes& data, const EllipticCurve& curve) {
    for (int i = 0; i < 256; ++i) {
        Bytes info{static_cast<unsigned char>(i)};
        std::optional<UInt320> value = hash_to_int(data, two_p(), info);
        if (!value.has_value()) {
            continue;
        }
        UInt320 x_candidate = value->shifted_right(1);
        FieldElement x = FieldElement::from_uint256(narrow<4>(x_candidate));
        if (curve.is_x_coord(x)) {
            std::optional<JacobianPoint> point = curve.lift_x(x);
            if (!point.has_value()) {
                continue;
            }
            if (value->bit(0)) {
                return curve.negate(*point);
            }
            return *point;
        }
    }
    throw std::runtime_error("hash_to_curve failed");
}

inline const JacobianPoint& generator1() {
    static const JacobianPoint value = [] {
        JacobianPoint point = hash_to_curve(bytes_from_ascii("Generator/1"), curve1());
        if (!curve1().mul(point, order_n1()).infinity) {
            throw std::runtime_error("G1 order check failed");
        }
        return point;
    }();
    return value;
}

inline const JacobianPoint& generator2() {
    static const JacobianPoint value = [] {
        JacobianPoint point = hash_to_curve(bytes_from_ascii("Generator/2"), curve2());
        if (!curve2().mul(point, order_n2()).infinity) {
            throw std::runtime_error("G2 order check failed");
        }
        return point;
    }();
    return value;
}

inline std::pair<UInt256, UInt256> unpack_secret(const UInt512& z) {
    auto qr = divmod_same(z, widen<8>(half_n1()));
    UInt256 z1 = narrow<4>(qr.second);
    UInt256 z2 = narrow<4>(qr.first);
    z1.add_small(1);
    z2.add_small(1);
    return {z1, z2};
}

inline std::pair<UInt256, UInt256> unpack_public(const UInt512& packed) {
    auto qr = divmod_same(packed, widen<8>(prime_p()));
    return {narrow<4>(qr.second), narrow<4>(qr.first)};
}

inline UInt512 pack_public(const UInt256& x1, const UInt256& x2) {
    UInt512 out = multiply(prime_p(), x2);
    out.add_assign(widen<8>(x1));
    return out;
}

inline FieldElement combine(const FieldElement& x1, const FieldElement& x2) {
    FieldElement u = x1;
    FieldElement v = x2 * field_di();
    FieldElement w = (u - v).inverse();
    return ((u + v) * (field_a() + u * v) + FieldElement::from_int(2) * field_b()) * w * w;
}

inline std::vector<int> key_to_bits(UInt256 n, int bits) {
    n.sub_assign(UInt256::one());
    if (static_cast<int>(n.bit_length()) > bits) {
        throw std::runtime_error("Key out of range");
    }
    std::vector<int> out(bits);
    for (int i = 0; i < bits; ++i) {
        out[i] = n.bit(static_cast<std::size_t>(i)) ? 1 : 0;
    }
    for (int i = 3; i < bits; i += 3) {
        if (!out[i]) {
            out[i - 1] = 1 - out[i - 1];
            out[i - 2] = 1 - out[i - 2];
        }
        out[i] = 1 - out[i];
    }
    return out;
}

class Expr {
public:
    Expr() : constant_(FieldElement::zero()) {}
    explicit Expr(const FieldElement& value) : constant_(value) {}
    explicit Expr(std::int64_t value) : constant_(FieldElement::from_int(value)) {}

    static Expr variable(const std::string& name) {
        Expr out;
        out.linear_.push_back({name, FieldElement::one()});
        return out;
    }

    const FieldElement& constant() const {
        return constant_;
    }

    std::vector<std::pair<std::string, FieldElement>>& linear() {
        return linear_;
    }

    const std::vector<std::pair<std::string, FieldElement>>& linear() const {
        return linear_;
    }

    friend Expr operator+(const Expr& lhs, const Expr& rhs) {
        Expr out(lhs.constant_ + rhs.constant_);
        std::size_t i = 0;
        std::size_t j = 0;
        while (i < lhs.linear_.size() || j < rhs.linear_.size()) {
            if (j == rhs.linear_.size() || (i < lhs.linear_.size() && lhs.linear_[i].first < rhs.linear_[j].first)) {
                out.push_term(lhs.linear_[i]);
                ++i;
            } else if (i == lhs.linear_.size() || rhs.linear_[j].first < lhs.linear_[i].first) {
                out.push_term(rhs.linear_[j]);
                ++j;
            } else {
                out.push_term({lhs.linear_[i].first, lhs.linear_[i].second + rhs.linear_[j].second});
                ++i;
                ++j;
            }
        }
        return out;
    }

    friend Expr operator+(const Expr& lhs, std::int64_t rhs) {
        return lhs + Expr(rhs);
    }

    friend Expr operator+(std::int64_t lhs, const Expr& rhs) {
        return Expr(lhs) + rhs;
    }

    friend Expr operator-(const Expr& lhs, const Expr& rhs) {
        return lhs + (-rhs);
    }

    friend Expr operator-(const Expr& lhs, std::int64_t rhs) {
        return lhs - Expr(rhs);
    }

    friend Expr operator-(std::int64_t lhs, const Expr& rhs) {
        return Expr(lhs) - rhs;
    }

    friend Expr operator-(const Expr& value) {
        return value * FieldElement::from_int(-1);
    }

    friend Expr operator*(const Expr& expr, const FieldElement& scalar) {
        if (scalar.is_zero()) {
            return Expr(0);
        }
        Expr out(expr.constant_ * scalar);
        out.linear_.reserve(expr.linear_.size());
        for (const auto& term : expr.linear_) {
            out.linear_.push_back({term.first, term.second * scalar});
        }
        return out;
    }

    friend Expr operator*(const FieldElement& scalar, const Expr& expr) {
        return expr * scalar;
    }

    friend Expr operator*(const Expr& expr, std::int64_t scalar) {
        return expr * FieldElement::from_int(scalar);
    }

    friend Expr operator*(std::int64_t scalar, const Expr& expr) {
        return expr * scalar;
    }

    std::string to_string() const {
        std::vector<std::string> terms;
        if (!constant_.is_zero() || linear_.empty()) {
            terms.push_back(constant_.to_decimal());
        }
        for (const auto& term : linear_) {
            if (term.second == FieldElement::one()) {
                terms.push_back(term.first);
            } else {
                terms.push_back(term.second.to_decimal() + " * " + term.first);
            }
        }
        if (terms.empty()) {
            return "0";
        }
        std::ostringstream out;
        for (std::size_t i = 0; i < terms.size(); ++i) {
            if (i != 0) {
                out << " + ";
            }
            out << terms[i];
        }
        return out.str();
    }

    std::optional<FieldElement> evaluate(const std::unordered_map<std::string, std::optional<FieldElement>>& values) const {
        FieldElement out = constant_;
        for (const auto& term : linear_) {
            auto it = values.find(term.first);
            if (it == values.end() || !it->second.has_value()) {
                return std::nullopt;
            }
            out = out + (*it->second * term.second);
        }
        return out;
    }

    std::pair<Expr, Expr> split() const {
        Expr linear_expr(0);
        linear_expr.linear_ = linear_;
        return {Expr(constant_), linear_expr};
    }

private:
    void push_term(const std::pair<std::string, FieldElement>& term) {
        if (term.second.is_zero()) {
            return;
        }
        if (!linear_.empty() && linear_.back().first == term.first) {
            linear_.back().second = linear_.back().second + term.second;
            if (linear_.back().second.is_zero()) {
                linear_.pop_back();
            }
            return;
        }
        linear_.push_back(term);
    }

    FieldElement constant_;
    std::vector<std::pair<std::string, FieldElement>> linear_;
};

inline std::ostream& operator<<(std::ostream& out, const Expr& expr) {
    out << expr.to_string();
    return out;
}

class Transcript {
public:
    Expr secret(const std::optional<FieldElement>& value) {
        std::size_t index = varmap_.size();
        std::string name = std::format("v[{}]", index);
        varmap_[name] = value;
        return Expr::variable(name);
    }

    Expr mul(const Expr& lhs, const Expr& rhs) {
        std::string lhs_str = lhs.to_string();
        std::string rhs_str = rhs.to_string();
        auto direct = std::make_pair(lhs_str, rhs_str);
        auto reverse = std::make_pair(rhs_str, lhs_str);
        auto it = mul_cache_.find(direct);
        if (it != mul_cache_.end()) {
            return it->second;
        }
        it = mul_cache_.find(reverse);
        if (it != mul_cache_.end()) {
            return it->second;
        }
        std::optional<FieldElement> lhs_val = lhs.evaluate(varmap_);
        std::optional<FieldElement> rhs_val = rhs.evaluate(varmap_);
        std::optional<FieldElement> value;
        if (lhs_val.has_value() && rhs_val.has_value()) {
            value = *lhs_val * *rhs_val;
        }
        Expr out = secret(value);
        mul_cache_[direct] = out;
        muls_.push_back({lhs, rhs, out});
        return out;
    }

    Expr div(const Expr& lhs, const Expr& rhs) {
        std::string lhs_str = lhs.to_string();
        std::string rhs_str = rhs.to_string();
        auto direct = std::make_pair(lhs_str, rhs_str);
        auto it = div_cache_.find(direct);
        if (it != div_cache_.end()) {
            return it->second;
        }
        std::optional<FieldElement> lhs_val = lhs.evaluate(varmap_);
        std::optional<FieldElement> rhs_val = rhs.evaluate(varmap_);
        if (rhs_val.has_value() && rhs_val->is_zero()) {
            throw std::runtime_error("Division by zero");
        }
        std::optional<FieldElement> value;
        if (lhs_val.has_value() && rhs_val.has_value()) {
            value = *lhs_val * rhs_val->inverse();
        }
        Expr out = secret(value);
        div_cache_[direct] = out;
        muls_.push_back({out, rhs, lhs});
        return out;
    }

    Expr boolean(const Expr& expr) {
        std::string key = expr.to_string();
        if (bool_cache_.count(key) != 0) {
            return expr;
        }
        std::optional<FieldElement> value = expr.evaluate(varmap_);
        if (value.has_value() && *value != FieldElement::zero() && *value != FieldElement::one()) {
            throw std::runtime_error("Boolean constraint on non-boolean value");
        }
        bool_cache_.insert(key);
        muls_.push_back({expr, expr - 1, Expr(0)});
        return expr;
    }

    void equal(const Expr& lhs, const Expr& rhs) {
        Expr diff = lhs - rhs;
        std::optional<FieldElement> value = diff.evaluate(varmap_);
        if (value.has_value() && !value->is_zero()) {
            throw std::runtime_error("Equation mismatch");
        }
        eqs_.push_back(diff);
    }

    std::optional<FieldElement> evaluate(const Expr& expr) const {
        return expr.evaluate(varmap_);
    }

    const std::unordered_map<std::string, std::optional<FieldElement>>& varmap() const {
        return varmap_;
    }

    struct MulConstraint {
        Expr lhs;
        Expr rhs;
        Expr out;
    };

    const std::vector<MulConstraint>& muls() const {
        return muls_;
    }

private:
    std::unordered_map<std::string, std::optional<FieldElement>> varmap_;
    std::vector<MulConstraint> muls_;
    std::map<std::pair<std::string, std::string>, Expr> mul_cache_;
    std::map<std::pair<std::string, std::string>, Expr> div_cache_;
    std::unordered_set<std::string> bool_cache_;
    std::vector<Expr> eqs_;
};

struct BulletproofAssignmentData {
    std::vector<FieldElement> left;
    std::vector<FieldElement> right;
    std::vector<FieldElement> output;
    std::vector<FieldElement> commitments;

    Bytes serialize() const {
        if (left.size() != right.size() || left.size() != output.size()) {
            throw std::runtime_error("Mismatched bulletproof assignment columns");
        }

        Bytes out;
        out.reserve(4 + 4 + 8 + ((left.size() * 3) + commitments.size()) * 33);
        auto append_u32_le = [&](std::uint32_t value) {
            for (int i = 0; i < 4; ++i) {
                out.push_back(static_cast<unsigned char>((value >> (8 * i)) & 0xffU));
            }
        };
        auto append_u64_le = [&](std::uint64_t value) {
            for (int i = 0; i < 8; ++i) {
                out.push_back(static_cast<unsigned char>((value >> (8 * i)) & 0xffU));
            }
        };
        auto write_column = [&](const std::vector<FieldElement>& column) {
            for (const FieldElement& value : column) {
                out.push_back(static_cast<unsigned char>(0x20));
                std::array<unsigned char, 32> bytes = value.to_bytes_le();
                out.insert(out.end(), bytes.begin(), bytes.end());
            }
        };

        append_u32_le(1);
        append_u32_le(static_cast<std::uint32_t>(commitments.size()));
        append_u64_le(static_cast<std::uint64_t>(left.size()));
        write_column(left);
        write_column(right);
        write_column(output);
        write_column(commitments);
        return out;
    }
};

struct NativeBulletproofCircuitTerm {
    std::size_t idx = 0;
    FieldElement scalar;
};

struct NativeBulletproofCircuitRow {
    std::vector<NativeBulletproofCircuitTerm> entries;

    void add(std::size_t idx, const FieldElement& scalar) {
        if (scalar.is_zero()) {
            return;
        }
        entries.push_back({idx, scalar});
    }
};

struct NativeBulletproofCircuit {
    std::size_t n_gates = 0;
    std::size_t n_commitments = 0;
    std::size_t n_bits = 0;
    std::vector<NativeBulletproofCircuitRow> wl;
    std::vector<NativeBulletproofCircuitRow> wr;
    std::vector<NativeBulletproofCircuitRow> wo;
    std::vector<NativeBulletproofCircuitRow> wv;
    std::vector<FieldElement> c;

    NativeBulletproofCircuit() = default;

    NativeBulletproofCircuit(std::size_t gates, std::size_t commitments, std::size_t bits = 0)
        : n_gates(gates), n_commitments(commitments), n_bits(bits), wl(gates), wr(gates), wo(gates), wv(commitments) {}

    void resize(std::size_t gates, std::size_t commitments, std::size_t bits = 0) {
        n_gates = gates;
        n_commitments = commitments;
        n_bits = bits;
        wl.assign(gates, {});
        wr.assign(gates, {});
        wo.assign(gates, {});
        wv.assign(commitments, {});
        c.clear();
    }

    bool has_valid_shape() const {
        return wl.size() == n_gates
            && wr.size() == n_gates
            && wo.size() == n_gates
            && wv.size() == n_commitments;
    }

    std::size_t add_constraint(const FieldElement& constant = FieldElement::zero()) {
        c.push_back(constant);
        return c.size() - 1;
    }

    void add_left_term(std::size_t gate_idx, std::size_t constraint_idx, const FieldElement& scalar) {
        add_row_term(wl, n_gates, gate_idx, constraint_idx, scalar);
    }

    void add_right_term(std::size_t gate_idx, std::size_t constraint_idx, const FieldElement& scalar) {
        add_row_term(wr, n_gates, gate_idx, constraint_idx, scalar);
    }

    void add_output_term(std::size_t gate_idx, std::size_t constraint_idx, const FieldElement& scalar) {
        add_row_term(wo, n_gates, gate_idx, constraint_idx, scalar);
    }

    void add_commitment_term(std::size_t commitment_idx, std::size_t constraint_idx, const FieldElement& scalar) {
        // W_V is accumulated against -V during evaluation, so store the negated coefficient here.
        add_row_term(wv, n_commitments, commitment_idx, constraint_idx, scalar.negate());
    }

    bool evaluate(const BulletproofAssignmentData& assignment) const {
        if (!has_valid_shape()) {
            return false;
        }
        if (assignment.left.size() != n_gates || assignment.right.size() != n_gates || assignment.output.size() != n_gates) {
            return false;
        }
        if (assignment.commitments.size() != n_commitments) {
            return false;
        }

        for (std::size_t i = 0; i < n_gates; ++i) {
            if (assignment.left[i] * assignment.right[i] != assignment.output[i]) {
                return false;
            }
        }

        std::vector<FieldElement> acc(c.size(), FieldElement::zero());
        auto accumulate = [&](const std::vector<NativeBulletproofCircuitRow>& rows, const std::vector<FieldElement>& values) {
            if (rows.size() != values.size()) {
                return false;
            }
            for (std::size_t i = 0; i < rows.size(); ++i) {
                for (const NativeBulletproofCircuitTerm& entry : rows[i].entries) {
                    if (entry.idx >= acc.size()) {
                        return false;
                    }
                    acc[entry.idx] = acc[entry.idx] + entry.scalar * values[i];
                }
            }
            return true;
        };
        if (!accumulate(wl, assignment.left) || !accumulate(wr, assignment.right) || !accumulate(wo, assignment.output)) {
            return false;
        }
        std::vector<FieldElement> negated_commitments;
        negated_commitments.reserve(assignment.commitments.size());
        for (const FieldElement& value : assignment.commitments) {
            negated_commitments.push_back(value.negate());
        }
        if (!accumulate(wv, negated_commitments)) {
            return false;
        }

        for (std::size_t i = 0; i < c.size(); ++i) {
            if (acc[i] != c[i]) {
                return false;
            }
        }
        return true;
    }

private:
    static void add_row_term(std::vector<NativeBulletproofCircuitRow>& rows, std::size_t expected_size,
                             std::size_t row_idx, std::size_t constraint_idx, const FieldElement& scalar) {
        if (rows.size() != expected_size) {
            throw std::runtime_error("Circuit rows are not initialized");
        }
        if (row_idx >= rows.size()) {
            throw std::runtime_error("Native circuit row index out of range");
        }
        rows[row_idx].add(constraint_idx, scalar);
    }
};

class BulletproofTranscript {
public:
    void replace_expr_v_with_bp_var(Expr& expr) {
        for (auto& term : expr.linear()) {
            auto it = v_to_a_.find(term.first);
            if (it != v_to_a_.end()) {
                term.first = it->second;
            }
        }
    }

    bool replace_and_insert(Expr& expr, const std::string& symbol) {
        if (!expr.linear().empty()) {
            replace_expr_v_with_bp_var(expr);
            if (expr.constant().is_zero() && expr.linear().size() == 1) {
                const std::string& name = expr.linear()[0].first;
                if (v_to_a_.count(name) == 0) {
                    v_to_a_[name] = symbol;
                    v_to_a_order_.push_back({name, symbol});
                    if (name.find("v[") != std::string::npos) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    void add_assignment(const std::string& symbol, Expr expr) {
        bool is_v = replace_and_insert(expr, symbol);
        assignments_.push_back({symbol, std::move(expr), is_v});
    }

    void from_transcript(const Transcript& transcript, std::size_t n_bits) {
        n_bits_ = n_bits;
        std::size_t source_muls = transcript.muls().size();
        n_muls_ = 1;
        while (n_muls_ < std::max<std::size_t>(1, source_muls)) {
            n_muls_ <<= 1;
        }
        for (std::size_t i = 0; i < source_muls; ++i) {
            const auto& mul = transcript.muls()[i];
            add_assignment(std::format("L{}", i), mul.lhs);
            add_assignment(std::format("R{}", i), mul.rhs);
            add_assignment(std::format("O{}", i), mul.out);
        }
        for (std::size_t i = source_muls; i < n_muls_; ++i) {
            add_assignment(std::format("L{}", i), Expr(0));
            add_assignment(std::format("R{}", i), Expr(0));
            add_assignment(std::format("O{}", i), Expr(0));
        }
    }

    void add_pubkey_and_out(const UInt512& pubkey, Expr p1x, Expr p2x, Expr out) {
        auto unpacked = unpack_public(pubkey);
        auto add_constraint = [&](const UInt256& packed, Expr expr) {
            replace_expr_v_with_bp_var(expr);
            auto parts = expr.split();
            constraints_.push_back({parts.second, Expr(FieldElement::from_uint256(packed)) - parts.first});
        };
        add_constraint(unpacked.first, std::move(p1x));
        add_constraint(unpacked.second, std::move(p2x));
        replace_expr_v_with_bp_var(out);
        constraints_.push_back({out - Expr::variable("V0"), Expr(0)});
    }

    std::string to_string() const {
        std::size_t n_constraints = 0;
        for (const auto& assignment : assignments_) {
            if (!assignment.is_v) {
                ++n_constraints;
            }
        }
        n_constraints += constraints_.size();
        std::ostringstream out;
        out << n_muls_ << "," << n_commitments_ << "," << n_bits_ << "," << (n_constraints - 2 * n_bits_) << ";";
        std::size_t i = 0;
        for (const auto& assignment : assignments_) {
            if (!assignment.is_v) {
                if (i < 2 * n_bits_) {
                    ++i;
                    continue;
                }
                auto parts = assignment.expr.split();
                out << assignment.symbol;
                if (!parts.second.linear().empty()) {
                    out << " + " << (-parts.second).to_string();
                }
                out << " = " << parts.first.to_string() << ";";
            }
        }
        for (const auto& constraint : constraints_) {
            out << constraint.first.to_string() << " = " << constraint.second.to_string() << ";";
        }
        return out.str();
    }

    bool evaluate(const std::unordered_map<std::string, std::optional<FieldElement>>& vars, const FieldElement& commitment) const {
        std::unordered_map<std::string, FieldElement> values;
        values.reserve(vars.size() + assignments_.size() + v_to_a_.size() + 1);
        for (const auto& item : vars) {
            if (item.second.has_value()) {
                values[item.first] = *item.second;
            }
        }
        values["V0"] = commitment;
        for (const auto& item : v_to_a_order_) {
            auto it = values.find(item.first);
            if (it == values.end()) {
                throw std::runtime_error("Missing mapped assignment value for " + item.first);
            }
            values[item.second] = it->second;
        }
        for (const auto& assignment : assignments_) {
            values[assignment.symbol] = evaluate_known(assignment.expr, values);
        }
        for (std::size_t i = 0; i < n_muls_; ++i) {
            std::string suffix = std::format("{}", i);
            if (values.at("L" + suffix) * values.at("R" + suffix) != values.at("O" + suffix)) {
                return false;
            }
        }
        for (const auto& constraint : constraints_) {
            if (evaluate_known(constraint.first, values) != evaluate_known(constraint.second, values)) {
                return false;
            }
        }
        return true;
    }

    NativeBulletproofCircuit native_circuit() const {
        NativeBulletproofCircuit circuit;
        circuit.n_gates = n_muls_;
        circuit.n_commitments = n_commitments_;
        circuit.n_bits = n_bits_;
        circuit.wl.resize(n_muls_);
        circuit.wr.resize(n_muls_);
        circuit.wo.resize(n_muls_);
        circuit.wv.resize(n_commitments_);

        auto parse_symbol = [](std::string_view symbol) -> std::pair<char, std::size_t> {
            if (symbol.size() < 2) {
                throw std::runtime_error("Invalid circuit symbol");
            }
            std::size_t index = 0;
            auto result = std::from_chars(symbol.data() + 1, symbol.data() + symbol.size(), index);
            if (result.ec != std::errc() || result.ptr != symbol.data() + symbol.size()) {
                throw std::runtime_error("Invalid circuit symbol index");
            }
            return {symbol.front(), index};
        };
        auto append_constraint = [&](const Expr& lhs, const Expr& rhs) {
            Expr combined = lhs - rhs;
            std::size_t constraint_idx = circuit.c.size();
            circuit.c.push_back(combined.constant().negate());
            for (const auto& term : combined.linear()) {
                auto [kind, index] = parse_symbol(term.first);
                if (kind == 'L') {
                    if (index >= circuit.wl.size()) {
                        throw std::runtime_error("L index out of range");
                    }
                    circuit.wl[index].add(constraint_idx, term.second);
                } else if (kind == 'R') {
                    if (index >= circuit.wr.size()) {
                        throw std::runtime_error("R index out of range");
                    }
                    circuit.wr[index].add(constraint_idx, term.second);
                } else if (kind == 'O') {
                    if (index >= circuit.wo.size()) {
                        throw std::runtime_error("O index out of range");
                    }
                    circuit.wo[index].add(constraint_idx, term.second);
                } else if (kind == 'V') {
                    if (index >= circuit.wv.size()) {
                        throw std::runtime_error("V index out of range");
                    }
                    // Match the W_V convention used by NativeBulletproofCircuit::evaluate().
                    circuit.wv[index].add(constraint_idx, term.second.negate());
                } else {
                    throw std::runtime_error("Unsupported native circuit symbol: " + term.first);
                }
            }
        };

        for (const auto& assignment : assignments_) {
            if (!assignment.is_v) {
                append_constraint(Expr::variable(assignment.symbol), assignment.expr);
            }
        }
        for (const auto& constraint : constraints_) {
            append_constraint(constraint.first, constraint.second);
        }
        return circuit;
    }

    BulletproofAssignmentData assignment_data(const std::unordered_map<std::string, std::optional<FieldElement>>& vars) const {
        std::unordered_map<std::string, FieldElement> values;
        values.reserve(vars.size() + assignments_.size() + v_to_a_.size());
        for (const auto& item : vars) {
            if (item.second.has_value()) {
                values[item.first] = *item.second;
            }
        }
        for (const auto& item : v_to_a_order_) {
            auto it = values.find(item.first);
            if (it == values.end()) {
                throw std::runtime_error("Missing mapped write-assignment value for " + item.first);
            }
            values[item.second] = it->second;
        }
        for (const auto& assignment : assignments_) {
            values[assignment.symbol] = evaluate_known(assignment.expr, values);
        }

        BulletproofAssignmentData assignment;
        assignment.left.reserve(n_muls_);
        assignment.right.reserve(n_muls_);
        assignment.output.reserve(n_muls_);
        assignment.commitments.reserve(n_commitments_);
        auto read_column = [&](std::string_view prefix, std::vector<FieldElement>& column) {
            for (std::size_t i = 0; i < n_muls_; ++i) {
                std::string key = std::format("{}{}", prefix, i);
                auto it = values.find(key);
                if (it == values.end()) {
                    throw std::runtime_error("Missing serialized assignment column " + key);
                }
                column.push_back(it->second);
            }
        };
        read_column("L", assignment.left);
        read_column("R", assignment.right);
        read_column("O", assignment.output);
        for (std::size_t i = 0; i < n_commitments_; ++i) {
            std::string key = std::format("V{}", i);
            auto it = values.find(key);
            if (it == values.end()) {
                throw std::runtime_error("Missing serialized commitment " + key);
            }
            assignment.commitments.push_back(it->second);
        }
        return assignment;
    }

    Bytes serialize_assignment(const std::unordered_map<std::string, std::optional<FieldElement>>& vars) const {
        return assignment_data(vars).serialize();
    }

private:
    struct Assignment {
        std::string symbol;
        Expr expr;
        bool is_v;
    };

    static FieldElement evaluate_known(const Expr& expr, const std::unordered_map<std::string, FieldElement>& values) {
        FieldElement out = expr.constant();
        for (const auto& term : expr.linear()) {
            auto it = values.find(term.first);
            if (it == values.end()) {
                throw std::runtime_error("Missing assignment value");
            }
            out = out + it->second * term.second;
        }
        return out;
    }

    std::vector<Assignment> assignments_;
    std::vector<std::pair<Expr, Expr>> constraints_;
    std::unordered_map<std::string, std::string> v_to_a_;
    std::vector<std::pair<std::string, std::string>> v_to_a_order_;
    std::size_t n_muls_ = 0;
    std::size_t n_commitments_ = 1;
    std::size_t n_bits_ = 0;
};

inline Expr circuit_1bit(const std::array<FieldElement, 2>& values, Transcript&, const Expr& x) {
    return Expr(values[0]) + x * (values[1] - values[0]);
}

inline Expr circuit_2bit(const std::array<FieldElement, 4>& values, Transcript& transcript, const Expr& x, const Expr& y) {
    Expr xy = transcript.mul(x, y);
    return Expr(values[0])
        + x * (values[1] - values[0])
        + y * (values[2] - values[0])
        + xy * (values[0] + values[3] - values[1] - values[2]);
}

inline Expr circuit_3bit(const std::array<FieldElement, 8>& values, Transcript& transcript, const Expr& x, const Expr& y, const Expr& z) {
    Expr xy = transcript.mul(x, y);
    Expr yz = transcript.mul(y, z);
    Expr zx = transcript.mul(z, x);
    Expr xyz = transcript.mul(xy, z);
    return Expr(values[0])
        + x * (values[1] - values[0])
        + y * (values[2] - values[0])
        + z * (values[4] - values[0])
        + xy * (values[0] + values[3] - values[1] - values[2])
        + zx * (values[0] + values[5] - values[1] - values[4])
        + yz * (values[0] + values[6] - values[2] - values[4])
        + xyz * (values[1] + values[2] + values[4] + values[7] - values[0] - values[3] - values[5] - values[6]);
}

using ExprPoint = std::pair<Expr, Expr>;

inline ExprPoint circuit_1bit_point(const EllipticCurve& curve, const std::array<JacobianPoint, 2>& points, Transcript& transcript, const Expr& b0) {
    std::array<AffinePoint, 2> affine_points{curve.affine(points[0]), curve.affine(points[1])};
    return {
        circuit_1bit({affine_points[0].x, affine_points[1].x}, transcript, b0),
        circuit_1bit({affine_points[0].y, affine_points[1].y}, transcript, b0)
    };
}

inline ExprPoint circuit_2bit_point(const EllipticCurve& curve, const std::array<JacobianPoint, 4>& points, Transcript& transcript, const Expr& b0, const Expr& b1) {
    std::array<AffinePoint, 4> affine_points{curve.affine(points[0]), curve.affine(points[1]), curve.affine(points[2]), curve.affine(points[3])};
    return {
        circuit_2bit({affine_points[0].x, affine_points[1].x, affine_points[2].x, affine_points[3].x}, transcript, b0, b1),
        circuit_2bit({affine_points[0].y, affine_points[1].y, affine_points[2].y, affine_points[3].y}, transcript, b0, b1)
    };
}

inline ExprPoint circuit_3bit_point(const EllipticCurve& curve, const std::array<JacobianPoint, 8>& points, Transcript& transcript, const Expr& b0, const Expr& b1, const Expr& b2) {
    std::array<AffinePoint, 8> affine_points{
        curve.affine(points[0]), curve.affine(points[1]), curve.affine(points[2]), curve.affine(points[3]),
        curve.affine(points[4]), curve.affine(points[5]), curve.affine(points[6]), curve.affine(points[7])
    };
    return {
        circuit_3bit({affine_points[0].x, affine_points[1].x, affine_points[2].x, affine_points[3].x,
                      affine_points[4].x, affine_points[5].x, affine_points[6].x, affine_points[7].x},
                     transcript, b0, b1, b2),
        circuit_3bit({affine_points[0].y, affine_points[1].y, affine_points[2].y, affine_points[3].y,
                      affine_points[4].y, affine_points[5].y, affine_points[6].y, affine_points[7].y},
                     transcript, b0, b1, b2)
    };
}

inline ExprPoint circuit_optionally_negate_ec(const ExprPoint& point, Transcript& transcript, const Expr& negate_bit) {
    return {point.first, transcript.mul(Expr(1) - 2 * negate_bit, point.second)};
}

inline ExprPoint circuit_ec_add(Transcript& transcript, const ExprPoint& p1, const ExprPoint& p2) {
    Expr lambda = transcript.div(p2.second - p1.second, p2.first - p1.first);
    Expr x = transcript.mul(lambda, lambda) - p1.first - p2.first;
    Expr y = transcript.mul(lambda, p1.first - x) - p1.second;
    return {x, y};
}

inline Expr circuit_ec_add_x(Transcript& transcript, const ExprPoint& p1, const ExprPoint& p2) {
    Expr lambda = transcript.div(p2.second - p1.second, p2.first - p1.first);
    return transcript.mul(lambda, lambda) - p1.first - p2.first;
}

inline Expr circuit_ec_multiply_x(const EllipticCurve& curve, Transcript& transcript, const JacobianPoint& point, const std::vector<Expr>& bits) {
    std::vector<JacobianPoint> powers;
    powers.reserve(bits.size());
    powers.push_back(point);
    for (std::size_t i = 1; i < bits.size(); ++i) {
        powers.push_back(curve.double_point(powers.back()));
    }

    std::vector<ExprPoint> lookups;
    for (std::size_t i = 0; i < (bits.size() - 1) / 3; ++i) {
        JacobianPoint p1 = powers[i * 3];
        JacobianPoint p3 = curve.add(p1, powers[i * 3 + 1]);
        JacobianPoint p5 = curve.add(p3, powers[i * 3 + 1]);
        JacobianPoint p7 = curve.add(p5, powers[i * 3 + 1]);
        lookups.push_back(circuit_optionally_negate_ec(
            circuit_2bit_point(curve, {p1, p3, p5, p7}, transcript, bits[i * 3 + 1], bits[i * 3 + 2]),
            transcript,
            bits[i * 3 + 3]));
    }

    if (bits.size() % 3 == 0) {
        JacobianPoint pn = powers[powers.size() - 3];
        JacobianPoint p3n = curve.add(pn, powers[powers.size() - 2]);
        JacobianPoint p5n = curve.add(p3n, powers[powers.size() - 2]);
        JacobianPoint p7n = curve.add(p5n, powers[powers.size() - 2]);
        JacobianPoint pn1 = curve.add(pn, powers[0]);
        JacobianPoint p3n1 = curve.add(p3n, powers[0]);
        JacobianPoint p5n1 = curve.add(p5n, powers[0]);
        JacobianPoint p7n1 = curve.add(p7n, powers[0]);
        lookups.push_back(circuit_3bit_point(curve, {pn, pn1, p3n, p3n1, p5n, p5n1, p7n, p7n1},
                                             transcript, bits[0], bits[bits.size() - 2], bits[bits.size() - 1]));
    } else if (bits.size() % 3 == 1) {
        JacobianPoint pn = powers.back();
        JacobianPoint pn1 = curve.add(pn, powers[0]);
        lookups.push_back(circuit_1bit_point(curve, {pn, pn1}, transcript, bits[0]));
    } else {
        JacobianPoint pn = powers[powers.size() - 2];
        JacobianPoint p3n = curve.add(pn, powers.back());
        JacobianPoint pn1 = curve.add(pn, powers[0]);
        JacobianPoint p3n1 = curve.add(p3n, powers[0]);
        lookups.push_back(circuit_2bit_point(curve, {pn, pn1, p3n, p3n1}, transcript, bits[0], bits.back()));
    }

    ExprPoint out = lookups[0];
    for (std::size_t i = 1; i + 1 < lookups.size(); ++i) {
        out = circuit_ec_add(transcript, out, lookups[i]);
    }
    return circuit_ec_add_x(transcript, out, lookups.back());
}

inline Expr circuit_combine(Transcript& transcript, const Expr& x1, const Expr& x2) {
    Expr u = x1;
    Expr v = x2 * field_di();
    return transcript.div(transcript.mul(u + v, transcript.mul(u, v) + Expr(field_a())) + Expr(FieldElement::from_int(2) * field_b()),
                          transcript.mul(u - v, u - v));
}

struct CircuitMainResult {
    Expr out;
    Expr p1x;
    Expr p2x;
    std::size_t n_bits;
};

inline CircuitMainResult circuit_main(Transcript& transcript, const JacobianPoint& m1, const JacobianPoint& m2,
                                      const std::optional<UInt256>& z1 = std::nullopt,
                                      const std::optional<UInt256>& z2 = std::nullopt) {
    int z1_bits_len = static_cast<int>(order_n1().bit_length()) - 1;
    int z2_bits_len = static_cast<int>(order_n2().bit_length()) - 1;
    std::vector<int> z1_values(z1_bits_len, -1);
    std::vector<int> z2_values(z2_bits_len, -1);
    if (z1.has_value() && z2.has_value()) {
        z1_values = key_to_bits(*z1, z1_bits_len);
        z2_values = key_to_bits(*z2, z2_bits_len);
    }
    std::vector<Expr> z1_bits;
    std::vector<Expr> z2_bits;
    z1_bits.reserve(z1_values.size());
    z2_bits.reserve(z2_values.size());
    for (int bit : z1_values) {
        z1_bits.push_back(transcript.boolean(transcript.secret(bit < 0 ? std::nullopt : std::optional<FieldElement>(FieldElement::from_int(bit)))));
    }
    for (int bit : z2_values) {
        z2_bits.push_back(transcript.boolean(transcript.secret(bit < 0 ? std::nullopt : std::optional<FieldElement>(FieldElement::from_int(bit)))));
    }
    std::size_t n_bits = z1_bits.size() + z2_bits.size();
    Expr out_p1x = circuit_ec_multiply_x(curve1(), transcript, generator1(), z1_bits);
    Expr out_p2x = circuit_ec_multiply_x(curve2(), transcript, generator2(), z2_bits);
    Expr out_x1 = circuit_ec_multiply_x(curve1(), transcript, m1, z1_bits);
    Expr out_x2 = circuit_ec_multiply_x(curve2(), transcript, m2, z2_bits);
    return {circuit_combine(transcript, out_x1, out_x2), out_p1x, out_p2x, n_bits};
}

struct GeneratedKey {
    UInt512 secret;
    UInt512 public_key;
};

struct BulletproofWitnessData {
    UInt512 public_key;
    FieldElement output;
    BulletproofAssignmentData assignment;
};

inline UInt512 key_space_size() {
    static const UInt512 value = multiply(half_n1(), half_n2());
    return value;
}

inline GeneratedKey derive_key(const UInt512& secret) {
    auto unpacked = unpack_secret(secret);
    AffinePoint p1 = curve1().affine(curve1().mul(generator1(), unpacked.first));
    AffinePoint p2 = curve2().affine(curve2().mul(generator2(), unpacked.second));
    return {secret, pack_public(p1.x.to_uint256(), p2.x.to_uint256())};
}

inline FieldElement eval(const UInt512& secret, const Bytes& message) {
    auto unpacked = unpack_secret(secret);
    JacobianPoint m1 = hash_to_curve(bytes_from_ascii("Eval/1/") + message, curve1());
    JacobianPoint m2 = hash_to_curve(bytes_from_ascii("Eval/2/") + message, curve2());
    AffinePoint q1 = curve1().affine(curve1().mul(m1, unpacked.first));
    AffinePoint q2 = curve2().affine(curve2().mul(m2, unpacked.second));
    return combine(q1.x, q2.x);
}

inline std::string verifier(const Bytes& message, const UInt512& pubkey) {
    JacobianPoint m1 = hash_to_curve(bytes_from_ascii("Eval/1/") + message, curve1());
    JacobianPoint m2 = hash_to_curve(bytes_from_ascii("Eval/2/") + message, curve2());
    Transcript transcript;
    CircuitMainResult result = circuit_main(transcript, m1, m2);
    BulletproofTranscript bp;
    bp.from_transcript(transcript, result.n_bits);
    bp.add_pubkey_and_out(pubkey, result.p1x, result.p2x, result.out);
    return bp.to_string();
}

inline NativeBulletproofCircuit verifier_circuit(const Bytes& message, const UInt512& pubkey) {
    JacobianPoint m1 = hash_to_curve(bytes_from_ascii("Eval/1/") + message, curve1());
    JacobianPoint m2 = hash_to_curve(bytes_from_ascii("Eval/2/") + message, curve2());
    Transcript transcript;
    CircuitMainResult result = circuit_main(transcript, m1, m2);
    BulletproofTranscript bp;
    bp.from_transcript(transcript, result.n_bits);
    bp.add_pubkey_and_out(pubkey, result.p1x, result.p2x, result.out);
    return bp.native_circuit();
}

inline BulletproofWitnessData prove_assignment_data(const Bytes& message, const UInt512& secret) {
    auto unpacked = unpack_secret(secret);
    JacobianPoint m1 = hash_to_curve(bytes_from_ascii("Eval/1/") + message, curve1());
    JacobianPoint m2 = hash_to_curve(bytes_from_ascii("Eval/2/") + message, curve2());
    AffinePoint p1 = curve1().affine(curve1().mul(generator1(), unpacked.first));
    AffinePoint p2 = curve2().affine(curve2().mul(generator2(), unpacked.second));
    AffinePoint q1 = curve1().affine(curve1().mul(m1, unpacked.first));
    AffinePoint q2 = curve2().affine(curve2().mul(m2, unpacked.second));
    FieldElement native_out = combine(q1.x, q2.x);

    Transcript transcript;
    CircuitMainResult result = circuit_main(transcript, m1, m2, unpacked.first, unpacked.second);
    if (transcript.evaluate(result.p1x) != std::optional<FieldElement>(p1.x)) {
        throw std::runtime_error("P1x mismatch");
    }
    if (transcript.evaluate(result.p2x) != std::optional<FieldElement>(p2.x)) {
        throw std::runtime_error("P2x mismatch");
    }
    if (transcript.evaluate(result.out) != std::optional<FieldElement>(native_out)) {
        throw std::runtime_error("Output mismatch");
    }

    UInt512 pubkey = pack_public(p1.x.to_uint256(), p2.x.to_uint256());
    BulletproofTranscript bp;
    bp.from_transcript(transcript, result.n_bits);
    bp.add_pubkey_and_out(pubkey, result.p1x, result.p2x, result.out);
    if (!bp.evaluate(transcript.varmap(), native_out)) {
        throw std::runtime_error("Bulletproof transcript check failed");
    }

    auto vars = transcript.varmap();
    auto it = vars.find("V0");
    if (it == vars.end()) {
        vars.insert({"V0", native_out});
    } else {
        vars["V0"] = native_out;
    }
    return {pubkey, native_out, bp.assignment_data(vars)};
}

inline bool evaluate_verifier_circuit(const Bytes& message, const BulletproofWitnessData& witness) {
    return verifier_circuit(message, witness.public_key).evaluate(witness.assignment);
}

inline bool evaluate_verifier_circuit(const Bytes& message, const UInt512& secret) {
    return evaluate_verifier_circuit(message, prove_assignment_data(message, secret));
}

inline Bytes prove_assignment(const Bytes& message, const UInt512& secret) {
    return prove_assignment_data(message, secret).assignment.serialize();
}

}  // namespace purify
