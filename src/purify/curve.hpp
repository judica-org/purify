// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include "purify/numeric.hpp"

namespace purify {

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

}  // namespace purify
