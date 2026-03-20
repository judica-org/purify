// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file purify_curve.cpp
 * @brief Compiled elliptic-curve helpers, parameters, and key encoding logic for Purify.
 */

#include "purify/curve.hpp"

namespace purify {

JacobianPoint JacobianPoint::infinity_point() {
    return {FieldElement::zero(), FieldElement::one(), FieldElement::zero(), true};
}

EllipticCurve::EllipticCurve(FieldElement a, FieldElement b, UInt256 n)
    : a_(std::move(a)), b_(std::move(b)), n_(std::move(n)) {}

AffinePoint EllipticCurve::affine(const JacobianPoint& point) const {
    if (point.infinity || point.z.is_zero()) {
        return {FieldElement::zero(), FieldElement::zero(), true};
    }
    FieldElement inv = point.z.inverse();
    FieldElement inv2 = inv * inv;
    FieldElement inv3 = inv2 * inv;
    return {inv2 * point.x, inv3 * point.y, false};
}

JacobianPoint EllipticCurve::negate(const JacobianPoint& point) const {
    if (point.infinity) {
        return point;
    }
    return {point.x, point.y.negate(), point.z, false};
}

bool EllipticCurve::is_x_coord(const FieldElement& x) const {
    FieldElement v = square(x) * x + a_ * x + b_;
    return legendre_symbol(v) != -1;
}

std::optional<JacobianPoint> EllipticCurve::lift_x(const FieldElement& x) const {
    FieldElement v = square(x) * x + a_ * x + b_;
    std::optional<FieldElement> y = v.sqrt();
    if (!y.has_value()) {
        return std::nullopt;
    }
    return JacobianPoint{x, *y, FieldElement::one(), false};
}

JacobianPoint EllipticCurve::double_point(const JacobianPoint& point) const {
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

JacobianPoint EllipticCurve::add_mixed(const JacobianPoint& lhs, const AffinePoint& rhs) const {
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

JacobianPoint EllipticCurve::add(const JacobianPoint& lhs, const JacobianPoint& rhs) const {
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

JacobianPoint EllipticCurve::mul(const JacobianPoint& point, const UInt256& scalar) const {
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

Result<AffinePoint> EllipticCurve::mul_secret_affine(const JacobianPoint& point, const UInt256& scalar) const {
    CompleteProjectivePoint r0 = complete_identity();
    CompleteProjectivePoint r1 = secret_input_point(point);
    unsigned prev_bit = 0;
    std::size_t bits = n_.bit_length();
    for (std::size_t i = bits; i-- > 0;) {
        unsigned bit = scalar.bit(i) ? 1U : 0U;
        conditional_swap(r0, r1, bit ^ prev_bit);
        CompleteProjectivePoint sum = complete_add(r0, r1);
        CompleteProjectivePoint doubled = complete_double(r0);
        r1 = std::move(sum);
        r0 = std::move(doubled);
        prev_bit = bit;
    }
    conditional_swap(r0, r1, prev_bit);
    if (r0.z.is_zero()) {
        return unexpected_error(ErrorCode::InternalMismatch, "EllipticCurve::mul_secret_affine:point_at_infinity");
    }
    FieldElement inv = r0.z.inverse_consttime();
    return AffinePoint{r0.x * inv, r0.y * inv, false};
}

CompleteProjectivePoint EllipticCurve::complete_identity() {
    return {FieldElement::zero(), FieldElement::one(), FieldElement::zero()};
}

CompleteProjectivePoint EllipticCurve::secret_input_point(const JacobianPoint& point) const {
    if (point.infinity || point.z.is_zero()) {
        return complete_identity();
    }
    if (point.z.is_one()) {
        return {point.x, point.y, point.z};
    }
    AffinePoint normalized = affine(point);
    return {normalized.x, normalized.y, FieldElement::one()};
}

void EllipticCurve::conditional_assign(CompleteProjectivePoint& dst, const CompleteProjectivePoint& src, bool flag) {
    dst.x.conditional_assign(src.x, flag);
    dst.y.conditional_assign(src.y, flag);
    dst.z.conditional_assign(src.z, flag);
}

void EllipticCurve::conditional_swap(CompleteProjectivePoint& lhs, CompleteProjectivePoint& rhs, bool flag) {
    CompleteProjectivePoint tmp = lhs;
    conditional_assign(lhs, rhs, flag);
    conditional_assign(rhs, tmp, flag);
}

CompleteProjectivePoint EllipticCurve::complete_add(const CompleteProjectivePoint& lhs, const CompleteProjectivePoint& rhs) const {
    FieldElement b3 = b_ + b_ + b_;
    FieldElement t0 = lhs.x * rhs.x;
    FieldElement t1 = lhs.y * rhs.y;
    FieldElement t2 = lhs.z * rhs.z;
    FieldElement t3 = lhs.x + lhs.y;
    FieldElement t4 = rhs.x + rhs.y;
    t3 = t3 * t4;
    t4 = t0 + t1;
    t3 = t3 - t4;
    t4 = lhs.x + lhs.z;
    FieldElement t5 = rhs.x + rhs.z;
    t4 = t4 * t5;
    t5 = t0 + t2;
    t4 = t4 - t5;
    t5 = lhs.y + lhs.z;
    FieldElement x3 = rhs.y + rhs.z;
    t5 = t5 * x3;
    x3 = t1 + t2;
    t5 = t5 - x3;
    FieldElement z3 = a_ * t4;
    x3 = b3 * t2;
    z3 = x3 + z3;
    x3 = t1 - z3;
    z3 = t1 + z3;
    FieldElement y3 = x3 * z3;
    t1 = t0 + t0;
    t1 = t1 + t0;
    t2 = a_ * t2;
    t4 = b3 * t4;
    t1 = t1 + t2;
    t2 = t0 - t2;
    t2 = a_ * t2;
    t4 = t4 + t2;
    t0 = t1 * t4;
    y3 = y3 + t0;
    t0 = t5 * t4;
    x3 = t3 * x3;
    x3 = x3 - t0;
    t0 = t3 * t1;
    z3 = t5 * z3;
    z3 = z3 + t0;
    return {x3, y3, z3};
}

CompleteProjectivePoint EllipticCurve::complete_double(const CompleteProjectivePoint& point) const {
    FieldElement b3 = b_ + b_ + b_;
    FieldElement t0 = point.x * point.x;
    FieldElement t1 = point.y * point.y;
    FieldElement t2 = point.z * point.z;
    FieldElement t3 = point.x * point.y;
    t3 = t3 + t3;
    FieldElement z3 = point.x * point.z;
    z3 = z3 + z3;
    FieldElement x3 = a_ * z3;
    FieldElement y3 = b3 * t2;
    y3 = x3 + y3;
    x3 = t1 - y3;
    y3 = t1 + y3;
    y3 = x3 * y3;
    x3 = t3 * x3;
    z3 = b3 * z3;
    t2 = a_ * t2;
    t3 = t0 - t2;
    t3 = a_ * t3;
    t3 = t3 + z3;
    z3 = t0 + t0;
    t0 = z3 + t0;
    t0 = t0 + t2;
    t0 = t0 * t3;
    y3 = y3 + t0;
    t2 = point.y * point.z;
    t2 = t2 + t2;
    t0 = t2 * t3;
    x3 = x3 - t0;
    z3 = t2 * t1;
    z3 = z3 + z3;
    z3 = z3 + z3;
    return {x3, y3, z3};
}

Bytes bytes_from_ascii(std::string_view input) {
    return Bytes(input.begin(), input.end());
}

Bytes operator+(Bytes lhs, const Bytes& rhs) {
    lhs.insert(lhs.end(), rhs.begin(), rhs.end());
    return lhs;
}

std::uint64_t ceil_div(std::uint64_t lhs, std::uint64_t rhs) {
    return (lhs + rhs - 1) / rhs;
}

Bytes hmac_sha256(const Bytes& key, const Bytes& data) {
    Bytes out(32);
    purify_hmac_sha256(out.data(), key.data(), key.size(), data.data(), data.size());
    return out;
}

Bytes hkdf(std::size_t length, const Bytes& ikm, const Bytes& salt, const Bytes& info) {
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

const UInt256& prime_p() {
    static const UInt256 value = UInt256::from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    return value;
}

const UInt256& order_n1() {
    static const UInt256 value = UInt256::from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA328F244053472128A5A2A2C58E547E9");
    return value;
}

const UInt256& order_n2() {
    static const UInt256 value = UInt256::from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDD234C789595CCE64F54A92ED47873A9B");
    return value;
}

const UInt256& half_n1() {
    static const UInt256 value = UInt256::from_hex("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD1947922029A3909452D15162C72A3F4");
    return value;
}

const UInt256& half_n2() {
    static const UInt256 value = UInt256::from_hex("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEE91A63C4ACAE67327AA54976A3C39D4D");
    return value;
}

const UInt512& packed_secret_key_space_size() {
    static const UInt512 value = multiply(half_n1(), half_n2());
    return value;
}

const UInt512& packed_public_key_space_size() {
    static const UInt512 value = multiply(prime_p(), prime_p());
    return value;
}

const UInt320& two_p() {
    static const UInt320 value = [] {
        UInt320 out = widen<5>(prime_p());
        out.mul_small(2);
        return out;
    }();
    return value;
}

FieldElement field_a() {
    return FieldElement::from_int(118);
}

FieldElement field_b() {
    return FieldElement::from_int(339);
}

FieldElement field_d() {
    return FieldElement::from_int(5);
}

FieldElement field_di() {
    static const FieldElement value = FieldElement::from_uint256(
        UInt256::from_hex("66666666666666666666666666666665E445F1F5DFB6A67E4CBA8C385348E6E7"));
    return value;
}

const EllipticCurve& curve1() {
    static const EllipticCurve curve(field_a(), field_b(), order_n1());
    return curve;
}

const EllipticCurve& curve2() {
    static const EllipticCurve curve(field_a() * field_d() * field_d(),
                                     field_b() * field_d() * field_d() * field_d(),
                                     order_n2());
    return curve;
}

Result<JacobianPoint> hash_to_curve(const Bytes& data, const EllipticCurve& curve) {
    static const TaggedHash kHashToCurveTag("Purify/HashToCurve");
    for (int i = 0; i < 256; ++i) {
        Bytes info{static_cast<unsigned char>(i)};
#if PURIFY_USE_LEGACY_FIELD_HASHES
        std::optional<UInt320> value = hash_to_int(data, two_p(), info);
#else
        std::optional<UInt320> value =
            tagged_hash_to_int<5>(std::span<const unsigned char>(data.data(), data.size()), two_p(), kHashToCurveTag, info);
#endif
        if (!value.has_value()) {
            continue;
        }
        UInt320 x_candidate = value->shifted_right(1);
        Result<UInt256> narrowed = try_narrow<4>(x_candidate);
        assert(narrowed.has_value() && "hash_to_curve() x-coordinate candidate should fit in 256 bits");
        if (!narrowed.has_value()) {
            return unexpected_error(ErrorCode::InternalMismatch, "hash_to_curve:narrow_x_candidate");
        }
        FieldElement x = FieldElement::from_uint256(*narrowed);
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
    return unexpected_error(ErrorCode::HashToCurveExhausted, "hash_to_curve:exhausted_retries");
}

const JacobianPoint& generator1() {
    static const JacobianPoint value = [] {
        Result<JacobianPoint> point_result = hash_to_curve(bytes_from_ascii("Generator/1"), curve1());
        assert(point_result.has_value() && "generator1() hash_to_curve should not exhaust");
        JacobianPoint point = *point_result;
        assert(curve1().mul(point, order_n1()).infinity && "generator1() subgroup order check failed");
        return point;
    }();
    return value;
}

const JacobianPoint& generator2() {
    static const JacobianPoint value = [] {
        Result<JacobianPoint> point_result = hash_to_curve(bytes_from_ascii("Generator/2"), curve2());
        assert(point_result.has_value() && "generator2() hash_to_curve should not exhaust");
        JacobianPoint point = *point_result;
        assert(curve2().mul(point, order_n2()).infinity && "generator2() subgroup order check failed");
        return point;
    }();
    return value;
}

bool is_valid_secret_key(const UInt512& z) {
    return z.compare(packed_secret_key_space_size()) < 0;
}

bool is_valid_public_key(const UInt512& packed) {
    return packed.compare(packed_public_key_space_size()) < 0;
}

Status validate_secret_key(const UInt512& z) {
    if (!is_valid_secret_key(z)) {
        return unexpected_error(ErrorCode::RangeViolation, "validate_secret_key:out_of_range");
    }
    return {};
}

Status validate_public_key(const UInt512& packed) {
    if (!is_valid_public_key(packed)) {
        return unexpected_error(ErrorCode::RangeViolation, "validate_public_key:out_of_range");
    }
    return {};
}

Result<std::pair<UInt256, UInt256>> unpack_secret(const UInt512& z) {
    Status status = validate_secret_key(z);
    if (!status.has_value()) {
        return unexpected_error(status.error(), "unpack_secret:validate_secret_key");
    }
    auto qr = divmod_same(z, widen<8>(half_n1()));
    UInt256 z1 = narrow<4>(qr.second);
    UInt256 z2 = narrow<4>(qr.first);
    z1.add_small(1);
    z2.add_small(1);
    return std::make_pair(z1, z2);
}

Result<std::pair<UInt256, UInt256>> unpack_public(const UInt512& packed) {
    Status status = validate_public_key(packed);
    if (!status.has_value()) {
        return unexpected_error(status.error(), "unpack_public:validate_public_key");
    }
    auto qr = divmod_same(packed, widen<8>(prime_p()));
    return std::make_pair(narrow<4>(qr.second), narrow<4>(qr.first));
}

UInt512 pack_public(const UInt256& x1, const UInt256& x2) {
    UInt512 out = multiply(prime_p(), x2);
    out.add_assign(widen<8>(x1));
    return out;
}

FieldElement combine(const FieldElement& x1, const FieldElement& x2) {
    FieldElement u = x1;
    FieldElement v = x2 * field_di();
    FieldElement w = (u - v).inverse_consttime();
    return ((u + v) * (field_a() + u * v) + FieldElement::from_int(2) * field_b()) * w * w;
}

Result<std::vector<int>> key_to_bits(UInt256 n, const UInt256& max_value) {
    if (n.is_zero() || n.compare(max_value) > 0) {
        return unexpected_error(ErrorCode::RangeViolation, "key_to_bits:out_of_range");
    }
    int bits = static_cast<int>(max_value.bit_length());
    n.sub_assign(UInt256::one());
    std::vector<int> out(bits);
    for (int i = 0; i < bits; ++i) {
        out[i] = static_cast<int>(n.bit(static_cast<std::size_t>(i)));
    }
    for (int i = 3; i < bits; i += 3) {
        int flip = 1 - out[i];
        out[i - 1] ^= flip;
        out[i - 2] ^= flip;
        out[i] ^= 1;
    }
    return out;
}

}  // namespace purify
