// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file purify_curve.cpp
 * @brief Compiled elliptic-curve helpers, parameters, and key encoding logic for Purify.
 */

#include "purify/curve.hpp"

#include <algorithm>

#include "purify_curve_core.h"

namespace purify {

namespace {

purify_fe to_core(const FieldElement& value) {
    return purify_fe{detail::FieldElementAccess::raw(value)};
}

FieldElement from_core(const purify_fe& value) {
    return detail::FieldElementAccess::from_raw(value.value);
}

purify_jacobian_point to_core(const JacobianPoint& point) {
    return purify_jacobian_point{to_core(point.x), to_core(point.y), to_core(point.z), point.infinity ? 1 : 0};
}

JacobianPoint from_core(const purify_jacobian_point& point) {
    return JacobianPoint{from_core(point.x), from_core(point.y), from_core(point.z), point.infinity != 0};
}

purify_affine_point to_core(const AffinePoint& point) {
    return purify_affine_point{to_core(point.x), to_core(point.y), point.infinity ? 1 : 0};
}

AffinePoint from_core(const purify_affine_point& point) {
    return AffinePoint{from_core(point.x), from_core(point.y), point.infinity != 0};
}

UInt256 uint256_from_core(void (*fill)(uint64_t*)) {
    UInt256 out;
    fill(out.limbs.data());
    return out;
}

UInt320 uint320_from_core(void (*fill)(uint64_t*)) {
    UInt320 out;
    fill(out.limbs.data());
    return out;
}

UInt512 uint512_from_core(void (*fill)(uint64_t*)) {
    UInt512 out;
    fill(out.limbs.data());
    return out;
}

FieldElement field_from_core(void (*fill)(purify_fe*)) {
    purify_fe out{};
    fill(&out);
    return from_core(out);
}

purify_curve make_core_curve(const FieldElement& a, const FieldElement& b, const UInt256& n) {
    purify_curve out{};
    out.a = to_core(a);
    out.b = to_core(b);
    std::copy(n.limbs.begin(), n.limbs.end(), out.n);
    return out;
}

}  // namespace

JacobianPoint JacobianPoint::infinity_point() {
    purify_jacobian_point out{};
    purify_curve_jacobian_infinity(&out);
    return from_core(out);
}

EllipticCurve::EllipticCurve(FieldElement a, FieldElement b, UInt256 n)
    : a_(std::move(a)), b_(std::move(b)), n_(std::move(n)) {}

AffinePoint EllipticCurve::affine(const JacobianPoint& point) const {
    purify_curve curve = make_core_curve(a_, b_, n_);
    purify_jacobian_point in = to_core(point);
    purify_affine_point out{};
    purify_curve_affine(&out, &curve, &in);
    return from_core(out);
}

JacobianPoint EllipticCurve::negate(const JacobianPoint& point) const {
    purify_jacobian_point in = to_core(point);
    purify_jacobian_point out{};
    purify_curve_negate(&out, &in);
    return from_core(out);
}

bool EllipticCurve::is_x_coord(const FieldElement& x) const {
    purify_curve curve = make_core_curve(a_, b_, n_);
    purify_fe in = to_core(x);
    return purify_curve_is_x_coord(&curve, &in) != 0;
}

std::optional<JacobianPoint> EllipticCurve::lift_x(const FieldElement& x) const {
    purify_curve curve = make_core_curve(a_, b_, n_);
    purify_fe in = to_core(x);
    purify_jacobian_point out{};
    if (purify_curve_lift_x(&out, &curve, &in) == 0) {
        return std::nullopt;
    }
    return from_core(out);
}

JacobianPoint EllipticCurve::double_point(const JacobianPoint& point) const {
    purify_curve curve = make_core_curve(a_, b_, n_);
    purify_jacobian_point in = to_core(point);
    purify_jacobian_point out{};
    purify_curve_double(&out, &curve, &in);
    return from_core(out);
}

JacobianPoint EllipticCurve::add_mixed(const JacobianPoint& lhs, const AffinePoint& rhs) const {
    purify_curve curve = make_core_curve(a_, b_, n_);
    purify_jacobian_point lhs_core = to_core(lhs);
    purify_affine_point rhs_core = to_core(rhs);
    purify_jacobian_point out{};
    purify_curve_add_mixed(&out, &curve, &lhs_core, &rhs_core);
    return from_core(out);
}

JacobianPoint EllipticCurve::add(const JacobianPoint& lhs, const JacobianPoint& rhs) const {
    purify_curve curve = make_core_curve(a_, b_, n_);
    purify_jacobian_point lhs_core = to_core(lhs);
    purify_jacobian_point rhs_core = to_core(rhs);
    purify_jacobian_point out{};
    purify_curve_add(&out, &curve, &lhs_core, &rhs_core);
    return from_core(out);
}

JacobianPoint EllipticCurve::mul(const JacobianPoint& point, const UInt256& scalar) const {
    purify_curve curve = make_core_curve(a_, b_, n_);
    purify_jacobian_point in = to_core(point);
    purify_jacobian_point out{};
    purify_curve_mul(&out, &curve, &in, scalar.limbs.data());
    return from_core(out);
}

Result<AffinePoint> EllipticCurve::mul_secret_affine(const JacobianPoint& point, const UInt256& scalar) const {
    purify_curve curve = make_core_curve(a_, b_, n_);
    purify_jacobian_point point_core = to_core(point);
    purify_affine_point out{};
    if (purify_curve_mul_secret_affine(&out, &curve, &point_core, scalar.limbs.data()) == 0) {
        return unexpected_error(ErrorCode::InternalMismatch,
                                "EllipticCurve::mul_secret_affine:purify_curve_mul_secret_affine");
    }
    return from_core(out);
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
    static const UInt256 value = uint256_from_core(purify_curve_prime_p);
    return value;
}

const UInt256& order_n1() {
    static const UInt256 value = uint256_from_core(purify_curve_order_n1);
    return value;
}

const UInt256& order_n2() {
    static const UInt256 value = uint256_from_core(purify_curve_order_n2);
    return value;
}

const UInt256& half_n1() {
    static const UInt256 value = uint256_from_core(purify_curve_half_n1);
    return value;
}

const UInt256& half_n2() {
    static const UInt256 value = uint256_from_core(purify_curve_half_n2);
    return value;
}

const UInt512& packed_secret_key_space_size() {
    static const UInt512 value = uint512_from_core(purify_curve_packed_secret_key_space_size);
    return value;
}

const UInt512& packed_public_key_space_size() {
    static const UInt512 value = uint512_from_core(purify_curve_packed_public_key_space_size);
    return value;
}

const UInt320& two_p() {
    static const UInt320 value = uint320_from_core(purify_curve_two_p);
    return value;
}

FieldElement field_a() {
    return field_from_core(purify_curve_field_a);
}

FieldElement field_b() {
    return field_from_core(purify_curve_field_b);
}

FieldElement field_d() {
    return field_from_core(purify_curve_field_d);
}

FieldElement field_di() {
    static const FieldElement value = field_from_core(purify_curve_field_di);
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
    purify_curve curve_core = make_core_curve(curve.a_, curve.b_, curve.n_);
    purify_jacobian_point out{};
    if (purify_curve_hash_to_curve(&out, &curve_core, data.data(), data.size()) == 0) {
        return unexpected_error(ErrorCode::HashToCurveExhausted, "hash_to_curve:purify_curve_hash_to_curve");
    }
    return from_core(out);
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
    return purify_curve_is_valid_secret_key(z.limbs.data()) != 0;
}

bool is_valid_public_key(const UInt512& packed) {
    return purify_curve_is_valid_public_key(packed.limbs.data()) != 0;
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
    UInt256 first;
    UInt256 second;
    if (purify_curve_unpack_secret(first.limbs.data(), second.limbs.data(), z.limbs.data()) == 0) {
        return unexpected_error(ErrorCode::RangeViolation, "unpack_secret:validate_secret_key");
    }
    return std::make_pair(first, second);
}

Result<std::pair<UInt256, UInt256>> unpack_public(const UInt512& packed) {
    UInt256 first;
    UInt256 second;
    if (purify_curve_unpack_public(first.limbs.data(), second.limbs.data(), packed.limbs.data()) == 0) {
        return unexpected_error(ErrorCode::RangeViolation, "unpack_public:validate_public_key");
    }
    return std::make_pair(first, second);
}

UInt512 pack_public(const UInt256& x1, const UInt256& x2) {
    UInt512 out;
    purify_curve_pack_public(out.limbs.data(), x1.limbs.data(), x2.limbs.data());
    return out;
}

FieldElement combine(const FieldElement& x1, const FieldElement& x2) {
    purify_fe lhs = to_core(x1);
    purify_fe rhs = to_core(x2);
    purify_fe out{};
    purify_curve_combine(&out, &lhs, &rhs);
    return from_core(out);
}

Result<std::vector<int>> key_to_bits(UInt256 n, const UInt256& max_value) {
    std::vector<int> out(max_value.bit_length());
    if (purify_curve_key_to_bits(out.data(), out.size(), n.limbs.data(), max_value.limbs.data()) == 0) {
        return unexpected_error(ErrorCode::RangeViolation, "key_to_bits:out_of_range");
    }
    return out;
}

}  // namespace purify
