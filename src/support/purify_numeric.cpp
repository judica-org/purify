// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file purify_numeric.cpp
 * @brief Compiled FieldElement implementation for Purify numeric helpers.
 */

#include "purify/numeric.hpp"

#include "purify_field.h"

namespace purify {

namespace {

purify_fe to_core(const FieldElement& value) {
    return purify_fe{detail::FieldElementAccess::raw(value)};
}

FieldElement from_core(const purify_fe& value) {
    return detail::FieldElementAccess::from_raw(value.value);
}

}  // namespace

FieldElement::FieldElement() {
    purify_scalar_set_int(&value_, 0);
}

FieldElement FieldElement::zero() {
    return FieldElement();
}

FieldElement FieldElement::one() {
    return from_u64(1);
}

FieldElement FieldElement::from_u64(std::uint64_t value) {
    FieldElement out;
    purify_scalar_set_u64(&out.value_, value);
    return out;
}

FieldElement FieldElement::from_int(std::int64_t value) {
    if (value >= 0) {
        return from_u64(static_cast<std::uint64_t>(value));
    }
    return from_u64(static_cast<std::uint64_t>(-value)).negate();
}

Result<FieldElement> FieldElement::try_from_bytes32(const std::array<unsigned char, 32>& bytes) {
    FieldElement out;
    int overflow = 0;
    purify_scalar_set_b32(&out.value_, bytes.data(), &overflow);
    if (overflow != 0) {
        return unexpected_error(ErrorCode::RangeViolation, "FieldElement::try_from_bytes32:out_of_range");
    }
    return out;
}

FieldElement FieldElement::from_bytes32(const std::array<unsigned char, 32>& bytes) {
    Result<FieldElement> out = try_from_bytes32(bytes);
    assert(out.has_value() && "FieldElement::from_bytes32() requires a canonical field element");
    return std::move(*out);
}

Result<FieldElement> FieldElement::try_from_uint256(const UInt256& value) {
    return try_from_bytes32(value.to_bytes_be());
}

FieldElement FieldElement::from_uint256(const UInt256& value) {
    Result<FieldElement> out = try_from_uint256(value);
    assert(out.has_value() && "FieldElement::from_uint256() requires a canonical field element");
    return std::move(*out);
}

UInt256 FieldElement::to_uint256() const {
    std::array<unsigned char, 32> bytes = to_bytes_be();
    return UInt256::from_bytes_be(bytes.data(), bytes.size());
}

std::array<unsigned char, 32> FieldElement::to_bytes_be() const {
    std::array<unsigned char, 32> bytes{};
    purify_scalar_get_b32(bytes.data(), &value_);
    return bytes;
}

std::array<unsigned char, 32> FieldElement::to_bytes_le() const {
    std::array<unsigned char, 32> bytes = to_bytes_be();
    std::reverse(bytes.begin(), bytes.end());
    return bytes;
}

std::string FieldElement::to_hex() const {
    return to_uint256().to_hex();
}

std::string FieldElement::to_decimal() const {
    return to_uint256().to_decimal();
}

bool FieldElement::is_zero() const {
    return purify_scalar_is_zero(&value_) != 0;
}

bool FieldElement::is_one() const {
    return purify_scalar_is_one(&value_) != 0;
}

bool FieldElement::is_odd() const {
    return purify_scalar_is_even(&value_) == 0;
}

bool FieldElement::is_square() const {
    const purify_fe input = to_core(*this);
    return purify_fe_is_square(&input) != 0;
}

FieldElement FieldElement::negate() const {
    FieldElement out;
    purify_scalar_negate(&out.value_, &value_);
    return out;
}

void FieldElement::conditional_assign(const FieldElement& other, bool flag) {
    purify_scalar_cmov(&value_, &other.value_, flag ? 1 : 0);
}

FieldElement FieldElement::inverse_consttime() const {
    FieldElement out;
    purify_scalar_inverse(&out.value_, &value_);
    return out;
}

FieldElement FieldElement::inverse() const {
    FieldElement out;
    purify_scalar_inverse_var(&out.value_, &value_);
    return out;
}

std::optional<FieldElement> FieldElement::sqrt() const {
    const purify_fe input = to_core(*this);
    purify_fe output{};
    if (purify_fe_sqrt(&output, &input) == 0) {
        return std::nullopt;
    }
    return from_core(output);
}

FieldElement FieldElement::pow(const UInt256& exponent) const {
    const purify_fe input = to_core(*this);
    purify_fe output{};
    purify_fe_pow(&output, &input, exponent.limbs.data());
    return from_core(output);
}

bool operator==(const FieldElement& lhs, const FieldElement& rhs) {
    return purify_scalar_eq(&lhs.value_, &rhs.value_) != 0;
}

bool operator!=(const FieldElement& lhs, const FieldElement& rhs) {
    return !(lhs == rhs);
}

FieldElement operator+(const FieldElement& lhs, const FieldElement& rhs) {
    FieldElement out;
    purify_scalar_add(&out.value_, &lhs.value_, &rhs.value_);
    return out;
}

FieldElement operator-(const FieldElement& lhs, const FieldElement& rhs) {
    return lhs + rhs.negate();
}

FieldElement operator*(const FieldElement& lhs, const FieldElement& rhs) {
    FieldElement out;
    purify_scalar_mul(&out.value_, &lhs.value_, &rhs.value_);
    return out;
}

FieldElement square(const FieldElement& value) {
    const purify_fe input = to_core(value);
    purify_fe output{};
    purify_fe_square(&output, &input);
    return from_core(output);
}

int legendre_symbol(const FieldElement& value) {
    const purify_fe input = to_core(value);
    return purify_fe_legendre_symbol(&input);
}

}  // namespace purify
