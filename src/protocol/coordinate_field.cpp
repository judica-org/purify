// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "coordinate_field.hpp"

#include <algorithm>
#include <exception>
#include <utility>

#include "bppp_bridge.h"
#include "purify/numeric.hpp"

namespace purify::bppp::candidate {
namespace {

const UInt256& coordinate_modulus() {
    static const UInt256 modulus =
        UInt256::from_hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
    return modulus;
}

CoordinateFieldElement from_integer(const UInt256& value) {
    auto parsed = CoordinateFieldElement::from_bytes_be(value.to_bytes_be());
    if (!parsed.has_value()) std::terminate();
    return std::move(*parsed);
}

} // namespace

Result<CoordinateFieldElement> CoordinateFieldElement::from_bytes_be(const Encoding& encoded) {
    if (purify_bppp_coordinate_field_validate(encoded.data()) == 0) {
        return unexpected_error(ErrorCode::RangeViolation, "coordinate_field:noncanonical");
    }
    return CoordinateFieldElement(encoded);
}

CoordinateFieldElement CoordinateFieldElement::from_reduced_bytes_be(const Encoding& encoded) {
    UInt256 value = UInt256::from_bytes_be(encoded.data(), encoded.size());
    if (value >= coordinate_modulus()) {
        value.sub_assign(coordinate_modulus());
    }
    return from_integer(value);
}

CoordinateFieldElement CoordinateFieldElement::from_u64(std::uint64_t value) {
    return from_integer(UInt256::from_u64(value));
}

CoordinateFieldElement CoordinateFieldElement::zero() { return CoordinateFieldElement(); }

CoordinateFieldElement CoordinateFieldElement::one() { return from_u64(1); }

bool CoordinateFieldElement::is_zero() const noexcept {
    return std::all_of(encoded_.begin(), encoded_.end(),
                       [](unsigned char byte) { return byte == 0; });
}

Result<CoordinateFieldElement> CoordinateFieldElement::inverse() const {
    Encoding out{};
    if (purify_bppp_coordinate_field_inverse(encoded_.data(), out.data()) == 0) {
        return unexpected_error(ErrorCode::RangeViolation, "coordinate_field:inverse_zero");
    }
    return CoordinateFieldElement(out);
}

CoordinateFieldElement operator+(const CoordinateFieldElement& left,
                                 const CoordinateFieldElement& right) {
    CoordinateFieldElement::Encoding out{};
    const int ok =
        purify_bppp_coordinate_field_add(
            left.encoded_.data(), right.encoded_.data(), out.data());
    if (ok == 0) std::terminate();
    return CoordinateFieldElement(out);
}

CoordinateFieldElement operator-(const CoordinateFieldElement& left,
                                 const CoordinateFieldElement& right) {
    CoordinateFieldElement::Encoding out{};
    const int ok =
        purify_bppp_coordinate_field_subtract(left.encoded_.data(),
                                               right.encoded_.data(),
                                               out.data());
    if (ok == 0) std::terminate();
    return CoordinateFieldElement(out);
}

CoordinateFieldElement operator*(const CoordinateFieldElement& left,
                                 const CoordinateFieldElement& right) {
    CoordinateFieldElement::Encoding out{};
    const int ok =
        purify_bppp_coordinate_field_multiply(left.encoded_.data(),
                                               right.encoded_.data(),
                                               out.data());
    if (ok == 0) std::terminate();
    return CoordinateFieldElement(out);
}

} // namespace purify::bppp::candidate
