// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "purify/error.hpp"

namespace purify::bppp::candidate {

/** Canonical public value in the secp256k1 coordinate field. */
class CoordinateFieldElement {
public:
    static constexpr std::size_t kSerializedSize = 32;
    using Encoding = std::array<unsigned char, kSerializedSize>;

    CoordinateFieldElement() = default;

    [[nodiscard]] static Result<CoordinateFieldElement> from_bytes_be(const Encoding& encoded);
    [[nodiscard]] static CoordinateFieldElement from_reduced_bytes_be(const Encoding& encoded);
    [[nodiscard]] static CoordinateFieldElement from_u64(std::uint64_t value);
    [[nodiscard]] static CoordinateFieldElement zero();
    [[nodiscard]] static CoordinateFieldElement one();

    [[nodiscard]] const Encoding& bytes() const noexcept { return encoded_; }
    [[nodiscard]] bool is_zero() const noexcept;
    [[nodiscard]] Result<CoordinateFieldElement> inverse() const;

    friend bool operator==(const CoordinateFieldElement& left,
                           const CoordinateFieldElement& right) = default;
    friend CoordinateFieldElement operator+(const CoordinateFieldElement& left,
                                            const CoordinateFieldElement& right);
    friend CoordinateFieldElement operator-(const CoordinateFieldElement& left,
                                            const CoordinateFieldElement& right);
    friend CoordinateFieldElement operator*(const CoordinateFieldElement& left,
                                            const CoordinateFieldElement& right);

private:
    explicit CoordinateFieldElement(Encoding encoded) : encoded_(encoded) {}

    Encoding encoded_{};
};

} // namespace purify::bppp::candidate
