// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file curve.hpp
 * @brief Elliptic-curve helpers, fixed parameters, and hash-to-curve utilities for Purify.
 */

#pragma once

#include "purify/numeric.hpp"

namespace purify {

/** @brief Jacobian point representation used for curve arithmetic. */
struct JacobianPoint {
    FieldElement x;
    FieldElement y;
    FieldElement z;
    bool infinity = false;

    /** @brief Returns the point at infinity in Jacobian coordinates. */
    static JacobianPoint infinity_point();
};

/** @brief Affine point representation used for serialization and lookup tables. */
struct AffinePoint {
    FieldElement x;
    FieldElement y;
    bool infinity = false;
};

/** @brief Projective point used by the hardened secret-scalar multiplication path. */
struct CompleteProjectivePoint {
    FieldElement x;
    FieldElement y;
    FieldElement z;
};

/**
 * @brief Minimal elliptic-curve arithmetic over the Purify base field.
 *
 * The curve equation is `y^2 = x^3 + ax + b`.
 */
class EllipticCurve {
public:
    /** @brief Constructs a curve from its Weierstrass coefficients and subgroup order. */
    EllipticCurve(FieldElement a, FieldElement b, UInt256 n);

    /** @brief Returns the subgroup order used for scalar multiplication checks. */
    const UInt256& order() const {
        return n_;
    }

    /** @brief Converts a Jacobian point to affine coordinates. */
    AffinePoint affine(const JacobianPoint& point) const;

    /** @brief Negates a point without changing its projective scale. */
    JacobianPoint negate(const JacobianPoint& point) const;

    /** @brief Returns true if the supplied x-coordinate lifts to a curve point. */
    bool is_x_coord(const FieldElement& x) const;

    /** @brief Lifts an x-coordinate to a Jacobian point when a square root exists. */
    std::optional<JacobianPoint> lift_x(const FieldElement& x) const;

    /** @brief Doubles a Jacobian point. */
    JacobianPoint double_point(const JacobianPoint& point) const;

    /** @brief Adds an affine point to a Jacobian point. */
    JacobianPoint add_mixed(const JacobianPoint& lhs, const AffinePoint& rhs) const;

    /** @brief Adds two Jacobian points. */
    JacobianPoint add(const JacobianPoint& lhs, const JacobianPoint& rhs) const;

    /** @brief Multiplies a point by a scalar using double-and-add. */
    JacobianPoint mul(const JacobianPoint& point, const UInt256& scalar) const;

    /**
     * @brief Multiplies a public point by a secret scalar using exception-free complete formulas.
     *
     * The point input is treated as public and may be normalized with the variable-time affine
     * helper before entering the constant-time ladder. The ladder itself, point selection, final
     * inversion, and the Purify secret-dependent arithmetic remain constant-time in `scalar`.
     */
    Result<AffinePoint> mul_secret_affine(const JacobianPoint& point, const UInt256& scalar) const;

private:
    static CompleteProjectivePoint complete_identity();
    CompleteProjectivePoint secret_input_point(const JacobianPoint& point) const;
    static void conditional_assign(CompleteProjectivePoint& dst, const CompleteProjectivePoint& src, bool flag);
    static void conditional_swap(CompleteProjectivePoint& lhs, CompleteProjectivePoint& rhs, bool flag);
    CompleteProjectivePoint complete_add(const CompleteProjectivePoint& lhs, const CompleteProjectivePoint& rhs) const;
    CompleteProjectivePoint complete_double(const CompleteProjectivePoint& point) const;

    FieldElement a_;
    FieldElement b_;
    UInt256 n_;
};

/** @brief Encodes an ASCII string as a byte vector. */
Bytes bytes_from_ascii(std::string_view input);

/** @brief Concatenates two byte vectors. */
Bytes operator+(Bytes lhs, const Bytes& rhs);

/** @brief Computes ceiling division for unsigned 64-bit values. */
std::uint64_t ceil_div(std::uint64_t lhs, std::uint64_t rhs);

/** @brief Computes an HMAC-SHA256 digest using the secp bridge implementation. */
Bytes hmac_sha256(const Bytes& key, const Bytes& data);

/** @brief Expands input key material using HKDF-SHA256. */
Bytes hkdf(std::size_t length, const Bytes& ikm, const Bytes& salt = {}, const Bytes& info = {});

/** @brief Rejection-samples a uniformly distributed integer below `range`. */
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

/** @brief Returns the Purify base-field modulus. */
const UInt256& prime_p();

/** @brief Returns the subgroup order for the first curve. */
const UInt256& order_n1();

/** @brief Returns the subgroup order for the second curve. */
const UInt256& order_n2();

/** @brief Returns `floor(order_n1 / 2)`. */
const UInt256& half_n1();

/** @brief Returns `floor(order_n2 / 2)`. */
const UInt256& half_n2();

/** @brief Returns the size of the packed secret-key encoding space. */
const UInt512& packed_secret_key_space_size();

/** @brief Returns the size of the packed public-key encoding space. */
const UInt512& packed_public_key_space_size();

/** @brief Returns `2 * prime_p()` as a widened integer for hash-to-curve sampling. */
const UInt320& two_p();

/** @brief Returns the shared Weierstrass `a` coefficient used by Purify. */
FieldElement field_a();

/** @brief Returns the shared Weierstrass `b` coefficient used by Purify. */
FieldElement field_b();

/** @brief Returns the twist factor used to derive the second curve. */
FieldElement field_d();

/** @brief Returns the inverse of the twist factor in the field. */
FieldElement field_di();

/** @brief Returns the first Purify curve instance. */
const EllipticCurve& curve1();

/** @brief Returns the second Purify curve instance. */
const EllipticCurve& curve2();

/** @brief Hashes arbitrary data onto the supplied curve by rejection sampling x-coordinates. */
Result<JacobianPoint> hash_to_curve(const Bytes& data, const EllipticCurve& curve);

/** @brief Returns the fixed generator for the first curve. */
const JacobianPoint& generator1();

/** @brief Returns the fixed generator for the second curve. */
const JacobianPoint& generator2();

/** @brief Returns true when a packed secret is encoded canonically. */
bool is_valid_secret_key(const UInt512& z);

/** @brief Returns true when a packed public key is encoded canonically. */
bool is_valid_public_key(const UInt512& packed);

/** @brief Validates the packed secret-key encoding range. */
Status validate_secret_key(const UInt512& z);

/** @brief Validates the packed public-key encoding range. */
Status validate_public_key(const UInt512& packed);

/** @brief Splits a packed private key into its two per-curve secret scalars. */
Result<std::pair<UInt256, UInt256>> unpack_secret(const UInt512& z);

/** @brief Splits a packed public key into its two x-coordinates. */
Result<std::pair<UInt256, UInt256>> unpack_public(const UInt512& packed);

/** @brief Packs two x-coordinates into the reference 512-bit public-key encoding. */
UInt512 pack_public(const UInt256& x1, const UInt256& x2);

/** @brief Applies the Purify curve-combination map to two x-coordinates. */
FieldElement combine(const FieldElement& x1, const FieldElement& x2);

/** @brief Encodes a scalar into the signed 3-bit window bit schedule used by the circuit. */
Result<std::vector<int>> key_to_bits(UInt256 n, const UInt256& max_value);

}  // namespace purify
