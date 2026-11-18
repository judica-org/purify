// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file bulletproof_gadgets.cpp
 * @brief Arithmetic-circuit gadgets that build the Purify evaluation circuit over a transcript.
 */

#include "purify/bulletproof.hpp"

#include <array>
#include <cstddef>
#include <optional>
#include <vector>

namespace purify {

Expr circuit_1bit(const std::array<FieldElement, 2>& values, Transcript&, const Expr& x) {
    return ExprBuilder::reserved(x.linear().size())
        .add(values[0])
        .add_scaled(x, values[1] - values[0])
        .build();
}

Expr circuit_2bit(const std::array<FieldElement, 4>& values, Transcript& transcript, const Expr& x, const Expr& y) {
    Expr xy = transcript.mul(x, y);
    return ExprBuilder::reserved(x.linear().size() + y.linear().size() + xy.linear().size())
        .add(values[0])
        .add_scaled(x, values[1] - values[0])
        .add_scaled(y, values[2] - values[0])
        .add_scaled(xy, values[0] + values[3] - values[1] - values[2])
        .build();
}

Expr circuit_3bit(const std::array<FieldElement, 8>& values, Transcript& transcript, const Expr& x, const Expr& y, const Expr& z) {
    Expr xy = transcript.mul(x, y);
    Expr yz = transcript.mul(y, z);
    Expr zx = transcript.mul(z, x);
    Expr xyz = transcript.mul(xy, z);
    return ExprBuilder::reserved(x.linear().size() + y.linear().size() + z.linear().size()
                                 + xy.linear().size() + yz.linear().size() + zx.linear().size() + xyz.linear().size())
        .add(values[0])
        .add_scaled(x, values[1] - values[0])
        .add_scaled(y, values[2] - values[0])
        .add_scaled(z, values[4] - values[0])
        .add_scaled(xy, values[0] + values[3] - values[1] - values[2])
        .add_scaled(zx, values[0] + values[5] - values[1] - values[4])
        .add_scaled(yz, values[0] + values[6] - values[2] - values[4])
        .add_scaled(xyz, values[1] + values[2] + values[4] + values[7] - values[0] - values[3] - values[5] - values[6])
        .build();
}

ExprPoint circuit_1bit_point(const EllipticCurve& curve, const std::array<JacobianPoint, 2>& points,
                             Transcript& transcript, const Expr& b0) {
    std::array<AffinePoint, 2> affine_points{curve.affine(points[0]), curve.affine(points[1])};
    return {
        circuit_1bit({affine_points[0].x, affine_points[1].x}, transcript, b0),
        circuit_1bit({affine_points[0].y, affine_points[1].y}, transcript, b0)
    };
}

ExprPoint circuit_2bit_point(const EllipticCurve& curve, const std::array<JacobianPoint, 4>& points,
                             Transcript& transcript, const Expr& b0, const Expr& b1) {
    std::array<AffinePoint, 4> affine_points{curve.affine(points[0]), curve.affine(points[1]), curve.affine(points[2]), curve.affine(points[3])};
    return {
        circuit_2bit({affine_points[0].x, affine_points[1].x, affine_points[2].x, affine_points[3].x}, transcript, b0, b1),
        circuit_2bit({affine_points[0].y, affine_points[1].y, affine_points[2].y, affine_points[3].y}, transcript, b0, b1)
    };
}

ExprPoint circuit_3bit_point(const EllipticCurve& curve, const std::array<JacobianPoint, 8>& points,
                             Transcript& transcript, const Expr& b0, const Expr& b1, const Expr& b2) {
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

ExprPoint circuit_optionally_negate_ec(const ExprPoint& point, Transcript& transcript, const Expr& negate_bit) {
    return {point.first, transcript.mul(Expr(1) - 2 * negate_bit, point.second)};
}

ExprPoint circuit_ec_add(Transcript& transcript, const ExprPoint& p1, const ExprPoint& p2) {
    Expr lambda = transcript.div(p2.second - p1.second, p2.first - p1.first);
    Expr lambda_sq = transcript.mul(lambda, lambda);
    Expr x = ExprBuilder::reserved(lambda_sq.linear().size() + p1.first.linear().size() + p2.first.linear().size())
        .add(lambda_sq)
        .subtract(p1.first)
        .subtract(p2.first)
        .build();
    Expr delta = ExprBuilder::reserved(p1.first.linear().size() + x.linear().size())
        .add(p1.first)
        .subtract(x)
        .build();
    Expr lambda_delta = transcript.mul(lambda, delta);
    Expr y = ExprBuilder::reserved(lambda_delta.linear().size() + p1.second.linear().size())
        .add(lambda_delta)
        .subtract(p1.second)
        .build();
    return {x, y};
}

Expr circuit_ec_add_x(Transcript& transcript, const ExprPoint& p1, const ExprPoint& p2) {
    Expr lambda = transcript.div(p2.second - p1.second, p2.first - p1.first);
    Expr lambda_sq = transcript.mul(lambda, lambda);
    return ExprBuilder::reserved(lambda_sq.linear().size() + p1.first.linear().size() + p2.first.linear().size())
        .add(lambda_sq)
        .subtract(p1.first)
        .subtract(p2.first)
        .build();
}

namespace {

enum class CircuitEcMultiplyOutput {
    XOnly,
    FullPoint,
};

ExprPoint circuit_ec_multiply_impl(const EllipticCurve& curve, Transcript& transcript,
                                   const JacobianPoint& point, const std::vector<Expr>& bits,
                                   CircuitEcMultiplyOutput output) {
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
    if (output == CircuitEcMultiplyOutput::FullPoint) {
        return circuit_ec_add(transcript, out, lookups.back());
    }
    // Keep the historical x-only circuit byte-for-byte stable. Computing an
    // unused final y-coordinate would append one multiplication gate and
    // change every existing circuit transcript and proof vector.
    return {circuit_ec_add_x(transcript, out, lookups.back()), Expr(0)};
}

}  // namespace

ExprPoint circuit_ec_multiply_point(const EllipticCurve& curve, Transcript& transcript,
                                    const JacobianPoint& point, const std::vector<Expr>& bits) {
    return circuit_ec_multiply_impl(curve, transcript, point, bits,
                                    CircuitEcMultiplyOutput::FullPoint);
}

Expr circuit_ec_multiply_x(const EllipticCurve& curve, Transcript& transcript,
                           const JacobianPoint& point, const std::vector<Expr>& bits) {
    return circuit_ec_multiply_impl(curve, transcript, point, bits,
                                    CircuitEcMultiplyOutput::XOnly)
        .first;
}

Expr circuit_combine(Transcript& transcript, const Expr& x1, const Expr& x2) {
    Expr v = ExprBuilder::reserved(x2.linear().size())
        .add_scaled(x2, field_di())
        .build();
    Expr u_plus_v = ExprBuilder::reserved(x1.linear().size() + v.linear().size())
        .add(x1)
        .add(v)
        .build();
    Expr uv = transcript.mul(x1, v);
    Expr uv_plus_a = ExprBuilder::reserved(uv.linear().size())
        .add(field_a())
        .add(uv)
        .build();
    Expr numerator_mul = transcript.mul(u_plus_v, uv_plus_a);
    Expr numerator = ExprBuilder::reserved(numerator_mul.linear().size())
        .add(FieldElement::from_int(2) * field_b())
        .add(numerator_mul)
        .build();
    Expr u_minus_v = ExprBuilder::reserved(x1.linear().size() + v.linear().size())
        .add(x1)
        .subtract(v)
        .build();
    Expr denominator = transcript.mul(u_minus_v, u_minus_v);
    return transcript.div(numerator, denominator);
}

Result<CircuitMainResult> circuit_main(Transcript& transcript, const JacobianPoint& m1, const JacobianPoint& m2,
                                       const std::optional<UInt256>& z1, const std::optional<UInt256>& z2) {
    int z1_bits_len = static_cast<int>(half_n1().bit_length());
    int z2_bits_len = static_cast<int>(half_n2().bit_length());
    std::vector<int> z1_values(static_cast<std::size_t>(z1_bits_len), -1);
    std::vector<int> z2_values(static_cast<std::size_t>(z2_bits_len), -1);
    if (z1.has_value() && z2.has_value()) {
        Result<std::vector<int>> z1_result = key_to_bits(*z1, half_n1());
        if (!z1_result.has_value()) {
            return unexpected_error(z1_result.error());
        }
        Result<std::vector<int>> z2_result = key_to_bits(*z2, half_n2());
        if (!z2_result.has_value()) {
            return unexpected_error(z2_result.error());
        }
        z1_values = *z1_result;
        z2_values = *z2_result;
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
    return CircuitMainResult{circuit_combine(transcript, out_x1, out_x2), out_p1x, out_p2x, n_bits};
}

}  // namespace purify
