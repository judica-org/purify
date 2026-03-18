// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include "purify/curve.hpp"
#include "purify/expr.hpp"

namespace purify {

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
        circuit.c.reserve(
            std::count_if(assignments_.begin(), assignments_.end(),
                          [](const auto& assignment) { return !assignment.is_v; })
            + constraints_.size());

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

}  // namespace purify
