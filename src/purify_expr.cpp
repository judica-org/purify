// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file purify_expr.cpp
 * @brief Compiled symbolic expression and transcript machinery for Purify.
 */

#include "purify/expr.hpp"

#include <cassert>
#include <format>
#include <sstream>

namespace {

int compare_field_elements(const purify::FieldElement& lhs, const purify::FieldElement& rhs) {
    return lhs.to_uint256().compare(rhs.to_uint256());
}

}  // namespace

namespace purify {

Symbol Symbol::witness(std::uint32_t index) {
    return {SymbolKind::Witness, index};
}

Symbol Symbol::left(std::uint32_t index) {
    return {SymbolKind::Left, index};
}

Symbol Symbol::right(std::uint32_t index) {
    return {SymbolKind::Right, index};
}

Symbol Symbol::output(std::uint32_t index) {
    return {SymbolKind::Output, index};
}

Symbol Symbol::commitment(std::uint32_t index) {
    return {SymbolKind::Commitment, index};
}

std::string Symbol::to_string() const {
    switch (kind) {
    case SymbolKind::Witness:
        return std::format("v[{}]", index);
    case SymbolKind::Left:
        return std::format("L{}", index);
    case SymbolKind::Right:
        return std::format("R{}", index);
    case SymbolKind::Output:
        return std::format("O{}", index);
    case SymbolKind::Commitment:
        return std::format("V{}", index);
    }
    assert(false && "unknown SymbolKind");
    return "?";
}

Expr::Expr() : constant_(FieldElement::zero()) {}

Expr::Expr(const FieldElement& value) : constant_(value) {}

Expr::Expr(std::int64_t value) : constant_(FieldElement::from_int(value)) {}

Expr Expr::variable(Symbol symbol) {
    Expr out;
    out.linear_.push_back({symbol, FieldElement::one()});
    return out;
}

std::string Expr::to_string() const {
    std::ostringstream out;
    bool first = true;
    if (!constant_.is_zero() || linear_.empty()) {
        out << constant_.to_decimal();
        first = false;
    }
    for (const auto& term : linear_) {
        if (!first) {
            out << " + ";
        }
        if (term.second == FieldElement::one()) {
            out << term.first.to_string();
        } else {
            out << term.second.to_decimal() << " * " << term.first.to_string();
        }
        first = false;
    }
    return out.str();
}

std::optional<FieldElement> Expr::evaluate(const WitnessAssignments& values) const {
    FieldElement out = constant_;
    for (const auto& term : linear_) {
        if (term.first.kind != SymbolKind::Witness) {
            return std::nullopt;
        }
        std::size_t index = term.first.index;
        if (index >= values.size() || !values[index].has_value()) {
            return std::nullopt;
        }
        out = out + (*values[index] * term.second);
    }
    return out;
}

std::pair<Expr, Expr> Expr::split() const {
    Expr linear_expr(0);
    linear_expr.linear_ = linear_;
    return {Expr(constant_), linear_expr};
}

void Expr::push_term(const Term& term) {
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

Expr operator+(const Expr& lhs, const Expr& rhs) {
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

Expr operator+(const Expr& lhs, std::int64_t rhs) {
    return lhs + Expr(rhs);
}

Expr operator+(std::int64_t lhs, const Expr& rhs) {
    return Expr(lhs) + rhs;
}

Expr operator-(const Expr& lhs, const Expr& rhs) {
    return lhs + (-rhs);
}

Expr operator-(const Expr& lhs, std::int64_t rhs) {
    return lhs - Expr(rhs);
}

Expr operator-(std::int64_t lhs, const Expr& rhs) {
    return Expr(lhs) - rhs;
}

Expr operator-(const Expr& value) {
    return value * FieldElement::from_int(-1);
}

Expr operator*(const Expr& expr, const FieldElement& scalar) {
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

Expr operator*(const FieldElement& scalar, const Expr& expr) {
    return expr * scalar;
}

Expr operator*(const Expr& expr, std::int64_t scalar) {
    return expr * FieldElement::from_int(scalar);
}

Expr operator*(std::int64_t scalar, const Expr& expr) {
    return expr * scalar;
}

bool operator==(const Expr& lhs, const Expr& rhs) {
    return lhs.constant_ == rhs.constant_ && lhs.linear_ == rhs.linear_;
}

bool operator<(const Expr& lhs, const Expr& rhs) {
    int constant_cmp = compare_field_elements(lhs.constant_, rhs.constant_);
    if (constant_cmp != 0) {
        return constant_cmp < 0;
    }
    std::size_t common = std::min(lhs.linear_.size(), rhs.linear_.size());
    for (std::size_t i = 0; i < common; ++i) {
        if (lhs.linear_[i].first != rhs.linear_[i].first) {
            return lhs.linear_[i].first < rhs.linear_[i].first;
        }
        int coeff_cmp = compare_field_elements(lhs.linear_[i].second, rhs.linear_[i].second);
        if (coeff_cmp != 0) {
            return coeff_cmp < 0;
        }
    }
    return lhs.linear_.size() < rhs.linear_.size();
}

std::ostream& operator<<(std::ostream& out, const Expr& expr) {
    out << expr.to_string();
    return out;
}

Expr Transcript::secret(const std::optional<FieldElement>& value) {
    std::size_t index = varmap_.size();
    assert(index <= static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max())
           && "Transcript::secret() witness index must fit in uint32_t");
    varmap_.push_back(value);
    return Expr::variable(Symbol::witness(static_cast<std::uint32_t>(index)));
}

Expr Transcript::mul(const Expr& lhs, const Expr& rhs) {
    auto direct = std::make_pair(lhs, rhs);
    auto reverse = std::make_pair(rhs, lhs);
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

Expr Transcript::div(const Expr& lhs, const Expr& rhs) {
    auto direct = std::make_pair(lhs, rhs);
    auto it = div_cache_.find(direct);
    if (it != div_cache_.end()) {
        return it->second;
    }
    std::optional<FieldElement> lhs_val = lhs.evaluate(varmap_);
    std::optional<FieldElement> rhs_val = rhs.evaluate(varmap_);
    assert((!rhs_val.has_value() || !rhs_val->is_zero()) && "Transcript::div() requires a non-zero known divisor");
    std::optional<FieldElement> value;
    if (lhs_val.has_value() && rhs_val.has_value()) {
        value = *lhs_val * rhs_val->inverse();
    }
    Expr out = secret(value);
    div_cache_[direct] = out;
    muls_.push_back({out, rhs, lhs});
    return out;
}

Expr Transcript::boolean(const Expr& expr) {
    if (bool_cache_.count(expr) != 0) {
        return expr;
    }
#ifndef NDEBUG
    std::optional<FieldElement> value = expr.evaluate(varmap_);
    assert((!value.has_value() || *value == FieldElement::zero() || *value == FieldElement::one())
           && "Transcript::boolean() requires a known value to be 0 or 1");
#endif
    bool_cache_.insert(expr);
    muls_.push_back({expr, expr - 1, Expr(0)});
    return expr;
}

void Transcript::equal(const Expr& lhs, const Expr& rhs) {
    Expr diff = lhs - rhs;
#ifndef NDEBUG
    std::optional<FieldElement> value = diff.evaluate(varmap_);
    assert((!value.has_value() || value->is_zero()) && "Transcript::equal() requires known values to match");
#endif
    eqs_.push_back(diff);
}

std::optional<FieldElement> Transcript::evaluate(const Expr& expr) const {
    return expr.evaluate(varmap_);
}

}  // namespace purify
