// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file purify_expr.cpp
 * @brief Compiled symbolic expression and transcript machinery for Purify.
 */

#include "purify/expr.hpp"

namespace purify {

Expr::Expr() : constant_(FieldElement::zero()) {}

Expr::Expr(const FieldElement& value) : constant_(value) {}

Expr::Expr(std::int64_t value) : constant_(FieldElement::from_int(value)) {}

Expr Expr::variable(const std::string& name) {
    Expr out;
    out.linear_.push_back({name, FieldElement::one()});
    return out;
}

std::string Expr::to_string() const {
    std::vector<std::string> terms;
    if (!constant_.is_zero() || linear_.empty()) {
        terms.push_back(constant_.to_decimal());
    }
    for (const auto& term : linear_) {
        if (term.second == FieldElement::one()) {
            terms.push_back(term.first);
        } else {
            terms.push_back(term.second.to_decimal() + " * " + term.first);
        }
    }
    if (terms.empty()) {
        return "0";
    }
    std::ostringstream out;
    for (std::size_t i = 0; i < terms.size(); ++i) {
        if (i != 0) {
            out << " + ";
        }
        out << terms[i];
    }
    return out.str();
}

std::optional<FieldElement> Expr::evaluate(const std::unordered_map<std::string, std::optional<FieldElement>>& values) const {
    FieldElement out = constant_;
    for (const auto& term : linear_) {
        auto it = values.find(term.first);
        if (it == values.end() || !it->second.has_value()) {
            return std::nullopt;
        }
        out = out + (*it->second * term.second);
    }
    return out;
}

std::pair<Expr, Expr> Expr::split() const {
    Expr linear_expr(0);
    linear_expr.linear_ = linear_;
    return {Expr(constant_), linear_expr};
}

void Expr::push_term(const std::pair<std::string, FieldElement>& term) {
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

std::ostream& operator<<(std::ostream& out, const Expr& expr) {
    out << expr.to_string();
    return out;
}

Expr Transcript::secret(const std::optional<FieldElement>& value) {
    std::size_t index = varmap_.size();
    std::string name = std::format("v[{}]", index);
    varmap_[name] = value;
    return Expr::variable(name);
}

Expr Transcript::mul(const Expr& lhs, const Expr& rhs) {
    std::string lhs_str = lhs.to_string();
    std::string rhs_str = rhs.to_string();
    auto direct = std::make_pair(lhs_str, rhs_str);
    auto reverse = std::make_pair(rhs_str, lhs_str);
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
    std::string lhs_str = lhs.to_string();
    std::string rhs_str = rhs.to_string();
    auto direct = std::make_pair(lhs_str, rhs_str);
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
    std::string key = expr.to_string();
    if (bool_cache_.count(key) != 0) {
        return expr;
    }
#ifndef NDEBUG
    std::optional<FieldElement> value = expr.evaluate(varmap_);
    assert((!value.has_value() || *value == FieldElement::zero() || *value == FieldElement::one())
           && "Transcript::boolean() requires a known value to be 0 or 1");
#endif
    bool_cache_.insert(key);
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
