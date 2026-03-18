// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file expr.hpp
 * @brief Symbolic expression and transcript machinery used to derive Purify circuits.
 */

#pragma once

#include "purify/numeric.hpp"

namespace purify {

/**
 * @brief Symbolic affine expression over named variables and field coefficients.
 *
 * This type is used while deriving circuit relations before they are lowered into
 * native multiplication gates and linear constraints.
 */
class Expr {
public:
    /** @brief Constructs the zero expression. */
    Expr() : constant_(FieldElement::zero()) {}
    /** @brief Constructs a pure constant expression from a field element. */
    explicit Expr(const FieldElement& value) : constant_(value) {}
    /** @brief Constructs a pure constant expression from a signed integer. */
    explicit Expr(std::int64_t value) : constant_(FieldElement::from_int(value)) {}

    /** @brief Returns a single-variable expression with coefficient one. */
    static Expr variable(const std::string& name) {
        Expr out;
        out.linear_.push_back({name, FieldElement::one()});
        return out;
    }

    /** @brief Returns the constant term of the affine expression. */
    const FieldElement& constant() const {
        return constant_;
    }

    /** @brief Returns mutable access to the sorted linear term list. */
    std::vector<std::pair<std::string, FieldElement>>& linear() {
        return linear_;
    }

    /** @brief Returns read-only access to the sorted linear term list. */
    const std::vector<std::pair<std::string, FieldElement>>& linear() const {
        return linear_;
    }

    /** @brief Adds two affine expressions and merges like terms. */
    friend Expr operator+(const Expr& lhs, const Expr& rhs) {
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

    /** @brief Adds an integer constant to an affine expression. */
    friend Expr operator+(const Expr& lhs, std::int64_t rhs) {
        return lhs + Expr(rhs);
    }

    /** @brief Adds an affine expression to an integer constant. */
    friend Expr operator+(std::int64_t lhs, const Expr& rhs) {
        return Expr(lhs) + rhs;
    }

    /** @brief Subtracts one affine expression from another. */
    friend Expr operator-(const Expr& lhs, const Expr& rhs) {
        return lhs + (-rhs);
    }

    /** @brief Subtracts an integer constant from an affine expression. */
    friend Expr operator-(const Expr& lhs, std::int64_t rhs) {
        return lhs - Expr(rhs);
    }

    /** @brief Subtracts an affine expression from an integer constant. */
    friend Expr operator-(std::int64_t lhs, const Expr& rhs) {
        return Expr(lhs) - rhs;
    }

    /** @brief Negates every coefficient in the affine expression. */
    friend Expr operator-(const Expr& value) {
        return value * FieldElement::from_int(-1);
    }

    /** @brief Scales an affine expression by a field element. */
    friend Expr operator*(const Expr& expr, const FieldElement& scalar) {
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

    /** @brief Scales an affine expression by a field element. */
    friend Expr operator*(const FieldElement& scalar, const Expr& expr) {
        return expr * scalar;
    }

    /** @brief Scales an affine expression by an integer constant. */
    friend Expr operator*(const Expr& expr, std::int64_t scalar) {
        return expr * FieldElement::from_int(scalar);
    }

    /** @brief Scales an affine expression by an integer constant. */
    friend Expr operator*(std::int64_t scalar, const Expr& expr) {
        return expr * scalar;
    }

    /** @brief Formats the expression in a stable human-readable form used for caches and debugging. */
    std::string to_string() const {
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

    /** @brief Evaluates the expression against a possibly partial variable assignment. */
    std::optional<FieldElement> evaluate(const std::unordered_map<std::string, std::optional<FieldElement>>& values) const {
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

    /** @brief Splits the expression into a pure constant and a pure linear component. */
    std::pair<Expr, Expr> split() const {
        Expr linear_expr(0);
        linear_expr.linear_ = linear_;
        return {Expr(constant_), linear_expr};
    }

private:
    /** @brief Appends or merges a linear term while preserving canonical ordering. */
    void push_term(const std::pair<std::string, FieldElement>& term) {
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

    FieldElement constant_;
    std::vector<std::pair<std::string, FieldElement>> linear_;
};

/** @brief Streams the human-readable expression form to an output stream. */
inline std::ostream& operator<<(std::ostream& out, const Expr& expr) {
    out << expr.to_string();
    return out;
}

/**
 * @brief Mutable transcript used to record symbolic multiplication, division, and boolean constraints.
 */
class Transcript {
public:
    /** @brief Allocates a new secret witness variable, optionally with a known concrete value. */
    Expr secret(const std::optional<FieldElement>& value) {
        std::size_t index = varmap_.size();
        std::string name = std::format("v[{}]", index);
        varmap_[name] = value;
        return Expr::variable(name);
    }

    /** @brief Allocates or reuses a multiplication witness enforcing `lhs * rhs = out`. */
    Expr mul(const Expr& lhs, const Expr& rhs) {
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

    /** @brief Allocates or reuses a division witness enforcing `out * rhs = lhs`. */
    Expr div(const Expr& lhs, const Expr& rhs) {
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

    /** @brief Constrains an expression to be boolean by adding `x * (x - 1) = 0`. */
    Expr boolean(const Expr& expr) {
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

    /** @brief Records a linear equality constraint between two expressions. */
    void equal(const Expr& lhs, const Expr& rhs) {
        Expr diff = lhs - rhs;
#ifndef NDEBUG
        std::optional<FieldElement> value = diff.evaluate(varmap_);
        assert((!value.has_value() || value->is_zero()) && "Transcript::equal() requires known values to match");
#endif
        eqs_.push_back(diff);
    }

    /** @brief Evaluates an expression against the transcript's current variable map. */
    std::optional<FieldElement> evaluate(const Expr& expr) const {
        return expr.evaluate(varmap_);
    }

    /** @brief Returns the underlying variable assignment map. */
    const std::unordered_map<std::string, std::optional<FieldElement>>& varmap() const {
        return varmap_;
    }

    /** @brief One multiplicative relation emitted by the symbolic transcript. */
    struct MulConstraint {
        Expr lhs;
        Expr rhs;
        Expr out;
    };

    /** @brief Returns the multiplication and division constraints accumulated so far. */
    const std::vector<MulConstraint>& muls() const {
        return muls_;
    }

    /** @brief Returns the linear equality constraints accumulated so far. */
    const std::vector<Expr>& eqs() const {
        return eqs_;
    }

private:
    std::unordered_map<std::string, std::optional<FieldElement>> varmap_;
    std::vector<MulConstraint> muls_;
    std::map<std::pair<std::string, std::string>, Expr> mul_cache_;
    std::map<std::pair<std::string, std::string>, Expr> div_cache_;
    std::unordered_set<std::string> bool_cache_;
    std::vector<Expr> eqs_;
};

}  // namespace purify
