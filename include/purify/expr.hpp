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
    Expr();
    /** @brief Constructs a pure constant expression from a field element. */
    explicit Expr(const FieldElement& value);
    /** @brief Constructs a pure constant expression from a signed integer. */
    explicit Expr(std::int64_t value);

    /** @brief Returns a single-variable expression with coefficient one. */
    static Expr variable(const std::string& name);

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
    friend Expr operator+(const Expr& lhs, const Expr& rhs);

    /** @brief Adds an integer constant to an affine expression. */
    friend Expr operator+(const Expr& lhs, std::int64_t rhs);

    /** @brief Adds an affine expression to an integer constant. */
    friend Expr operator+(std::int64_t lhs, const Expr& rhs);

    /** @brief Subtracts one affine expression from another. */
    friend Expr operator-(const Expr& lhs, const Expr& rhs);

    /** @brief Subtracts an integer constant from an affine expression. */
    friend Expr operator-(const Expr& lhs, std::int64_t rhs);

    /** @brief Subtracts an affine expression from an integer constant. */
    friend Expr operator-(std::int64_t lhs, const Expr& rhs);

    /** @brief Negates every coefficient in the affine expression. */
    friend Expr operator-(const Expr& value);

    /** @brief Scales an affine expression by a field element. */
    friend Expr operator*(const Expr& expr, const FieldElement& scalar);

    /** @brief Scales an affine expression by a field element. */
    friend Expr operator*(const FieldElement& scalar, const Expr& expr);

    /** @brief Scales an affine expression by an integer constant. */
    friend Expr operator*(const Expr& expr, std::int64_t scalar);

    /** @brief Scales an affine expression by an integer constant. */
    friend Expr operator*(std::int64_t scalar, const Expr& expr);

    /** @brief Formats the expression in a stable human-readable form used for caches and debugging. */
    std::string to_string() const;

    /** @brief Evaluates the expression against a possibly partial variable assignment. */
    std::optional<FieldElement> evaluate(const std::unordered_map<std::string, std::optional<FieldElement>>& values) const;

    /** @brief Splits the expression into a pure constant and a pure linear component. */
    std::pair<Expr, Expr> split() const;

private:
    /** @brief Appends or merges a linear term while preserving canonical ordering. */
    void push_term(const std::pair<std::string, FieldElement>& term);

    FieldElement constant_;
    std::vector<std::pair<std::string, FieldElement>> linear_;
};

/** @brief Streams the human-readable expression form to an output stream. */
std::ostream& operator<<(std::ostream& out, const Expr& expr);

/**
 * @brief Mutable transcript used to record symbolic multiplication, division, and boolean constraints.
 */
class Transcript {
public:
    /** @brief Allocates a new secret witness variable, optionally with a known concrete value. */
    Expr secret(const std::optional<FieldElement>& value);

    /** @brief Allocates or reuses a multiplication witness enforcing `lhs * rhs = out`. */
    Expr mul(const Expr& lhs, const Expr& rhs);

    /** @brief Allocates or reuses a division witness enforcing `out * rhs = lhs`. */
    Expr div(const Expr& lhs, const Expr& rhs);

    /** @brief Constrains an expression to be boolean by adding `x * (x - 1) = 0`. */
    Expr boolean(const Expr& expr);

    /** @brief Records a linear equality constraint between two expressions. */
    void equal(const Expr& lhs, const Expr& rhs);

    /** @brief Evaluates an expression against the transcript's current variable map. */
    std::optional<FieldElement> evaluate(const Expr& expr) const;

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

Expr operator+(const Expr& lhs, const Expr& rhs);
Expr operator+(const Expr& lhs, std::int64_t rhs);
Expr operator+(std::int64_t lhs, const Expr& rhs);
Expr operator-(const Expr& lhs, const Expr& rhs);
Expr operator-(const Expr& lhs, std::int64_t rhs);
Expr operator-(std::int64_t lhs, const Expr& rhs);
Expr operator-(const Expr& value);
Expr operator*(const Expr& expr, const FieldElement& scalar);
Expr operator*(const FieldElement& scalar, const Expr& expr);
Expr operator*(const Expr& expr, std::int64_t scalar);
Expr operator*(std::int64_t scalar, const Expr& expr);

}  // namespace purify
