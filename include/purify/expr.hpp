// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file expr.hpp
 * @brief Symbolic expression and transcript machinery used to derive Purify circuits.
 */

#pragma once

#include <compare>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "purify/numeric.hpp"

namespace purify {

/** @brief Symbol classes used while deriving witness and Bulletproof wire relations. */
enum class SymbolKind : std::uint8_t {
    Witness = 0,
    Left = 1,
    Right = 2,
    Output = 3,
    Commitment = 4,
};

/** @brief Compact symbolic variable identifier used inside expressions and transcripts. */
struct Symbol {
    SymbolKind kind = SymbolKind::Witness;
    std::uint32_t index = 0;

    static Symbol witness(std::uint32_t index);
    static Symbol left(std::uint32_t index);
    static Symbol right(std::uint32_t index);
    static Symbol output(std::uint32_t index);
    static Symbol commitment(std::uint32_t index);

    std::string to_string() const;
    auto operator<=>(const Symbol&) const = default;
};

/** @brief Partial witness assignment vector indexed by transcript witness id. */
using WitnessAssignments = std::vector<std::optional<FieldElement>>;

/**
 * @brief Symbolic affine expression over indexed variables and field coefficients.
 *
 * This type is used while deriving circuit relations before they are lowered into
 * native multiplication gates and linear constraints.
 */
class Expr {
public:
    using Term = std::pair<Symbol, FieldElement>;

    /** @brief Constructs the zero expression. */
    Expr();
    /** @brief Constructs a pure constant expression from a field element. */
    explicit Expr(const FieldElement& value);
    /** @brief Constructs a pure constant expression from a signed integer. */
    explicit Expr(std::int64_t value);

    /** @brief Returns a single-variable expression with coefficient one. */
    static Expr variable(Symbol symbol);

    /** @brief Returns the constant term of the affine expression. */
    const FieldElement& constant() const {
        return constant_;
    }

    /** @brief Returns mutable access to the sorted linear term list. */
    std::vector<Term>& linear() {
        return linear_;
    }

    /** @brief Returns read-only access to the sorted linear term list. */
    const std::vector<Term>& linear() const {
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

    /** @brief Compares two affine expressions structurally. */
    friend bool operator==(const Expr& lhs, const Expr& rhs);

    /** @brief Orders affine expressions structurally for cache keys. */
    friend bool operator<(const Expr& lhs, const Expr& rhs);

    /** @brief Formats the expression in a stable human-readable form used for debugging and serialization. */
    std::string to_string() const;

    /** @brief Evaluates the expression against a possibly partial transcript witness assignment. */
    std::optional<FieldElement> evaluate(const WitnessAssignments& values) const;

    /** @brief Splits the expression into a pure constant and a pure linear component. */
    std::pair<Expr, Expr> split() const;

private:
    /** @brief Appends or merges a linear term while preserving canonical ordering. */
    void push_term(const Term& term);

    FieldElement constant_;
    std::vector<Term> linear_;
};

/**
 * @brief Small runtime builder that flattens affine combinations into one expression.
 *
 * This avoids repeated intermediate `Expr` allocations in gadgets that know they are
 * constructing a linear combination of existing expressions.
 */
class ExprBuilder {
public:
    /** @brief Returns a builder with storage reserved for approximately `terms` linear slots. */
    static ExprBuilder reserved(std::size_t terms);

    /** @brief Reserves storage for approximately `terms` linear slots. */
    ExprBuilder& reserve(std::size_t terms);

    /** @brief Adds a constant field term to the pending affine expression. */
    ExprBuilder& add(const FieldElement& value);

    /** @brief Adds an integer constant term to the pending affine expression. */
    ExprBuilder& add(std::int64_t value);

    /** @brief Adds one scaled symbolic variable term. */
    ExprBuilder& add_term(Symbol symbol, const FieldElement& scale);

    /** @brief Adds an existing expression with implicit coefficient one. */
    ExprBuilder& add(const Expr& expr);

    /** @brief Subtracts an existing expression with implicit coefficient minus one. */
    ExprBuilder& subtract(const Expr& expr);

    /** @brief Adds an existing expression scaled by a field element. */
    ExprBuilder& add_scaled(const Expr& expr, const FieldElement& scale);

    /** @brief Adds an existing expression scaled by an integer constant. */
    ExprBuilder& add_scaled(const Expr& expr, std::int64_t scale);

    /** @brief Materializes the flattened affine expression. */
    Expr build();

private:
    FieldElement constant_ = FieldElement::zero();
    std::vector<Expr::Term> terms_;
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

    /** @brief Evaluates an expression against the transcript's current witness vector. */
    std::optional<FieldElement> evaluate(const Expr& expr) const;

    /** @brief Returns the underlying witness assignment vector. */
    const WitnessAssignments& varmap() const {
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
    WitnessAssignments varmap_;
    std::vector<MulConstraint> muls_;
    std::map<std::pair<Expr, Expr>, Expr> mul_cache_;
    std::map<std::pair<Expr, Expr>, Expr> div_cache_;
    std::set<Expr> bool_cache_;
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
bool operator==(const Expr& lhs, const Expr& rhs);
bool operator<(const Expr& lhs, const Expr& rhs);

}  // namespace purify
