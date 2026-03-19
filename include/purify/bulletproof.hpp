// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file bulletproof.hpp
 * @brief Native Bulletproof-style circuit types and witness serialization helpers.
 */

#pragma once

#include <array>
#include <cstddef>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "purify/curve.hpp"
#include "purify/expr.hpp"

namespace purify {

using BulletproofScalarBytes = std::array<unsigned char, 32>;
using BulletproofPointBytes = std::array<unsigned char, 33>;
using BulletproofGeneratorBytes = std::array<unsigned char, 33>;

/** @brief Columnar witness assignment compatible with the native Bulletproof circuit layout. */
struct BulletproofAssignmentData {
    std::vector<FieldElement> left;
    std::vector<FieldElement> right;
    std::vector<FieldElement> output;
    std::vector<FieldElement> commitments;

    /** @brief Serializes the witness columns in the legacy assignment blob format. */
    Result<Bytes> serialize() const;
};

/** @brief One sparse matrix entry in a native circuit row. */
struct NativeBulletproofCircuitTerm {
    std::size_t idx = 0;
    FieldElement scalar;
};

/** @brief One sparse row of circuit coefficients. */
struct NativeBulletproofCircuitRow {
    std::vector<NativeBulletproofCircuitTerm> entries;

    /** @brief Appends a sparse coefficient to the row, skipping zero entries. */
    void add(std::size_t idx, const FieldElement& scalar);

    /**
     * @brief Non-owning packed row view used by `NativeBulletproofCircuit::PackedWithSlack`.
     *
     * The underlying storage lives inside the packed circuit slab.
     */
    struct PackedWithSlack {
        const NativeBulletproofCircuitTerm* data = nullptr;
        std::size_t size = 0;
        std::size_t capacity = 0;

        [[nodiscard]] std::span<const NativeBulletproofCircuitTerm> entries_view() const noexcept {
            return std::span<const NativeBulletproofCircuitTerm>(data, size);
        }
    };
};

/**
 * @brief Native in-memory representation of a Bulletproof-style arithmetic circuit.
 *
 * The matrices are stored in sparse row form per gate column so the circuit can be
 * built directly in C++ without parser round-trips.
 */
struct NativeBulletproofCircuit {
    struct PackedSlack {
        std::size_t constraint_slack = 0;
        std::vector<std::size_t> wl;
        std::vector<std::size_t> wr;
        std::vector<std::size_t> wo;
        std::vector<std::size_t> wv;
    };

    /**
     * @brief Resettable packed circuit representation backed by one aligned slab allocation.
     *
     * This keeps row metadata, sparse terms, and constants in a single allocation sized for the
     * base circuit plus caller-supplied slack. It supports two cache-friendly modes:
     * copying the object cheaply as one slab for const use, or mutating it in place and then
     * calling `reset()` to return to the original packed base shape.
     */
    class PackedWithSlack {
    public:
        PackedWithSlack() = default;

        [[nodiscard]] std::size_t n_gates() const noexcept {
            return n_gates_;
        }

        [[nodiscard]] std::size_t n_commitments() const noexcept {
            return n_commitments_;
        }

        [[nodiscard]] std::size_t n_bits() const noexcept {
            return n_bits_;
        }

        [[nodiscard]] std::size_t constraint_count() const noexcept {
            return constraint_size_;
        }

        [[nodiscard]] std::size_t constraint_capacity() const noexcept {
            return constraint_capacity_;
        }

        [[nodiscard]] bool has_valid_shape() const noexcept;

        /** @brief Restores the packed circuit to its original base row sizes and constraint count. */
        void reset() noexcept;

        /** @brief Appends a new linear constraint constant term and returns its index. */
        std::size_t add_constraint(const FieldElement& constant = FieldElement::zero());

        /** @brief Adds a coefficient to the left-wire matrix. */
        void add_left_term(std::size_t gate_idx, std::size_t constraint_idx, const FieldElement& scalar);

        /** @brief Adds a coefficient to the right-wire matrix. */
        void add_right_term(std::size_t gate_idx, std::size_t constraint_idx, const FieldElement& scalar);

        /** @brief Adds a coefficient to the output-wire matrix. */
        void add_output_term(std::size_t gate_idx, std::size_t constraint_idx, const FieldElement& scalar);

        /** @brief Adds a coefficient to the commitment matrix using the Bulletproof sign convention. */
        void add_commitment_term(std::size_t commitment_idx, std::size_t constraint_idx, const FieldElement& scalar);

        /** @brief Evaluates the packed circuit directly against a witness assignment. */
        [[nodiscard]] bool evaluate(const BulletproofAssignmentData& assignment) const;

        /** @brief Materializes the packed circuit back into the ergonomic row-vector representation. */
        [[nodiscard]] Result<NativeBulletproofCircuit> unpack() const;

        /** @brief Returns a read-only packed left-wire row view. */
        [[nodiscard]] NativeBulletproofCircuitRow::PackedWithSlack left_row(std::size_t gate_idx) const noexcept;
        /** @brief Returns a read-only packed right-wire row view. */
        [[nodiscard]] NativeBulletproofCircuitRow::PackedWithSlack right_row(std::size_t gate_idx) const noexcept;
        /** @brief Returns a read-only packed output-wire row view. */
        [[nodiscard]] NativeBulletproofCircuitRow::PackedWithSlack output_row(std::size_t gate_idx) const noexcept;
        /** @brief Returns a read-only packed commitment row view. */
        [[nodiscard]] NativeBulletproofCircuitRow::PackedWithSlack commitment_row(std::size_t commitment_idx) const noexcept;

        /** @brief Returns the live constraint constants stored in the slab. */
        [[nodiscard]] std::span<const FieldElement> constants() const noexcept;

    private:
        struct PackedRowHeader {
            std::size_t offset = 0;
            std::size_t size = 0;
            std::size_t base_size = 0;
            std::size_t capacity = 0;
        };

        enum class RowFamily : unsigned char {
            Left,
            Right,
            Output,
            Commitment,
        };

        PackedRowHeader& row_header(RowFamily family, std::size_t idx) noexcept;
        const PackedRowHeader& row_header(RowFamily family, std::size_t idx) const noexcept;
        NativeBulletproofCircuitTerm* term_data() noexcept;
        const NativeBulletproofCircuitTerm* term_data() const noexcept;
        FieldElement* constant_data() noexcept;
        const FieldElement* constant_data() const noexcept;
        NativeBulletproofCircuitRow::PackedWithSlack row_view(const PackedRowHeader& header) const noexcept;
        void add_row_term(RowFamily family, std::size_t expected_size, std::size_t row_idx,
                          std::size_t constraint_idx, const FieldElement& scalar);

        std::size_t n_gates_ = 0;
        std::size_t n_commitments_ = 0;
        std::size_t n_bits_ = 0;
        std::size_t constraint_size_ = 0;
        std::size_t constraint_base_size_ = 0;
        std::size_t constraint_capacity_ = 0;
        std::size_t term_bytes_offset_ = 0;
        std::size_t constant_bytes_offset_ = 0;
        std::vector<std::max_align_t> storage_;

        friend struct NativeBulletproofCircuit;
        friend class NativeBulletproofCircuitTemplate;
    };

    std::size_t n_gates = 0;
    std::size_t n_commitments = 0;
    std::size_t n_bits = 0;
    std::vector<NativeBulletproofCircuitRow> wl;
    std::vector<NativeBulletproofCircuitRow> wr;
    std::vector<NativeBulletproofCircuitRow> wo;
    std::vector<NativeBulletproofCircuitRow> wv;
    std::vector<FieldElement> c;

    NativeBulletproofCircuit() = default;
    NativeBulletproofCircuit(std::size_t gates, std::size_t commitments, std::size_t bits = 0);

    /** @brief Reinitializes the circuit shape and clears all accumulated constraints. */
    void resize(std::size_t gates, std::size_t commitments, std::size_t bits = 0);

    /** @brief Returns true when the sparse matrix vectors match the declared circuit dimensions. */
    bool has_valid_shape() const;

    /** @brief Appends a new linear constraint constant term and returns its index. */
    std::size_t add_constraint(const FieldElement& constant = FieldElement::zero());

    /** @brief Adds a coefficient to the left-wire matrix. */
    void add_left_term(std::size_t gate_idx, std::size_t constraint_idx, const FieldElement& scalar);

    /** @brief Adds a coefficient to the right-wire matrix. */
    void add_right_term(std::size_t gate_idx, std::size_t constraint_idx, const FieldElement& scalar);

    /** @brief Adds a coefficient to the output-wire matrix. */
    void add_output_term(std::size_t gate_idx, std::size_t constraint_idx, const FieldElement& scalar);

    /** @brief Adds a coefficient to the commitment matrix using the Bulletproof sign convention. */
    void add_commitment_term(std::size_t commitment_idx, std::size_t constraint_idx, const FieldElement& scalar);

    /** @brief Evaluates the circuit against a witness assignment and checks all gate and row equations. */
    bool evaluate(const BulletproofAssignmentData& assignment) const;

    /** @brief Packs the circuit into one aligned slab with no additional row or constraint slack. */
    Result<PackedWithSlack> pack_with_slack() const;
    /** @brief Packs the circuit into one aligned slab with caller-specified slack for later mutation. */
    Result<PackedWithSlack> pack_with_slack(const PackedSlack& slack) const;

private:
    /** @brief Shared bounds-checked helper for appending a sparse term to one matrix family. */
    static void add_row_term(std::vector<NativeBulletproofCircuitRow>& rows, std::size_t expected_size,
                             std::size_t row_idx, std::size_t constraint_idx, const FieldElement& scalar);
};

/**
 * @brief Experimental single-proof wrapper over the imported legacy Bulletproof circuit backend.
 *
 * This artifact is wire-ready: when the circuit exposes one committed scalar it carries the exact
 * compressed public point alongside the proof bytes. The proof transcript is always bound to a
 * canonical digest of the native circuit and optional statement-binding bytes supplied to the
 * prove/verify helpers below.
 */
struct ExperimentalBulletproofProof {
    static constexpr unsigned char kSerializationVersion = 2;

    BulletproofPointBytes commitment{};
    Bytes proof;

    Result<Bytes> serialize() const;
    static Result<ExperimentalBulletproofProof> deserialize(std::span<const unsigned char> bytes);
};

/**
 * @brief Public-key-agnostic native verifier-circuit template.
 *
 * This caches the message/topic-dependent lowering work up to, but not including, the final
 * public-key binding step. Instantiate it with a packed Purify public key when you need the exact
 * native circuit for a specific user.
 */
class NativeBulletproofCircuitTemplate {
public:
    Result<NativeBulletproofCircuit::PackedWithSlack> instantiate_packed(const UInt512& pubkey) const;
    Result<NativeBulletproofCircuit> instantiate(const UInt512& pubkey) const;

private:
    NativeBulletproofCircuit::PackedWithSlack base_packed_;
    Expr p1x_;
    Expr p2x_;
    Expr out_;

    friend Result<NativeBulletproofCircuitTemplate> verifier_circuit_template(const Bytes& message);
};

/**
 * @brief Proves a native circuit with the experimental imported Bulletproof circuit backend.
 *
 * This wrapper only supports circuits with exactly one committed scalar. Providing `blind =
 * std::nullopt` yields the exact public point commitment `assignment.commitments[0] *
 * value_generator`, which is the form needed for `R = rG` style statements.
 */
Result<ExperimentalBulletproofProof> prove_experimental_circuit(
    const NativeBulletproofCircuit& circuit,
    const BulletproofAssignmentData& assignment,
    const BulletproofScalarBytes& nonce,
    const BulletproofGeneratorBytes& value_generator,
    std::span<const unsigned char> statement_binding = {},
    std::optional<BulletproofScalarBytes> blind = std::nullopt);
Result<ExperimentalBulletproofProof> prove_experimental_circuit(
    const NativeBulletproofCircuit::PackedWithSlack& circuit,
    const BulletproofAssignmentData& assignment,
    const BulletproofScalarBytes& nonce,
    const BulletproofGeneratorBytes& value_generator,
    std::span<const unsigned char> statement_binding = {},
    std::optional<BulletproofScalarBytes> blind = std::nullopt);

/** @brief Verifies a proof produced by `prove_experimental_circuit` against the same one-commitment native circuit. */
Result<bool> verify_experimental_circuit(
    const NativeBulletproofCircuit& circuit,
    const ExperimentalBulletproofProof& proof,
    const BulletproofGeneratorBytes& value_generator,
    std::span<const unsigned char> statement_binding = {});
Result<bool> verify_experimental_circuit(
    const NativeBulletproofCircuit::PackedWithSlack& circuit,
    const ExperimentalBulletproofProof& proof,
    const BulletproofGeneratorBytes& value_generator,
    std::span<const unsigned char> statement_binding = {});

/** @brief Builds a reusable public-key-agnostic verifier-circuit template for a message. */
Result<NativeBulletproofCircuitTemplate> verifier_circuit_template(const Bytes& message);

/**
 * @brief Lowering helper that converts a symbolic transcript into native Bulletproof witness and circuit forms.
 */
class BulletproofTranscript {
public:
    /** @brief Rewrites transcript variable names to their eventual Bulletproof wire aliases. */
    void replace_expr_v_with_bp_var(Expr& expr);

    /** @brief Detects simple witness aliases and records them for later assignment lowering. */
    bool replace_and_insert(Expr& expr, Symbol symbol);

    /** @brief Adds one symbolic wire assignment to the lowering state. */
    void add_assignment(Symbol symbol, Expr expr);

    /** @brief Imports a symbolic transcript and pads it to a power-of-two multiplication count. */
    Status from_transcript(const Transcript& transcript, std::size_t n_bits);

    /** @brief Binds packed public-key coordinates and the output commitment into explicit constraints. */
    Status add_pubkey_and_out(const UInt512& pubkey, Expr p1x, Expr p2x, Expr out);

    /** @brief Renders the lowered circuit in the legacy textual verifier format. */
    std::string to_string() const;

    /** @brief Evaluates the lowered symbolic constraints with a concrete commitment value. */
    bool evaluate(const WitnessAssignments& vars, const FieldElement& commitment) const;

    /** @brief Builds the native sparse circuit object from the lowered assignments and constraints. */
    NativeBulletproofCircuit native_circuit() const;

    /** @brief Materializes the witness columns expected by the native circuit representation. */
    Result<BulletproofAssignmentData> assignment_data(const WitnessAssignments& vars) const;

    /** @brief Materializes the witness columns with an explicit output commitment value. */
    Result<BulletproofAssignmentData> assignment_data(const WitnessAssignments& vars, const FieldElement& commitment) const;

    /** @brief Serializes the derived witness assignment using the legacy blob format. */
    Result<Bytes> serialize_assignment(const WitnessAssignments& vars) const;

private:
    struct Assignment {
        Symbol symbol;
        Expr expr;
        bool is_v;
    };

    static bool is_transcript_var(Symbol symbol);
    static bool contains_transcript_var(const Expr& expr);
    Result<BulletproofAssignmentData> assignment_data_impl(const WitnessAssignments& vars, const FieldElement* commitment) const;

    std::vector<Assignment> assignments_;
    std::vector<std::pair<Expr, Expr>> constraints_;
    std::vector<std::optional<Symbol>> witness_to_a_;
    std::vector<std::pair<std::uint32_t, Symbol>> witness_to_a_order_;
    std::size_t n_witnesses_ = 0;
    std::size_t n_muls_ = 0;
    std::size_t n_commitments_ = 1;
    std::size_t n_bits_ = 0;
};

/** @brief Selects one of two field constants using a single boolean expression bit. */
Expr circuit_1bit(const std::array<FieldElement, 2>& values, Transcript& transcript, const Expr& x);

/** @brief Selects one of four field constants using two boolean expression bits. */
Expr circuit_2bit(const std::array<FieldElement, 4>& values, Transcript& transcript, const Expr& x, const Expr& y);

/** @brief Selects one of eight field constants using three boolean expression bits. */
Expr circuit_3bit(const std::array<FieldElement, 8>& values, Transcript& transcript,
                  const Expr& x, const Expr& y, const Expr& z);

/** @brief Symbolic affine point represented as independent x and y expressions. */
using ExprPoint = std::pair<Expr, Expr>;

/** @brief Selects between two affine point constants using one boolean expression bit. */
ExprPoint circuit_1bit_point(const EllipticCurve& curve, const std::array<JacobianPoint, 2>& points,
                             Transcript& transcript, const Expr& b0);

/** @brief Selects between four affine point constants using two boolean expression bits. */
ExprPoint circuit_2bit_point(const EllipticCurve& curve, const std::array<JacobianPoint, 4>& points,
                             Transcript& transcript, const Expr& b0, const Expr& b1);

/** @brief Selects between eight affine point constants using three boolean expression bits. */
ExprPoint circuit_3bit_point(const EllipticCurve& curve, const std::array<JacobianPoint, 8>& points,
                             Transcript& transcript, const Expr& b0, const Expr& b1, const Expr& b2);

/** @brief Conditionally negates an elliptic-curve point encoded as symbolic affine expressions. */
ExprPoint circuit_optionally_negate_ec(const ExprPoint& point, Transcript& transcript, const Expr& negate_bit);

/** @brief Symbolically adds two affine elliptic-curve points. */
ExprPoint circuit_ec_add(Transcript& transcript, const ExprPoint& p1, const ExprPoint& p2);

/** @brief Symbolically adds two affine points and returns only the resulting x-coordinate. */
Expr circuit_ec_add_x(Transcript& transcript, const ExprPoint& p1, const ExprPoint& p2);

/** @brief Builds the symbolic x-coordinate multiplication gadget for one curve point. */
Expr circuit_ec_multiply_x(const EllipticCurve& curve, Transcript& transcript,
                           const JacobianPoint& point, const std::vector<Expr>& bits);

/** @brief Builds the symbolic Purify output combiner over two x-coordinates. */
Expr circuit_combine(Transcript& transcript, const Expr& x1, const Expr& x2);

/** @brief Result bundle returned by the main symbolic Purify circuit construction. */
struct CircuitMainResult {
    Expr out;
    Expr p1x;
    Expr p2x;
    std::size_t n_bits;
};

/** @brief Builds the full symbolic Purify circuit from message points and optional witness scalars. */
Result<CircuitMainResult> circuit_main(Transcript& transcript, const JacobianPoint& m1, const JacobianPoint& m2,
                                       const std::optional<UInt256>& z1 = std::nullopt,
                                       const std::optional<UInt256>& z2 = std::nullopt);

}  // namespace purify
