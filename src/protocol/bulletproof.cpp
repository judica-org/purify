// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file bulletproof.cpp
 * @brief Lowering and native circuit helpers for Purify's Bulletproof-style verifier model.
 */

#include "purify/bulletproof.hpp"
#include "bulletproof_internal.hpp"
#include "bppp_bridge.h"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <new>
#include <sstream>
#include <type_traits>
#include <unordered_map>

namespace purify {

struct BulletproofBackendResourceDeleter {
    void operator()(purify_bulletproof_backend_resources* resources) const noexcept {
        purify_bulletproof_backend_resources_destroy(resources);
    }
};

using BulletproofBackendResourcePtr =
    std::unique_ptr<purify_bulletproof_backend_resources, BulletproofBackendResourceDeleter>;

struct ExperimentalBulletproofBackendCache::Impl {
    std::unordered_map<std::size_t, BulletproofBackendResourcePtr> resources;
};

ExperimentalBulletproofBackendCache::ExperimentalBulletproofBackendCache() : impl_(std::make_unique<Impl>()) {}

ExperimentalBulletproofBackendCache::ExperimentalBulletproofBackendCache(
    ExperimentalBulletproofBackendCache&& other) noexcept = default;

ExperimentalBulletproofBackendCache& ExperimentalBulletproofBackendCache::operator=(
    ExperimentalBulletproofBackendCache&& other) noexcept = default;

ExperimentalBulletproofBackendCache::~ExperimentalBulletproofBackendCache() = default;

void ExperimentalBulletproofBackendCache::clear() {
    if (impl_ != nullptr) {
        impl_->resources.clear();
    }
}

std::size_t ExperimentalBulletproofBackendCache::size() const noexcept {
    return impl_ != nullptr ? impl_->resources.size() : 0;
}

purify_bulletproof_backend_resources* ExperimentalBulletproofBackendCache::get_or_create(std::size_t n_gates) {
    if (impl_ == nullptr) {
        return nullptr;
    }

    auto it = impl_->resources.find(n_gates);
    if (it != impl_->resources.end()) {
        return it->second.get();
    }

    purify_bulletproof_backend_resources* created = purify_bulletproof_backend_resources_create(n_gates);
    if (created == nullptr) {
        return nullptr;
    }

    auto inserted = impl_->resources.emplace(n_gates, BulletproofBackendResourcePtr(created));
    return inserted.first->second.get();
}

}  // namespace purify

namespace {

using purify::Expr;
using purify::ErrorCode;
using purify::ExperimentalBulletproofBackendCache;
using purify::ExperimentalBulletproofProof;
using purify::FieldElement;
using purify::Result;
using purify::Symbol;
using purify::SymbolKind;
using purify::WitnessAssignments;
using purify::Bytes;
using purify::BulletproofAssignmentData;
using purify::BulletproofGeneratorBytes;
using purify::BulletproofPointBytes;
using purify::BulletproofScalarBytes;
using PackedCircuit = purify::NativeBulletproofCircuit::PackedWithSlack;

static_assert(std::is_trivially_copyable_v<purify::NativeBulletproofCircuitTerm>,
              "Packed circuit storage requires trivially copyable terms");
static_assert(std::is_trivially_copyable_v<purify::FieldElement>,
              "Packed circuit storage requires trivially copyable field elements");

std::uint32_t narrow_symbol_index(std::size_t index) {
    assert(index <= static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max())
           && "symbol index must fit in uint32_t");
    return static_cast<std::uint32_t>(index);
}

struct ResolvedValues {
    WitnessAssignments witness;
    std::vector<std::optional<FieldElement>> left;
    std::vector<std::optional<FieldElement>> right;
    std::vector<std::optional<FieldElement>> output;
    std::vector<std::optional<FieldElement>> commitment;

    ResolvedValues(std::size_t witness_count, std::size_t gate_count, std::size_t commitment_count)
        : witness(witness_count), left(gate_count), right(gate_count), output(gate_count), commitment(commitment_count) {}

    std::optional<FieldElement> get(Symbol symbol) const {
        std::size_t index = symbol.index;
        switch (symbol.kind) {
        case SymbolKind::Witness:
            if (index >= witness.size()) {
                return std::nullopt;
            }
            return witness[index];
        case SymbolKind::Left:
            if (index >= left.size()) {
                return std::nullopt;
            }
            return left[index];
        case SymbolKind::Right:
            if (index >= right.size()) {
                return std::nullopt;
            }
            return right[index];
        case SymbolKind::Output:
            if (index >= output.size()) {
                return std::nullopt;
            }
            return output[index];
        case SymbolKind::Commitment:
            if (index >= commitment.size()) {
                return std::nullopt;
            }
            return commitment[index];
        }
        return std::nullopt;
    }

    bool set(Symbol symbol, const FieldElement& value) {
        std::size_t index = symbol.index;
        switch (symbol.kind) {
        case SymbolKind::Witness:
            if (index >= witness.size()) {
                return false;
            }
            witness[index] = value;
            return true;
        case SymbolKind::Left:
            if (index >= left.size()) {
                return false;
            }
            left[index] = value;
            return true;
        case SymbolKind::Right:
            if (index >= right.size()) {
                return false;
            }
            right[index] = value;
            return true;
        case SymbolKind::Output:
            if (index >= output.size()) {
                return false;
            }
            output[index] = value;
            return true;
        case SymbolKind::Commitment:
            if (index >= commitment.size()) {
                return false;
            }
            commitment[index] = value;
            return true;
        }
        return false;
    }
};

Result<FieldElement> evaluate_known(const Expr& expr, const ResolvedValues& values) {
    FieldElement out = expr.constant();
    for (const auto& term : expr.linear()) {
        std::optional<FieldElement> value = values.get(term.first);
        if (!value.has_value()) {
            return purify::unexpected_error(purify::ErrorCode::MissingValue, "BulletproofTranscript::evaluate_known:missing_term");
        }
        out = out + *value * term.second;
    }
    return out;
}

bool is_power_of_two(std::size_t value) {
    return value != 0 && (value & (value - 1)) == 0;
}

bool checked_add_size(std::size_t lhs, std::size_t rhs, std::size_t& out) {
    if (rhs > std::numeric_limits<std::size_t>::max() - lhs) {
        return false;
    }
    out = lhs + rhs;
    return true;
}

bool checked_mul_size(std::size_t lhs, std::size_t rhs, std::size_t& out) {
    if (lhs != 0 && rhs > std::numeric_limits<std::size_t>::max() / lhs) {
        return false;
    }
    out = lhs * rhs;
    return true;
}

bool checked_align_up(std::size_t value, std::size_t alignment, std::size_t& out) {
    assert(alignment != 0 && "alignment must be non-zero");
    const std::size_t remainder = value % alignment;
    if (remainder == 0) {
        out = value;
        return true;
    }
    return checked_add_size(value, alignment - remainder, out);
}

bool packed_row_count(std::size_t n_gates, std::size_t n_commitments, std::size_t& out) {
    std::size_t gate_rows = 0;
    return checked_mul_size(n_gates, 3, gate_rows) && checked_add_size(gate_rows, n_commitments, out);
}

std::byte* allocate_packed_circuit_storage(std::size_t bytes) {
    if (bytes == 0) {
        return nullptr;
    }
    return static_cast<std::byte*>(::operator new(bytes, std::align_val_t(alignof(std::max_align_t))));
}

void append_u32_le(Bytes& out, std::uint32_t value) {
    for (int i = 0; i < 4; ++i) {
        out.push_back(static_cast<unsigned char>((value >> (8 * i)) & 0xffU));
    }
}

void append_u64_le(Bytes& out, std::uint64_t value) {
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<unsigned char>((value >> (8 * i)) & 0xffU));
    }
}

void append_symbol_digest(Bytes& out, const purify::Symbol& symbol) {
    using SymbolRank = std::underlying_type_t<purify::SymbolKind>;
    append_u64_le(out, static_cast<std::uint64_t>(static_cast<SymbolRank>(symbol.kind)));
    append_u64_le(out, static_cast<std::uint64_t>(symbol.index));
}

void append_expr_digest(Bytes& out, const purify::Expr& expr) {
    const auto constant = expr.constant().to_bytes_be();
    out.insert(out.end(), constant.begin(), constant.end());
    append_u64_le(out, static_cast<std::uint64_t>(expr.linear().size()));
    for (const auto& term : expr.linear()) {
        append_symbol_digest(out, term.first);
        const auto coeff = term.second.to_bytes_be();
        out.insert(out.end(), coeff.begin(), coeff.end());
    }
}

std::optional<std::uint32_t> read_u32_le(std::span<const unsigned char> bytes, std::size_t offset) {
    std::uint32_t value = 0;
    if (offset + 4 > bytes.size()) {
        return std::nullopt;
    }
    for (int i = 0; i < 4; ++i) {
        value |= static_cast<std::uint32_t>(bytes[offset + i]) << (8 * i);
    }
    return value;
}

Bytes flatten_scalars32(const std::vector<FieldElement>& values) {
    Bytes out;
    out.reserve(values.size() * 32);
    for (const FieldElement& value : values) {
        auto bytes = value.to_bytes_be();
        out.insert(out.end(), bytes.begin(), bytes.end());
    }
    return out;
}

template <typename RowEntriesFn>
void append_row_family_digest_generic(Bytes& out, std::size_t row_count, const RowEntriesFn& row_entries) {
    append_u64_le(out, static_cast<std::uint64_t>(row_count));
    for (std::size_t i = 0; i < row_count; ++i) {
        std::span<const purify::NativeBulletproofCircuitTerm> entries = row_entries(i);
        append_u64_le(out, static_cast<std::uint64_t>(entries.size()));
        for (const auto& entry : entries) {
            append_u64_le(out, static_cast<std::uint64_t>(entry.idx));
            auto scalar = entry.scalar.to_bytes_be();
            out.insert(out.end(), scalar.begin(), scalar.end());
        }
    }
}

Bytes circuit_binding_digest(const purify::NativeBulletproofCircuit& circuit, std::span<const unsigned char> statement_binding) {
    static const purify::TaggedHash kCircuitBindingTag("Purify/ExperimentalBulletproof/CircuitV1");
    Bytes serialized;
    serialized.reserve(64 + circuit.c.size() * 32);
    append_u64_le(serialized, static_cast<std::uint64_t>(circuit.n_gates));
    append_u64_le(serialized, static_cast<std::uint64_t>(circuit.n_commitments));
    append_u64_le(serialized, static_cast<std::uint64_t>(circuit.n_bits));
    append_u64_le(serialized, static_cast<std::uint64_t>(circuit.c.size()));
    append_row_family_digest_generic(serialized, circuit.wl.size(),
                                     [&](std::size_t i) { return std::span<const purify::NativeBulletproofCircuitTerm>(circuit.wl[i].entries); });
    append_row_family_digest_generic(serialized, circuit.wr.size(),
                                     [&](std::size_t i) { return std::span<const purify::NativeBulletproofCircuitTerm>(circuit.wr[i].entries); });
    append_row_family_digest_generic(serialized, circuit.wo.size(),
                                     [&](std::size_t i) { return std::span<const purify::NativeBulletproofCircuitTerm>(circuit.wo[i].entries); });
    append_row_family_digest_generic(serialized, circuit.wv.size(),
                                     [&](std::size_t i) { return std::span<const purify::NativeBulletproofCircuitTerm>(circuit.wv[i].entries); });
    for (const FieldElement& constant : circuit.c) {
        auto bytes = constant.to_bytes_be();
        serialized.insert(serialized.end(), bytes.begin(), bytes.end());
    }
    append_u64_le(serialized, static_cast<std::uint64_t>(statement_binding.size()));
    serialized.insert(serialized.end(), statement_binding.begin(), statement_binding.end());
    std::array<unsigned char, 32> digest =
        kCircuitBindingTag.digest(std::span<const unsigned char>(serialized.data(), serialized.size()));
    return Bytes(digest.begin(), digest.end());
}

Bytes circuit_binding_digest(const PackedCircuit& circuit, std::span<const unsigned char> statement_binding) {
    static const purify::TaggedHash kCircuitBindingTag("Purify/ExperimentalBulletproof/CircuitV1");
    Bytes serialized;
    serialized.reserve(64 + circuit.constraint_count() * 32);
    append_u64_le(serialized, static_cast<std::uint64_t>(circuit.n_gates()));
    append_u64_le(serialized, static_cast<std::uint64_t>(circuit.n_commitments()));
    append_u64_le(serialized, static_cast<std::uint64_t>(circuit.n_bits()));
    append_u64_le(serialized, static_cast<std::uint64_t>(circuit.constraint_count()));
    append_row_family_digest_generic(serialized, circuit.n_gates(),
                                     [&](std::size_t i) { return circuit.left_row(i).entries_view(); });
    append_row_family_digest_generic(serialized, circuit.n_gates(),
                                     [&](std::size_t i) { return circuit.right_row(i).entries_view(); });
    append_row_family_digest_generic(serialized, circuit.n_gates(),
                                     [&](std::size_t i) { return circuit.output_row(i).entries_view(); });
    append_row_family_digest_generic(serialized, circuit.n_commitments(),
                                     [&](std::size_t i) { return circuit.commitment_row(i).entries_view(); });
    for (const FieldElement& constant : circuit.constants()) {
        auto bytes = constant.to_bytes_be();
        serialized.insert(serialized.end(), bytes.begin(), bytes.end());
    }
    append_u64_le(serialized, static_cast<std::uint64_t>(statement_binding.size()));
    serialized.insert(serialized.end(), statement_binding.begin(), statement_binding.end());
    std::array<unsigned char, 32> digest =
        kCircuitBindingTag.digest(std::span<const unsigned char>(serialized.data(), serialized.size()));
    return Bytes(digest.begin(), digest.end());
}

template <typename CircuitLike>
void append_constraint_to_circuit(CircuitLike& circuit, const Expr& lhs, const Expr& rhs) {
    Expr combined = lhs - rhs;
    std::size_t constraint_idx = circuit.add_constraint(combined.constant().negate());
    for (const auto& term : combined.linear()) {
        std::size_t index = term.first.index;
        switch (term.first.kind) {
        case SymbolKind::Left:
            circuit.add_left_term(index, constraint_idx, term.second);
            break;
        case SymbolKind::Right:
            circuit.add_right_term(index, constraint_idx, term.second);
            break;
        case SymbolKind::Output:
            circuit.add_output_term(index, constraint_idx, term.second);
            break;
        case SymbolKind::Commitment:
            circuit.add_commitment_term(index, constraint_idx, term.second);
            break;
        case SymbolKind::Witness:
            assert(false && "append_constraint_to_circuit() encountered an unmapped witness symbol");
            break;
        }
    }
}

struct FlattenedRowFamily {
    std::vector<purify_bulletproof_row_view> views;
    std::vector<std::size_t> indices;
    Bytes scalars32;
};

template <typename RowEntriesFn>
FlattenedRowFamily flatten_row_family_generic(std::size_t row_count, const RowEntriesFn& row_entries,
                                              std::size_t constraint_offset) {
    FlattenedRowFamily flat;
    std::vector<std::size_t> offsets;
    std::vector<std::size_t> counts;
    offsets.reserve(row_count);
    counts.reserve(row_count);
    flat.views.resize(row_count);

    std::size_t total_entries = 0;
    for (std::size_t i = 0; i < row_count; ++i) {
        std::span<const purify::NativeBulletproofCircuitTerm> entries = row_entries(i);
        total_entries += std::count_if(entries.begin(), entries.end(),
                                       [&](const auto& entry) { return entry.idx >= constraint_offset; });
    }
    flat.indices.reserve(total_entries);
    flat.scalars32.reserve(total_entries * 32);

    for (std::size_t i = 0; i < row_count; ++i) {
        std::span<const purify::NativeBulletproofCircuitTerm> entries = row_entries(i);
        std::size_t kept = 0;
        offsets.push_back(flat.indices.size());
        for (const auto& entry : entries) {
            if (entry.idx < constraint_offset) {
                continue;
            }
            ++kept;
            flat.indices.push_back(entry.idx - constraint_offset);
            auto bytes = entry.scalar.to_bytes_be();
            flat.scalars32.insert(flat.scalars32.end(), bytes.begin(), bytes.end());
        }
        counts.push_back(kept);
    }

    const std::size_t* indices_base = flat.indices.empty() ? nullptr : flat.indices.data();
    const unsigned char* scalars_base = flat.scalars32.empty() ? nullptr : flat.scalars32.data();
    for (std::size_t i = 0; i < row_count; ++i) {
        const std::size_t count = counts[i];
        const std::size_t start = offsets[i];
        flat.views[i].size = count;
        flat.views[i].indices = count == 0 ? nullptr : indices_base + start;
        flat.views[i].scalars32 = count == 0 ? nullptr : scalars_base + start * 32;
    }
    return flat;
}

struct FlattenedCircuitView {
    FlattenedRowFamily wl;
    FlattenedRowFamily wr;
    FlattenedRowFamily wo;
    FlattenedRowFamily wv;
    Bytes constants32;
    purify_bulletproof_circuit_view view{};
};

FlattenedCircuitView flatten_circuit_view(const purify::NativeBulletproofCircuit& circuit) {
    FlattenedCircuitView flat;
    const std::size_t implicit_bit_constraints = 2 * circuit.n_bits;
    assert(circuit.c.size() >= implicit_bit_constraints && "native circuit must contain all implicit bit constraints");
    flat.wl = flatten_row_family_generic(circuit.wl.size(),
                                         [&](std::size_t i) { return std::span<const purify::NativeBulletproofCircuitTerm>(circuit.wl[i].entries); },
                                         implicit_bit_constraints);
    flat.wr = flatten_row_family_generic(circuit.wr.size(),
                                         [&](std::size_t i) { return std::span<const purify::NativeBulletproofCircuitTerm>(circuit.wr[i].entries); },
                                         implicit_bit_constraints);
    flat.wo = flatten_row_family_generic(circuit.wo.size(),
                                         [&](std::size_t i) { return std::span<const purify::NativeBulletproofCircuitTerm>(circuit.wo[i].entries); },
                                         implicit_bit_constraints);
    flat.wv = flatten_row_family_generic(circuit.wv.size(),
                                         [&](std::size_t i) { return std::span<const purify::NativeBulletproofCircuitTerm>(circuit.wv[i].entries); },
                                         implicit_bit_constraints);
    std::vector<FieldElement> explicit_constants(circuit.c.begin() + static_cast<std::ptrdiff_t>(implicit_bit_constraints), circuit.c.end());
    flat.constants32 = flatten_scalars32(explicit_constants);
    flat.view.n_gates = circuit.n_gates;
    flat.view.n_commits = circuit.n_commitments;
    flat.view.n_bits = circuit.n_bits;
    flat.view.n_constraints = explicit_constants.size();
    flat.view.wl = flat.wl.views.data();
    flat.view.wr = flat.wr.views.data();
    flat.view.wo = flat.wo.views.data();
    flat.view.wv = flat.wv.views.data();
    flat.view.c32 = flat.constants32.empty() ? nullptr : flat.constants32.data();
    return flat;
}

FlattenedCircuitView flatten_circuit_view(const PackedCircuit& circuit) {
    FlattenedCircuitView flat;
    const std::size_t implicit_bit_constraints = 2 * circuit.n_bits();
    assert(circuit.constraint_count() >= implicit_bit_constraints
           && "packed circuit must contain all implicit bit constraints");
    flat.wl = flatten_row_family_generic(circuit.n_gates(),
                                         [&](std::size_t i) { return circuit.left_row(i).entries_view(); },
                                         implicit_bit_constraints);
    flat.wr = flatten_row_family_generic(circuit.n_gates(),
                                         [&](std::size_t i) { return circuit.right_row(i).entries_view(); },
                                         implicit_bit_constraints);
    flat.wo = flatten_row_family_generic(circuit.n_gates(),
                                         [&](std::size_t i) { return circuit.output_row(i).entries_view(); },
                                         implicit_bit_constraints);
    flat.wv = flatten_row_family_generic(circuit.n_commitments(),
                                         [&](std::size_t i) { return circuit.commitment_row(i).entries_view(); },
                                         implicit_bit_constraints);
    std::vector<FieldElement> explicit_constants(circuit.constants().begin() + static_cast<std::ptrdiff_t>(implicit_bit_constraints),
                                                 circuit.constants().end());
    flat.constants32 = flatten_scalars32(explicit_constants);
    flat.view.n_gates = circuit.n_gates();
    flat.view.n_commits = circuit.n_commitments();
    flat.view.n_bits = circuit.n_bits();
    flat.view.n_constraints = explicit_constants.size();
    flat.view.wl = flat.wl.views.data();
    flat.view.wr = flat.wr.views.data();
    flat.view.wo = flat.wo.views.data();
    flat.view.wv = flat.wv.views.data();
    flat.view.c32 = flat.constants32.empty() ? nullptr : flat.constants32.data();
    return flat;
}

struct FlattenedAssignmentView {
    Bytes left32;
    Bytes right32;
    Bytes output32;
    Bytes commitments32;
    purify_bulletproof_assignment_view view{};
};

FlattenedAssignmentView flatten_assignment_view(const purify::BulletproofAssignmentData& assignment) {
    FlattenedAssignmentView flat;
    flat.left32 = flatten_scalars32(assignment.left);
    flat.right32 = flatten_scalars32(assignment.right);
    flat.output32 = flatten_scalars32(assignment.output);
    flat.commitments32 = flatten_scalars32(assignment.commitments);
    flat.view.n_gates = assignment.left.size();
    flat.view.n_commits = assignment.commitments.size();
    flat.view.al32 = flat.left32.empty() ? nullptr : flat.left32.data();
    flat.view.ar32 = flat.right32.empty() ? nullptr : flat.right32.data();
    flat.view.ao32 = flat.output32.empty() ? nullptr : flat.output32.data();
    flat.view.v32 = flat.commitments32.empty() ? nullptr : flat.commitments32.data();
    return flat;
}

std::size_t circuit_n_gates(const purify::NativeBulletproofCircuit& circuit) {
    return circuit.n_gates;
}

std::size_t circuit_n_gates(const PackedCircuit& circuit) {
    return circuit.n_gates();
}

std::size_t circuit_n_commitments(const purify::NativeBulletproofCircuit& circuit) {
    return circuit.n_commitments;
}

std::size_t circuit_n_commitments(const PackedCircuit& circuit) {
    return circuit.n_commitments();
}

struct ResolvedBulletproofBackendResources {
    purify_bulletproof_backend_resources* resources = nullptr;
    purify::BulletproofBackendResourcePtr owned_resources;
};

ResolvedBulletproofBackendResources resolve_bulletproof_backend_resources(
    std::size_t n_gates,
    purify::ExperimentalBulletproofBackendCache* cache) {
    ResolvedBulletproofBackendResources out;

    if (cache != nullptr) {
        out.resources = cache->get_or_create(n_gates);
        if (out.resources != nullptr) {
            return out;
        }
        return out;
    }

    purify_bulletproof_backend_resources* created = purify_bulletproof_backend_resources_create(n_gates);
    if (created == nullptr) {
        return out;
    }

    out.owned_resources.reset(created);
    out.resources = out.owned_resources.get();
    return out;
}

template <typename CircuitLike>
Result<ExperimentalBulletproofProof> prove_experimental_circuit_impl(
    const CircuitLike& circuit,
    const BulletproofAssignmentData& assignment,
    const BulletproofScalarBytes& nonce,
    const BulletproofGeneratorBytes& value_generator,
    std::span<const unsigned char> statement_binding,
    std::optional<BulletproofScalarBytes> blind,
    ExperimentalBulletproofBackendCache* backend_cache,
    bool require_assignment_validation,
    const char* shape_context,
    const char* gates_context,
    const char* commitments_context,
    const char* assignment_shape_context,
    const char* assignment_invalid_context,
    const char* proof_size_context,
    const char* bridge_context) {
    ExperimentalBulletproofProof out;
    if (!circuit.has_valid_shape()) {
        return unexpected_error(ErrorCode::InvalidDimensions, shape_context);
    }
    if (!is_power_of_two(circuit_n_gates(circuit))) {
        return unexpected_error(ErrorCode::InvalidDimensions, gates_context);
    }
    if (circuit_n_commitments(circuit) != 1) {
        return unexpected_error(ErrorCode::InvalidDimensions, commitments_context);
    }
    if (assignment.left.size() != circuit_n_gates(circuit)
        || assignment.right.size() != circuit_n_gates(circuit)
        || assignment.output.size() != circuit_n_gates(circuit)
        || assignment.commitments.size() != circuit_n_commitments(circuit)) {
        return unexpected_error(ErrorCode::SizeMismatch, assignment_shape_context);
    }
    if (require_assignment_validation && !circuit.evaluate(assignment)) {
        return unexpected_error(ErrorCode::EquationMismatch, assignment_invalid_context);
    }

    FlattenedCircuitView flat_circuit = flatten_circuit_view(circuit);
    FlattenedAssignmentView flat_assignment = flatten_assignment_view(assignment);
    Bytes binding_digest = circuit_binding_digest(circuit, statement_binding);
    Bytes proof_bytes(std::max<std::size_t>(purify_bulletproof_required_proof_size(circuit_n_gates(circuit)), 4096), 0);
    std::size_t proof_len = proof_bytes.size();
    BulletproofPointBytes commitment{};
    const unsigned char* blind_ptr = blind.has_value() ? blind->data() : nullptr;
    ResolvedBulletproofBackendResources resolved =
        resolve_bulletproof_backend_resources(circuit_n_gates(circuit), backend_cache);
    purify_bulletproof_backend_resources* resources = resolved.resources;

    if (proof_len == 0 || resources == nullptr) {
        return unexpected_error(ErrorCode::UnexpectedSize, proof_size_context);
    }
    const int ok = require_assignment_validation
        ? purify_bulletproof_prove_circuit_with_resources(resources, &flat_circuit.view, &flat_assignment.view, blind_ptr,
                                                          value_generator.data(), nonce.data(),
                                                          binding_digest.data(), binding_digest.size(),
                                                          commitment.data(), proof_bytes.data(), &proof_len)
        : purify_bulletproof_prove_circuit_assume_valid_with_resources(resources, &flat_circuit.view, &flat_assignment.view, blind_ptr,
                                                                       value_generator.data(), nonce.data(),
                                                                       binding_digest.data(), binding_digest.size(),
                                                                       commitment.data(), proof_bytes.data(), &proof_len);
    if (!ok) {
        return unexpected_error(ErrorCode::BackendRejectedInput, bridge_context);
    }

    proof_bytes.resize(proof_len);
    out.commitment = commitment;
    out.proof = std::move(proof_bytes);
    return out;
}

Result<FieldElement> evaluate_expr_with_assignment(const Expr& expr,
                                                   const purify::BulletproofAssignmentData& assignment) {
    FieldElement out = expr.constant();
    for (const auto& term : expr.linear()) {
        std::size_t index = term.first.index;
        switch (term.first.kind) {
        case SymbolKind::Left:
            if (index >= assignment.left.size()) {
                return purify::unexpected_error(purify::ErrorCode::MissingValue,
                                                "evaluate_expr_with_assignment:left_index");
            }
            out = out + (assignment.left[index] * term.second);
            break;
        case SymbolKind::Right:
            if (index >= assignment.right.size()) {
                return purify::unexpected_error(purify::ErrorCode::MissingValue,
                                                "evaluate_expr_with_assignment:right_index");
            }
            out = out + (assignment.right[index] * term.second);
            break;
        case SymbolKind::Output:
            if (index >= assignment.output.size()) {
                return purify::unexpected_error(purify::ErrorCode::MissingValue,
                                                "evaluate_expr_with_assignment:output_index");
            }
            out = out + (assignment.output[index] * term.second);
            break;
        case SymbolKind::Commitment:
            if (index >= assignment.commitments.size()) {
                return purify::unexpected_error(purify::ErrorCode::MissingValue,
                                                "evaluate_expr_with_assignment:commitment_index");
            }
            out = out + (assignment.commitments[index] * term.second);
            break;
        case SymbolKind::Witness:
            return purify::unexpected_error(purify::ErrorCode::MissingValue,
                                            "evaluate_expr_with_assignment:witness_symbol");
        }
    }
    return out;
}

}  // namespace

namespace purify {

Result<Bytes> BulletproofAssignmentData::serialize() const {
    if (left.size() != right.size() || left.size() != output.size()) {
        return unexpected_error(ErrorCode::SizeMismatch, "BulletproofAssignmentData::serialize:column_sizes");
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

void NativeBulletproofCircuitRow::add(std::size_t idx, const FieldElement& scalar) {
    if (scalar.is_zero()) {
        return;
    }
    entries.push_back({idx, scalar});
}

NativeBulletproofCircuit::NativeBulletproofCircuit(std::size_t gates, std::size_t commitments, std::size_t bits)
    : n_gates(gates), n_commitments(commitments), n_bits(bits), wl(gates), wr(gates), wo(gates), wv(commitments) {}

void NativeBulletproofCircuit::resize(std::size_t gates, std::size_t commitments, std::size_t bits) {
    n_gates = gates;
    n_commitments = commitments;
    n_bits = bits;
    wl.assign(gates, {});
    wr.assign(gates, {});
    wo.assign(gates, {});
    wv.assign(commitments, {});
    c.clear();
}

bool NativeBulletproofCircuit::has_valid_shape() const {
    return wl.size() == n_gates
        && wr.size() == n_gates
        && wo.size() == n_gates
        && wv.size() == n_commitments;
}

std::size_t NativeBulletproofCircuit::add_constraint(const FieldElement& constant) {
    c.push_back(constant);
    return c.size() - 1;
}

void NativeBulletproofCircuit::add_left_term(std::size_t gate_idx, std::size_t constraint_idx, const FieldElement& scalar) {
    add_row_term(wl, n_gates, gate_idx, constraint_idx, scalar);
}

void NativeBulletproofCircuit::add_right_term(std::size_t gate_idx, std::size_t constraint_idx, const FieldElement& scalar) {
    add_row_term(wr, n_gates, gate_idx, constraint_idx, scalar);
}

void NativeBulletproofCircuit::add_output_term(std::size_t gate_idx, std::size_t constraint_idx, const FieldElement& scalar) {
    add_row_term(wo, n_gates, gate_idx, constraint_idx, scalar);
}

void NativeBulletproofCircuit::add_commitment_term(std::size_t commitment_idx, std::size_t constraint_idx, const FieldElement& scalar) {
    add_row_term(wv, n_commitments, commitment_idx, constraint_idx, scalar.negate());
}

bool NativeBulletproofCircuit::evaluate(const BulletproofAssignmentData& assignment) const {
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
    auto accumulate = [&](const std::vector<NativeBulletproofCircuitRow>& rows,
                          const std::vector<FieldElement>& values,
                          bool negate_values = false) {
        if (rows.size() != values.size()) {
            return false;
        }
        for (std::size_t i = 0; i < rows.size(); ++i) {
            if (negate_values) {
                FieldElement negated = values[i].negate();
                for (const NativeBulletproofCircuitTerm& entry : rows[i].entries) {
                    if (entry.idx >= acc.size()) {
                        return false;
                    }
                    acc[entry.idx] = acc[entry.idx] + entry.scalar * negated;
                }
                continue;
            }
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
    if (!accumulate(wv, assignment.commitments, true)) {
        return false;
    }

    for (std::size_t i = 0; i < c.size(); ++i) {
        if (acc[i] != c[i]) {
            return false;
        }
    }
    return true;
}

void NativeBulletproofCircuit::add_row_term(std::vector<NativeBulletproofCircuitRow>& rows, std::size_t expected_size,
                                            std::size_t row_idx, std::size_t constraint_idx, const FieldElement& scalar) {
    (void)expected_size;
    assert(rows.size() == expected_size && "NativeBulletproofCircuit rows must be initialized before adding terms");
    assert(row_idx < rows.size() && "NativeBulletproofCircuit row index out of range");
    rows[row_idx].add(constraint_idx, scalar);
}

void NativeBulletproofCircuit::PackedWithSlack::PackedStorageDeleter::operator()(std::byte* storage) const noexcept {
    if (storage != nullptr) {
        ::operator delete(storage, std::align_val_t(alignof(std::max_align_t)));
    }
}

NativeBulletproofCircuit::PackedWithSlack::PackedWithSlack(const PackedWithSlack& other)
    : n_gates_(other.n_gates_), n_commitments_(other.n_commitments_), n_bits_(other.n_bits_),
      constraint_size_(other.constraint_size_), constraint_base_size_(other.constraint_base_size_),
      constraint_capacity_(other.constraint_capacity_), term_capacity_(other.term_capacity_),
      term_bytes_offset_(other.term_bytes_offset_), constant_bytes_offset_(other.constant_bytes_offset_),
      storage_bytes_(other.storage_bytes_) {
    if (storage_bytes_ != 0) {
        storage_.reset(allocate_packed_circuit_storage(storage_bytes_));
        start_storage_lifetimes();
        std::memcpy(storage_.get(), other.storage_.get(), storage_bytes_);
    }
}

NativeBulletproofCircuit::PackedWithSlack::PackedWithSlack(PackedWithSlack&& other) noexcept
    : n_gates_(other.n_gates_), n_commitments_(other.n_commitments_), n_bits_(other.n_bits_),
      constraint_size_(other.constraint_size_), constraint_base_size_(other.constraint_base_size_),
      constraint_capacity_(other.constraint_capacity_), term_capacity_(other.term_capacity_),
      term_bytes_offset_(other.term_bytes_offset_), constant_bytes_offset_(other.constant_bytes_offset_),
      storage_bytes_(other.storage_bytes_), storage_(std::move(other.storage_)) {
    other.reset_to_empty();
}

NativeBulletproofCircuit::PackedWithSlack&
NativeBulletproofCircuit::PackedWithSlack::operator=(const PackedWithSlack& other) {
    if (this == &other) {
        return *this;
    }
    PackedWithSlack copy(other);
    *this = std::move(copy);
    return *this;
}

NativeBulletproofCircuit::PackedWithSlack&
NativeBulletproofCircuit::PackedWithSlack::operator=(PackedWithSlack&& other) noexcept {
    if (this == &other) {
        return *this;
    }
    n_gates_ = other.n_gates_;
    n_commitments_ = other.n_commitments_;
    n_bits_ = other.n_bits_;
    constraint_size_ = other.constraint_size_;
    constraint_base_size_ = other.constraint_base_size_;
    constraint_capacity_ = other.constraint_capacity_;
    term_capacity_ = other.term_capacity_;
    term_bytes_offset_ = other.term_bytes_offset_;
    constant_bytes_offset_ = other.constant_bytes_offset_;
    storage_bytes_ = other.storage_bytes_;
    storage_ = std::move(other.storage_);
    other.reset_to_empty();
    return *this;
}

bool NativeBulletproofCircuit::PackedWithSlack::compute_storage_layout(std::size_t row_count, std::size_t term_capacity,
                                                                      std::size_t constraint_capacity,
                                                                      std::size_t& term_bytes_offset,
                                                                      std::size_t& constant_bytes_offset,
                                                                      std::size_t& storage_bytes) noexcept {
    std::size_t row_headers_bytes = 0;
    if (!checked_mul_size(row_count, sizeof(PackedRowHeader), row_headers_bytes)
        || !checked_align_up(row_headers_bytes, alignof(NativeBulletproofCircuitTerm), term_bytes_offset)) {
        return false;
    }
    std::size_t terms_bytes = 0;
    if (!checked_mul_size(term_capacity, sizeof(NativeBulletproofCircuitTerm), terms_bytes)) {
        return false;
    }
    std::size_t term_region_end = 0;
    if (!checked_add_size(term_bytes_offset, terms_bytes, term_region_end)
        || !checked_align_up(term_region_end, alignof(FieldElement), constant_bytes_offset)) {
        return false;
    }
    std::size_t constants_bytes = 0;
    if (!checked_mul_size(constraint_capacity, sizeof(FieldElement), constants_bytes)) {
        return false;
    }
    return checked_add_size(constant_bytes_offset, constants_bytes, storage_bytes);
}

void NativeBulletproofCircuit::PackedWithSlack::reset_to_empty() noexcept {
    storage_.reset();
    n_gates_ = 0;
    n_commitments_ = 0;
    n_bits_ = 0;
    constraint_size_ = 0;
    constraint_base_size_ = 0;
    constraint_capacity_ = 0;
    term_capacity_ = 0;
    term_bytes_offset_ = 0;
    constant_bytes_offset_ = 0;
    storage_bytes_ = 0;
}

bool NativeBulletproofCircuit::PackedWithSlack::has_valid_shape() const noexcept {
    if (constraint_base_size_ > constraint_size_ || constraint_size_ > constraint_capacity_) {
        return false;
    }
    std::size_t row_count = 0;
    if (!packed_row_count(n_gates_, n_commitments_, row_count)) {
        return false;
    }
    std::size_t expected_term_offset = 0;
    std::size_t expected_constant_offset = 0;
    std::size_t expected_storage_bytes = 0;
    if (!compute_storage_layout(row_count, term_capacity_, constraint_capacity_,
                                expected_term_offset, expected_constant_offset, expected_storage_bytes)) {
        return false;
    }
    if (term_bytes_offset_ != expected_term_offset || constant_bytes_offset_ != expected_constant_offset
        || storage_bytes_ != expected_storage_bytes) {
        return false;
    }
    if ((storage_ == nullptr) != (storage_bytes_ == 0)) {
        return false;
    }
    if (storage_bytes_ == 0) {
        return row_count == 0 && term_capacity_ == 0 && constraint_capacity_ == 0;
    }

    const PackedRowHeader* headers =
        std::launder(reinterpret_cast<const PackedRowHeader*>(raw_storage_bytes()));
    std::size_t term_cursor = 0;
    for (std::size_t i = 0; i < row_count; ++i) {
        const PackedRowHeader& header = headers[i];
        if (header.base_size > header.size || header.size > header.capacity) {
            return false;
        }
        if (header.offset != term_cursor) {
            return false;
        }
        if (term_cursor > term_capacity_ || header.capacity > term_capacity_ - term_cursor) {
            return false;
        }
        term_cursor += header.capacity;
    }
    return term_cursor == term_capacity_;
}

void NativeBulletproofCircuit::PackedWithSlack::reset() noexcept {
    constraint_size_ = constraint_base_size_;
    std::size_t row_count = 0;
    [[maybe_unused]] const bool ok = packed_row_count(n_gates_, n_commitments_, row_count);
    assert(ok && "PackedWithSlack row count should fit in size_t");
    PackedRowHeader* headers = row_count == 0 ? nullptr
                                              : std::launder(reinterpret_cast<PackedRowHeader*>(raw_storage_bytes()));
    for (std::size_t i = 0; i < row_count; ++i) {
        PackedRowHeader& header = headers[i];
        header.size = header.base_size;
    }
}

NativeBulletproofCircuit::PackedWithSlack::PackedRowHeader&
NativeBulletproofCircuit::PackedWithSlack::row_header(RowFamily family, std::size_t idx) noexcept {
    PackedRowHeader* headers = std::launder(reinterpret_cast<PackedRowHeader*>(raw_storage_bytes()));
    std::size_t base = 0;
    switch (family) {
    case RowFamily::Left:
        base = 0;
        break;
    case RowFamily::Right:
        base = n_gates_;
        break;
    case RowFamily::Output:
        base = 2 * n_gates_;
        break;
    case RowFamily::Commitment:
        base = 3 * n_gates_;
        break;
    }
    return headers[base + idx];
}

const NativeBulletproofCircuit::PackedWithSlack::PackedRowHeader&
NativeBulletproofCircuit::PackedWithSlack::row_header(RowFamily family, std::size_t idx) const noexcept {
    const PackedRowHeader* headers = std::launder(reinterpret_cast<const PackedRowHeader*>(raw_storage_bytes()));
    std::size_t base = 0;
    switch (family) {
    case RowFamily::Left:
        base = 0;
        break;
    case RowFamily::Right:
        base = n_gates_;
        break;
    case RowFamily::Output:
        base = 2 * n_gates_;
        break;
    case RowFamily::Commitment:
        base = 3 * n_gates_;
        break;
    }
    return headers[base + idx];
}

NativeBulletproofCircuitTerm* NativeBulletproofCircuit::PackedWithSlack::term_data() noexcept {
    if (term_capacity_ == 0) {
        return nullptr;
    }
    return std::launder(reinterpret_cast<NativeBulletproofCircuitTerm*>(raw_storage_bytes() + term_bytes_offset_));
}

const NativeBulletproofCircuitTerm* NativeBulletproofCircuit::PackedWithSlack::term_data() const noexcept {
    if (term_capacity_ == 0) {
        return nullptr;
    }
    return std::launder(reinterpret_cast<const NativeBulletproofCircuitTerm*>(raw_storage_bytes() + term_bytes_offset_));
}

FieldElement* NativeBulletproofCircuit::PackedWithSlack::constant_data() noexcept {
    if (constraint_capacity_ == 0) {
        return nullptr;
    }
    return std::launder(reinterpret_cast<FieldElement*>(raw_storage_bytes() + constant_bytes_offset_));
}

const FieldElement* NativeBulletproofCircuit::PackedWithSlack::constant_data() const noexcept {
    if (constraint_capacity_ == 0) {
        return nullptr;
    }
    return std::launder(reinterpret_cast<const FieldElement*>(raw_storage_bytes() + constant_bytes_offset_));
}

unsigned char* NativeBulletproofCircuit::PackedWithSlack::raw_storage_bytes() noexcept {
    return reinterpret_cast<unsigned char*>(storage_.get());
}

const unsigned char* NativeBulletproofCircuit::PackedWithSlack::raw_storage_bytes() const noexcept {
    return reinterpret_cast<const unsigned char*>(storage_.get());
}

void NativeBulletproofCircuit::PackedWithSlack::start_storage_lifetimes() noexcept {
    if (storage_ == nullptr) {
        return;
    }
    std::size_t row_count = 0;
    [[maybe_unused]] const bool ok = packed_row_count(n_gates_, n_commitments_, row_count);
    assert(ok && "PackedWithSlack row count should fit in size_t");
    if (row_count != 0) {
        PackedRowHeader* headers = reinterpret_cast<PackedRowHeader*>(raw_storage_bytes());
        std::uninitialized_value_construct_n(headers, row_count);
    }
    if (term_capacity_ != 0) {
        NativeBulletproofCircuitTerm* terms =
            reinterpret_cast<NativeBulletproofCircuitTerm*>(raw_storage_bytes() + term_bytes_offset_);
        std::uninitialized_value_construct_n(terms, term_capacity_);
    }
    if (constraint_capacity_ != 0) {
        FieldElement* constants = reinterpret_cast<FieldElement*>(raw_storage_bytes() + constant_bytes_offset_);
        std::uninitialized_value_construct_n(constants, constraint_capacity_);
    }
}

NativeBulletproofCircuitRow::PackedWithSlack
NativeBulletproofCircuit::PackedWithSlack::row_view(const PackedRowHeader& header) const noexcept {
    const NativeBulletproofCircuitTerm* terms = term_data();
    return {header.capacity == 0 ? nullptr : terms + header.offset, header.size, header.capacity};
}

std::size_t NativeBulletproofCircuit::PackedWithSlack::add_constraint(const FieldElement& constant) {
    assert(constraint_size_ < constraint_capacity_ && "PackedWithSlack constraint capacity exceeded");
    FieldElement* constants = constant_data();
    constants[constraint_size_] = constant;
    ++constraint_size_;
    return constraint_size_ - 1;
}

void NativeBulletproofCircuit::PackedWithSlack::add_row_term(RowFamily family, std::size_t expected_size,
                                                             std::size_t row_idx, std::size_t constraint_idx,
                                                             const FieldElement& scalar) {
    (void)expected_size;
    if (scalar.is_zero()) {
        return;
    }
    assert(constraint_idx < constraint_size_ && "PackedWithSlack constraint index out of range");
    assert(((family == RowFamily::Commitment) ? n_commitments_ : n_gates_) == expected_size
           && "PackedWithSlack expected row family size mismatch");
    assert(row_idx < expected_size && "PackedWithSlack row index out of range");
    PackedRowHeader& header = row_header(family, row_idx);
    assert(header.size < header.capacity && "PackedWithSlack row capacity exceeded");
    term_data()[header.offset + header.size] = {constraint_idx, scalar};
    ++header.size;
}

void NativeBulletproofCircuit::PackedWithSlack::add_left_term(std::size_t gate_idx, std::size_t constraint_idx,
                                                              const FieldElement& scalar) {
    add_row_term(RowFamily::Left, n_gates_, gate_idx, constraint_idx, scalar);
}

void NativeBulletproofCircuit::PackedWithSlack::add_right_term(std::size_t gate_idx, std::size_t constraint_idx,
                                                               const FieldElement& scalar) {
    add_row_term(RowFamily::Right, n_gates_, gate_idx, constraint_idx, scalar);
}

void NativeBulletproofCircuit::PackedWithSlack::add_output_term(std::size_t gate_idx, std::size_t constraint_idx,
                                                                const FieldElement& scalar) {
    add_row_term(RowFamily::Output, n_gates_, gate_idx, constraint_idx, scalar);
}

void NativeBulletproofCircuit::PackedWithSlack::add_commitment_term(std::size_t commitment_idx, std::size_t constraint_idx,
                                                                    const FieldElement& scalar) {
    add_row_term(RowFamily::Commitment, n_commitments_, commitment_idx, constraint_idx, scalar.negate());
}

NativeBulletproofCircuitRow::PackedWithSlack
NativeBulletproofCircuit::PackedWithSlack::left_row(std::size_t gate_idx) const noexcept {
    return row_view(row_header(RowFamily::Left, gate_idx));
}

NativeBulletproofCircuitRow::PackedWithSlack
NativeBulletproofCircuit::PackedWithSlack::right_row(std::size_t gate_idx) const noexcept {
    return row_view(row_header(RowFamily::Right, gate_idx));
}

NativeBulletproofCircuitRow::PackedWithSlack
NativeBulletproofCircuit::PackedWithSlack::output_row(std::size_t gate_idx) const noexcept {
    return row_view(row_header(RowFamily::Output, gate_idx));
}

NativeBulletproofCircuitRow::PackedWithSlack
NativeBulletproofCircuit::PackedWithSlack::commitment_row(std::size_t commitment_idx) const noexcept {
    return row_view(row_header(RowFamily::Commitment, commitment_idx));
}

std::span<const FieldElement> NativeBulletproofCircuit::PackedWithSlack::constants() const noexcept {
    return std::span<const FieldElement>(constant_data(), constraint_size_);
}

bool NativeBulletproofCircuit::PackedWithSlack::evaluate(const BulletproofAssignmentData& assignment) const {
    if (!has_valid_shape()) {
        return false;
    }
    if (assignment.left.size() != n_gates_ || assignment.right.size() != n_gates_ || assignment.output.size() != n_gates_) {
        return false;
    }
    if (assignment.commitments.size() != n_commitments_) {
        return false;
    }
    for (std::size_t i = 0; i < n_gates_; ++i) {
        if (assignment.left[i] * assignment.right[i] != assignment.output[i]) {
            return false;
        }
    }

    std::vector<FieldElement> acc(constraint_size_, FieldElement::zero());
    const NativeBulletproofCircuitTerm* all_terms = term_data();
    auto accumulate = [&](RowFamily family, std::size_t row_count, const std::vector<FieldElement>& values,
                          bool negate_values = false) {
        if (values.size() != row_count) {
            return false;
        }
        for (std::size_t i = 0; i < row_count; ++i) {
            const PackedRowHeader& header = row_header(family, i);
            FieldElement factor = negate_values ? values[i].negate() : values[i];
            if (header.size == 0) {
                continue;
            }
            const NativeBulletproofCircuitTerm* row_terms = all_terms + header.offset;
            for (std::size_t j = 0; j < header.size; ++j) {
                const NativeBulletproofCircuitTerm& entry = row_terms[j];
                if (entry.idx >= acc.size()) {
                    return false;
                }
                acc[entry.idx] = acc[entry.idx] + (entry.scalar * factor);
            }
        }
        return true;
    };
    if (!accumulate(RowFamily::Left, n_gates_, assignment.left)
        || !accumulate(RowFamily::Right, n_gates_, assignment.right)
        || !accumulate(RowFamily::Output, n_gates_, assignment.output)
        || !accumulate(RowFamily::Commitment, n_commitments_, assignment.commitments, true)) {
        return false;
    }
    for (std::size_t i = 0; i < constraint_size_; ++i) {
        if (acc[i] != constant_data()[i]) {
            return false;
        }
    }
    return true;
}

Result<NativeBulletproofCircuit> NativeBulletproofCircuit::PackedWithSlack::unpack() const {
    if (!has_valid_shape()) {
        return unexpected_error(ErrorCode::InvalidDimensions, "NativeBulletproofCircuit::PackedWithSlack::unpack:shape");
    }
    NativeBulletproofCircuit out(n_gates_, n_commitments_, n_bits_);
    if (constraint_size_ != 0) {
        const FieldElement* constants = constant_data();
        out.c.assign(constants, constants + static_cast<std::ptrdiff_t>(constraint_size_));
    }
    const NativeBulletproofCircuitTerm* all_terms = term_data();
    auto unpack_family = [&](RowFamily family, std::vector<NativeBulletproofCircuitRow>& rows, std::size_t row_count) {
        for (std::size_t i = 0; i < row_count; ++i) {
            const PackedRowHeader& header = row_header(family, i);
            if (header.size == 0) {
                rows[i].entries.clear();
                continue;
            }
            rows[i].entries.assign(all_terms + header.offset,
                                   all_terms + header.offset + static_cast<std::ptrdiff_t>(header.size));
        }
    };
    unpack_family(RowFamily::Left, out.wl, n_gates_);
    unpack_family(RowFamily::Right, out.wr, n_gates_);
    unpack_family(RowFamily::Output, out.wo, n_gates_);
    unpack_family(RowFamily::Commitment, out.wv, n_commitments_);
    return out;
}

Result<NativeBulletproofCircuit::PackedWithSlack> NativeBulletproofCircuit::PackedWithSlack::from_circuit(
    const NativeBulletproofCircuit& circuit,
    const PackedSlackPlan& slack) {
    if (!circuit.has_valid_shape()) {
        return unexpected_error(ErrorCode::InvalidDimensions, "NativeBulletproofCircuit::PackedWithSlack::from_circuit:shape");
    }
    auto validate_family_slack = [](const std::vector<std::size_t>& family_slack, std::size_t expected,
                                    const char* context) -> Status {
        if (!family_slack.empty() && family_slack.size() != expected) {
            return unexpected_error(ErrorCode::SizeMismatch, context);
        }
        return {};
    };
    Status wl_status = validate_family_slack(slack.wl, circuit.n_gates,
                                             "NativeBulletproofCircuit::PackedWithSlack::from_circuit:wl");
    if (!wl_status.has_value()) {
        return unexpected_error(wl_status.error(), "NativeBulletproofCircuit::PackedWithSlack::from_circuit:wl");
    }
    Status wr_status = validate_family_slack(slack.wr, circuit.n_gates,
                                             "NativeBulletproofCircuit::PackedWithSlack::from_circuit:wr");
    if (!wr_status.has_value()) {
        return unexpected_error(wr_status.error(), "NativeBulletproofCircuit::PackedWithSlack::from_circuit:wr");
    }
    Status wo_status = validate_family_slack(slack.wo, circuit.n_gates,
                                             "NativeBulletproofCircuit::PackedWithSlack::from_circuit:wo");
    if (!wo_status.has_value()) {
        return unexpected_error(wo_status.error(), "NativeBulletproofCircuit::PackedWithSlack::from_circuit:wo");
    }
    Status wv_status = validate_family_slack(slack.wv, circuit.n_commitments,
                                             "NativeBulletproofCircuit::PackedWithSlack::from_circuit:wv");
    if (!wv_status.has_value()) {
        return unexpected_error(wv_status.error(), "NativeBulletproofCircuit::PackedWithSlack::from_circuit:wv");
    }

    PackedWithSlack packed;
    packed.n_gates_ = circuit.n_gates;
    packed.n_commitments_ = circuit.n_commitments;
    packed.n_bits_ = circuit.n_bits;
    packed.constraint_size_ = circuit.c.size();
    packed.constraint_base_size_ = circuit.c.size();
    if (!checked_add_size(circuit.c.size(), slack.constraint_slack, packed.constraint_capacity_)) {
        return unexpected_error(ErrorCode::Overflow, "NativeBulletproofCircuit::PackedWithSlack::from_circuit:constraint_capacity");
    }

    std::size_t row_count = 0;
    if (!packed_row_count(circuit.n_gates, circuit.n_commitments, row_count)) {
        return unexpected_error(ErrorCode::Overflow, "NativeBulletproofCircuit::PackedWithSlack::from_circuit:row_count");
    }
    std::size_t total_term_capacity = 0;
    auto sum_capacity = [&](const std::vector<NativeBulletproofCircuitRow>& rows,
                            const std::vector<std::size_t>& family_slack) -> bool {
        for (std::size_t i = 0; i < rows.size(); ++i) {
            const std::size_t extra = family_slack.empty() ? 0 : family_slack[i];
            std::size_t row_capacity = 0;
            if (!checked_add_size(rows[i].entries.size(), extra, row_capacity)
                || !checked_add_size(total_term_capacity, row_capacity, total_term_capacity)) {
                return false;
            }
        }
        return true;
    };
    if (!sum_capacity(circuit.wl, slack.wl)
        || !sum_capacity(circuit.wr, slack.wr)
        || !sum_capacity(circuit.wo, slack.wo)
        || !sum_capacity(circuit.wv, slack.wv)) {
        return unexpected_error(ErrorCode::Overflow, "NativeBulletproofCircuit::PackedWithSlack::from_circuit:term_capacity");
    }
    packed.term_capacity_ = total_term_capacity;
    if (!compute_storage_layout(row_count, packed.term_capacity_, packed.constraint_capacity_,
                                packed.term_bytes_offset_, packed.constant_bytes_offset_, packed.storage_bytes_)) {
        return unexpected_error(ErrorCode::Overflow, "NativeBulletproofCircuit::PackedWithSlack::from_circuit:storage_layout");
    }
    packed.storage_.reset(allocate_packed_circuit_storage(packed.storage_bytes_));
    packed.start_storage_lifetimes();

    PackedWithSlack::PackedRowHeader* headers =
        row_count == 0 ? nullptr : std::launder(reinterpret_cast<PackedWithSlack::PackedRowHeader*>(packed.raw_storage_bytes()));
    FieldElement* constants = packed.constant_data();
    if (packed.constraint_capacity_ != 0) {
        std::fill_n(constants, packed.constraint_capacity_, FieldElement::zero());
        std::copy(circuit.c.begin(), circuit.c.end(), constants);
    }

    std::size_t row_cursor = 0;
    std::size_t term_cursor = 0;
    auto fill_family = [&](const std::vector<NativeBulletproofCircuitRow>& rows,
                           const std::vector<std::size_t>& family_slack) {
        for (std::size_t i = 0; i < rows.size(); ++i, ++row_cursor) {
            const std::size_t extra = family_slack.empty() ? 0 : family_slack[i];
            PackedWithSlack::PackedRowHeader& header = headers[row_cursor];
            header.offset = term_cursor;
            header.size = rows[i].entries.size();
            header.base_size = rows[i].entries.size();
            header.capacity = rows[i].entries.size() + extra;
            if (!rows[i].entries.empty()) {
                std::copy(rows[i].entries.begin(), rows[i].entries.end(),
                          packed.term_data() + static_cast<std::ptrdiff_t>(term_cursor));
            }
            term_cursor += header.capacity;
        }
    };
    fill_family(circuit.wl, slack.wl);
    fill_family(circuit.wr, slack.wr);
    fill_family(circuit.wo, slack.wo);
    fill_family(circuit.wv, slack.wv);
    assert(term_cursor == packed.term_capacity_ && "packed term cursor should consume the entire term buffer");

    return packed;
}

Result<NativeBulletproofCircuit::PackedWithSlack> NativeBulletproofCircuit::pack_with_slack(const PackedSlackPlan& slack) const {
    return PackedWithSlack::from_circuit(*this, slack);
}

Result<NativeBulletproofCircuit::PackedWithSlack> NativeBulletproofCircuit::pack_with_slack() const {
    return pack_with_slack(PackedSlackPlan{});
}

Result<Bytes> ExperimentalBulletproofProof::serialize() const {
    if (proof.size() > static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max())) {
        return unexpected_error(ErrorCode::UnexpectedSize, "ExperimentalBulletproofProof::serialize:proof_too_large");
    }

    Bytes out;
    out.reserve(1 + 4 + 33 + proof.size());
    out.push_back(kSerializationVersion);
    append_u32_le(out, static_cast<std::uint32_t>(proof.size()));
    out.insert(out.end(), commitment.begin(), commitment.end());
    out.insert(out.end(), proof.begin(), proof.end());
    return out;
}

Result<ExperimentalBulletproofProof> ExperimentalBulletproofProof::deserialize(std::span<const unsigned char> bytes) {
    ExperimentalBulletproofProof out;
    if (bytes.size() < 38) {
        return unexpected_error(ErrorCode::InvalidFixedSize, "ExperimentalBulletproofProof::deserialize:header");
    }
    if (bytes[0] != kSerializationVersion) {
        return unexpected_error(ErrorCode::BackendRejectedInput, "ExperimentalBulletproofProof::deserialize:version");
    }

    std::optional<std::uint32_t> proof_size = read_u32_le(bytes, 1);
    assert(proof_size.has_value() && "header length check should guarantee a proof length");
    std::size_t offset = 5;
    if (offset + 33 > bytes.size()) {
        return unexpected_error(ErrorCode::InvalidFixedSize, "ExperimentalBulletproofProof::deserialize:commitment");
    }
    std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(offset), 33, out.commitment.begin());
    offset += 33;
    if (offset + *proof_size != bytes.size()) {
        return unexpected_error(ErrorCode::InvalidFixedSize, "ExperimentalBulletproofProof::deserialize:proof_length");
    }
    out.proof.assign(bytes.begin() + static_cast<std::ptrdiff_t>(offset), bytes.end());
    return out;
}

Result<ExperimentalBulletproofProof> prove_experimental_circuit(
    const NativeBulletproofCircuit& circuit,
    const BulletproofAssignmentData& assignment,
    const BulletproofScalarBytes& nonce,
    const BulletproofGeneratorBytes& value_generator,
    std::span<const unsigned char> statement_binding,
    std::optional<BulletproofScalarBytes> blind,
    ExperimentalBulletproofBackendCache* backend_cache) {
    return prove_experimental_circuit_impl(circuit, assignment, nonce, value_generator, statement_binding,
                                           blind, backend_cache, true,
                                           "prove_experimental_circuit:circuit_shape",
                                           "prove_experimental_circuit:n_gates_power_of_two",
                                           "prove_experimental_circuit:n_commitments",
                                           "prove_experimental_circuit:assignment_shape",
                                           "prove_experimental_circuit:assignment_invalid",
                                           "prove_experimental_circuit:proof_size",
                                           "prove_experimental_circuit:bridge");
}

Result<ExperimentalBulletproofProof> prove_experimental_circuit(
    const NativeBulletproofCircuit::PackedWithSlack& circuit,
    const BulletproofAssignmentData& assignment,
    const BulletproofScalarBytes& nonce,
    const BulletproofGeneratorBytes& value_generator,
    std::span<const unsigned char> statement_binding,
    std::optional<BulletproofScalarBytes> blind,
    ExperimentalBulletproofBackendCache* backend_cache) {
    return prove_experimental_circuit_impl(circuit, assignment, nonce, value_generator, statement_binding,
                                           blind, backend_cache, true,
                                           "prove_experimental_circuit:packed_circuit_shape",
                                           "prove_experimental_circuit:packed_n_gates_power_of_two",
                                           "prove_experimental_circuit:packed_n_commitments",
                                           "prove_experimental_circuit:packed_assignment_shape",
                                           "prove_experimental_circuit:packed_assignment_invalid",
                                           "prove_experimental_circuit:packed_proof_size",
                                           "prove_experimental_circuit:packed_bridge");
}

Result<ExperimentalBulletproofProof> prove_experimental_circuit_assume_valid(
    const NativeBulletproofCircuit::PackedWithSlack& circuit,
    const BulletproofAssignmentData& assignment,
    const BulletproofScalarBytes& nonce,
    const BulletproofGeneratorBytes& value_generator,
    std::span<const unsigned char> statement_binding,
    std::optional<BulletproofScalarBytes> blind,
    ExperimentalBulletproofBackendCache* backend_cache) {
    return prove_experimental_circuit_impl(circuit, assignment, nonce, value_generator, statement_binding,
                                           blind, backend_cache, false,
                                           "prove_experimental_circuit_assume_valid:packed_circuit_shape",
                                           "prove_experimental_circuit_assume_valid:packed_n_gates_power_of_two",
                                           "prove_experimental_circuit_assume_valid:packed_n_commitments",
                                           "prove_experimental_circuit_assume_valid:packed_assignment_shape",
                                           "prove_experimental_circuit_assume_valid:packed_assignment_invalid",
                                           "prove_experimental_circuit_assume_valid:packed_proof_size",
                                           "prove_experimental_circuit_assume_valid:packed_bridge");
}

Result<bool> verify_experimental_circuit(
    const NativeBulletproofCircuit& circuit,
    const ExperimentalBulletproofProof& proof,
    const BulletproofGeneratorBytes& value_generator,
    std::span<const unsigned char> statement_binding,
    ExperimentalBulletproofBackendCache* backend_cache) {
    if (!circuit.has_valid_shape()) {
        return unexpected_error(ErrorCode::InvalidDimensions, "verify_experimental_circuit:circuit_shape");
    }
    if (!is_power_of_two(circuit.n_gates)) {
        return unexpected_error(ErrorCode::InvalidDimensions, "verify_experimental_circuit:n_gates_power_of_two");
    }
    if (circuit.n_commitments != 1) {
        return unexpected_error(ErrorCode::InvalidDimensions, "verify_experimental_circuit:n_commitments");
    }
    if (proof.proof.empty()) {
        return unexpected_error(ErrorCode::EmptyInput, "verify_experimental_circuit:proof_empty");
    }

    FlattenedCircuitView flat_circuit = flatten_circuit_view(circuit);
    Bytes binding_digest = circuit_binding_digest(circuit, statement_binding);
    ResolvedBulletproofBackendResources resolved = resolve_bulletproof_backend_resources(circuit.n_gates, backend_cache);
    purify_bulletproof_backend_resources* resources = resolved.resources;
    if (resources == nullptr) {
        return unexpected_error(ErrorCode::UnexpectedSize, "verify_experimental_circuit:backend_resources");
    }
    bool ok = purify_bulletproof_verify_circuit_with_resources(resources, &flat_circuit.view, proof.commitment.data(),
                                                               value_generator.data(), binding_digest.data(),
                                                               binding_digest.size(), proof.proof.data(),
                                                               proof.proof.size()) != 0;
    return ok;
}

Result<bool> verify_experimental_circuit(
    const NativeBulletproofCircuit::PackedWithSlack& circuit,
    const ExperimentalBulletproofProof& proof,
    const BulletproofGeneratorBytes& value_generator,
    std::span<const unsigned char> statement_binding,
    ExperimentalBulletproofBackendCache* backend_cache) {
    if (!circuit.has_valid_shape()) {
        return unexpected_error(ErrorCode::InvalidDimensions, "verify_experimental_circuit:packed_circuit_shape");
    }
    if (!is_power_of_two(circuit.n_gates())) {
        return unexpected_error(ErrorCode::InvalidDimensions, "verify_experimental_circuit:packed_n_gates_power_of_two");
    }
    if (circuit.n_commitments() != 1) {
        return unexpected_error(ErrorCode::InvalidDimensions, "verify_experimental_circuit:packed_n_commitments");
    }
    if (proof.proof.empty()) {
        return unexpected_error(ErrorCode::EmptyInput, "verify_experimental_circuit:packed_proof_empty");
    }

    FlattenedCircuitView flat_circuit = flatten_circuit_view(circuit);
    Bytes binding_digest = circuit_binding_digest(circuit, statement_binding);
    ResolvedBulletproofBackendResources resolved =
        resolve_bulletproof_backend_resources(circuit.n_gates(), backend_cache);
    purify_bulletproof_backend_resources* resources = resolved.resources;
    if (resources == nullptr) {
        return unexpected_error(ErrorCode::UnexpectedSize, "verify_experimental_circuit:packed_backend_resources");
    }
    bool ok = purify_bulletproof_verify_circuit_with_resources(resources, &flat_circuit.view, proof.commitment.data(),
                                                               value_generator.data(), binding_digest.data(),
                                                               binding_digest.size(), proof.proof.data(),
                                                               proof.proof.size()) != 0;
    return ok;
}

void BulletproofTranscript::replace_expr_v_with_bp_var(Expr& expr) {
    for (auto& term : expr.linear()) {
        if (term.first.kind == SymbolKind::Witness
            && term.first.index < witness_to_a_.size()
            && witness_to_a_[term.first.index].has_value()) {
            term.first = *witness_to_a_[term.first.index];
        }
    }
}

bool BulletproofTranscript::replace_and_insert(Expr& expr, Symbol symbol) {
    if (!expr.linear().empty()) {
        replace_expr_v_with_bp_var(expr);
        if (expr.constant().is_zero()
            && expr.linear().size() == 1
            && expr.linear()[0].second == FieldElement::one()
            && expr.linear()[0].first.kind == SymbolKind::Witness) {
            std::uint32_t witness_index = expr.linear()[0].first.index;
            if (witness_index < witness_to_a_.size() && !witness_to_a_[witness_index].has_value()) {
                witness_to_a_[witness_index] = symbol;
                witness_to_a_order_.push_back({witness_index, symbol});
                return true;
            }
        }
    }
    return false;
}

void BulletproofTranscript::add_assignment(Symbol symbol, Expr expr) {
    bool is_v = replace_and_insert(expr, symbol);
    assignments_.push_back({symbol, std::move(expr), is_v});
}

Status BulletproofTranscript::from_transcript(const Transcript& transcript, std::size_t n_bits) {
    assignments_.clear();
    constraints_.clear();
    witness_to_a_.assign(transcript.varmap().size(), std::nullopt);
    witness_to_a_order_.clear();
    n_witnesses_ = transcript.varmap().size();
    n_bits_ = n_bits;
    std::size_t source_muls = transcript.muls().size();
    for (std::size_t i = 0; i < source_muls; ++i) {
        const auto& mul = transcript.muls()[i];
        add_assignment(Symbol::left(narrow_symbol_index(i)), mul.lhs);
        add_assignment(Symbol::right(narrow_symbol_index(i)), mul.rhs);
        add_assignment(Symbol::output(narrow_symbol_index(i)), mul.out);
    }

    std::vector<std::uint32_t> unmapped_transcript_vars;
    std::vector<bool> seen_transcript_vars(n_witnesses_, false);
    for (const Expr& eq : transcript.eqs()) {
        for (const auto& term : eq.linear()) {
            if (!is_transcript_var(term.first)) {
                continue;
            }
            std::uint32_t witness_index = term.first.index;
            if (witness_index >= witness_to_a_.size() || witness_to_a_[witness_index].has_value()) {
                continue;
            }
            if (!seen_transcript_vars[witness_index]) {
                unmapped_transcript_vars.push_back(witness_index);
                seen_transcript_vars[witness_index] = true;
            }
        }
    }

    std::size_t total_gates = source_muls + unmapped_transcript_vars.size();
    n_muls_ = 1;
    while (n_muls_ < std::max<std::size_t>(1, total_gates)) {
        n_muls_ <<= 1;
    }

    for (std::size_t i = 0; i < unmapped_transcript_vars.size(); ++i) {
        std::size_t gate_idx = source_muls + i;
        std::uint32_t gate_symbol = narrow_symbol_index(gate_idx);
        add_assignment(Symbol::left(gate_symbol), Expr::variable(Symbol::witness(unmapped_transcript_vars[i])));
        add_assignment(Symbol::right(gate_symbol), Expr(0));
        add_assignment(Symbol::output(gate_symbol), Expr(0));
    }

    for (std::size_t i = total_gates; i < n_muls_; ++i) {
        std::uint32_t gate_symbol = narrow_symbol_index(i);
        add_assignment(Symbol::left(gate_symbol), Expr(0));
        add_assignment(Symbol::right(gate_symbol), Expr(0));
        add_assignment(Symbol::output(gate_symbol), Expr(0));
    }

    for (const Expr& eq : transcript.eqs()) {
        Expr lowered = eq;
        replace_expr_v_with_bp_var(lowered);
        if (contains_transcript_var(lowered)) {
            return unexpected_error(ErrorCode::UnsupportedSymbol, "BulletproofTranscript::from_transcript:unmapped_eq_var");
        }
        constraints_.push_back({lowered, Expr(0)});
    }
    return {};
}

Status BulletproofTranscript::add_pubkey_and_out(const UInt512& pubkey, Expr p1x, Expr p2x, Expr out) {
    Result<std::pair<UInt256, UInt256>> unpacked = unpack_public(pubkey);
    if (!unpacked.has_value()) {
        return unexpected_error(unpacked.error(), "BulletproofTranscript::add_pubkey_and_out:unpack_public");
    }
    auto add_constraint = [&](const UInt256& packed, Expr expr) -> Status {
        replace_expr_v_with_bp_var(expr);
        auto parts = expr.split();
        Result<FieldElement> constant = FieldElement::try_from_uint256(packed);
        if (!constant.has_value()) {
            return unexpected_error(constant.error(), "BulletproofTranscript::add_pubkey_and_out:field_constant");
        }
        constraints_.push_back({parts.second, Expr(*constant) - parts.first});
        return {};
    };
    Status p1_status = add_constraint(unpacked->first, std::move(p1x));
    if (!p1_status.has_value()) {
        return unexpected_error(p1_status.error(), "BulletproofTranscript::add_pubkey_and_out:p1x");
    }
    Status p2_status = add_constraint(unpacked->second, std::move(p2x));
    if (!p2_status.has_value()) {
        return unexpected_error(p2_status.error(), "BulletproofTranscript::add_pubkey_and_out:p2x");
    }
    replace_expr_v_with_bp_var(out);
    constraints_.push_back({out - Expr::variable(Symbol::commitment(0)), Expr(0)});
    return {};
}

std::string BulletproofTranscript::to_string() const {
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
            out << assignment.symbol.to_string();
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

bool BulletproofTranscript::evaluate(const WitnessAssignments& vars, const FieldElement& commitment) const {
    ResolvedValues values(n_witnesses_, n_muls_, n_commitments_);
    for (std::size_t i = 0; i < std::min(vars.size(), values.witness.size()); ++i) {
        values.witness[i] = vars[i];
    }
    if (!values.set(Symbol::commitment(0), commitment)) {
        return false;
    }
    for (const auto& item : witness_to_a_order_) {
        if (item.first >= values.witness.size() || !values.witness[item.first].has_value()) {
            return false;
        }
        if (!values.set(item.second, *values.witness[item.first])) {
            return false;
        }
    }
    for (const auto& assignment : assignments_) {
        Result<FieldElement> evaluated = ::evaluate_known(assignment.expr, values);
        if (!evaluated.has_value()) {
            return false;
        }
        if (!values.set(assignment.symbol, *evaluated)) {
            return false;
        }
    }
    for (std::size_t i = 0; i < n_muls_; ++i) {
        if (!values.left[i].has_value() || !values.right[i].has_value() || !values.output[i].has_value()) {
            return false;
        }
        if (*values.left[i] * *values.right[i] != *values.output[i]) {
            return false;
        }
    }
    for (const auto& constraint : constraints_) {
        Result<FieldElement> lhs = ::evaluate_known(constraint.first, values);
        Result<FieldElement> rhs = ::evaluate_known(constraint.second, values);
        if (!lhs.has_value() || !rhs.has_value() || *lhs != *rhs) {
            return false;
        }
    }
    return true;
}

NativeBulletproofCircuit BulletproofTranscript::native_circuit() const {
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

    for (const auto& assignment : assignments_) {
        if (!assignment.is_v) {
            append_constraint_to_circuit(circuit, Expr::variable(assignment.symbol), assignment.expr);
        }
    }
    for (const auto& constraint : constraints_) {
        append_constraint_to_circuit(circuit, constraint.first, constraint.second);
    }
    return circuit;
}

NativeBulletproofCircuitTemplate NativeBulletproofCircuitTemplate::from_parts(
    NativeBulletproofCircuit::PackedWithSlack base_packed,
    Expr p1x,
    Expr p2x,
    Expr out) {
    NativeBulletproofCircuitTemplate template_circuit;
    template_circuit.base_packed_ = std::move(base_packed);
    template_circuit.p1x_ = std::move(p1x);
    template_circuit.p2x_ = std::move(p2x);
    template_circuit.out_ = std::move(out);
    return template_circuit;
}

Result<bool> NativeBulletproofCircuitTemplate::partial_evaluate(const BulletproofAssignmentData& assignment) const {
    if (!base_packed_.has_valid_shape()) {
        return unexpected_error(ErrorCode::InvalidDimensions, "NativeBulletproofCircuitTemplate::partial_evaluate:shape");
    }
    if (assignment.left.size() != base_packed_.n_gates()
        || assignment.right.size() != base_packed_.n_gates()
        || assignment.output.size() != base_packed_.n_gates()
        || assignment.commitments.size() != base_packed_.n_commitments()) {
        return unexpected_error(ErrorCode::SizeMismatch, "NativeBulletproofCircuitTemplate::partial_evaluate:assignment_shape");
    }
    return base_packed_.evaluate(assignment);
}

Result<bool> NativeBulletproofCircuitTemplate::final_evaluate(const BulletproofAssignmentData& assignment,
                                                              const UInt512& pubkey) const {
    if (!base_packed_.has_valid_shape()) {
        return unexpected_error(ErrorCode::InvalidDimensions, "NativeBulletproofCircuitTemplate::final_evaluate:shape");
    }
    if (assignment.left.size() != base_packed_.n_gates()
        || assignment.right.size() != base_packed_.n_gates()
        || assignment.output.size() != base_packed_.n_gates()
        || assignment.commitments.size() != base_packed_.n_commitments()) {
        return unexpected_error(ErrorCode::SizeMismatch, "NativeBulletproofCircuitTemplate::final_evaluate:assignment_shape");
    }
    Result<std::pair<UInt256, UInt256>> unpacked = unpack_public(pubkey);
    if (!unpacked.has_value()) {
        return unexpected_error(unpacked.error(), "NativeBulletproofCircuitTemplate::final_evaluate:unpack_public");
    }
    Result<FieldElement> expected_p1 = FieldElement::try_from_uint256(unpacked->first);
    if (!expected_p1.has_value()) {
        return unexpected_error(expected_p1.error(), "NativeBulletproofCircuitTemplate::final_evaluate:expected_p1");
    }
    Result<FieldElement> expected_p2 = FieldElement::try_from_uint256(unpacked->second);
    if (!expected_p2.has_value()) {
        return unexpected_error(expected_p2.error(), "NativeBulletproofCircuitTemplate::final_evaluate:expected_p2");
    }
    Result<FieldElement> actual_p1 = evaluate_expr_with_assignment(p1x_, assignment);
    if (!actual_p1.has_value()) {
        return unexpected_error(actual_p1.error(), "NativeBulletproofCircuitTemplate::final_evaluate:actual_p1");
    }
    Result<FieldElement> actual_p2 = evaluate_expr_with_assignment(p2x_, assignment);
    if (!actual_p2.has_value()) {
        return unexpected_error(actual_p2.error(), "NativeBulletproofCircuitTemplate::final_evaluate:actual_p2");
    }
    Result<FieldElement> actual_out = evaluate_expr_with_assignment(out_, assignment);
    if (!actual_out.has_value()) {
        return unexpected_error(actual_out.error(), "NativeBulletproofCircuitTemplate::final_evaluate:actual_out");
    }
    return *actual_p1 == *expected_p1
        && *actual_p2 == *expected_p2
        && *actual_out == assignment.commitments[0];
}

Result<Bytes> NativeBulletproofCircuitTemplate::integrity_digest() const {
    if (!base_packed_.has_valid_shape()) {
        return unexpected_error(ErrorCode::InvalidDimensions, "NativeBulletproofCircuitTemplate::integrity_digest:shape");
    }

    static const TaggedHash kTemplateDigestTag("Purify/VerifierCircuitTemplate/V1");
    Bytes serialized = circuit_binding_digest(base_packed_, {});
    append_expr_digest(serialized, p1x_);
    append_expr_digest(serialized, p2x_);
    append_expr_digest(serialized, out_);
    const std::array<unsigned char, 32> digest =
        kTemplateDigestTag.digest(std::span<const unsigned char>(serialized.data(), serialized.size()));
    return Bytes(digest.begin(), digest.end());
}

Result<NativeBulletproofCircuit::PackedWithSlack> NativeBulletproofCircuitTemplate::instantiate_packed(const UInt512& pubkey) const {
    Result<std::pair<UInt256, UInt256>> unpacked = unpack_public(pubkey);
    if (!unpacked.has_value()) {
        return unexpected_error(unpacked.error(), "NativeBulletproofCircuitTemplate::instantiate_packed:unpack_public");
    }

    NativeBulletproofCircuit::PackedWithSlack circuit = base_packed_;
    circuit.reset();
    auto append_pubkey_constraint = [&](const UInt256& packed, const Expr& expr) -> Status {
        auto parts = expr.split();
        Result<FieldElement> constant = FieldElement::try_from_uint256(packed);
        if (!constant.has_value()) {
            return unexpected_error(constant.error(), "NativeBulletproofCircuitTemplate::instantiate_packed:field_constant");
        }
        append_constraint_to_circuit(circuit, parts.second, Expr(*constant) - parts.first);
        return {};
    };

    Status p1_status = append_pubkey_constraint(unpacked->first, p1x_);
    if (!p1_status.has_value()) {
        return unexpected_error(p1_status.error(), "NativeBulletproofCircuitTemplate::instantiate_packed:p1x");
    }
    Status p2_status = append_pubkey_constraint(unpacked->second, p2x_);
    if (!p2_status.has_value()) {
        return unexpected_error(p2_status.error(), "NativeBulletproofCircuitTemplate::instantiate_packed:p2x");
    }
    append_constraint_to_circuit(circuit, out_, Expr::variable(Symbol::commitment(0)));
    return circuit;
}

Result<NativeBulletproofCircuit> NativeBulletproofCircuitTemplate::instantiate(const UInt512& pubkey) const {
    Result<NativeBulletproofCircuit::PackedWithSlack> packed = instantiate_packed(pubkey);
    if (!packed.has_value()) {
        return unexpected_error(packed.error(), "NativeBulletproofCircuitTemplate::instantiate:instantiate_packed");
    }
    return packed->unpack();
}

Result<BulletproofAssignmentData> BulletproofTranscript::assignment_data(const WitnessAssignments& vars) const {
    return assignment_data_impl(vars, nullptr);
}

Result<BulletproofAssignmentData> BulletproofTranscript::assignment_data(const WitnessAssignments& vars,
                                                                         const FieldElement& commitment) const {
    return assignment_data_impl(vars, &commitment);
}

Result<BulletproofAssignmentData> BulletproofTranscript::assignment_data_impl(const WitnessAssignments& vars,
                                                                              const FieldElement* commitment) const {
    ResolvedValues values(n_witnesses_, n_muls_, n_commitments_);
    for (std::size_t i = 0; i < std::min(vars.size(), values.witness.size()); ++i) {
        values.witness[i] = vars[i];
    }
    if (commitment != nullptr && !values.set(Symbol::commitment(0), *commitment)) {
        return unexpected_error(ErrorCode::MissingValue, "BulletproofTranscript::assignment_data:commitment_slot");
    }
    for (const auto& item : witness_to_a_order_) {
        if (item.first >= values.witness.size() || !values.witness[item.first].has_value()) {
            return unexpected_error(ErrorCode::MissingValue, "BulletproofTranscript::assignment_data:mapped_value");
        }
        if (!values.set(item.second, *values.witness[item.first])) {
            return unexpected_error(ErrorCode::MissingValue, "BulletproofTranscript::assignment_data:mapped_symbol");
        }
    }
    for (const auto& assignment : assignments_) {
        Result<FieldElement> evaluated = ::evaluate_known(assignment.expr, values);
        if (!evaluated.has_value()) {
            return unexpected_error(evaluated.error(), "BulletproofTranscript::assignment_data:evaluate_assignment");
        }
        if (!values.set(assignment.symbol, *evaluated)) {
            return unexpected_error(ErrorCode::MissingValue, "BulletproofTranscript::assignment_data:store_assignment");
        }
    }

    BulletproofAssignmentData assignment;
    assignment.left.reserve(n_muls_);
    assignment.right.reserve(n_muls_);
    assignment.output.reserve(n_muls_);
    assignment.commitments.reserve(n_commitments_);
    auto read_column = [&](const std::vector<std::optional<FieldElement>>& source,
                           std::vector<FieldElement>& column) -> Status {
        for (const auto& value : source) {
            if (!value.has_value()) {
                return unexpected_error(ErrorCode::MissingValue, "BulletproofTranscript::assignment_data:column_value");
            }
            column.push_back(*value);
        }
        return {};
    };
    Status left_status = read_column(values.left, assignment.left);
    if (!left_status.has_value()) {
        return unexpected_error(left_status.error(), "BulletproofTranscript::assignment_data:left_column");
    }
    Status right_status = read_column(values.right, assignment.right);
    if (!right_status.has_value()) {
        return unexpected_error(right_status.error(), "BulletproofTranscript::assignment_data:right_column");
    }
    Status output_status = read_column(values.output, assignment.output);
    if (!output_status.has_value()) {
        return unexpected_error(output_status.error(), "BulletproofTranscript::assignment_data:output_column");
    }
    for (const auto& value : values.commitment) {
        if (!value.has_value()) {
            return unexpected_error(ErrorCode::MissingValue, "BulletproofTranscript::assignment_data:commitment");
        }
        assignment.commitments.push_back(*value);
    }
    return assignment;
}

Result<Bytes> BulletproofTranscript::serialize_assignment(const WitnessAssignments& vars) const {
    Result<BulletproofAssignmentData> assignment = assignment_data(vars);
    if (!assignment.has_value()) {
        return unexpected_error(assignment.error(), "BulletproofTranscript::serialize_assignment:assignment_data");
    }
    return assignment->serialize();
}

bool BulletproofTranscript::is_transcript_var(Symbol symbol) {
    return symbol.kind == SymbolKind::Witness;
}

bool BulletproofTranscript::contains_transcript_var(const Expr& expr) {
    return std::any_of(expr.linear().begin(), expr.linear().end(),
                       [](const auto& term) { return is_transcript_var(term.first); });
}

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

Expr circuit_ec_multiply_x(const EllipticCurve& curve, Transcript& transcript,
                           const JacobianPoint& point, const std::vector<Expr>& bits) {
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
            return unexpected_error(z1_result.error(), "circuit_main:key_to_bits_z1");
        }
        Result<std::vector<int>> z2_result = key_to_bits(*z2, half_n2());
        if (!z2_result.has_value()) {
            return unexpected_error(z2_result.error(), "circuit_main:key_to_bits_z2");
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

}  // namespace

namespace purify {

Bytes experimental_circuit_binding_digest(
    const NativeBulletproofCircuit& circuit,
    std::span<const unsigned char> statement_binding) {
    return ::circuit_binding_digest(circuit, statement_binding);
}

Bytes experimental_circuit_binding_digest(
    const NativeBulletproofCircuit::PackedWithSlack& circuit,
    std::span<const unsigned char> statement_binding) {
    return ::circuit_binding_digest(circuit, statement_binding);
}

}  // namespace purify
