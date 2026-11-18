// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file bulletproof.cpp
 * @brief Lowering and native circuit helpers for Purify's Bulletproof-style verifier model.
 */

#include "purify/bulletproof.hpp"
#include "purify/secret.hpp"
#include "bulletproof_internal.hpp"
#include "bulletproof_circuit_view.hpp"
#include "bppp_bridge.h"
#include "checked_size.hpp"
#include "secure_cleanup.hpp"

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

static_assert(sizeof(BulletproofPointBytes) == 33);
static_assert(sizeof(BulletproofScalarBytes) == 32);

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

Result<ExperimentalBulletproofBackendCache> ExperimentalBulletproofBackendCache::clone_for_thread(
    std::size_t n_gates) const {
    ExperimentalBulletproofBackendCache clone;
    if (impl_ == nullptr) {
        return clone;
    }

    auto it = impl_->resources.find(n_gates);
    if (it == impl_->resources.end()) {
        return clone;
    }

    purify_bulletproof_backend_resources* cloned =
        purify_bulletproof_backend_resources_clone(it->second.get());
    if (cloned == nullptr) {
        return unexpected_error(ErrorCode::BackendRejectedInput);
    }
    clone.impl_->resources.emplace(it->first, BulletproofBackendResourcePtr(cloned));
    return clone;
}

purify_bulletproof_backend_resources* ExperimentalBulletproofBackendCache::get_or_create(
    std::size_t n_gates,
    purify_secp_context* secp_context) {
    if (impl_ == nullptr || secp_context == nullptr) {
        return nullptr;
    }

    auto it = impl_->resources.find(n_gates);
    if (it != impl_->resources.end()) {
        return it->second.get();
    }

    purify_bulletproof_backend_resources* created =
        purify_bulletproof_backend_resources_create(secp_context, n_gates);
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
using purify::require_secp_context;
using purify::Symbol;
using purify::SymbolKind;
using purify::WitnessAssignments;
using purify::Bytes;
using purify::best_effort_reserve_mul;
using purify::detail::CheckedSize;
using purify::is_power_of_two_size;
using purify::narrow_size_to_u64;
using purify::size_fits_u32;
using purify::size_fits_u64;
using purify::Status;
using purify::BulletproofAssignmentData;
using purify::BulletproofGeneratorBytes;
using purify::BulletproofPointBytes;
using purify::BulletproofScalarBytes;
using PackedCircuit = purify::NativeBulletproofCircuit::PackedWithSlack;

using ::purify::detail::WipeOnDestruction;

std::uint32_t narrow_symbol_index(std::size_t index) {
    assert(index <= static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max())
           && "symbol index must fit in uint32_t");
    return static_cast<std::uint32_t>(index);
}

struct ResolvedValues {
    WitnessAssignments witness;
    WitnessAssignments left;
    WitnessAssignments right;
    WitnessAssignments output;
    WitnessAssignments commitment;

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
            return purify::unexpected_error(purify::ErrorCode::MissingValue);
        }
        out = out + *value * term.second;
    }
    return out;
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

Status append_symbol_digest(Bytes& out, const purify::Symbol& symbol) {
    using SymbolRank = std::underlying_type_t<purify::SymbolKind>;
    append_u64_le(out, static_cast<std::uint64_t>(static_cast<SymbolRank>(symbol.kind)));
    PURIFY_ASSIGN_OR_RETURN(const auto& symbol_index, narrow_size_to_u64(symbol.index));
    append_u64_le(out, symbol_index);
    return {};
}

Status append_expr_digest(Bytes& out, const purify::Expr& expr) {
    const auto constant = expr.constant().to_bytes_be();
    out.insert(out.end(), constant.begin(), constant.end());
    PURIFY_ASSIGN_OR_RETURN(const auto& term_count, narrow_size_to_u64(expr.linear().size()));
    append_u64_le(out, term_count);
    for (const auto& term : expr.linear()) {
        PURIFY_RETURN_IF_ERROR(append_symbol_digest(out, term.first));
        const auto coeff = term.second.to_bytes_be();
        out.insert(out.end(), coeff.begin(), coeff.end());
    }
    return {};
}

std::optional<std::uint32_t> read_u32_le(std::span<const unsigned char> bytes, std::size_t offset) {
    std::uint32_t value = 0;
    if (offset > bytes.size() || bytes.size() - offset < 4) {
        return std::nullopt;
    }
    for (int i = 0; i < 4; ++i) {
        value |= static_cast<std::uint32_t>(bytes[offset + i]) << (8 * i);
    }
    return value;
}

Bytes flatten_scalars32(std::span<const FieldElement> values) {
    Bytes out;
    best_effort_reserve_mul(out, values.size(), 32);
    for (const FieldElement& value : values) {
        auto bytes = value.to_bytes_be();
        out.insert(out.end(), bytes.begin(), bytes.end());
    }
    return out;
}

template <typename RowEntriesFn>
Status append_row_family_digest(Bytes& out, std::size_t row_count, const RowEntriesFn& row_entries) {
    PURIFY_ASSIGN_OR_RETURN(const auto& encoded_row_count, narrow_size_to_u64(row_count));
    append_u64_le(out, encoded_row_count);
    for (std::size_t i = 0; i < row_count; ++i) {
        std::span<const purify::NativeBulletproofCircuitTerm> entries = row_entries(i);
        PURIFY_ASSIGN_OR_RETURN(const auto& encoded_entry_count, narrow_size_to_u64(entries.size()));
        append_u64_le(out, encoded_entry_count);
        for (const auto& entry : entries) {
            PURIFY_ASSIGN_OR_RETURN(const auto& encoded_entry_index, narrow_size_to_u64(entry.idx));
            append_u64_le(out, encoded_entry_index);
            auto scalar = entry.scalar.to_bytes_be();
            out.insert(out.end(), scalar.begin(), scalar.end());
        }
    }
    return {};
}

template <typename Circuit>
Result<Bytes> circuit_binding_digest(const Circuit& circuit, std::span<const unsigned char> statement_binding) {
    static const purify::TaggedHash kCircuitBindingTag("Purify/ExperimentalBulletproof/CircuitV1");
    if (!circuit.has_valid_shape()) {
        return unexpected_error(ErrorCode::InvalidDimensions);
    }
    const auto view = purify::detail::circuit_view(circuit);
    std::size_t reserve_size = 0;
    if (!(CheckedSize(view.constants.size()) * 32 + 64).store(reserve_size)) {
        return unexpected_error(ErrorCode::Overflow);
    }

    Bytes serialized;
    serialized.reserve(reserve_size);
    for (const std::size_t size : {view.gate_count, view.commitment_count, view.bit_count, view.constants.size()}) {
        PURIFY_ASSIGN_OR_RETURN(const auto encoded_size, narrow_size_to_u64(size));
        append_u64_le(serialized, encoded_size);
    }
    PURIFY_RETURN_IF_ERROR(append_row_family_digest(serialized, view.gate_count, view.left_entries));
    PURIFY_RETURN_IF_ERROR(append_row_family_digest(serialized, view.gate_count, view.right_entries));
    PURIFY_RETURN_IF_ERROR(append_row_family_digest(serialized, view.gate_count, view.output_entries));
    PURIFY_RETURN_IF_ERROR(append_row_family_digest(serialized, view.commitment_count, view.commitment_entries));
    for (const FieldElement& constant : view.constants) {
        const auto bytes = constant.to_bytes_be();
        serialized.insert(serialized.end(), bytes.begin(), bytes.end());
    }
    PURIFY_ASSIGN_OR_RETURN(const auto& encoded_binding_size, narrow_size_to_u64(statement_binding.size()));
    append_u64_le(serialized, encoded_binding_size);
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

Result<std::size_t> sum_circuit_gate_count(const PackedCircuit& base,
                                          std::span<const purify::UInt512> public_keys) {
    if (public_keys.empty()) {
        return unexpected_error(ErrorCode::EmptyInput);
    }
    if (!base.has_valid_shape() || !is_power_of_two_size(base.n_gates())
        || base.n_commitments() != 1 || !base.commitment_row(0).entries_view().empty()) {
        return unexpected_error(ErrorCode::InvalidDimensions);
    }
    std::size_t used_gates = 0;
    if (!(CheckedSize(base.n_gates()) * public_keys.size()).store(used_gates)) {
        return unexpected_error(ErrorCode::Overflow);
    }
    std::size_t padded_gates = 1;
    while (padded_gates < used_gates) {
        if (!(CheckedSize(padded_gates) * 2).store(padded_gates)) {
            return unexpected_error(ErrorCode::Overflow);
        }
    }
    std::vector<purify::UInt512> sorted_keys(public_keys.begin(), public_keys.end());
    std::sort(sorted_keys.begin(), sorted_keys.end());
    if (std::adjacent_find(sorted_keys.begin(), sorted_keys.end()) != sorted_keys.end()) {
        return unexpected_error(ErrorCode::BindingMismatch);
    }
    for (const auto& public_key : public_keys) {
        PURIFY_RETURN_IF_ERROR(purify::unpack_public(public_key));
    }
    return padded_gates;
}

Status validate_sum_expression(const Expr& expr, std::size_t member_gates) {
    for (const auto& [symbol, scalar] : expr.linear()) {
        (void)scalar;
        if (symbol.kind == SymbolKind::Commitment || symbol.kind == SymbolKind::Witness) {
            return unexpected_error(ErrorCode::UnsupportedSymbol);
        }
        if (symbol.index >= member_gates) {
            return unexpected_error(ErrorCode::IndexOutOfRange);
        }
    }
    return {};
}

Status append_sum_expression(purify::NativeBulletproofCircuit& circuit, const Expr& expr,
                             std::size_t gate_offset, std::size_t member_gates,
                             std::size_t constraint_index) {
    PURIFY_RETURN_IF_ERROR(validate_sum_expression(expr, member_gates));
    for (const auto& [symbol, scalar] : expr.linear()) {
        const std::size_t gate_index = gate_offset + symbol.index;
        switch (symbol.kind) {
        case SymbolKind::Left:
            circuit.add_left_term(gate_index, constraint_index, scalar);
            break;
        case SymbolKind::Right:
            circuit.add_right_term(gate_index, constraint_index, scalar);
            break;
        case SymbolKind::Output:
            circuit.add_output_term(gate_index, constraint_index, scalar);
            break;
        case SymbolKind::Commitment:
        case SymbolKind::Witness:
        default:
            return unexpected_error(ErrorCode::UnsupportedSymbol);
        }
    }
    return {};
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
    best_effort_reserve_mul(flat.scalars32, total_entries, 32);

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
    std::vector<FieldElement> explicit_constants;
    std::span<const FieldElement> constants = circuit.constants();
    if (constants.size() > implicit_bit_constraints) {
        const FieldElement* constants_begin = constants.data();
        explicit_constants.assign(constants_begin + static_cast<std::ptrdiff_t>(implicit_bit_constraints),
                                  constants_begin + static_cast<std::ptrdiff_t>(constants.size()));
    }
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
};

ResolvedBulletproofBackendResources resolve_bulletproof_backend_resources(
    std::size_t n_gates,
    purify_secp_context* secp_context,
    purify::ExperimentalBulletproofBackendCache* cache) {
    ResolvedBulletproofBackendResources out;

    if (cache != nullptr) {
        out.resources = cache->get_or_create(n_gates, secp_context);
    }
    return out;
}

template <typename CircuitLike>
Result<ExperimentalBulletproofProof> prove_experimental_circuit_impl(
    const CircuitLike& circuit,
    const BulletproofAssignmentData& assignment,
    const BulletproofScalarBytes& nonce,
    const BulletproofGeneratorBytes& value_generator,
    purify_secp_context* secp_context,
    std::span<const unsigned char> statement_binding,
    std::span<const BulletproofScalarBytes> blinds,
    ExperimentalBulletproofBackendCache* backend_cache,
    bool require_assignment_validation) {
    PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context));
    ExperimentalBulletproofProof out;
    if (!circuit.has_valid_shape()) {
        return unexpected_error(ErrorCode::InvalidDimensions);
    }
    if (!is_power_of_two_size(circuit_n_gates(circuit))) {
        return unexpected_error(ErrorCode::InvalidDimensions);
    }
    if (circuit_n_commitments(circuit) == 0) {
        return unexpected_error(ErrorCode::InvalidDimensions);
    }
    if (assignment.left.size() != circuit_n_gates(circuit)
        || assignment.right.size() != circuit_n_gates(circuit)
        || assignment.output.size() != circuit_n_gates(circuit)
        || assignment.commitments.size() != circuit_n_commitments(circuit)) {
        return unexpected_error(ErrorCode::SizeMismatch);
    }
    if (!blinds.empty() && blinds.size() != circuit_n_commitments(circuit)) {
        return unexpected_error(ErrorCode::SizeMismatch);
    }
    if (require_assignment_validation && !circuit.evaluate(assignment)) {
        return unexpected_error(ErrorCode::EquationMismatch);
    }

    FlattenedCircuitView flat_circuit = flatten_circuit_view(circuit);
    FlattenedAssignmentView flat_assignment = flatten_assignment_view(assignment);
    PURIFY_ASSIGN_OR_RETURN(const auto& binding_digest, circuit_binding_digest(circuit, statement_binding));
    Bytes proof_bytes(std::max<std::size_t>(purify_bulletproof_required_proof_size(circuit_n_gates(circuit)), 4096), 0);
    std::size_t proof_len = proof_bytes.size();
    out.commitments.resize(circuit_n_commitments(circuit));
    const unsigned char* blind_ptr = blinds.empty() ? nullptr : reinterpret_cast<const unsigned char*>(blinds.data());
    ResolvedBulletproofBackendResources resolved =
        resolve_bulletproof_backend_resources(circuit_n_gates(circuit), secp_context, backend_cache);
    purify_bulletproof_backend_resources* resources = resolved.resources;

    if (proof_len == 0) {
        return unexpected_error(ErrorCode::UnexpectedSize);
    }
    const int ok =
        resources != nullptr
            ? (require_assignment_validation
                   ? purify_bulletproof_prove_circuit_with_resources(
                         resources, &flat_circuit.view, &flat_assignment.view, blind_ptr,
                         value_generator.data(), nonce.data(),
                         binding_digest.data(), binding_digest.size(),
                         reinterpret_cast<unsigned char*>(out.commitments.data()), proof_bytes.data(), &proof_len)
                   : purify_bulletproof_prove_circuit_assume_valid_with_resources(
                         resources, &flat_circuit.view, &flat_assignment.view, blind_ptr,
                         value_generator.data(), nonce.data(),
                         binding_digest.data(), binding_digest.size(),
                         reinterpret_cast<unsigned char*>(out.commitments.data()), proof_bytes.data(), &proof_len))
            : (require_assignment_validation
                   ? purify_bulletproof_prove_circuit(
                         secp_context, &flat_circuit.view, &flat_assignment.view, blind_ptr,
                         value_generator.data(), nonce.data(),
                         binding_digest.data(), binding_digest.size(),
                         reinterpret_cast<unsigned char*>(out.commitments.data()), proof_bytes.data(), &proof_len)
                   : purify_bulletproof_prove_circuit_assume_valid(
                         secp_context, &flat_circuit.view, &flat_assignment.view, blind_ptr,
                         value_generator.data(), nonce.data(),
                         binding_digest.data(), binding_digest.size(),
                         reinterpret_cast<unsigned char*>(out.commitments.data()), proof_bytes.data(), &proof_len));
    if (!ok) {
        return unexpected_error(ErrorCode::BackendRejectedInput);
    }

    proof_bytes.resize(proof_len);
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
                return purify::unexpected_error(purify::ErrorCode::MissingValue);
            }
            out = out + (assignment.left[index] * term.second);
            break;
        case SymbolKind::Right:
            if (index >= assignment.right.size()) {
                return purify::unexpected_error(purify::ErrorCode::MissingValue);
            }
            out = out + (assignment.right[index] * term.second);
            break;
        case SymbolKind::Output:
            if (index >= assignment.output.size()) {
                return purify::unexpected_error(purify::ErrorCode::MissingValue);
            }
            out = out + (assignment.output[index] * term.second);
            break;
        case SymbolKind::Commitment:
            if (index >= assignment.commitments.size()) {
                return purify::unexpected_error(purify::ErrorCode::MissingValue);
            }
            out = out + (assignment.commitments[index] * term.second);
            break;
        case SymbolKind::Witness:
            return purify::unexpected_error(purify::ErrorCode::MissingValue);
        }
    }
    return out;
}

}  // namespace

namespace purify {

Result<Bytes> BulletproofAssignmentData::serialize() const {
    if (left.size() != right.size() || left.size() != output.size()) {
        return unexpected_error(ErrorCode::SizeMismatch);
    }
    if (!size_fits_u32(commitments.size())) {
        return unexpected_error(ErrorCode::UnexpectedSize);
    }
    if (!size_fits_u64(left.size())) {
        return unexpected_error(ErrorCode::UnexpectedSize);
    }

    std::size_t serialized_size = 0;
    if (!((CheckedSize(left.size()) * 3 + commitments.size()) * 33 + 16).store(serialized_size)) {
        return unexpected_error(ErrorCode::Overflow);
    }

    Bytes out;
    out.reserve(serialized_size);
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
    auto write_column = [&](std::span<const FieldElement> column) {
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

Result<Bytes> ExperimentalBulletproofProof::serialize() const {
    if (commitments.empty() || proof.empty()) {
        return unexpected_error(ErrorCode::EmptyInput);
    }
    if (!size_fits_u32(proof.size()) || !size_fits_u32(commitments.size())) {
        return unexpected_error(ErrorCode::UnexpectedSize);
    }
    std::size_t serialized_size = 0;
    if (!(CheckedSize(commitments.size()) * 33 + 9 + proof.size()).store(serialized_size)) {
        return unexpected_error(ErrorCode::Overflow);
    }

    Bytes out;
    out.reserve(serialized_size);
    out.push_back(kSerializationVersion);
    append_u32_le(out, static_cast<std::uint32_t>(proof.size()));
    append_u32_le(out, static_cast<std::uint32_t>(commitments.size()));
    for (const auto& commitment : commitments) {
        out.insert(out.end(), commitment.begin(), commitment.end());
    }
    out.insert(out.end(), proof.begin(), proof.end());
    return out;
}

Result<ExperimentalBulletproofProof> ExperimentalBulletproofProof::deserialize(std::span<const unsigned char> bytes) {
    if (bytes.size() < 9) {
        return unexpected_error(ErrorCode::InvalidFixedSize);
    }
    if (bytes[0] != kSerializationVersion) {
        return unexpected_error(ErrorCode::BackendRejectedInput);
    }
    const auto proof_size = read_u32_le(bytes, 1);
    const auto commitment_count = read_u32_le(bytes, 5);
    assert(proof_size.has_value() && commitment_count.has_value());
    if (*proof_size == 0 || *commitment_count == 0) {
        return unexpected_error(ErrorCode::EmptyInput);
    }
    // Bound allocations by the received bytes before constructing any vectors.
    const std::size_t payload_size = bytes.size() - 9;
    if (*commitment_count > payload_size / 33) {
        return unexpected_error(ErrorCode::InvalidFixedSize);
    }
    const std::size_t commitment_bytes = std::size_t{*commitment_count} * 33;
    if (*proof_size != payload_size - commitment_bytes) {
        return unexpected_error(ErrorCode::InvalidFixedSize);
    }
    ExperimentalBulletproofProof out;
    out.commitments.resize(*commitment_count);
    std::size_t offset = 9;
    for (auto& commitment : out.commitments) {
        std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(offset), 33, commitment.begin());
        offset += 33;
    }
    out.proof.assign(bytes.begin() + static_cast<std::ptrdiff_t>(offset), bytes.end());
    return out;
}

Result<ExperimentalBulletproofProof> prove_experimental_circuit(
    const NativeBulletproofCircuit& circuit,
    const BulletproofAssignmentData& assignment,
    const BulletproofScalarBytes& nonce,
    const BulletproofGeneratorBytes& value_generator,
    purify_secp_context* secp_context,
    std::span<const unsigned char> statement_binding,
    std::span<const BulletproofScalarBytes> blinds,
    ExperimentalBulletproofBackendCache* backend_cache) {
    return prove_experimental_circuit_impl(circuit, assignment, nonce, value_generator, secp_context, statement_binding,
                                           blinds, backend_cache, true);
}

Result<ExperimentalBulletproofProof> prove_experimental_circuit(
    const NativeBulletproofCircuit::PackedWithSlack& circuit,
    const BulletproofAssignmentData& assignment,
    const BulletproofScalarBytes& nonce,
    const BulletproofGeneratorBytes& value_generator,
    purify_secp_context* secp_context,
    std::span<const unsigned char> statement_binding,
    std::span<const BulletproofScalarBytes> blinds,
    ExperimentalBulletproofBackendCache* backend_cache) {
    return prove_experimental_circuit_impl(circuit, assignment, nonce, value_generator, secp_context, statement_binding,
                                           blinds, backend_cache, true);
}

Result<ExperimentalBulletproofProof> prove_experimental_circuit_assume_valid(
    const NativeBulletproofCircuit::PackedWithSlack& circuit,
    const BulletproofAssignmentData& assignment,
    const BulletproofScalarBytes& nonce,
    const BulletproofGeneratorBytes& value_generator,
    purify_secp_context* secp_context,
    std::span<const unsigned char> statement_binding,
    std::span<const BulletproofScalarBytes> blinds,
    ExperimentalBulletproofBackendCache* backend_cache) {
    return prove_experimental_circuit_impl(circuit, assignment, nonce, value_generator, secp_context, statement_binding,
                                           blinds, backend_cache, false);
}

Result<bool> verify_experimental_circuit(
    const NativeBulletproofCircuit& circuit,
    const ExperimentalBulletproofProof& proof,
    const BulletproofGeneratorBytes& value_generator,
    purify_secp_context* secp_context,
    std::span<const unsigned char> statement_binding,
    ExperimentalBulletproofBackendCache* backend_cache) {
    PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context));
    if (!circuit.has_valid_shape()) {
        return unexpected_error(ErrorCode::InvalidDimensions);
    }
    if (!is_power_of_two_size(circuit.n_gates)) {
        return unexpected_error(ErrorCode::InvalidDimensions);
    }
    if (circuit.n_commitments == 0) {
        return unexpected_error(ErrorCode::InvalidDimensions);
    }
    if (proof.commitments.size() != circuit_n_commitments(circuit)) {
        return unexpected_error(ErrorCode::SizeMismatch);
    }
    if (proof.proof.empty()) {
        return unexpected_error(ErrorCode::EmptyInput);
    }

    FlattenedCircuitView flat_circuit = flatten_circuit_view(circuit);
    PURIFY_ASSIGN_OR_RETURN(const auto& binding_digest, circuit_binding_digest(circuit, statement_binding));
    ResolvedBulletproofBackendResources resolved =
        resolve_bulletproof_backend_resources(circuit.n_gates, secp_context, backend_cache);
    purify_bulletproof_backend_resources* resources = resolved.resources;
    bool ok =
        resources != nullptr
            ? purify_bulletproof_verify_circuit_with_resources(resources, &flat_circuit.view, reinterpret_cast<const unsigned char*>(proof.commitments.data()),
                                                               value_generator.data(), binding_digest.data(),
                                                               binding_digest.size(), proof.proof.data(),
                                                               proof.proof.size()) != 0
            : purify_bulletproof_verify_circuit(secp_context, &flat_circuit.view, reinterpret_cast<const unsigned char*>(proof.commitments.data()),
                                                value_generator.data(), binding_digest.data(),
                                                binding_digest.size(), proof.proof.data(),
                                                proof.proof.size()) != 0;
    return ok;
}

Result<bool> verify_experimental_circuit(
    const NativeBulletproofCircuit::PackedWithSlack& circuit,
    const ExperimentalBulletproofProof& proof,
    const BulletproofGeneratorBytes& value_generator,
    purify_secp_context* secp_context,
    std::span<const unsigned char> statement_binding,
    ExperimentalBulletproofBackendCache* backend_cache) {
    PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context));
    if (!circuit.has_valid_shape()) {
        return unexpected_error(ErrorCode::InvalidDimensions);
    }
    if (!is_power_of_two_size(circuit.n_gates())) {
        return unexpected_error(ErrorCode::InvalidDimensions);
    }
    if (circuit.n_commitments() == 0) {
        return unexpected_error(ErrorCode::InvalidDimensions);
    }
    if (proof.commitments.size() != circuit_n_commitments(circuit)) {
        return unexpected_error(ErrorCode::SizeMismatch);
    }
    if (proof.proof.empty()) {
        return unexpected_error(ErrorCode::EmptyInput);
    }

    FlattenedCircuitView flat_circuit = flatten_circuit_view(circuit);
    PURIFY_ASSIGN_OR_RETURN(const auto& binding_digest, circuit_binding_digest(circuit, statement_binding));
    ResolvedBulletproofBackendResources resolved =
        resolve_bulletproof_backend_resources(circuit.n_gates(), secp_context, backend_cache);
    purify_bulletproof_backend_resources* resources = resolved.resources;
    bool ok =
        resources != nullptr
            ? purify_bulletproof_verify_circuit_with_resources(resources, &flat_circuit.view, reinterpret_cast<const unsigned char*>(proof.commitments.data()),
                                                               value_generator.data(), binding_digest.data(),
                                                               binding_digest.size(), proof.proof.data(),
                                                               proof.proof.size()) != 0
            : purify_bulletproof_verify_circuit(secp_context, &flat_circuit.view, reinterpret_cast<const unsigned char*>(proof.commitments.data()),
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

Status BulletproofTranscript::from_transcript(
    const Transcript& transcript, std::size_t n_bits,
    std::size_t minimum_gate_count) {
    if (!is_power_of_two_size(minimum_gate_count) ||
        minimum_gate_count >
            static_cast<std::size_t>(
                std::numeric_limits<std::uint32_t>::max())) {
        return unexpected_error(ErrorCode::InvalidDimensions);
    }
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

    std::size_t total_gates = 0;
    if (!(CheckedSize(source_muls) + unmapped_transcript_vars.size()).store(total_gates)) {
        return unexpected_error(ErrorCode::Overflow);
    }
    if (total_gates >
        static_cast<std::size_t>(
            std::numeric_limits<std::uint32_t>::max())) {
        return unexpected_error(ErrorCode::InvalidDimensions);
    }
    n_muls_ = 1;
    while (n_muls_ < std::max<std::size_t>(1, total_gates)) {
        if (n_muls_ > std::numeric_limits<std::size_t>::max() / 2) {
            return unexpected_error(ErrorCode::Overflow);
        }
        n_muls_ <<= 1;
    }
    n_muls_ = std::max(n_muls_, minimum_gate_count);

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
            return unexpected_error(ErrorCode::UnsupportedSymbol);
        }
        constraints_.push_back({lowered, Expr(0)});
    }
    return {};
}

Status BulletproofTranscript::bind_output_to_commitment(Expr output) {
    if (n_muls_ == 0) {
        return unexpected_error(ErrorCode::UninitializedState);
    }
    replace_expr_v_with_bp_var(output);
    for (const auto& [symbol, scalar] : output.linear()) {
        (void)scalar;
        switch (symbol.kind) {
        case SymbolKind::Left:
        case SymbolKind::Right:
        case SymbolKind::Output:
            if (symbol.index >= n_muls_) {
                return unexpected_error(ErrorCode::IndexOutOfRange);
            }
            break;
        case SymbolKind::Witness:
        case SymbolKind::Commitment:
            return unexpected_error(ErrorCode::UnsupportedSymbol);
        default:
            return unexpected_error(ErrorCode::InvalidSymbol);
        }
    }
    constraints_.push_back(
        {output - Expr::variable(Symbol::commitment(0)), Expr(0)});
    return {};
}

Status BulletproofTranscript::add_pubkey_and_out(const UInt512& pubkey, Expr p1x, Expr p2x, Expr out) {
    Result<std::pair<UInt256, UInt256>> unpacked = unpack_public(pubkey);
    if (!unpacked.has_value()) {
        return unexpected_error(unpacked.error());
    }
    auto add_constraint = [&](const UInt256& packed, Expr expr) -> Status {
        replace_expr_v_with_bp_var(expr);
        auto parts = expr.split();
        Result<FieldElement> constant = FieldElement::try_from_uint256(packed);
        if (!constant.has_value()) {
            return unexpected_error(constant.error());
        }
        constraints_.push_back({parts.second, Expr(*constant) - parts.first});
        return {};
    };
    Status p1_status = add_constraint(unpacked->first, std::move(p1x));
    if (!p1_status.has_value()) {
        return unexpected_error(p1_status.error());
    }
    Status p2_status = add_constraint(unpacked->second, std::move(p2x));
    if (!p2_status.has_value()) {
        return unexpected_error(p2_status.error());
    }
    Status output_status = bind_output_to_commitment(std::move(out));
    if (!output_status.has_value()) {
        return unexpected_error(output_status.error());
    }
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
        return unexpected_error(ErrorCode::InvalidDimensions);
    }
    if (assignment.left.size() != base_packed_.n_gates()
        || assignment.right.size() != base_packed_.n_gates()
        || assignment.output.size() != base_packed_.n_gates()
        || assignment.commitments.size() != base_packed_.n_commitments()) {
        return unexpected_error(ErrorCode::SizeMismatch);
    }
    return base_packed_.evaluate(assignment);
}

Result<bool> NativeBulletproofCircuitTemplate::final_evaluate(const BulletproofAssignmentData& assignment,
                                                              const UInt512& pubkey) const {
    if (!base_packed_.has_valid_shape()) {
        return unexpected_error(ErrorCode::InvalidDimensions);
    }
    if (assignment.left.size() != base_packed_.n_gates()
        || assignment.right.size() != base_packed_.n_gates()
        || assignment.output.size() != base_packed_.n_gates()
        || assignment.commitments.size() != base_packed_.n_commitments()) {
        return unexpected_error(ErrorCode::SizeMismatch);
    }
    Result<std::pair<UInt256, UInt256>> unpacked = unpack_public(pubkey);
    if (!unpacked.has_value()) {
        return unexpected_error(unpacked.error());
    }
    Result<FieldElement> expected_p1 = FieldElement::try_from_uint256(unpacked->first);
    if (!expected_p1.has_value()) {
        return unexpected_error(expected_p1.error());
    }
    Result<FieldElement> expected_p2 = FieldElement::try_from_uint256(unpacked->second);
    if (!expected_p2.has_value()) {
        return unexpected_error(expected_p2.error());
    }
    Result<FieldElement> actual_p1 = evaluate_expr_with_assignment(p1x_, assignment);
    if (!actual_p1.has_value()) {
        return unexpected_error(actual_p1.error());
    }
    Result<FieldElement> actual_p2 = evaluate_expr_with_assignment(p2x_, assignment);
    if (!actual_p2.has_value()) {
        return unexpected_error(actual_p2.error());
    }
    Result<FieldElement> actual_out = evaluate_expr_with_assignment(out_, assignment);
    if (!actual_out.has_value()) {
        return unexpected_error(actual_out.error());
    }
    return *actual_p1 == *expected_p1
        && *actual_p2 == *expected_p2
        && *actual_out == assignment.commitments[0];
}

Result<Bytes> NativeBulletproofCircuitTemplate::integrity_digest() const {
    if (!base_packed_.has_valid_shape()) {
        return unexpected_error(ErrorCode::InvalidDimensions);
    }

    static const TaggedHash kTemplateDigestTag("Purify/VerifierCircuitTemplate/V1");
    PURIFY_ASSIGN_OR_RETURN(auto serialized, circuit_binding_digest(base_packed_, {}));
    PURIFY_RETURN_IF_ERROR(append_expr_digest(serialized, p1x_));
    PURIFY_RETURN_IF_ERROR(append_expr_digest(serialized, p2x_));
    PURIFY_RETURN_IF_ERROR(append_expr_digest(serialized, out_));
    const std::array<unsigned char, 32> digest =
        kTemplateDigestTag.digest(std::span<const unsigned char>(serialized.data(), serialized.size()));
    return Bytes(digest.begin(), digest.end());
}

Result<NativeBulletproofCircuit::PackedWithSlack> NativeBulletproofCircuitTemplate::instantiate_packed(const UInt512& pubkey) const {
    Result<std::pair<UInt256, UInt256>> unpacked = unpack_public(pubkey);
    if (!unpacked.has_value()) {
        return unexpected_error(unpacked.error());
    }

    NativeBulletproofCircuit::PackedWithSlack circuit = base_packed_;
    circuit.reset();
    auto append_pubkey_constraint = [&](const UInt256& packed, const Expr& expr) -> Status {
        auto parts = expr.split();
        Result<FieldElement> constant = FieldElement::try_from_uint256(packed);
        if (!constant.has_value()) {
            return unexpected_error(constant.error());
        }
        append_constraint_to_circuit(circuit, parts.second, Expr(*constant) - parts.first);
        return {};
    };

    Status p1_status = append_pubkey_constraint(unpacked->first, p1x_);
    if (!p1_status.has_value()) {
        return unexpected_error(p1_status.error());
    }
    Status p2_status = append_pubkey_constraint(unpacked->second, p2x_);
    if (!p2_status.has_value()) {
        return unexpected_error(p2_status.error());
    }
    append_constraint_to_circuit(circuit, out_, Expr::variable(Symbol::commitment(0)));
    return circuit;
}

Result<NativeBulletproofCircuit> NativeBulletproofCircuitTemplate::instantiate(const UInt512& pubkey) const {
    Result<NativeBulletproofCircuit::PackedWithSlack> packed = instantiate_packed(pubkey);
    if (!packed.has_value()) {
        return unexpected_error(packed.error());
    }
    return packed->unpack();
}

Result<NativeBulletproofCircuit> NativeBulletproofCircuitTemplate::instantiate_sum(
    std::span<const UInt512> public_keys) const {
    PURIFY_ASSIGN_OR_RETURN(const auto& gates, sum_circuit_gate_count(base_packed_, public_keys));
    std::size_t total_constraints = 0;
    if (!((CheckedSize(base_packed_.constraint_count()) + 2) * public_keys.size() + 1).store(total_constraints)) {
        return unexpected_error(ErrorCode::Overflow);
    }

    // Each member's bit equations are already explicit. They no longer form the
    // global gate prefix required by the legacy implicit-bit optimization.
    NativeBulletproofCircuit circuit(gates, 1, 0);
    circuit.c.reserve(total_constraints);
    const std::size_t member_gates = base_packed_.n_gates();
    auto append_row = [&](NativeBulletproofCircuitRow& destination,
                          NativeBulletproofCircuitRow::PackedWithSlack source,
                          std::size_t constraint_offset) -> Status {
        destination.entries.reserve(source.size);
        for (const auto& entry : source.entries_view()) {
            if (entry.idx >= base_packed_.constraint_count()) {
                return unexpected_error(ErrorCode::IndexOutOfRange);
            }
            destination.add(constraint_offset + entry.idx, entry.scalar);
        }
        return {};
    };

    for (std::size_t member = 0; member < public_keys.size(); ++member) {
        const std::size_t gate_offset = member * member_gates;
        const std::size_t constraint_offset = circuit.c.size();
        const auto constants = base_packed_.constants();
        circuit.c.insert(circuit.c.end(), constants.begin(), constants.end());
        for (std::size_t gate = 0; gate < member_gates; ++gate) {
            PURIFY_RETURN_IF_ERROR(append_row(circuit.wl[gate_offset + gate], base_packed_.left_row(gate), constraint_offset));
            PURIFY_RETURN_IF_ERROR(append_row(circuit.wr[gate_offset + gate], base_packed_.right_row(gate), constraint_offset));
            PURIFY_RETURN_IF_ERROR(append_row(circuit.wo[gate_offset + gate], base_packed_.output_row(gate), constraint_offset));
        }
        PURIFY_ASSIGN_OR_RETURN(const auto& unpacked, unpack_public(public_keys[member]));
        auto append_host_coordinate = [&](const UInt256& coordinate, const Expr& expr) -> Status {
            PURIFY_ASSIGN_OR_RETURN(const auto& value, FieldElement::try_from_uint256(coordinate));
            const std::size_t constraint = circuit.add_constraint(value - expr.constant());
            return append_sum_expression(circuit, expr, gate_offset, member_gates, constraint);
        };
        PURIFY_RETURN_IF_ERROR(append_host_coordinate(unpacked.first, p1x_));
        PURIFY_RETURN_IF_ERROR(append_host_coordinate(unpacked.second, p2x_));
    }

    const std::size_t sum_constraint = circuit.add_constraint();
    for (std::size_t member = 0; member < public_keys.size(); ++member) {
        circuit.c[sum_constraint] = circuit.c[sum_constraint] - out_.constant();
        PURIFY_RETURN_IF_ERROR(
            append_sum_expression(circuit, out_, member * member_gates, member_gates, sum_constraint));
    }
    circuit.add_commitment_term(0, sum_constraint, FieldElement::one().negate());
    return circuit;
}

Result<BulletproofAssignmentData> NativeBulletproofCircuitTemplate::sum_assignments(
    std::span<const UInt512> public_keys,
    std::span<const BulletproofAssignmentData> assignments) const {
    if (assignments.size() != public_keys.size()) {
        return unexpected_error(ErrorCode::SizeMismatch);
    }
    PURIFY_ASSIGN_OR_RETURN(const auto& gates, sum_circuit_gate_count(base_packed_, public_keys));
    for (const Expr* expr : {&p1x_, &p2x_, &out_}) {
        PURIFY_RETURN_IF_ERROR(validate_sum_expression(*expr, base_packed_.n_gates()));
    }
    for (std::size_t member = 0; member < assignments.size(); ++member) {
        PURIFY_ASSIGN_OR_RETURN(const auto& partial_ok, partial_evaluate(assignments[member]));
        if (!partial_ok) {
            return unexpected_error(ErrorCode::EquationMismatch);
        }
        PURIFY_ASSIGN_OR_RETURN(const auto& final_ok, final_evaluate(assignments[member], public_keys[member]));
        if (!final_ok) {
            return unexpected_error(ErrorCode::BindingMismatch);
        }
    }

    BulletproofAssignmentData sum;
    sum.left.reserve(gates);
    sum.right.reserve(gates);
    sum.output.reserve(gates);
    FieldElement output_sum = FieldElement::zero();
    for (const auto& assignment : assignments) {
        sum.left.insert(sum.left.end(), assignment.left.begin(), assignment.left.end());
        sum.right.insert(sum.right.end(), assignment.right.begin(), assignment.right.end());
        sum.output.insert(sum.output.end(), assignment.output.begin(), assignment.output.end());
        output_sum = output_sum + assignment.commitments.front();
    }
    sum.left.resize(gates, FieldElement::zero());
    sum.right.resize(gates, FieldElement::zero());
    sum.output.resize(gates, FieldElement::zero());
    sum.commitments.push_back(output_sum);
    return sum;
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
        return unexpected_error(ErrorCode::MissingValue);
    }
    for (const auto& item : witness_to_a_order_) {
        if (item.first >= values.witness.size() || !values.witness[item.first].has_value()) {
            return unexpected_error(ErrorCode::MissingValue);
        }
        if (!values.set(item.second, *values.witness[item.first])) {
            return unexpected_error(ErrorCode::MissingValue);
        }
    }
    for (const auto& assignment : assignments_) {
        Result<FieldElement> evaluated = ::evaluate_known(assignment.expr, values);
        if (!evaluated.has_value()) {
            return unexpected_error(evaluated.error());
        }
        if (!values.set(assignment.symbol, *evaluated)) {
            return unexpected_error(ErrorCode::MissingValue);
        }
    }

    BulletproofAssignmentData assignment;
    assignment.left.reserve(n_muls_);
    assignment.right.reserve(n_muls_);
    assignment.output.reserve(n_muls_);
    assignment.commitments.reserve(n_commitments_);
    auto read_column = [&](const WitnessAssignments& source,
                           BulletproofWitnessColumn& column) -> Status {
        for (const auto& value : source) {
            if (!value.has_value()) {
                return unexpected_error(ErrorCode::MissingValue);
            }
            column.push_back(*value);
        }
        return {};
    };
    Status left_status = read_column(values.left, assignment.left);
    if (!left_status.has_value()) {
        return unexpected_error(left_status.error());
    }
    Status right_status = read_column(values.right, assignment.right);
    if (!right_status.has_value()) {
        return unexpected_error(right_status.error());
    }
    Status output_status = read_column(values.output, assignment.output);
    if (!output_status.has_value()) {
        return unexpected_error(output_status.error());
    }
    for (const auto& value : values.commitment) {
        if (!value.has_value()) {
            return unexpected_error(ErrorCode::MissingValue);
        }
        assignment.commitments.push_back(*value);
    }
    return assignment;
}

Result<Bytes> BulletproofTranscript::serialize_assignment(const WitnessAssignments& vars) const {
    Result<BulletproofAssignmentData> assignment = assignment_data(vars);
    if (!assignment.has_value()) {
        return unexpected_error(assignment.error());
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

}  // namespace

namespace purify {

Result<Bytes> experimental_circuit_binding_digest(
    const NativeBulletproofCircuit& circuit,
    std::span<const unsigned char> statement_binding) {
    return ::circuit_binding_digest(circuit, statement_binding);
}

Result<Bytes> experimental_circuit_binding_digest(
    const NativeBulletproofCircuit::PackedWithSlack& circuit,
    std::span<const unsigned char> statement_binding) {
    return ::circuit_binding_digest(circuit, statement_binding);
}

}  // namespace purify
