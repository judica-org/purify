// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file bulletproof_circuit.cpp
 * @brief Native Bulletproof circuit containers: sparse rows, the packed layout, and their evaluation.
 */

#include "purify/bulletproof.hpp"

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstring>
#include <memory>
#include <new>
#include <span>
#include <type_traits>
#include <utility>
#include <vector>

#include "checked_size.hpp"
#include "secure_cleanup.hpp"

namespace {

using purify::detail::CheckedSize;

static_assert(std::is_trivially_copyable_v<purify::NativeBulletproofCircuitTerm>,
              "Packed circuit storage requires trivially copyable terms");
static_assert(std::is_trivially_copyable_v<purify::FieldElement>,
              "Packed circuit storage requires trivially copyable field elements");

using ::purify::detail::WipeOnDestruction;

bool packed_row_count(std::size_t n_gates, std::size_t n_commitments, std::size_t& out) {
    return (CheckedSize(n_gates) * 3 + n_commitments).store(out);
}

}  // namespace

namespace purify {

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
    if (wl.size() != n_gates
        || wr.size() != n_gates
        || wo.size() != n_gates
        || wv.size() != n_commitments) {
        return false;
    }
    const auto rows_are_valid = [&](const std::vector<NativeBulletproofCircuitRow>& rows) {
        for (const NativeBulletproofCircuitRow& row : rows) {
            for (const NativeBulletproofCircuitTerm& entry : row.entries) {
                if (entry.idx >= c.size()) {
                    return false;
                }
            }
        }
        return true;
    };
    return rows_are_valid(wl)
        && rows_are_valid(wr)
        && rows_are_valid(wo)
        && rows_are_valid(wv);
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

    purify::detail::SecretVector<FieldElement> acc(c.size(), FieldElement::zero());
    auto accumulate = [&](const std::vector<NativeBulletproofCircuitRow>& rows,
                          std::span<const FieldElement> values,
                          bool negate_values = false) {
        if (rows.size() != values.size()) {
            return false;
        }
        for (std::size_t i = 0; i < rows.size(); ++i) {
            if (negate_values) {
                FieldElement negated = values[i].negate();
                WipeOnDestruction negated_wiper(negated);
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
        ::operator delete(storage, std::align_val_t(NativeBulletproofCircuit::PackedWithSlack::kPackedStorageAlignment));
    }
}

std::byte* NativeBulletproofCircuit::PackedWithSlack::allocate_storage(std::size_t bytes) {
    if (bytes == 0) {
        return nullptr;
    }
    return static_cast<std::byte*>(::operator new(bytes, std::align_val_t(kPackedStorageAlignment)));
}

NativeBulletproofCircuit::PackedWithSlack::PackedWithSlack(const PackedWithSlack& other)
    : n_gates_(other.n_gates_), n_commitments_(other.n_commitments_), n_bits_(other.n_bits_),
      constraint_size_(other.constraint_size_), constraint_base_size_(other.constraint_base_size_),
      constraint_capacity_(other.constraint_capacity_), term_capacity_(other.term_capacity_),
      term_bytes_offset_(other.term_bytes_offset_), constant_bytes_offset_(other.constant_bytes_offset_),
      storage_bytes_(other.storage_bytes_) {
    assert((other.storage_ != nullptr) == (other.storage_bytes_ != 0)
           && "PackedWithSlack source storage must match its byte count");
    if (storage_bytes_ != 0) {
        storage_.reset(allocate_storage(storage_bytes_));
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
    const CheckedSize term_offset =
        (CheckedSize(row_count) * sizeof(PackedRowHeader)).aligned_up(alignof(NativeBulletproofCircuitTerm));
    const CheckedSize constant_offset =
        (term_offset + CheckedSize(term_capacity) * sizeof(NativeBulletproofCircuitTerm))
            .aligned_up(alignof(FieldElement));
    const CheckedSize storage = constant_offset + CheckedSize(constraint_capacity) * sizeof(FieldElement);
    return term_offset.store(term_bytes_offset) && constant_offset.store(constant_bytes_offset) &&
           storage.store(storage_bytes);
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
        const NativeBulletproofCircuitTerm* terms = term_data();
        for (std::size_t j = 0; j < header.size; ++j) {
            if (terms[header.offset + j].idx >= constraint_size_) {
                return false;
            }
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

    purify::detail::SecretVector<FieldElement> acc(constraint_size_, FieldElement::zero());
    const NativeBulletproofCircuitTerm* all_terms = term_data();
    auto accumulate = [&](RowFamily family, std::size_t row_count,
                          std::span<const FieldElement> values,
                          bool negate_values = false) {
        if (values.size() != row_count) {
            return false;
        }
        for (std::size_t i = 0; i < row_count; ++i) {
            const PackedRowHeader& header = row_header(family, i);
            FieldElement factor = negate_values ? values[i].negate() : values[i];
            WipeOnDestruction factor_wiper(factor);
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
        return unexpected_error(ErrorCode::InvalidDimensions);
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
        return unexpected_error(ErrorCode::InvalidDimensions);
    }
    auto validate_family_slack = [](const std::vector<std::size_t>& family_slack, std::size_t expected) -> Status {
        if (!family_slack.empty() && family_slack.size() != expected) {
            return unexpected_error(ErrorCode::SizeMismatch);
        }
        return {};
    };
    PURIFY_RETURN_IF_ERROR(validate_family_slack(slack.wl, circuit.n_gates));
    PURIFY_RETURN_IF_ERROR(validate_family_slack(slack.wr, circuit.n_gates));
    PURIFY_RETURN_IF_ERROR(validate_family_slack(slack.wo, circuit.n_gates));
    PURIFY_RETURN_IF_ERROR(validate_family_slack(slack.wv, circuit.n_commitments));

    PackedWithSlack packed;
    packed.n_gates_ = circuit.n_gates;
    packed.n_commitments_ = circuit.n_commitments;
    packed.n_bits_ = circuit.n_bits;
    packed.constraint_size_ = circuit.c.size();
    packed.constraint_base_size_ = circuit.c.size();
    if (!(CheckedSize(circuit.c.size()) + slack.constraint_slack).store(packed.constraint_capacity_)) {
        return unexpected_error(ErrorCode::Overflow);
    }

    std::size_t row_count = 0;
    if (!packed_row_count(circuit.n_gates, circuit.n_commitments, row_count)) {
        return unexpected_error(ErrorCode::Overflow);
    }
    std::size_t total_term_capacity = 0;
    auto sum_capacity = [&](const std::vector<NativeBulletproofCircuitRow>& rows,
                            const std::vector<std::size_t>& family_slack) -> bool {
        for (std::size_t i = 0; i < rows.size(); ++i) {
            const std::size_t extra = family_slack.empty() ? 0 : family_slack[i];
            if (!(CheckedSize(total_term_capacity) + rows[i].entries.size() + extra).store(total_term_capacity)) {
                return false;
            }
        }
        return true;
    };
    if (!sum_capacity(circuit.wl, slack.wl)
        || !sum_capacity(circuit.wr, slack.wr)
        || !sum_capacity(circuit.wo, slack.wo)
        || !sum_capacity(circuit.wv, slack.wv)) {
        return unexpected_error(ErrorCode::Overflow);
    }
    packed.term_capacity_ = total_term_capacity;
    if (!compute_storage_layout(row_count, packed.term_capacity_, packed.constraint_capacity_,
                                packed.term_bytes_offset_, packed.constant_bytes_offset_, packed.storage_bytes_)) {
        return unexpected_error(ErrorCode::Overflow);
    }
    packed.storage_.reset(allocate_storage(packed.storage_bytes_));
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

}  // namespace purify
