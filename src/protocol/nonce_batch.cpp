// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "purify/nonce_batch.hpp"

#include <bit>
#include <limits>
#include <utility>

namespace purify {
namespace {

Result<std::size_t> checked_sum(std::size_t lhs, std::size_t rhs) {
    if (rhs > std::numeric_limits<std::size_t>::max() - lhs) {
        return unexpected_error(ErrorCode::Overflow, "nonce_batch:dimension_sum");
    }
    return lhs + rhs;
}

Result<std::size_t> padded_gates(std::size_t gates) {
    constexpr std::size_t max_power =
        std::size_t{1} << (std::numeric_limits<std::size_t>::digits - 1);
    if (gates == 0 || gates > max_power) {
        return unexpected_error(ErrorCode::Overflow, "nonce_batch:padded_gates");
    }
    return std::bit_ceil(gates);
}

void append_rows(std::vector<NativeBulletproofCircuitRow>& destination,
                 std::vector<NativeBulletproofCircuitRow>& source,
                 std::size_t constraint_offset) {
    for (auto& row : source) {
        for (auto& term : row.entries) {
            term.idx += constraint_offset;
        }
        destination.push_back(std::move(row));
    }
}

} // namespace

Result<NativeBulletproofCircuit> nonce_batch_circuit(
    std::span<const NonceBatchGroup> groups) {
    if (groups.empty()) {
        return unexpected_error(ErrorCode::InvalidDimensions, "nonce_batch_circuit:empty");
    }

    NativeBulletproofCircuit result(0, groups.size(), 0);
    std::size_t group_index = 0;
    for (const auto& group : groups) {
        PURIFY_ASSIGN_OR_RETURN(auto circuit_template, verifier_circuit_template(group.evaluation_input),
                                "nonce_batch_circuit:template");
        PURIFY_ASSIGN_OR_RETURN(auto circuit, circuit_template.instantiate_sum(group.hosts),
                                "nonce_batch_circuit:group");
        PURIFY_ASSIGN_OR_RETURN(const auto next_gates, checked_sum(result.n_gates, circuit.n_gates),
                                "nonce_batch_circuit:gates");
        PURIFY_RETURN_IF_ERROR(checked_sum(result.c.size(), circuit.c.size()),
                               "nonce_batch_circuit:constraints");
        const std::size_t constraint_offset = result.c.size();
        result.c.insert(result.c.end(), circuit.c.begin(), circuit.c.end());
        append_rows(result.wl, circuit.wl, constraint_offset);
        append_rows(result.wr, circuit.wr, constraint_offset);
        append_rows(result.wo, circuit.wo, constraint_offset);
        for (const auto& term : circuit.wv[0].entries) {
            result.wv[group_index].add(constraint_offset + term.idx, term.scalar);
        }
        result.n_gates = next_gates;
        ++group_index;
    }

    PURIFY_ASSIGN_OR_RETURN(const auto gates, padded_gates(result.n_gates),
                            "nonce_batch_circuit:padding");
    result.n_gates = gates;
    result.wl.resize(gates);
    result.wr.resize(gates);
    result.wo.resize(gates);
    return result;
}

Result<BulletproofAssignmentData> nonce_batch_assignments(
    std::span<const NonceBatchGroup> groups,
    std::span<const std::vector<BulletproofAssignmentData>> assignments) {
    if (groups.empty()) {
        return unexpected_error(ErrorCode::InvalidDimensions, "nonce_batch_assignments:empty");
    }
    if (groups.size() != assignments.size()) {
        return unexpected_error(ErrorCode::SizeMismatch, "nonce_batch_assignments:groups");
    }

    BulletproofAssignmentData result;
    result.commitments.reserve(groups.size());
    for (std::size_t group_index = 0; group_index < groups.size(); ++group_index) {
        const auto& group = groups[group_index];
        PURIFY_ASSIGN_OR_RETURN(auto circuit_template, verifier_circuit_template(group.evaluation_input),
                                "nonce_batch_assignments:template");
        PURIFY_ASSIGN_OR_RETURN(auto assignment,
                                circuit_template.sum_assignments(group.hosts, assignments[group_index]),
                                "nonce_batch_assignments:group");
        PURIFY_RETURN_IF_ERROR(checked_sum(result.left.size(), assignment.left.size()),
                               "nonce_batch_assignments:gates");
        result.left.insert(result.left.end(), assignment.left.begin(), assignment.left.end());
        result.right.insert(result.right.end(), assignment.right.begin(), assignment.right.end());
        result.output.insert(result.output.end(), assignment.output.begin(), assignment.output.end());
        result.commitments.push_back(assignment.commitments[0]);
    }

    PURIFY_ASSIGN_OR_RETURN(const auto gates, padded_gates(result.left.size()),
                            "nonce_batch_assignments:padding");
    result.left.resize(gates, FieldElement::zero());
    result.right.resize(gates, FieldElement::zero());
    result.output.resize(gates, FieldElement::zero());
    return result;
}

} // namespace purify
