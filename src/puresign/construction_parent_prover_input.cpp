// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "purify/puresign/construction_parent_prover_input.hpp"

#include "construction_parent_input_internal.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <vector>

#include "../bridge/bppp_bridge.h"

namespace purify::accountable {
namespace {

constexpr std::array<unsigned char, 16> kWit3Magic{
    'P', 'u', 'r', 'i', 'f', 'y', '/', 'N',
    'o', 'v', 'a', '/', 'W', 'i', 't', '3'};
constexpr std::size_t kDescriptorSize =
    detail::kConstructionParentDescriptorSize;
constexpr std::size_t kReductionProofSize = 1'022;
constexpr std::size_t kStepProofSize = 1'056;
constexpr std::size_t kHeaderSize =
    kWit3Magic.size() + 32 + 32 + 64 + 4 + 4;
constexpr std::size_t kSetupWitnessSize =
    kDescriptorSize + 33 + RecoveryRootContribution::kSerializedSize +
    kReductionProofSize + kStepProofSize;
constexpr std::size_t kAnchorWitnessSize =
    kDescriptorSize + 33 + AnchorEscrowRecord::kSerializedSize +
    kReductionProofSize + kStepProofSize;

template <std::size_t N>
void append(Bytes& output, const std::array<unsigned char, N>& bytes) {
    output.insert(output.end(), bytes.begin(), bytes.end());
}

void append(Bytes& output, std::span<const unsigned char> bytes) {
    output.insert(output.end(), bytes.begin(), bytes.end());
}

void append_u32_be(Bytes& output, std::uint32_t value) {
    output.push_back(static_cast<unsigned char>((value >> 24) & 0xffU));
    output.push_back(static_cast<unsigned char>((value >> 16) & 0xffU));
    output.push_back(static_cast<unsigned char>((value >> 8) & 0xffU));
    output.push_back(static_cast<unsigned char>(value & 0xffU));
}

bool same_roster(const NonceHostBoundSigningRoster& left,
                 const NonceHostBoundSigningRoster& right) {
    if (left.signing_key() != right.signing_key() ||
        left.key_list_hash() != right.key_list_hash() ||
        left.aggregate_was_negated() != right.aggregate_was_negated() ||
        left.coalition_core_digest() != right.coalition_core_digest() ||
        left.nonce_host_commitment() != right.nonce_host_commitment() ||
        left.members().size() != right.members().size()) {
        return false;
    }
    for (std::size_t index = 0; index < left.members().size(); ++index) {
        if (left.members()[index].public_key !=
                right.members()[index].public_key ||
            left.members()[index].coefficient !=
                right.members()[index].coefficient) {
            return false;
        }
    }
    return true;
}

Result<bppp::PointBytes> effective_member_point(
    const NonceHostBoundSigningRoster& roster, std::size_t member_index,
    purify_secp_context* secp_context) {
    if (member_index >= roster.members().size()) {
        return unexpected_error(ErrorCode::IndexOutOfRange,
                                "construction_wit3:member_index");
    }
    const auto& member = roster.members()[member_index];
    const auto coefficient = member.coefficient.to_bytes_be();
    bppp::PointBytes weighted{};
    if (purify_point_scale(secp_context, member.public_key.data(),
                           coefficient.data(), weighted.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput,
                                "construction_wit3:weighted_member");
    }
    return weighted;
}

bool same_ciphertext(const AnchorEscrowCiphertext& left,
                     const AnchorEscrowCiphertext& right) {
    return left.ephemeral_key == right.ephemeral_key &&
           left.masked_scalar == right.masked_scalar;
}

std::span<const unsigned char> descriptor_at(
    const detail::ResolvedConstructionParentPublicInputs& inputs,
    std::size_t index) {
    return std::span<const unsigned char>{inputs.descriptors}
        .subspan(index * kDescriptorSize, kDescriptorSize);
}

} // namespace

Result<Bytes> serialize_accepted_construction_parent_wit3(
    const ResolvedConstructionSetup& resolved_setup,
    const VerifiedDistributedRecoverySetup& verified_setup,
    const ConstructionReceiptPayload& payload,
    std::span<const ResolvedConstructionReceiptEntry> resolved_entries,
    std::span<const ConstructionParentSetupWitness> setup_witnesses,
    std::span<const ConstructionParentAnchorWitness> anchor_witnesses,
    const ConstructionReceiptAccumulator& accumulator,
    purify_secp_context* secp_context,
    bppp::ExperimentalCircuitBackend* cache) {
    PURIFY_RETURN_IF_ERROR(
        require_secp_context(secp_context, "construction_wit3:context"),
        "construction_wit3:context");
    PURIFY_ASSIGN_OR_RETURN(
        auto inputs,
        detail::resolve_construction_parent_public_inputs(
            resolved_setup, payload, resolved_entries,
            accumulator.leaves(), secp_context),
        "construction_wit3:public_inputs");

    const auto setup_entries = payload.setup_entries();
    const auto anchor_entries = payload.anchor_entries();
    if (setup_witnesses.size() != setup_entries.size() ||
        anchor_witnesses.size() != anchor_entries.size()) {
        return unexpected_error(ErrorCode::SizeMismatch,
                                "construction_wit3:witness_count");
    }
    if (verified_setup.roster().recovery_root() !=
            resolved_setup.recovery_root() ||
        verified_setup.aggregate().recovery_root() !=
            resolved_setup.recovery_root() ||
        !same_roster(verified_setup.roster(),
                     resolved_setup.roster())) {
        return unexpected_error(ErrorCode::BindingMismatch,
                                "construction_wit3:verified_setup");
    }

    std::size_t setup_size = 0;
    std::size_t anchor_size = 0;
    std::size_t body_size = 0;
    std::size_t expected_size = 0;
    constexpr std::size_t kFinalRootSize =
        ConstructionReceiptAccumulator::kRootClaimSerializedSize;
    if (!checked_mul_size(setup_witnesses.size(), kSetupWitnessSize,
                          setup_size) ||
        !checked_mul_size(anchor_witnesses.size(), kAnchorWitnessSize,
                          anchor_size) ||
        !checked_add_size(setup_size, anchor_size, body_size) ||
        !checked_add_size(kHeaderSize, body_size, expected_size) ||
        !checked_add_size(expected_size, kFinalRootSize,
                          expected_size)) {
        return unexpected_error(ErrorCode::Overflow,
                                "construction_wit3:encoded_size");
    }

    std::array<unsigned char, kFinalRootSize> empty_root{};
    PURIFY_ASSIGN_OR_RETURN(
        auto current,
        bppp::accumulation::parse_root_claim(
            accumulator.leaves().basis(), empty_root, secp_context),
        "construction_wit3:empty_root");

    for (std::size_t index = 0; index < setup_witnesses.size(); ++index) {
        const auto& witness = setup_witnesses[index];
        const auto& entry = setup_entries[index];
        if (witness.contribution.share().serialize() !=
            entry.share.serialize()) {
            return unexpected_error(ErrorCode::BindingMismatch,
                                    "construction_wit3:setup_share");
        }
        PURIFY_ASSIGN_OR_RETURN(
            auto prepared,
            accumulator.leaves().prepare(
                resolved_setup.roster(), resolved_setup.formation(),
                index, witness.contribution, secp_context, cache),
            "construction_wit3:prepare_setup");
        if (prepared.circuit_precommitment() !=
            entry.circuit_precommitment) {
            return unexpected_error(
                ErrorCode::BindingMismatch,
                "construction_wit3:setup_precommitment");
        }
        PURIFY_ASSIGN_OR_RETURN(
            auto leaf,
            bppp::accumulation::verify_algebraic_norm_reduction(
                accumulator.leaves().basis(), prepared.norm(),
                witness.reduction, secp_context),
            "construction_wit3:verify_setup_reduction");
        const std::array claims{current, leaf};
        PURIFY_ASSIGN_OR_RETURN(
            current,
            bppp::accumulation::verify_algebraic_step(
                accumulator.leaves().basis(), claims, witness.step,
                secp_context),
            "construction_wit3:verify_setup_step");
    }

    for (std::size_t index = 0; index < anchor_witnesses.size(); ++index) {
        const auto& witness = anchor_witnesses[index];
        const auto& entry = anchor_entries[index];
        const auto& resolved = resolved_entries[index];
        if (!same_ciphertext(witness.record.ciphertext(),
                             entry.ciphertext)) {
            return unexpected_error(ErrorCode::BindingMismatch,
                                    "construction_wit3:ciphertext");
        }
        PURIFY_ASSIGN_OR_RETURN(
            auto prepared,
            accumulator.leaves().prepare(
                verified_setup.roster(), resolved.anchor_root,
                resolved.punishment_key, resolved.context_digest,
                witness.record, secp_context, cache),
            "construction_wit3:prepare_anchor");
        if (prepared.circuit_precommitment() !=
            entry.circuit_precommitment) {
            return unexpected_error(
                ErrorCode::BindingMismatch,
                "construction_wit3:anchor_precommitment");
        }
        PURIFY_ASSIGN_OR_RETURN(
            auto leaf,
            bppp::accumulation::verify_algebraic_norm_reduction(
                accumulator.leaves().basis(), prepared.norm(),
                witness.reduction, secp_context),
            "construction_wit3:verify_anchor_reduction");
        const std::array claims{current, leaf};
        PURIFY_ASSIGN_OR_RETURN(
            current,
            bppp::accumulation::verify_algebraic_step(
                accumulator.leaves().basis(), claims, witness.step,
                secp_context),
            "construction_wit3:verify_anchor_step");
    }

    PURIFY_RETURN_IF_ERROR(
        bppp::accumulation::decide(
            accumulator.leaves().basis(), current, secp_context),
        "construction_wit3:decide");

    Bytes encoded;
    encoded.reserve(expected_size);
    append(encoded, kWit3Magic);
    append(encoded, inputs.statement_digest);
    append(encoded, resolved_setup.resolved_digest().bytes());
    append(encoded, resolved_setup.recovery_root().to_bytes_be());
    append_u32_be(encoded, inputs.setup_count);
    append_u32_be(encoded, inputs.anchor_count);

    for (std::size_t index = 0; index < setup_witnesses.size(); ++index) {
        const auto& witness = setup_witnesses[index];
        PURIFY_ASSIGN_OR_RETURN(
            auto weighted,
            effective_member_point(resolved_setup.roster(), index,
                                   secp_context),
            "construction_wit3:effective_member");
        PURIFY_ASSIGN_OR_RETURN(
            auto contribution_bytes,
            witness.contribution.serialize(secp_context),
            "construction_wit3:serialize_contribution");
        PURIFY_ASSIGN_OR_RETURN(
            auto reduction_bytes,
            bppp::accumulation::serialize_algebraic_norm_reduction(
                accumulator.leaves().basis(), witness.reduction,
                secp_context),
            "construction_wit3:serialize_setup_reduction");
        PURIFY_ASSIGN_OR_RETURN(
            auto step_bytes,
            bppp::accumulation::serialize_algebraic_step(
                accumulator.leaves().basis(), witness.step,
                secp_context),
            "construction_wit3:serialize_setup_step");
        if (contribution_bytes.size() !=
                RecoveryRootContribution::kSerializedSize ||
            reduction_bytes.size() != kReductionProofSize ||
            step_bytes.size() != kStepProofSize) {
            return unexpected_error(ErrorCode::InternalMismatch,
                                    "construction_wit3:setup_size");
        }

        append(encoded, descriptor_at(inputs, index));
        append(encoded, weighted);
        append(encoded, contribution_bytes);
        append(encoded, reduction_bytes);
        append(encoded, step_bytes);
    }

    for (std::size_t index = 0; index < anchor_witnesses.size(); ++index) {
        const auto& witness = anchor_witnesses[index];
        const auto& resolved = resolved_entries[index];
        bppp::PointBytes punishment{};
        punishment[0] = 0x02;
        std::copy(resolved.punishment_key.xonly().begin(),
                  resolved.punishment_key.xonly().end(),
                  punishment.begin() + 1);
        PURIFY_ASSIGN_OR_RETURN(
            auto record_bytes,
            witness.record.serialize(secp_context),
            "construction_wit3:serialize_anchor_record");
        PURIFY_ASSIGN_OR_RETURN(
            auto reduction_bytes,
            bppp::accumulation::serialize_algebraic_norm_reduction(
                accumulator.leaves().basis(), witness.reduction,
                secp_context),
            "construction_wit3:serialize_anchor_reduction");
        PURIFY_ASSIGN_OR_RETURN(
            auto step_bytes,
            bppp::accumulation::serialize_algebraic_step(
                accumulator.leaves().basis(), witness.step,
                secp_context),
            "construction_wit3:serialize_anchor_step");
        if (record_bytes.size() != AnchorEscrowRecord::kSerializedSize ||
            reduction_bytes.size() != kReductionProofSize ||
            step_bytes.size() != kStepProofSize) {
            return unexpected_error(ErrorCode::InternalMismatch,
                                    "construction_wit3:anchor_size");
        }

        append(encoded,
               descriptor_at(inputs, setup_witnesses.size() + index));
        append(encoded, punishment);
        append(encoded, record_bytes);
        append(encoded, reduction_bytes);
        append(encoded, step_bytes);
    }

    PURIFY_ASSIGN_OR_RETURN(
        auto final_root,
        bppp::accumulation::serialize_root_claim(
            accumulator.leaves().basis(), current, secp_context),
        "construction_wit3:serialize_root");
    if (final_root.size() != kFinalRootSize) {
        return unexpected_error(ErrorCode::InternalMismatch,
                                "construction_wit3:root_size");
    }
    append(encoded, final_root);
    if (encoded.size() != expected_size) {
        return unexpected_error(ErrorCode::InternalMismatch,
                                "construction_wit3:final_size");
    }
    return encoded;
}

} // namespace purify::accountable
