// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "purify/puresign/construction_receipt.hpp"
#include "purify/puresign/construction_receipt_accumulation.hpp"
#include "purify/puresign/construction_receipt_envelope.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <limits>
#include <utility>
#include <vector>

#include "checked_size.hpp"
#include "purify/curve.hpp"

namespace purify::accountable {
namespace {

using ::purify::detail::CheckedSize;

const TaggedHash kConstructionReceiptStatementHash(
    "Purify/Accountable/ConstructionReceiptStatement/v5");

Status validate_ciphertext(const AnchorEscrowCiphertext& ciphertext) {
    return validate_public_points(ciphertext.ephemeral_key);
}

Status validate_circuit_precommitment(
    const bppp::ScalarBytes& circuit_precommitment) {
    PURIFY_ASSIGN_OR_RETURN(const auto& scalar, FieldElement::try_from_bytes32(
                                                    circuit_precommitment));
    if (scalar.is_zero()) {
        return unexpected_error(ErrorCode::RangeViolation);
    }
    return {};
}

Status validate_anchor_entries(
    std::span<const ConstructionReceiptAnchorEntry> entries) {
    if (entries.empty()) {
        return unexpected_error(ErrorCode::EmptyInput);
    }
    if (!size_fits_u32(entries.size())) {
        return unexpected_error(ErrorCode::UnexpectedSize);
    }
    for (const ConstructionReceiptAnchorEntry& entry : entries) {
        PURIFY_RETURN_IF_ERROR(validate_ciphertext(entry.ciphertext));
        PURIFY_RETURN_IF_ERROR(
            validate_circuit_precommitment(entry.circuit_precommitment));
    }
    return {};
}

Status validate_setup_entries(
    const UInt512& recovery_root,
    std::span<const ConstructionReceiptSetupEntry> entries) {
    if (entries.empty()) {
        return unexpected_error(ErrorCode::EmptyInput);
    }
    if (!size_fits_u32(entries.size())) {
        return unexpected_error(ErrorCode::UnexpectedSize);
    }
    std::vector<RecoveryRootShare> shares;
    shares.reserve(entries.size());
    for (const ConstructionReceiptSetupEntry& entry : entries) {
        PURIFY_RETURN_IF_ERROR(
            validate_circuit_precommitment(entry.circuit_precommitment));
        shares.push_back(entry.share);
    }
    PURIFY_ASSIGN_OR_RETURN(const auto aggregate,
                            aggregate_recovery_root_shares(shares));
    if (aggregate.recovery_root() != recovery_root) {
        return unexpected_error(ErrorCode::BindingMismatch);
    }
    return {};
}

void append_u32_be(Bytes& out, std::uint32_t value) {
    out.push_back(static_cast<unsigned char>((value >> 24) & 0xffU));
    out.push_back(static_cast<unsigned char>((value >> 16) & 0xffU));
    out.push_back(static_cast<unsigned char>((value >> 8) & 0xffU));
    out.push_back(static_cast<unsigned char>(value & 0xffU));
}

std::uint32_t read_u32_be(std::span<const unsigned char, 4> encoded) {
    return (static_cast<std::uint32_t>(encoded[0]) << 24) |
           (static_cast<std::uint32_t>(encoded[1]) << 16) |
           (static_cast<std::uint32_t>(encoded[2]) << 8) |
           static_cast<std::uint32_t>(encoded[3]);
}

template <std::size_t Size>
void append_array(Bytes& out, const std::array<unsigned char, Size>& value) {
    out.insert(out.end(), value.begin(), value.end());
}

void append_ciphertext(Bytes& out,
                       const AnchorEscrowCiphertext& ciphertext) {
    append_array(out, ciphertext.ephemeral_key.to_bytes_be());
    append_array(out, ciphertext.masked_scalar.to_bytes_be());
}

Result<AnchorEscrowCiphertext> parse_ciphertext(
    std::span<const unsigned char, AnchorEscrowCiphertext::kSerializedSize>
        encoded) {
    AnchorEscrowCiphertext ciphertext;
    std::size_t offset = 0;
    ciphertext.ephemeral_key =
        UInt512::from_bytes_be(encoded.data() + offset, 64);
    offset += 64;
    std::array<unsigned char, 32> encoded_scalar{};
    std::copy_n(encoded.data() + offset,
                encoded_scalar.size(), encoded_scalar.begin());
    PURIFY_ASSIGN_OR_RETURN(ciphertext.masked_scalar,
                            FieldElement::try_from_bytes32(encoded_scalar));
    offset += 32;
    assert(offset == encoded.size());
    PURIFY_RETURN_IF_ERROR(validate_ciphertext(ciphertext));
    return ciphertext;
}

Result<std::size_t> encoded_size_for_counts(
    std::size_t setup_count, std::size_t anchor_count) {
    std::size_t entry_count = 0;
    if (!size_fits_u32(setup_count) ||
        !size_fits_u32(anchor_count) ||
        !(CheckedSize(setup_count) + anchor_count).store(entry_count) ||
        !size_fits_u32(entry_count)) {
        return unexpected_error(ErrorCode::UnexpectedSize);
    }
    std::size_t encoded_size = 0;
    if (!(CheckedSize(setup_count) *
              ConstructionReceiptPayload::kSetupEntrySize +
          CheckedSize(anchor_count) *
              ConstructionReceiptPayload::kAnchorEntrySize +
          ConstructionReceiptPayload::kFixedHeaderSize)
             .store(encoded_size)) {
        return unexpected_error(ErrorCode::UnexpectedSize);
    }
    return encoded_size;
}

}  // namespace

Result<ResolvedConstructionSetupDigest>
ResolvedConstructionSetupDigest::create(
    const ResolvedConstructionSetupDigestBytes& digest) {
    if (std::all_of(digest.begin(), digest.end(),
                    [](unsigned char byte) { return byte == 0; })) {
        return unexpected_error(ErrorCode::RangeViolation);
    }
    return ResolvedConstructionSetupDigest(digest);
}

Result<ConstructionReceiptPayload> ConstructionReceiptPayload::create(
    UInt512 recovery_root,
    std::vector<ConstructionReceiptSetupEntry> setup_entries,
    std::vector<ConstructionReceiptAnchorEntry> anchor_entries) {
    PURIFY_RETURN_IF_ERROR(validate_public_points(recovery_root));
    PURIFY_ASSIGN_OR_RETURN(
        const auto encoded_size,
        encoded_size_for_counts(setup_entries.size(), anchor_entries.size()));
    (void)encoded_size;
    PURIFY_RETURN_IF_ERROR(
        validate_setup_entries(recovery_root, setup_entries));
    PURIFY_RETURN_IF_ERROR(validate_anchor_entries(anchor_entries));
    return ConstructionReceiptPayload(
        recovery_root, std::move(setup_entries),
        std::move(anchor_entries));
}

Bytes ConstructionReceiptPayload::serialize() const {
    Bytes encoded;
    encoded.reserve(serialized_size());
    encoded.push_back(kSerializationVersion);
    append_array(encoded, recovery_root_.to_bytes_be());
    assert(size_fits_u32(setup_entries_.size()));
    assert(size_fits_u32(anchor_entries_.size()));
    append_u32_be(
        encoded, static_cast<std::uint32_t>(setup_entries_.size()));
    append_u32_be(
        encoded, static_cast<std::uint32_t>(anchor_entries_.size()));
    for (const ConstructionReceiptSetupEntry& entry : setup_entries_) {
        const auto share = entry.share.serialize();
        encoded.insert(encoded.end(), share.begin(), share.end());
        append_array(encoded, entry.circuit_precommitment);
    }
    for (const ConstructionReceiptAnchorEntry& entry : anchor_entries_) {
        append_ciphertext(encoded, entry.ciphertext);
        append_array(encoded, entry.circuit_precommitment);
    }
    assert(encoded.size() == serialized_size());
    return encoded;
}

Result<ConstructionReceiptPayload> ConstructionReceiptPayload::deserialize(
    std::span<const unsigned char> encoded) {
    if (encoded.size() < kFixedHeaderSize) {
        return unexpected_error(ErrorCode::InvalidFixedSize);
    }
    if (encoded[0] != kSerializationVersion) {
        return unexpected_error(ErrorCode::UnsupportedSymbol);
    }

    std::size_t offset = 1;
    UInt512 recovery_root =
        UInt512::from_bytes_be(encoded.data() + offset, 64);
    offset += 64;
    PURIFY_RETURN_IF_ERROR(validate_public_points(recovery_root));

    const std::span<const unsigned char, 4> encoded_setup_count(
        encoded.data() + offset, 4);
    const std::uint32_t setup_count =
        read_u32_be(encoded_setup_count);
    offset += 4;
    const std::span<const unsigned char, 4> encoded_anchor_count(
        encoded.data() + offset, 4);
    const std::uint32_t anchor_count =
        read_u32_be(encoded_anchor_count);
    offset += 4;
    if (setup_count == 0 || anchor_count == 0) {
        return unexpected_error(ErrorCode::EmptyInput);
    }
    PURIFY_ASSIGN_OR_RETURN(
        const std::size_t expected_size,
        encoded_size_for_counts(static_cast<std::size_t>(setup_count),
                                static_cast<std::size_t>(anchor_count)));
    if (encoded.size() != expected_size) {
        return unexpected_error(ErrorCode::InvalidFixedSize);
    }

    std::vector<ConstructionReceiptSetupEntry> setup_entries;
    setup_entries.reserve(setup_count);
    for (std::uint32_t i = 0; i < setup_count; ++i) {
        PURIFY_ASSIGN_OR_RETURN(
            auto share, RecoveryRootShare::deserialize(encoded.subspan(
                            offset, RecoveryRootShare::kSerializedSize)));
        offset += RecoveryRootShare::kSerializedSize;
        bppp::ScalarBytes precommitment{};
        std::copy_n(encoded.begin() + offset,
                    precommitment.size(), precommitment.begin());
        offset += precommitment.size();
        PURIFY_RETURN_IF_ERROR(validate_circuit_precommitment(precommitment));
        setup_entries.emplace_back(std::move(share), precommitment);
    }

    std::vector<ConstructionReceiptAnchorEntry> anchor_entries;
    anchor_entries.reserve(anchor_count);
    for (std::uint32_t i = 0; i < anchor_count; ++i) {
        ConstructionReceiptAnchorEntry entry;
        const std::span<const unsigned char,
                        AnchorEscrowCiphertext::kSerializedSize>
            encoded_ciphertext(encoded.data() + offset,
                               AnchorEscrowCiphertext::kSerializedSize);
        PURIFY_ASSIGN_OR_RETURN(entry.ciphertext,
                                parse_ciphertext(encoded_ciphertext));
        offset += AnchorEscrowCiphertext::kSerializedSize;
        std::copy_n(
            encoded.begin() + offset,
            entry.circuit_precommitment.size(),
            entry.circuit_precommitment.begin());
        offset += entry.circuit_precommitment.size();
        PURIFY_RETURN_IF_ERROR(
            validate_circuit_precommitment(entry.circuit_precommitment));
        anchor_entries.push_back(std::move(entry));
    }
    assert(offset == encoded.size());
    PURIFY_RETURN_IF_ERROR(
        validate_setup_entries(recovery_root, setup_entries));
    PURIFY_RETURN_IF_ERROR(validate_anchor_entries(anchor_entries));
    return ConstructionReceiptPayload(
        recovery_root, std::move(setup_entries),
        std::move(anchor_entries));
}

Result<ConstructionReceiptStatementDigest>
construction_receipt_statement_digest(
    const ConstructionReceiptPayload& payload,
    const ResolvedConstructionSetupDigest& resolved_setup,
    std::span<const ResolvedConstructionReceiptEntry> resolved_entries) {
    if (resolved_entries.size() != payload.anchor_entries().size()) {
        return unexpected_error(ErrorCode::InvalidFixedSize);
    }

    Bytes statement = payload.serialize();
    statement.reserve(statement.size() +
                      ResolvedConstructionSetupDigest::kSerializedSize +
                      resolved_entries.size() * (32 + 64 + 33 + 32));
    append_array(statement, resolved_setup.bytes());
    for (std::size_t i = 0; i < resolved_entries.size(); ++i) {
        const ResolvedConstructionReceiptEntry& resolved =
            resolved_entries[i];
        for (std::size_t prior = 0; prior < i; ++prior) {
            if (resolved_entries[prior].anchor_reference ==
                resolved.anchor_reference) {
                return unexpected_error(ErrorCode::BindingMismatch);
            }
            if (resolved_entries[prior].anchor_root ==
                resolved.anchor_root) {
                return unexpected_error(ErrorCode::BindingMismatch);
            }
            if (resolved_entries[prior].punishment_key ==
                resolved.punishment_key) {
                return unexpected_error(ErrorCode::BindingMismatch);
            }
        }
        PURIFY_RETURN_IF_ERROR(validate_public_points(resolved.anchor_root));
        append_array(statement, resolved.anchor_reference);
        append_array(statement, resolved.anchor_root.to_bytes_be());
        std::array<unsigned char, 33> punishment{};
        punishment[0] = 0x02;
        std::copy(resolved.punishment_key.xonly().begin(),
                  resolved.punishment_key.xonly().end(),
                  punishment.begin() + 1);
        append_array(statement, punishment);
        append_array(statement, resolved.context_digest);
    }
    return kConstructionReceiptStatementHash.digest(statement);
}

}  // namespace purify::accountable

namespace purify::accountable {

Result<ConstructionReceiptAccumulator>
ConstructionReceiptAccumulator::create(
    purify_secp_context* secp_context) {
    PURIFY_ASSIGN_OR_RETURN(auto leaves,
                            ConstructionLeafAccumulator::create(secp_context));
    return ConstructionReceiptAccumulator(std::move(leaves));
}

Result<ResolvedConstructionSetup>
ResolvedConstructionSetup::create(
    NonceHostBoundSigningRoster roster,
    CoalitionFormation formation,
    UInt512 recovery_root,
    ResolvedConstructionSetupDigest resolved_digest) {
    if (roster.members().empty() ||
        !size_fits_u32(roster.members().size())) {
        return unexpected_error(ErrorCode::RangeViolation);
    }
    PURIFY_RETURN_IF_ERROR(validate_public_points(recovery_root));
    if (formation.core_digest() != roster.coalition_core_digest()) {
        return unexpected_error(ErrorCode::BindingMismatch);
    }
    return ResolvedConstructionSetup(
        std::move(roster), std::move(formation), recovery_root,
        std::move(resolved_digest));
}

Result<ConstructionReceiptEnvelope> ConstructionReceiptEnvelope::create(
    ConstructionReceiptPayload payload,
    Bytes parent_proof) {
    if (parent_proof.size() != kParentProofSize) {
        return unexpected_error(ErrorCode::InvalidFixedSize);
    }
    return ConstructionReceiptEnvelope(std::move(payload),
                                       std::move(parent_proof));
}

Result<ConstructionReceiptEnvelope>
ConstructionReceiptEnvelope::deserialize(
    std::span<const unsigned char> encoded) {
    constexpr std::size_t minimum_size =
        ConstructionReceiptPayload::kFixedHeaderSize +
        kParentProofSize;
    if (encoded.size() < minimum_size) {
        return unexpected_error(ErrorCode::InvalidFixedSize);
    }
    const std::size_t payload_size =
        encoded.size() - kParentProofSize;
    PURIFY_ASSIGN_OR_RETURN(
        auto payload,
        ConstructionReceiptPayload::deserialize(encoded.first(payload_size)));
    Bytes parent_proof(encoded.begin() + payload_size, encoded.end());
    return create(std::move(payload), std::move(parent_proof));
}

Bytes ConstructionReceiptEnvelope::serialize() const {
    Bytes encoded = payload_.serialize();
    encoded.reserve(serialized_size());
    encoded.insert(encoded.end(), parent_proof_.begin(),
                   parent_proof_.end());
    assert(encoded.size() == serialized_size());
    return encoded;
}

std::size_t ConstructionReceiptEnvelope::serialized_size() const noexcept {
    return payload_.serialized_size() + parent_proof_.size();
}

}  // namespace purify::accountable
