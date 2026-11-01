// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "purify/puresign/construction_receipt.hpp"
#include "purify/puresign/construction_receipt_accumulation.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <limits>
#include <utility>
#include <vector>

#include "purify/curve.hpp"

namespace purify::accountable {
namespace {

const TaggedHash kConstructionReceiptStatementHash(
    "Purify/Accountable/ConstructionReceiptStatement/v1");

Status validate_public_root(const UInt512& encoded, const char* label) {
    PURIFY_ASSIGN_OR_RETURN(const auto& coords, unpack_public(encoded), label);
    PURIFY_ASSIGN_OR_RETURN(const auto& first_x,
                            FieldElement::try_from_uint256(coords.first),
                            label);
    PURIFY_ASSIGN_OR_RETURN(const auto& second_x,
                            FieldElement::try_from_uint256(coords.second),
                            label);
    const auto first = curve1().lift_x(first_x);
    const auto second = curve2().lift_x(second_x);
    if (!first || !second || first->infinity || second->infinity ||
        !curve1().mul(*first, order_n1()).infinity ||
        !curve2().mul(*second, order_n2()).infinity) {
        return unexpected_error(ErrorCode::BackendRejectedInput, label);
    }
    return {};
}

Status validate_ciphertext(const AnchorEscrowCiphertext& ciphertext) {
    for (const UInt512& ephemeral : ciphertext.ephemeral_keys) {
        PURIFY_RETURN_IF_ERROR(
            validate_public_root(ephemeral,
                                 "construction_receipt:ephemeral_key"),
            "construction_receipt:ephemeral_key");
    }
    if (ciphertext.ephemeral_keys[0] == ciphertext.ephemeral_keys[1]) {
        return unexpected_error(ErrorCode::BindingMismatch,
                                "construction_receipt:duplicate_ephemeral");
    }
    return {};
}

Status validate_entries(
    std::span<const ConstructionReceiptEntry> entries) {
    if (entries.empty()) {
        return unexpected_error(ErrorCode::EmptyInput,
                                "construction_receipt:entries");
    }
    if (!size_fits_u32(entries.size())) {
        return unexpected_error(ErrorCode::UnexpectedSize,
                                "construction_receipt:entry_count");
    }
    for (const ConstructionReceiptEntry& entry : entries) {
        PURIFY_RETURN_IF_ERROR(validate_ciphertext(entry.ciphertext),
                               "construction_receipt:ciphertext");
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
    for (std::size_t i = 0; i < ciphertext.ephemeral_keys.size(); ++i) {
        append_array(out, ciphertext.ephemeral_keys[i].to_bytes_be());
        append_array(out, ciphertext.masked_scalars[i].to_bytes_be());
    }
}

Result<AnchorEscrowCiphertext> parse_ciphertext(
    std::span<const unsigned char, AnchorEscrowCiphertext::kSerializedSize>
        encoded) {
    AnchorEscrowCiphertext ciphertext;
    std::size_t offset = 0;
    for (std::size_t i = 0; i < ciphertext.ephemeral_keys.size(); ++i) {
        ciphertext.ephemeral_keys[i] =
            UInt512::from_bytes_be(encoded.data() + offset, 64);
        offset += 64;
        std::array<unsigned char, 32> encoded_scalar{};
        std::copy_n(encoded.data() + offset,
                    encoded_scalar.size(),
                    encoded_scalar.begin());
        PURIFY_ASSIGN_OR_RETURN(
            ciphertext.masked_scalars[i],
            FieldElement::try_from_bytes32(encoded_scalar),
            "construction_receipt:masked_scalar");
        offset += 32;
    }
    assert(offset == encoded.size());
    PURIFY_RETURN_IF_ERROR(validate_ciphertext(ciphertext),
                           "construction_receipt:ciphertext");
    return ciphertext;
}

Result<std::size_t> encoded_size_for_count(std::size_t entry_count) {
    std::size_t entries_size = 0;
    std::size_t encoded_size = 0;
    if (!checked_mul_size(entry_count,
                          ConstructionReceiptPayload::kEntrySize,
                          entries_size) ||
        !checked_add_size(ConstructionReceiptPayload::kFixedHeaderSize,
                          entries_size,
                          encoded_size)) {
        return unexpected_error(ErrorCode::UnexpectedSize,
                                "construction_receipt:encoded_size");
    }
    return encoded_size;
}

}  // namespace

Result<ConstructionReceiptPayload> ConstructionReceiptPayload::create(
    UInt512 recovery_root,
    std::vector<ConstructionReceiptEntry> entries) {
    PURIFY_RETURN_IF_ERROR(
        validate_public_root(recovery_root,
                             "construction_receipt:recovery_root"),
        "construction_receipt:recovery_root");
    PURIFY_RETURN_IF_ERROR(validate_entries(entries),
                           "construction_receipt:entries");
    return ConstructionReceiptPayload(recovery_root,
                                      std::move(entries));
}

Bytes ConstructionReceiptPayload::serialize() const {
    Bytes encoded;
    encoded.reserve(serialized_size());
    encoded.push_back(kSerializationVersion);
    append_array(encoded, recovery_root_.to_bytes_be());
    assert(size_fits_u32(entries_.size()));
    append_u32_be(encoded, static_cast<std::uint32_t>(entries_.size()));
    for (const ConstructionReceiptEntry& entry : entries_) {
        append_ciphertext(encoded, entry.ciphertext);
    }
    assert(encoded.size() == serialized_size());
    return encoded;
}

Result<ConstructionReceiptPayload> ConstructionReceiptPayload::deserialize(
    std::span<const unsigned char> encoded) {
    if (encoded.size() < kFixedHeaderSize) {
        return unexpected_error(ErrorCode::InvalidFixedSize,
                                "construction_receipt:header");
    }
    if (encoded[0] != kSerializationVersion) {
        return unexpected_error(ErrorCode::UnsupportedSymbol,
                                "construction_receipt:version");
    }

    std::size_t offset = 1;
    UInt512 recovery_root =
        UInt512::from_bytes_be(encoded.data() + offset, 64);
    offset += 64;

    const std::span<const unsigned char, 4> encoded_count(
        encoded.data() + offset, 4);
    const std::uint32_t entry_count = read_u32_be(encoded_count);
    offset += 4;
    if (entry_count == 0) {
        return unexpected_error(ErrorCode::EmptyInput,
                                "construction_receipt:entry_count");
    }
    PURIFY_ASSIGN_OR_RETURN(
        const std::size_t expected_size,
        encoded_size_for_count(static_cast<std::size_t>(entry_count)),
        "construction_receipt:encoded_size");
    if (encoded.size() != expected_size) {
        return unexpected_error(ErrorCode::InvalidFixedSize,
                                "construction_receipt:encoded_size");
    }

    std::vector<ConstructionReceiptEntry> entries;
    entries.reserve(entry_count);
    for (std::uint32_t i = 0; i < entry_count; ++i) {
        ConstructionReceiptEntry entry;
        const std::span<const unsigned char,
                        AnchorEscrowCiphertext::kSerializedSize>
            encoded_ciphertext(encoded.data() + offset,
                               AnchorEscrowCiphertext::kSerializedSize);
        PURIFY_ASSIGN_OR_RETURN(entry.ciphertext,
                                parse_ciphertext(encoded_ciphertext),
                                "construction_receipt:ciphertext");
        offset += AnchorEscrowCiphertext::kSerializedSize;
        entries.push_back(std::move(entry));
    }
    assert(offset == encoded.size());
    return create(recovery_root, std::move(entries));
}

Result<ConstructionReceiptStatementDigest>
construction_receipt_statement_digest(
    const ConstructionReceiptPayload& payload,
    std::span<const ResolvedConstructionReceiptEntry> resolved_entries) {
    if (resolved_entries.size() != payload.entries().size()) {
        return unexpected_error(ErrorCode::InvalidFixedSize,
                                "construction_receipt:resolved_count");
    }

    Bytes statement = payload.serialize();
    statement.reserve(statement.size() +
                      resolved_entries.size() * (32 + 64 + 32));
    for (std::size_t i = 0; i < resolved_entries.size(); ++i) {
        const ResolvedConstructionReceiptEntry& resolved =
            resolved_entries[i];
        for (std::size_t prior = 0; prior < i; ++prior) {
            if (resolved_entries[prior].anchor_reference ==
                resolved.anchor_reference) {
                return unexpected_error(
                    ErrorCode::BindingMismatch,
                    "construction_receipt:duplicate_anchor_reference");
            }
        }
        PURIFY_RETURN_IF_ERROR(
            validate_public_root(resolved.anchor_root,
                                 "construction_receipt:anchor_root"),
            "construction_receipt:anchor_root");
        append_array(statement, resolved.anchor_reference);
        append_array(statement, resolved.anchor_root.to_bytes_be());
        append_array(statement, resolved.context_digest);
    }
    return kConstructionReceiptStatementHash.digest(statement);
}

Result<ConstructionReceiptAccumulator>
ConstructionReceiptAccumulator::create(
    purify_secp_context* secp_context) {
    PURIFY_ASSIGN_OR_RETURN(
        auto setup, RecoveryRootSetupAccumulator::create(secp_context),
        "construction_accumulation:setup_basis");
    PURIFY_ASSIGN_OR_RETURN(
        auto anchors, AnchorEscrowAccumulator::create(secp_context),
        "construction_accumulation:anchor_basis");
    return ConstructionReceiptAccumulator(std::move(setup),
                                          std::move(anchors));
}

Result<bppp::accumulation::PendingClaim>
ConstructionReceiptAccumulator::promote_setup_claim(
    const bppp::accumulation::PendingClaim& setup_claim) const {
    const auto& source = setup_.basis();
    const auto& target = anchors_.basis();
    if (setup_claim.basis_digest() != source.digest()) {
        return unexpected_error(
            ErrorCode::BindingMismatch,
            "construction_accumulation:setup_claim_basis");
    }
    if (source.dimension() >= target.dimension() ||
        !std::equal(source.points().begin(), source.points().end(),
                    target.points().begin())) {
        return unexpected_error(
            ErrorCode::InternalMismatch,
            "construction_accumulation:basis_prefix");
    }
    const auto& polynomial = setup_claim.polynomial();
    if (polynomial.empty() || polynomial.size() > 3) {
        return unexpected_error(
            ErrorCode::InvalidDimensions,
            "construction_accumulation:setup_claim_shape");
    }
    for (const auto& term : polynomial) {
        if (term.factors.size() >=
            std::numeric_limits<std::size_t>::digits) {
            return unexpected_error(
                ErrorCode::Overflow,
                "construction_accumulation:setup_claim_degree");
        }
        const std::size_t width =
            std::size_t{1} << term.factors.size();
        if (width > source.dimension() ||
            term.offset > source.dimension() - width) {
            return unexpected_error(
                ErrorCode::InvalidDimensions,
                "construction_accumulation:setup_claim_degree");
        }
    }
    return bppp::accumulation::PendingClaim(
        target.digest(), setup_claim.point(), polynomial);
}

}  // namespace purify::accountable
