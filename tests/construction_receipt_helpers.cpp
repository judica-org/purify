// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "construction_receipt_helpers.hpp"

#include <algorithm>
#include <cstdint>
#include <limits>

namespace purify_test::construction_receipt {

Result<PreparedInputs> prepare_inputs(const PointBytes& coalition, const UInt512& recipient,
    const Bytes& context, std::span<const UInt512> expected_roots, const Proof& setup_proof,
    std::span<const EncryptionPacket> packets, purify_secp_context* secp) {
    if (secp == nullptr || expected_roots.empty() || expected_roots.size() != packets.size()) {
        return purify::unexpected_error(purify::ErrorCode::SizeMismatch, "receipt:coverage");
    }
    // The caller supplies the authenticated, ordered registry manifest. Packet
    // arrival order is immaterial; no proof may replace or duplicate a root.
    std::vector<const EncryptionPacket*> ordered;
    ordered.reserve(expected_roots.size());
    for (auto it = expected_roots.begin(); it != expected_roots.end(); ++it) {
        if (std::find(expected_roots.begin(), it, *it) != it) {
            return purify::unexpected_error(purify::ErrorCode::BindingMismatch, "receipt:duplicate_root");
        }
        const auto found = std::find_if(packets.begin(), packets.end(), [&](const auto& packet) {
            return packet.encrypted.root == *it;
        });
        if (found == packets.end()) {
            return purify::unexpected_error(purify::ErrorCode::BindingMismatch, "receipt:missing_root");
        }
        ordered.push_back(&*found);
    }
    PURIFY_ASSIGN_OR_RETURN(const auto& setup_ok,
        canonical_root::verify_setup(coalition, recipient, context, setup_proof, secp), "receipt:setup");
    if (!setup_ok) {
        return purify::unexpected_error(purify::ErrorCode::BindingMismatch, "receipt:setup_proof");
    }
    PreparedInputs out{{coalition, recipient, context, {}}, setup_proof, {}};
    out.statement.roots.reserve(ordered.size());
    out.encryption_proofs.reserve(ordered.size());
    for (const auto* packet : ordered) {
        const auto& root = packet->encrypted;
        PURIFY_ASSIGN_OR_RETURN(const auto& accepted,
            scalar_escrow::verify(recipient, root.root, root.ciphertext, context, packet->proof, secp),
            "receipt:encryption");
        if (!accepted) {
            return purify::unexpected_error(purify::ErrorCode::BindingMismatch, "receipt:encryption_proof");
        }
        out.statement.roots.push_back(root);
        out.encryption_proofs.push_back(packet->proof);
    }
    return out;
}

Result<Bytes> statement_bytes(const Statement& statement) {
    if (statement.context.size() > std::numeric_limits<std::uint32_t>::max() ||
        statement.roots.size() > std::numeric_limits<std::uint32_t>::max()) {
        return purify::unexpected_error(purify::ErrorCode::SizeMismatch, "receipt:encoding_size");
    }
    Bytes out{1};
    const auto append = [&](std::span<const unsigned char> bytes) {
        out.insert(out.end(), bytes.begin(), bytes.end());
    };
    const auto append_u32 = [&](std::uint32_t value) {
        for (unsigned int shift : {24U, 16U, 8U, 0U}) {
            out.push_back(static_cast<unsigned char>(value >> shift));
        }
    };
    append(statement.coalition);
    append(statement.recipient.to_bytes_be());
    append_u32(static_cast<std::uint32_t>(statement.context.size()));
    append(statement.context);
    append_u32(static_cast<std::uint32_t>(statement.roots.size()));
    for (const auto& root : statement.roots) {
        append(root.root.to_bytes_be());
        append(scalar_escrow::ciphertext_bytes(root.ciphertext));
    }
    return out;
}

std::size_t proof_bytes(const Proof& proof) {
    return proof.a_commitment.size() + proof.s_commitment.size() + proof.t2.size() + proof.proof.size();
}

} // namespace purify_test::construction_receipt
