// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include <array>
#include <optional>
#include <utility>
#include <vector>

#include "purify.hpp"
#include "purify/bppp.hpp"

namespace purify_test::scalar_escrow {

using purify::Bytes;
using purify::Expr;
using purify::FieldElement;
using purify::Result;
using purify::UInt256;
using purify::UInt512;
using PointPair = std::pair<purify::JacobianPoint, purify::JacobianPoint>;

struct Ciphertext {
    std::array<UInt512, 2> ephemeral;
    std::array<FieldElement, 2> masked;
};

struct Opening {
    const purify::SecretKey& payload;
    std::array<const purify::GeneratedKey*, 2> ephemeral;
};

Result<PointPair> decode_points(const UInt512& encoded);
Result<purify::GeneratedKey> key_from_pair(UInt256 first, UInt256 second);
Result<purify::GeneratedKey> recipient_from_scalar(const FieldElement& scalar);
Result<FieldElement> shared_pad(const purify::SecretKey& secret, const UInt512& peer);
Result<Ciphertext> encrypt(const UInt512& recipient, const Opening& opening);
Expr exceeds_bound(purify::Transcript& transcript, const std::vector<Expr>& bits, const UInt256& bound);
std::vector<Expr> ordinary_bits(purify::Transcript& transcript, const std::optional<UInt256>& value);
std::vector<Expr> signed_window_bits(purify::Transcript& transcript, const std::vector<Expr>& ordinary);
Expr canonical_payload(purify::Transcript& transcript, const std::vector<Expr>& bits, UInt256 limit);
Result<purify::CircuitMainResult> escrow_relation(purify::Transcript& transcript, const UInt512& recipient,
    const Ciphertext& ciphertext, const Opening* opening);
Result<purify::NativeBulletproofCircuit> public_circuit(const UInt512& recipient, const UInt512& payload,
    const Ciphertext& ciphertext);
Result<purify::BulletproofAssignmentData> assignment(const UInt512& recipient, const UInt512& payload,
    const Ciphertext& ciphertext, const Opening& opening);
Bytes ciphertext_bytes(const Ciphertext& ciphertext);
Bytes binding(const UInt512& recipient, const UInt512& payload, const Ciphertext& ciphertext, const Bytes& context);
Result<purify::bppp::PointBytes> secp_point(const FieldElement& scalar, purify_secp_context* secp);
Result<bool> verify(const UInt512& recipient, const UInt512& payload, const Ciphertext& ciphertext,
    const Bytes& context, const purify::bppp::ExperimentalCircuitZkNormArgProof& proof, purify_secp_context* secp);
Result<purify::GeneratedKey> decrypt_checked(const purify::SecretKey& recipient_secret, const UInt512& recipient,
    const UInt512& payload, const Ciphertext& ciphertext, const Bytes& context,
    const purify::bppp::ExperimentalCircuitZkNormArgProof& proof, purify_secp_context* secp);

} // namespace purify_test::scalar_escrow
