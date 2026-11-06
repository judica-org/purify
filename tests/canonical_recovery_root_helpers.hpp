// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include <optional>
#include <utility>
#include <vector>

#include "purify.hpp"
#include "purify/bppp.hpp"

namespace purify_test::canonical_root {

using purify::Bytes;
using purify::Expr;
using purify::FieldElement;
using purify::Result;
using purify::UInt256;
using purify::UInt512;
using PointPair = std::pair<purify::JacobianPoint, purify::JacobianPoint>;
using PointBytes = purify::bppp::PointBytes;

UInt256 half_secp_order();
UInt256 magnitude(const FieldElement& scalar);
Result<PointBytes> secp_point(const FieldElement& value, purify_secp_context* context);
Result<PointPair> decode_root(const UInt512& encoded);
Result<purify::GeneratedKey> root_from_scalar(const FieldElement& scalar);
std::vector<Expr> ordinary_bits(purify::Transcript& transcript, const std::optional<UInt256>& value);
Expr exceeds_bound(purify::Transcript& transcript, const std::vector<Expr>& bits, const UInt256& bound);
std::vector<Expr> signed_window_bits(purify::Transcript& transcript, const std::vector<Expr>& ordinary);
Result<purify::CircuitMainResult> setup_relation(purify::Transcript& transcript,
    const std::optional<FieldElement>& scalar = std::nullopt);
Result<purify::NativeBulletproofCircuit> public_setup_circuit(const UInt512& root);
Result<purify::BulletproofAssignmentData> setup_assignment(const UInt512& root, const FieldElement& scalar);
Bytes binding(const PointBytes& key, const UInt512& root, const Bytes& context);
Result<bool> verify_setup(const PointBytes& key, const UInt512& root, const Bytes& context,
    const purify::bppp::ExperimentalCircuitZkNormArgProof& proof, purify_secp_context* secp);
Result<purify::GeneratedKey> recover_root(const FieldElement& scalar, const PointBytes& key,
    const UInt512& expected_root, purify_secp_context* secp);
Result<FieldElement> leaf_output(const purify::SecretKey& secret, const UInt512& peer);

} // namespace purify_test::canonical_root
