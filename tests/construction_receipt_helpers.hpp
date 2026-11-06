// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include <span>
#include <vector>

#include "canonical_recovery_root_helpers.hpp"
#include "companion_scalar_escrow_helpers.hpp"

namespace purify_test::construction_receipt {

using purify::Bytes;
using purify::Result;
using purify::UInt512;
using Proof = purify::bppp::ExperimentalCircuitZkNormArgProof;
using PointBytes = purify::bppp::PointBytes;

struct EncryptedRoot {
    UInt512 root;
    scalar_escrow::Ciphertext ciphertext;
};

// Each owner publishes this packet out of band. Its proof is independent of
// the eventual receipt's other participants and their arrival order.
struct EncryptionPacket {
    EncryptedRoot encrypted;
    Proof proof;
};

struct Statement {
    PointBytes coalition;
    UInt512 recipient;
    Bytes context;
    std::vector<EncryptedRoot> roots;
};

// Inputs for a future public outer prover, not a compressed proof or an
// accepted receipt. All fields are public, including every child proof.
struct PreparedInputs {
    Statement statement;
    Proof setup_proof;
    std::vector<Proof> encryption_proofs;
};

Result<PreparedInputs> prepare_inputs(const PointBytes& coalition, const UInt512& recipient,
    const Bytes& context, std::span<const UInt512> expected_roots, const Proof& setup_proof,
    std::span<const EncryptionPacket> packets, purify_secp_context* secp);

// A test-local full-statement encoding. Full public roots are deliberately
// counted here; an application may authenticate them through registry refs.
Result<Bytes> statement_bytes(const Statement& statement);

std::size_t proof_bytes(const Proof& proof);

} // namespace purify_test::construction_receipt
