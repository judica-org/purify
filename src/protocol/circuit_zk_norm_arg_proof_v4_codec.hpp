// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include <algorithm>
#include <cstddef>
#include <span>

#include "purify/detail/circuit_zk_norm_arg_proof_v4.hpp"

namespace purify::bppp::candidate {

inline void append_circuit_proof_body_v4(Bytes& out,
                                         const CircuitZkNormArgProofV4& proof) {
    const auto append = [&](const auto& field) {
        out.insert(out.end(), field.begin(), field.end());
    };
    append(proof.raw_commitment);
    append(proof.mask_commitment);
    append(proof.t2);
    append(proof.public_commitment_dlog_nonce);
    append(proof.public_commitment_dlog_response);
    append(proof.norm_proof);
}

/** Split a length-checked body into fields for subsequent canonical validation. */
template <std::size_t Size>
CircuitZkNormArgProofV4 read_circuit_proof_body_v4(
    std::span<const unsigned char, Size> body) {
    static_assert(Size != std::dynamic_extent &&
                  Size >= CircuitZkNormArgProofV4::kPrefixSize);
    CircuitZkNormArgProofV4 proof;
    std::span<const unsigned char> remaining = body;
    const auto read = [&](auto& field) {
        std::copy_n(remaining.begin(), field.size(), field.begin());
        remaining = remaining.subspan(field.size());
    };
    read(proof.raw_commitment);
    read(proof.mask_commitment);
    read(proof.t2);
    read(proof.public_commitment_dlog_nonce);
    read(proof.public_commitment_dlog_response);
    proof.norm_proof.assign(remaining.begin(), remaining.end());
    return proof;
}

} // namespace purify::bppp::candidate
