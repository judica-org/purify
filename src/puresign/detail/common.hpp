// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

#include "purify/puresign/legacy.hpp"

namespace purify::detail {

inline Bytes copy_bytes(std::span<const unsigned char> input) {
    return Bytes(input.begin(), input.end());
}

inline Bytes tagged_eval_input(std::string_view tag, std::span<const unsigned char> input) {
    Bytes out;
    out.reserve(tag.size() + input.size());
    out.insert(out.end(), tag.begin(), tag.end());
    out.insert(out.end(), input.begin(), input.end());
    return out;
}

inline void append_u32_le(Bytes& out, std::uint32_t value) {
    for (int i = 0; i < 4; ++i) {
        out.push_back(static_cast<unsigned char>((value >> (8 * i)) & 0xffU));
    }
}

inline std::optional<std::uint32_t> read_u32_le(std::span<const unsigned char> bytes,
                                                std::size_t offset) {
    std::uint32_t value = 0;
    if (offset + 4 > bytes.size()) {
        return std::nullopt;
    }
    for (int i = 0; i < 4; ++i) {
        value |= static_cast<std::uint32_t>(bytes[offset + i]) << (8 * i);
    }
    return value;
}

inline bool is_power_of_two_size(std::size_t value) {
    return value != 0 && (value & (value - 1)) == 0;
}

inline std::size_t circuit_n_gates(const NativeBulletproofCircuit& circuit) {
    return circuit.n_gates;
}

inline std::size_t circuit_n_gates(const NativeBulletproofCircuit::PackedWithSlack& circuit) {
    return circuit.n_gates();
}

inline std::size_t circuit_n_commitments(const NativeBulletproofCircuit& circuit) {
    return circuit.n_commitments;
}

inline std::size_t circuit_n_commitments(const NativeBulletproofCircuit::PackedWithSlack& circuit) {
    return circuit.n_commitments();
}

template <typename CircuitLike>
Status validate_proof_cache_circuit(const CircuitLike& circuit, const char* context) {
    if (!circuit.has_valid_shape()) {
        return unexpected_error(ErrorCode::InvalidDimensions, context);
    }
    if (!is_power_of_two_size(circuit_n_gates(circuit))) {
        return unexpected_error(ErrorCode::InvalidDimensions, context);
    }
    if (circuit_n_commitments(circuit) != 1) {
        return unexpected_error(ErrorCode::InvalidDimensions, context);
    }
    return {};
}

template <typename CacheLike>
inline Status validate_message_proof_cache(const CacheLike& cache,
                                           std::string_view nonce_tag) {
    if (cache.eval_input != tagged_eval_input(nonce_tag, cache.message)) {
        return unexpected_error(ErrorCode::BindingMismatch, "validate_message_proof_cache:eval_input");
    }
    return {};
}

template <typename CacheLike>
inline Status validate_topic_proof_cache(const CacheLike& cache,
                                         std::string_view nonce_tag) {
    if (cache.topic.empty()) {
        return unexpected_error(ErrorCode::EmptyInput, "validate_topic_proof_cache:empty_topic");
    }
    if (cache.eval_input != tagged_eval_input(nonce_tag, cache.topic)) {
        return unexpected_error(ErrorCode::BindingMismatch, "validate_topic_proof_cache:eval_input");
    }
    return {};
}

}  // namespace purify::detail
