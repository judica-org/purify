// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include <array>
#include <cstdint>
#include <span>

#include "purify/common.hpp"
#include "purify/numeric.hpp"

namespace purify::bppp::candidate {

using TranscriptBytes32 = std::array<unsigned char, 32>;
using TranscriptDigest = TranscriptBytes32;

/** One SHA-256 transcript state and its nonzero 255-bit scalar image. */
struct Sha256Challenge {
    TranscriptDigest digest{};
    FieldElement scalar;

    friend bool operator==(const Sha256Challenge&,
                           const Sha256Challenge&) = default;
};

/**
 * Versioned, typed SHA-256 transcript for native and constrained replay.
 *
 * The transcript starts from `SHA256("Purify/SHA256Transcript/v1")`.
 * Appended items collect in a pending byte string. A challenge hashes the
 * current state, the pending items, and a typed round marker, then replaces
 * the state with that digest and clears the pending string. This bounds every
 * constrained challenge to one SHA-256 compression chain over only the data
 * added since the previous challenge.
 */
class Sha256Transcript {
public:
    Sha256Transcript();

    void append_field(const TranscriptBytes32& value);
    void append_scalar(const FieldElement& value);
    [[nodiscard]] Status append_point(unsigned char prefix,
                                      const TranscriptBytes32& x);
    [[nodiscard]] Status append_point_pair(unsigned char parity,
                                           const TranscriptBytes32& first_x,
                                           const TranscriptBytes32& second_x);
    [[nodiscard]] Status append_bytes(std::span<const unsigned char> bytes);
    void append_u64(std::uint64_t value);

    /** Advance the transcript and derive one nonzero 255-bit scalar. */
    [[nodiscard]] Result<Sha256Challenge> challenge(std::uint64_t round);

    /**
     * Derive an opening scalar from a non-mutating transcript fork.
     *
     * The fork additionally binds the basis digest and a typed opening role.
     */
    [[nodiscard]] Result<Sha256Challenge>
    opening_base_scalar(const TranscriptDigest& basis_digest,
                        std::uint64_t role) const;

private:
    void append_header(std::uint32_t item_type, std::uint64_t auxiliary);
    void append_payload(std::span<const unsigned char> payload);

    TranscriptDigest state_{};
    Bytes pending_;
};

} // namespace purify::bppp::candidate
