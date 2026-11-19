// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "sha256_transcript.hpp"

#include <algorithm>
#include <array>
#include <exception>
#include <string_view>
#include <utility>

#include "purify/secp_bridge.h"

namespace purify::bppp::candidate {
namespace {

constexpr std::uint32_t kFieldItem = 0x4649'454c;       // FIEL
constexpr std::uint32_t kScalarItem = 0x5343'414c;      // SCAL
constexpr std::uint32_t kPointItem = 0x504f'494e;       // POIN
constexpr std::uint32_t kPointPairItem = 0x5041'4952;   // PAIR
constexpr std::uint32_t kBytesItem = 0x4259'5445;       // BYTE
constexpr std::uint32_t kU64Item = 0x5536'3420;         // U64<space>
constexpr std::uint32_t kChallengeItem = 0x4348'414c;   // CHAL
constexpr std::uint32_t kOpeningBaseItem = 0x4f42'4153; // OBAS

constexpr std::string_view kSuiteId = "Purify/SHA256Transcript/v1";
constexpr std::size_t kHeaderSize = 12;

std::array<unsigned char, kHeaderSize> header(std::uint32_t item_type,
                                               std::uint64_t auxiliary) {
    std::array<unsigned char, kHeaderSize> out{};
    for (std::size_t index = 0; index < 4; ++index) {
        out[index] = static_cast<unsigned char>(item_type >> (24 - 8 * index));
    }
    for (std::size_t index = 0; index < 8; ++index) {
        out[4 + index] =
            static_cast<unsigned char>(auxiliary >> (56 - 8 * index));
    }
    return out;
}

TranscriptDigest sha256_many(
    std::span<const std::span<const unsigned char>> segments) {
    TranscriptDigest out{};
    std::array<const unsigned char*, 5> items{};
    std::array<std::size_t, 5> lengths{};
    if (segments.size() > items.size()) std::terminate();
    for (std::size_t index = 0; index < segments.size(); ++index) {
        items[index] = segments[index].empty() ? nullptr : segments[index].data();
        lengths[index] = segments[index].size();
    }
    if (purify_sha256_many(out.data(), items.data(), lengths.data(),
                           segments.size()) == 0) {
        std::terminate();
    }
    return out;
}

Result<Sha256Challenge> make_challenge(const TranscriptDigest& digest) {
    auto scalar_bytes = digest;
    scalar_bytes[0] &= 0x7f;
    PURIFY_ASSIGN_OR_RETURN(auto scalar,
                            FieldElement::try_from_bytes32(scalar_bytes),
                            "sha256_transcript:scalar");
    if (scalar.is_zero()) {
        return unexpected_error(ErrorCode::RangeViolation,
                                "sha256_transcript:zero_challenge");
    }
    return Sha256Challenge{digest, std::move(scalar)};
}

} // namespace

Sha256Transcript::Sha256Transcript() {
    purify_sha256(state_.data(),
                  reinterpret_cast<const unsigned char*>(kSuiteId.data()),
                  kSuiteId.size());
}

void Sha256Transcript::append_header(std::uint32_t item_type,
                                     std::uint64_t auxiliary) {
    const auto encoded = header(item_type, auxiliary);
    append_payload(encoded);
}

void Sha256Transcript::append_payload(
    std::span<const unsigned char> payload) {
    best_effort_reserve_add(pending_, pending_.size(), payload.size());
    pending_.insert(pending_.end(), payload.begin(), payload.end());
}

void Sha256Transcript::append_field(const TranscriptBytes32& value) {
    append_header(kFieldItem, 0);
    append_payload(value);
}

void Sha256Transcript::append_scalar(const FieldElement& value) {
    append_header(kScalarItem, 0);
    const auto encoded = value.to_bytes_be();
    append_payload(encoded);
}

Status Sha256Transcript::append_point(unsigned char prefix,
                                      const TranscriptBytes32& x) {
    if (prefix != 0 && prefix != 2 && prefix != 3) {
        return unexpected_error(ErrorCode::UnsupportedSymbol,
                                "sha256_transcript:point_prefix");
    }
    if (prefix == 0 &&
        std::any_of(x.begin(), x.end(), [](unsigned char byte) {
            return byte != 0;
        })) {
        return unexpected_error(ErrorCode::BindingMismatch,
                                "sha256_transcript:point_identity");
    }
    append_header(kPointItem, prefix);
    append_payload(x);
    return {};
}

Status Sha256Transcript::append_point_pair(
    unsigned char parity, const TranscriptBytes32& first_x,
    const TranscriptBytes32& second_x) {
    if (parity > 3) {
        return unexpected_error(ErrorCode::RangeViolation,
                                "sha256_transcript:pair_parity");
    }
    append_header(kPointPairItem, parity);
    append_payload(first_x);
    append_payload(second_x);
    return {};
}

Status Sha256Transcript::append_bytes(std::span<const unsigned char> bytes) {
    if (!size_fits_u64(bytes.size())) {
        return unexpected_error(ErrorCode::Overflow,
                                "sha256_transcript:byte_length");
    }
    append_header(kBytesItem, static_cast<std::uint64_t>(bytes.size()));
    append_payload(bytes);
    return {};
}

void Sha256Transcript::append_u64(std::uint64_t value) {
    append_header(kU64Item, value);
}

Result<Sha256Challenge> Sha256Transcript::challenge(std::uint64_t round) {
    const auto challenge_header = header(kChallengeItem, round);
    const std::array<std::span<const unsigned char>, 3> segments{
        state_, pending_, challenge_header};
    const auto digest = sha256_many(segments);
    PURIFY_ASSIGN_OR_RETURN(auto challenge, make_challenge(digest),
                            "sha256_transcript:challenge");
    state_ = digest;
    pending_.clear();
    return challenge;
}

Result<Sha256Challenge> Sha256Transcript::opening_base_scalar(
    const TranscriptDigest& basis_digest, std::uint64_t role) const {
    const auto bytes_header = header(kBytesItem, basis_digest.size());
    const auto opening_header = header(kOpeningBaseItem, role);
    const std::array<std::span<const unsigned char>, 5> segments{
        state_, pending_, bytes_header, basis_digest, opening_header};
    return make_challenge(sha256_many(segments));
}

} // namespace purify::bppp::candidate
