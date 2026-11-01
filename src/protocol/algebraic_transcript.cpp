// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "algebraic_transcript.hpp"

#include <algorithm>
#include <exception>
#include <string_view>
#include <utility>

namespace purify::bppp::candidate {
namespace {

constexpr std::size_t kRate = kPoseidonWidth - 1;

constexpr std::uint32_t kFieldItem = 0x4649'454c;       // FIEL
constexpr std::uint32_t kScalarItem = 0x5343'414c;      // SCAL
constexpr std::uint32_t kPointItem = 0x504f'494e;       // POIN
constexpr std::uint32_t kPointPairItem = 0x5041'4952;   // PAIR
constexpr std::uint32_t kBytesItem = 0x4259'5445;       // BYTE
constexpr std::uint32_t kU64Item = 0x5536'3420;         // U64<space>
constexpr std::uint32_t kChallengeItem = 0x4348'414c;   // CHAL
constexpr std::uint32_t kOpeningBaseItem = 0x4f42'4153; // OBAS

constexpr std::string_view kSuiteId = "Purify/PoseidonTranscript/v1";

CoordinateFieldElement from_integer(const UInt256& value) {
    auto parsed = CoordinateFieldElement::from_bytes_be(value.to_bytes_be());
    if (!parsed.has_value()) std::terminate();
    return std::move(*parsed);
}

CoordinateFieldElement header(std::uint32_t item_type, std::uint64_t auxiliary) {
    UInt256 value = UInt256::from_u64(item_type).shifted_left(64);
    const bool added =
        value.try_add_assign(UInt256::from_u64(auxiliary));
    if (!added) std::terminate();
    return from_integer(value);
}

CoordinateFieldElement suite_capacity() {
    static_assert(kSuiteId.size() <= CoordinateFieldElement::kSerializedSize);
    CoordinateFieldElement::Encoding encoded{};
    std::copy(kSuiteId.begin(), kSuiteId.end(),
              encoded.end() - static_cast<std::ptrdiff_t>(kSuiteId.size()));
    auto parsed = CoordinateFieldElement::from_bytes_be(encoded);
    if (!parsed.has_value()) std::terminate();
    return std::move(*parsed);
}

CoordinateFieldElement byte_word(std::span<const unsigned char> bytes) {
    if (bytes.size() > 31) std::terminate();
    CoordinateFieldElement::Encoding encoded{};
    std::copy(bytes.begin(), bytes.end(),
              encoded.end() - static_cast<std::ptrdiff_t>(bytes.size()));
    auto parsed = CoordinateFieldElement::from_bytes_be(encoded);
    if (!parsed.has_value()) std::terminate();
    return std::move(*parsed);
}

} // namespace

AlgebraicTranscript::AlgebraicTranscript()
    : state_{suite_capacity(), CoordinateFieldElement::zero(), CoordinateFieldElement::zero()} {}

void AlgebraicTranscript::absorb(const CoordinateFieldElement& value) {
    const std::size_t lane = rate_index_ + 1;
    state_[lane] = state_[lane] + value;
    ++rate_index_;
    if (rate_index_ == kRate) {
        state_ = poseidon_permute(state_);
        rate_index_ = 0;
    }
}

void AlgebraicTranscript::append_field(const CoordinateFieldElement& value) {
    absorb(header(kFieldItem, 0));
    absorb(value);
}

void AlgebraicTranscript::append_scalar(const FieldElement& value) {
    absorb(header(kScalarItem, 0));
    auto embedded = CoordinateFieldElement::from_bytes_be(value.to_bytes_be());
    if (!embedded.has_value()) std::terminate();
    absorb(*embedded);
}

Status AlgebraicTranscript::append_point(unsigned char prefix, const CoordinateFieldElement& x) {
    if (prefix != 0 && prefix != 2 && prefix != 3) {
        return unexpected_error(ErrorCode::UnsupportedSymbol, "poseidon_transcript:point_prefix");
    }
    if (prefix == 0 && !x.is_zero()) {
        return unexpected_error(ErrorCode::BindingMismatch, "poseidon_transcript:point_identity");
    }
    absorb(header(kPointItem, prefix));
    absorb(x);
    return {};
}

Status AlgebraicTranscript::append_point_pair(unsigned char parity,
                                              const CoordinateFieldElement& first_x,
                                              const CoordinateFieldElement& second_x) {
    if (parity > 3) {
        return unexpected_error(ErrorCode::RangeViolation, "poseidon_transcript:pair_parity");
    }
    absorb(header(kPointPairItem, parity));
    absorb(first_x);
    absorb(second_x);
    return {};
}

Status AlgebraicTranscript::append_bytes(std::span<const unsigned char> bytes) {
    if (!size_fits_u64(bytes.size())) {
        return unexpected_error(ErrorCode::Overflow, "poseidon_transcript:byte_length");
    }
    absorb(header(kBytesItem, static_cast<std::uint64_t>(bytes.size())));
    for (std::size_t offset = 0; offset < bytes.size(); offset += 31) {
        absorb(byte_word(bytes.subspan(offset, std::min<std::size_t>(31, bytes.size() - offset))));
    }
    return {};
}

void AlgebraicTranscript::append_u64(std::uint64_t value) { absorb(header(kU64Item, value)); }

std::array<CoordinateFieldElement, 2> AlgebraicTranscript::challenge(std::uint64_t round) const {
    AlgebraicTranscript challenge = *this;
    challenge.absorb(header(kChallengeItem, round));
    challenge.absorb(CoordinateFieldElement::one());
    while (challenge.rate_index_ != 0) {
        challenge.absorb(CoordinateFieldElement::zero());
    }
    return {challenge.state_[1], challenge.state_[2]};
}

std::array<CoordinateFieldElement, 2>
AlgebraicTranscript::opening_base_scalar(const TranscriptDigest& basis_digest,
                                         std::uint64_t role) const {
    AlgebraicTranscript challenge = *this;
    const Status appended =
        challenge.append_bytes(basis_digest);
    if (!appended.has_value()) std::terminate();
    challenge.absorb(header(kOpeningBaseItem, role));
    challenge.absorb(CoordinateFieldElement::one());
    while (challenge.rate_index_ != 0) {
        challenge.absorb(CoordinateFieldElement::zero());
    }
    return {challenge.state_[1], challenge.state_[2]};
}

Result<FieldElement> select_nonzero_scalar(const std::array<CoordinateFieldElement, 2>& lanes) {
    for (const auto& lane : lanes) {
        auto candidate = FieldElement::try_from_bytes32(lane.bytes());
        if (candidate && !candidate->is_zero()) return candidate;
    }
    return unexpected_error(ErrorCode::RangeViolation, "poseidon_transcript:challenge_exhausted");
}

} // namespace purify::bppp::candidate
