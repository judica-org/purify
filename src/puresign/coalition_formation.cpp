// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "purify/puresign/coalition_formation.hpp"

#include <algorithm>
#include <array>
#include <limits>

#include "purify/curve.hpp"

namespace purify::accountable {
namespace {

std::array<unsigned char, 4> encode_u32_le(std::uint32_t value) {
    return {
        static_cast<unsigned char>(value & 0xffU),
        static_cast<unsigned char>((value >> 8) & 0xffU),
        static_cast<unsigned char>((value >> 16) & 0xffU),
        static_cast<unsigned char>((value >> 24) & 0xffU),
    };
}

template <std::size_t Size>
bool is_zero(const std::array<unsigned char, Size>& value) {
    return std::all_of(value.begin(), value.end(),
                       [](unsigned char byte) { return byte == 0; });
}

bool is_null_outpoint(const BitcoinOutpoint& outpoint) {
    return outpoint.output_index ==
               std::numeric_limits<std::uint32_t>::max() &&
           is_zero(outpoint.transaction_id);
}

} // namespace

Result<CoalitionFormation> CoalitionFormation::create(
    CoalitionFormationInput input) {
    if (is_zero(input.genesis_hash)) {
        return unexpected_error(
            ErrorCode::RangeViolation,
            "coalition_formation:zero_genesis_hash");
    }
    if (is_zero(input.deployment_id)) {
        return unexpected_error(
            ErrorCode::RangeViolation,
            "coalition_formation:zero_deployment_id");
    }
    if (is_zero(input.manifest_digest)) {
        return unexpected_error(
            ErrorCode::RangeViolation,
            "coalition_formation:zero_manifest_digest");
    }
    if (is_null_outpoint(input.permit)) {
        return unexpected_error(
            ErrorCode::RangeViolation,
            "coalition_formation:null_permit");
    }

    static const TaggedHash permit_hash(
        "Purify/Accountable/CoalitionPermit/v1");
    static const TaggedHash formation_hash(
        "Purify/Accountable/CoalitionFormation/v1");
    const auto output_index = encode_u32_le(input.permit.output_index);
    auto permit_id = permit_hash.digest_many<4>({
        input.genesis_hash,
        input.deployment_id,
        input.permit.transaction_id,
        output_index,
    });
    auto core_digest = formation_hash.digest_many<2>({
        permit_id,
        input.manifest_digest,
    });
    return CoalitionFormation(input, permit_id, core_digest);
}

} // namespace purify::accountable
