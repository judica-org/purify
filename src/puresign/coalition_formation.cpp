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

bool is_null_outpoint(const BitcoinOutpoint& outpoint) {
    return outpoint.output_index ==
               std::numeric_limits<std::uint32_t>::max() &&
           std::all_of(outpoint.transaction_id.begin(),
                       outpoint.transaction_id.end(),
                       [](unsigned char byte) { return byte == 0; });
}

} // namespace

Result<CoalitionFormation> CoalitionFormation::create(
    BitcoinGenesisHash genesis_hash,
    CoalitionDeploymentId deployment_id,
    BitcoinOutpoint permit,
    CoalitionManifestDigest manifest_digest) {
    if (is_null_outpoint(permit)) {
        return unexpected_error(
            ErrorCode::RangeViolation,
            "coalition_formation:null_permit");
    }

    static const TaggedHash hash(
        "Purify/Accountable/CoalitionFormation/v1");
    const auto output_index = encode_u32_le(permit.output_index);
    auto id = hash.digest_many<5>({
        genesis_hash,
        deployment_id,
        permit.transaction_id,
        output_index,
        manifest_digest,
    });
    return CoalitionFormation(
        genesis_hash, deployment_id, permit, manifest_digest, id);
}

} // namespace purify::accountable
