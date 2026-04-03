// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file puresign/codecs/legacy.cpp
 * @brief Wire-format codecs for the legacy PureSign surface.
 */

#include "purify/puresign/legacy.hpp"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <limits>
#include <optional>

#include "../detail/common.hpp"
#include "purify/secp_bridge.h"

namespace purify::puresign {

namespace {

Result<bool> nonce_proof_matches_nonce(const NonceProof& nonce_proof, purify_secp_context* secp_context) {
    XOnly32 xonly{};
    int parity = 0;
    PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context, "nonce_proof_matches_nonce:secp_context"),
                           "nonce_proof_matches_nonce:secp_context");
    if (purify_bip340_xonly_from_point(secp_context, nonce_proof.proof.commitment.data(), xonly.data(), &parity) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput, "nonce_proof_matches_nonce:invalid_commitment");
    }
    (void)parity;
    return xonly == nonce_proof.nonce.xonly;
}

}  // namespace

Bytes PublicKey::serialize() const {
    Bytes out;
    out.reserve(kSerializedSize);
    std::array<unsigned char, 64> packed = purify_pubkey.to_bytes_be();
    out.insert(out.end(), packed.begin(), packed.end());
    out.insert(out.end(), bip340_pubkey.begin(), bip340_pubkey.end());
    return out;
}

Result<PublicKey> PublicKey::deserialize(std::span<const unsigned char> serialized,
                                         purify_secp_context* secp_context) {
    if (serialized.size() != kSerializedSize) {
        return unexpected_error(ErrorCode::InvalidFixedSize, "PublicKey::deserialize:size");
    }
    UInt512 purify_pubkey = UInt512::from_bytes_be(serialized.data(), 64);
    PURIFY_RETURN_IF_ERROR(validate_public_key(purify_pubkey), "PublicKey::deserialize:validate_public_key");

    PublicKey out{};
    out.purify_pubkey = purify_pubkey;
    std::copy(serialized.begin() + 64, serialized.end(), out.bip340_pubkey.begin());
    PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context, "PublicKey::deserialize:secp_context"),
                           "PublicKey::deserialize:secp_context");
    if (purify_bip340_validate_xonly_pubkey(secp_context, out.bip340_pubkey.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput, "PublicKey::deserialize:bip340_validate_xonly_pubkey");
    }
    return out;
}

Bytes Nonce::serialize() const {
    return Bytes(xonly.begin(), xonly.end());
}

Result<Nonce> Nonce::deserialize(std::span<const unsigned char> serialized,
                                 purify_secp_context* secp_context) {
    if (serialized.size() != kSerializedSize) {
        return unexpected_error(ErrorCode::InvalidFixedSize, "Nonce::deserialize:size");
    }
    Nonce out{};
    std::copy(serialized.begin(), serialized.end(), out.xonly.begin());
    PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context, "Nonce::deserialize:secp_context"),
                           "Nonce::deserialize:secp_context");
    if (purify_bip340_validate_xonly_pubkey(secp_context, out.xonly.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput, "Nonce::deserialize:bip340_validate_xonly_pubkey");
    }
    return out;
}

Nonce Signature::nonce() const {
    Nonce out{};
    std::copy(bytes.begin(), bytes.begin() + 32, out.xonly.begin());
    return out;
}

Scalar32 Signature::s() const {
    Scalar32 out{};
    std::copy(bytes.begin() + 32, bytes.end(), out.begin());
    return out;
}

Bytes Signature::serialize() const {
    return Bytes(bytes.begin(), bytes.end());
}

Result<Signature> Signature::deserialize(std::span<const unsigned char> serialized,
                                         purify_secp_context* secp_context) {
    if (serialized.size() != kSerializedSize) {
        return unexpected_error(ErrorCode::InvalidFixedSize, "Signature::deserialize:size");
    }
    Signature out{};
    std::copy(serialized.begin(), serialized.end(), out.bytes.begin());
    PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context, "Signature::deserialize:secp_context"),
                           "Signature::deserialize:secp_context");
    if (purify_bip340_validate_signature(secp_context, out.bytes.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput, "Signature::deserialize:bip340_validate_signature");
    }
    return out;
}

Result<Bytes> NonceProof::serialize(purify_secp_context* secp_context) const {
    PURIFY_ASSIGN_OR_RETURN(auto match, nonce_proof_matches_nonce(*this, secp_context),
                            "NonceProof::serialize:nonce_proof_matches_nonce");
    if (!match) {
        return unexpected_error(ErrorCode::BindingMismatch, "NonceProof::serialize:nonce_mismatch");
    }
    PURIFY_ASSIGN_OR_RETURN(const auto& proof_bytes, proof.serialize(), "NonceProof::serialize:proof");
    if (proof_bytes.size() > static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max())) {
        return unexpected_error(ErrorCode::UnexpectedSize, "NonceProof::serialize:proof_size");
    }

    Bytes out;
    out.reserve(1 + 4 + 32 + proof_bytes.size());
    out.push_back(static_cast<unsigned char>(2));
    detail::append_u32_le(out, static_cast<std::uint32_t>(proof_bytes.size()));
    out.insert(out.end(), nonce.xonly.begin(), nonce.xonly.end());
    out.insert(out.end(), proof_bytes.begin(), proof_bytes.end());
    return out;
}

Result<NonceProof> NonceProof::deserialize(std::span<const unsigned char> serialized,
                                           purify_secp_context* secp_context) {
    if (serialized.size() < 37) {
        return unexpected_error(ErrorCode::InvalidFixedSize, "NonceProof::deserialize:header");
    }
    if (serialized[0] != 2) {
        return unexpected_error(ErrorCode::BackendRejectedInput, "NonceProof::deserialize:version");
    }
    std::optional<std::uint32_t> proof_size = detail::read_u32_le(serialized, 1);
    assert(proof_size.has_value() && "header length check should guarantee a u32 proof size");
    if (37 + *proof_size != serialized.size()) {
        return unexpected_error(ErrorCode::InvalidFixedSize, "NonceProof::deserialize:proof_size");
    }

    NonceProof out{};
    std::copy_n(serialized.begin() + 5, 32, out.nonce.xonly.begin());
    PURIFY_ASSIGN_OR_RETURN(auto proof_value,
                            ExperimentalBulletproofProof::deserialize(serialized.subspan(37, *proof_size)),
                            "NonceProof::deserialize:proof");
    out.proof = std::move(proof_value);
    PURIFY_ASSIGN_OR_RETURN(auto match, nonce_proof_matches_nonce(out, secp_context),
                            "NonceProof::deserialize:nonce_proof_matches_nonce");
    if (!match) {
        return unexpected_error(ErrorCode::BindingMismatch, "NonceProof::deserialize:nonce_mismatch");
    }
    return out;
}

Result<Bytes> ProvenSignature::serialize(purify_secp_context* secp_context) const {
    PURIFY_ASSIGN_OR_RETURN(const auto& nonce_proof_bytes, nonce_proof.serialize(secp_context),
                            "ProvenSignature::serialize:nonce_proof");
    if (nonce_proof_bytes.size() > static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max())) {
        return unexpected_error(ErrorCode::UnexpectedSize, "ProvenSignature::serialize:nonce_proof_size");
    }

    Bytes out;
    out.reserve(1 + 4 + nonce_proof_bytes.size() + 64);
    out.push_back(static_cast<unsigned char>(1));
    detail::append_u32_le(out, static_cast<std::uint32_t>(nonce_proof_bytes.size()));
    out.insert(out.end(), nonce_proof_bytes.begin(), nonce_proof_bytes.end());
    out.insert(out.end(), signature.bytes.begin(), signature.bytes.end());
    return out;
}

Result<ProvenSignature> ProvenSignature::deserialize(std::span<const unsigned char> serialized,
                                                     purify_secp_context* secp_context) {
    if (serialized.size() < 69) {
        return unexpected_error(ErrorCode::InvalidFixedSize, "ProvenSignature::deserialize:header");
    }
    if (serialized[0] != 1) {
        return unexpected_error(ErrorCode::BackendRejectedInput, "ProvenSignature::deserialize:version");
    }
    std::optional<std::uint32_t> nonce_proof_size = detail::read_u32_le(serialized, 1);
    assert(nonce_proof_size.has_value() && "header length check should guarantee a u32 nonce proof size");
    if (5 + *nonce_proof_size + 64 != serialized.size()) {
        return unexpected_error(ErrorCode::InvalidFixedSize, "ProvenSignature::deserialize:size");
    }

    PURIFY_ASSIGN_OR_RETURN(auto nonce_proof_value,
                            NonceProof::deserialize(serialized.subspan(5, *nonce_proof_size), secp_context),
                            "ProvenSignature::deserialize:nonce_proof");
    PURIFY_ASSIGN_OR_RETURN(auto signature_value,
                            Signature::deserialize(serialized.subspan(5 + *nonce_proof_size, 64), secp_context),
                            "ProvenSignature::deserialize:signature");
    return ProvenSignature{signature_value, nonce_proof_value};
}

}  // namespace purify::puresign
