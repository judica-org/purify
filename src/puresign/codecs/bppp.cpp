// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file puresign/codecs/bppp.cpp
 * @brief Wire-format codecs for the BPPP-backed PureSign++ surface.
 */

#include "purify/puresign/bppp.hpp"

#include <algorithm>
#include <cassert>

#include "../detail/common.hpp"
#include "purify/secp_bridge.h"

namespace purify::puresign_plusplus {

namespace {

Result<bool> nonce_proof_matches_nonce(const NonceProof& nonce_proof, purify_secp_context* secp_context) {
    XOnly32 xonly{};
    int parity = 0;
    PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context, "nonce_proof_matches_nonce:secp_context"),
                           "nonce_proof_matches_nonce:secp_context");
    if (purify_bip340_xonly_from_point(secp_context, nonce_proof.commitment_point.data(), xonly.data(), &parity) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput,
                                "nonce_proof_matches_nonce:invalid_commitment_point");
    }
    (void)parity;
    return xonly == nonce_proof.nonce.xonly;
}

Status validate_circuit_proof_encoding(
    const bppp::ExperimentalCircuitZkNormArgProof& proof,
    purify_secp_context* secp_context) {
    PURIFY_RETURN_IF_ERROR(
        require_secp_context(secp_context,
                             "NonceProof:circuit_proof:secp_context"),
        "NonceProof:circuit_proof:secp_context");
    if (proof.proof.size() != NonceProof::kInnerProofSize) {
        return unexpected_error(ErrorCode::InvalidFixedSize,
                                "NonceProof:circuit_proof:proof_size");
    }
    for (const auto* point : {&proof.a_commitment, &proof.s_commitment}) {
        XOnly32 xonly{};
        int parity = 0;
        if (purify_bip340_xonly_from_point(
                secp_context, point->data(), xonly.data(), &parity) == 0) {
            return unexpected_error(ErrorCode::BackendRejectedInput,
                                    "NonceProof:circuit_proof:point");
        }
    }
    PURIFY_ASSIGN_OR_RETURN(const auto& t2,
                            FieldElement::try_from_bytes32(proof.t2),
                            "NonceProof:circuit_proof:t2");
    (void)t2;
    if (purify_bip340_validate_xonly_pubkey(
            secp_context, proof.public_commitment_dlog_nonce.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput,
                                "NonceProof:circuit_proof:dlog_nonce");
    }
    PURIFY_ASSIGN_OR_RETURN(
        const auto& dlog_response,
        FieldElement::try_from_bytes32(
            proof.public_commitment_dlog_response),
        "NonceProof:circuit_proof:dlog_response");
    if (dlog_response.is_zero()) {
        return unexpected_error(ErrorCode::BackendRejectedInput,
                                "NonceProof:circuit_proof:dlog_response");
    }
    return {};
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
    PublicKey out{};
    out.purify_pubkey = UInt512::from_bytes_be(serialized.data(), 64);
    PURIFY_RETURN_IF_ERROR(validate_public_key(out.purify_pubkey), "PublicKey::deserialize:validate_public_key");
    std::copy(serialized.begin() + 64, serialized.end(), out.bip340_pubkey.begin());
    PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context, "PublicKey::deserialize:secp_context"),
                           "PublicKey::deserialize:secp_context");
    if (purify_bip340_validate_xonly_pubkey(secp_context, out.bip340_pubkey.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput,
                                "PublicKey::deserialize:bip340_validate_xonly_pubkey");
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
    PURIFY_RETURN_IF_ERROR(
        validate_circuit_proof_encoding(proof, secp_context),
        "NonceProof::serialize:circuit_proof");

    Bytes out;
    out.reserve(kSerializedSize);
    out.push_back(kSerializationVersion);
    out.insert(out.end(), nonce.xonly.begin(), nonce.xonly.end());
    out.insert(out.end(), commitment_point.begin(), commitment_point.end());
    out.insert(out.end(), proof.a_commitment.begin(), proof.a_commitment.end());
    out.insert(out.end(), proof.s_commitment.begin(), proof.s_commitment.end());
    out.insert(out.end(), proof.t2.begin(), proof.t2.end());
    out.insert(out.end(), proof.public_commitment_dlog_nonce.begin(),
               proof.public_commitment_dlog_nonce.end());
    out.insert(out.end(), proof.public_commitment_dlog_response.begin(),
               proof.public_commitment_dlog_response.end());
    out.insert(out.end(), proof.proof.begin(), proof.proof.end());
    assert(out.size() == kSerializedSize);
    return out;
}

Result<NonceProof> NonceProof::deserialize(std::span<const unsigned char> serialized,
                                           purify_secp_context* secp_context) {
    constexpr std::size_t kHeaderSize =
        1 + 32 + 33 + 33 + 33 + 32 + 32 + 32;
    static_assert(kHeaderSize + kInnerProofSize == kSerializedSize);
    if (serialized.size() != kSerializedSize) {
        return unexpected_error(ErrorCode::InvalidFixedSize, "NonceProof::deserialize:header");
    }
    if (serialized[0] != kSerializationVersion) {
        return unexpected_error(ErrorCode::BackendRejectedInput, "NonceProof::deserialize:version");
    }
    NonceProof out{};
    std::copy_n(serialized.begin() + 1, 32, out.nonce.xonly.begin());
    PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context, "NonceProof::deserialize:secp_context"),
                           "NonceProof::deserialize:secp_context");
    if (purify_bip340_validate_xonly_pubkey(secp_context, out.nonce.xonly.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput, "NonceProof::deserialize:nonce");
    }
    std::copy_n(serialized.begin() + 33, 33, out.commitment_point.begin());
    std::copy_n(serialized.begin() + 66, 33, out.proof.a_commitment.begin());
    std::copy_n(serialized.begin() + 99, 33, out.proof.s_commitment.begin());
    std::copy_n(serialized.begin() + 132, 32, out.proof.t2.begin());
    std::copy_n(serialized.begin() + 164, 32,
                out.proof.public_commitment_dlog_nonce.begin());
    std::copy_n(serialized.begin() + 196, 32,
                out.proof.public_commitment_dlog_response.begin());
    out.proof.proof.assign(serialized.begin() + kHeaderSize,
                           serialized.end());
    PURIFY_RETURN_IF_ERROR(
        validate_circuit_proof_encoding(out.proof, secp_context),
        "NonceProof::deserialize:circuit_proof");

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
    Bytes out;
    out.reserve(kSerializedSize);
    out.push_back(kSerializationVersion);
    out.insert(out.end(), nonce_proof_bytes.begin(), nonce_proof_bytes.end());
    out.insert(out.end(), signature.bytes.begin(), signature.bytes.end());
    assert(out.size() == kSerializedSize);
    return out;
}

Result<ProvenSignature> ProvenSignature::deserialize(std::span<const unsigned char> serialized,
                                                     purify_secp_context* secp_context) {
    if (serialized.size() != kSerializedSize) {
        return unexpected_error(ErrorCode::InvalidFixedSize, "ProvenSignature::deserialize:header");
    }
    if (serialized[0] != kSerializationVersion) {
        return unexpected_error(ErrorCode::BackendRejectedInput, "ProvenSignature::deserialize:version");
    }
    PURIFY_ASSIGN_OR_RETURN(auto nonce_proof_value,
                            NonceProof::deserialize(
                                serialized.subspan(1, NonceProof::kSerializedSize),
                                secp_context),
                            "ProvenSignature::deserialize:nonce_proof");
    PURIFY_ASSIGN_OR_RETURN(auto signature_value,
                            Signature::deserialize(
                                serialized.subspan(1 + NonceProof::kSerializedSize,
                                                   Signature::kSerializedSize),
                                secp_context),
                            "ProvenSignature::deserialize:signature");
    return ProvenSignature{signature_value, nonce_proof_value};
}

}  // namespace purify::puresign_plusplus
