// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file puresign/bppp.cpp
 * @brief The experimental BPPP backend of PureSign: its proof operations and wire formats.
 *
 * Everything that does not depend on the proof system lives in `core.cpp` and
 * `detail/core_impl.hpp`.
 */

#include "purify/puresign/bppp.hpp"

#include <algorithm>
#include <array>
#include <cassert>

#include "detail/core_impl.hpp"
#include "purify/secp_bridge.h"

namespace purify::puresign_plusplus {

struct Backend::Ops {
    static constexpr std::string_view kMessageProofTag = "PureSign/BPPP/Proof/Message/V1";
    static constexpr std::string_view kTopicProofTag = "PureSign/BPPP/Proof/Topic/V1";

    static Result<NativeBulletproofCircuit> instantiate(const NativeBulletproofCircuitTemplate& circuit_template,
                                                        const UInt512& purify_pubkey) {
        return circuit_template.instantiate(purify_pubkey);
    }

    /** The nonce point is public, so the nonce scalar is committed with a zero blind. */
    static Result<NonceProof> prove(const NativeBulletproofCircuit& circuit,
                                    const BulletproofAssignmentData& assignment, const Scalar32& prover_seed,
                                    const Nonce& nonce, std::span<const unsigned char> statement_binding,
                                    purify_secp_context* secp_context, CircuitCache* circuit_cache) {
        Scalar32 blind{};
        PURIFY_ASSIGN_OR_RETURN(auto commitment_point,
                                bppp::pedersen_commit_char(blind, bppp::scalar_bytes(assignment.commitments.front()),
                                                           secp_context, bppp::base_generator(secp_context),
                                                           bppp::base_generator(secp_context)));
        std::array<bppp::PointBytes, 1> public_commitments{commitment_point};
        PURIFY_ASSIGN_OR_RETURN(auto proof, bppp::prove_experimental_circuit_zk_norm_arg_with_public_commitments(
                                                circuit, assignment, prover_seed, public_commitments, secp_context,
                                                statement_binding, circuit_cache));

        NonceProof out{};
        out.nonce = nonce;
        out.commitment_point = commitment_point;
        out.proof = std::move(proof);
        return out;
    }

    static Result<bool> verify(const NativeBulletproofCircuit& circuit, const NonceProof& nonce_proof,
                               std::span<const unsigned char> statement_binding,
                               purify_secp_context* secp_context, CircuitCache* circuit_cache) {
        std::array<bppp::PointBytes, 1> public_commitments{nonce_proof.commitment_point};
        return bppp::verify_experimental_circuit_zk_norm_arg_with_public_commitments(
            circuit, nonce_proof.proof, public_commitments, secp_context, statement_binding, circuit_cache);
    }

    static Result<bool> matches_nonce(const NonceProof& nonce_proof, purify_secp_context* secp_context) {
        return puresign_core::detail::nonce_matches_point(nonce_proof.nonce, nonce_proof.commitment_point,
                                                          secp_context);
    }

    static Result<Scalar32> raw_scalar(const PreparedNonce& prepared, const NonceProof& nonce_proof) {
        if (!prepared.available()) {
            return unexpected_error(ErrorCode::UninitializedState);
        }
        if (nonce_proof.commitment_point[0] != 0x02 && nonce_proof.commitment_point[0] != 0x03) {
            return unexpected_error(ErrorCode::RangeViolation);
        }
        if (!std::equal(nonce_proof.commitment_point.begin() + 1, nonce_proof.commitment_point.end(),
                        prepared.public_nonce().xonly.begin())) {
            return unexpected_error(ErrorCode::BindingMismatch);
        }
        PURIFY_ASSIGN_OR_RETURN(auto out, prepared.scalar());
        if (nonce_proof.commitment_point[0] == 0x03) {
            purify_scalar scalar{};
            int overflow = 0;
            purify_scalar_set_b32(&scalar, out.data(), &overflow);
            if (overflow != 0 || purify_scalar_is_zero(&scalar) != 0) {
                ::purify::detail::secure_clear_bytes(&scalar, sizeof(scalar));
                ::purify::detail::secure_clear_bytes(out.data(), out.size());
                return unexpected_error(ErrorCode::InternalMismatch);
            }
            purify_scalar_negate(&scalar, &scalar);
            purify_scalar_get_b32(out.data(), &scalar);
            ::purify::detail::secure_clear_bytes(&scalar, sizeof(scalar));
        }
        return out;
    }
};

namespace {

Status validate_circuit_proof_encoding(
    const bppp::ExperimentalCircuitZkNormArgProof& proof,
    purify_secp_context* secp_context) {
    PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context));
    if (proof.proof.size() != NonceProof::kInnerProofSize) {
        return unexpected_error(ErrorCode::InvalidFixedSize);
    }
    for (const auto* point : {&proof.a_commitment, &proof.s_commitment}) {
        XOnly32 xonly{};
        int parity = 0;
        if (purify_bip340_xonly_from_point(
                secp_context, point->data(), xonly.data(), &parity) == 0) {
            return unexpected_error(ErrorCode::BackendRejectedInput);
        }
    }
    PURIFY_ASSIGN_OR_RETURN(const auto& t2,
                            FieldElement::try_from_bytes32(proof.t2));
    (void)t2;
    if (purify_bip340_validate_xonly_pubkey(
            secp_context, proof.public_commitment_dlog_nonce.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput);
    }
    PURIFY_ASSIGN_OR_RETURN(
        const auto& dlog_response,
        FieldElement::try_from_bytes32(proof.public_commitment_dlog_response));
    if (dlog_response.is_zero()) {
        return unexpected_error(ErrorCode::BackendRejectedInput);
    }
    return {};
}

}  // namespace

Result<Bytes> NonceProof::serialize(purify_secp_context* secp_context) const {
    PURIFY_ASSIGN_OR_RETURN(auto match, Backend::Ops::matches_nonce(*this, secp_context));
    if (!match) {
        return unexpected_error(ErrorCode::BindingMismatch);
    }
    PURIFY_RETURN_IF_ERROR(validate_circuit_proof_encoding(proof, secp_context));

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
        return unexpected_error(ErrorCode::InvalidFixedSize);
    }
    if (serialized[0] != kSerializationVersion) {
        return unexpected_error(ErrorCode::BackendRejectedInput);
    }
    NonceProof out{};
    std::copy_n(serialized.begin() + 1, 32, out.nonce.xonly.begin());
    PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context));
    if (purify_bip340_validate_xonly_pubkey(secp_context, out.nonce.xonly.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput);
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
    PURIFY_RETURN_IF_ERROR(validate_circuit_proof_encoding(out.proof, secp_context));

    PURIFY_ASSIGN_OR_RETURN(auto match, Backend::Ops::matches_nonce(out, secp_context));
    if (!match) {
        return unexpected_error(ErrorCode::BindingMismatch);
    }
    return out;
}

Result<Bytes> ProvenSignature::serialize(purify_secp_context* secp_context) const {
    PURIFY_ASSIGN_OR_RETURN(const auto& nonce_proof_bytes, nonce_proof.serialize(secp_context));
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
        return unexpected_error(ErrorCode::InvalidFixedSize);
    }
    if (serialized[0] != kSerializationVersion) {
        return unexpected_error(ErrorCode::BackendRejectedInput);
    }
    PURIFY_ASSIGN_OR_RETURN(
        auto nonce_proof_value,
        NonceProof::deserialize(serialized.subspan(1, NonceProof::kSerializedSize), secp_context));
    PURIFY_ASSIGN_OR_RETURN(
        auto signature_value,
        Signature::deserialize(
            serialized.subspan(1 + NonceProof::kSerializedSize, Signature::kSerializedSize),
            secp_context));
    return ProvenSignature{signature_value, nonce_proof_value};
}

}  // namespace purify::puresign_plusplus

namespace purify::puresign_core {

template struct PublicKey<puresign_plusplus::Backend>;
template struct MessageProofCache<puresign_plusplus::Backend>;
template struct TopicProofCache<puresign_plusplus::Backend>;
template class PreparedNonceWithProof<puresign_plusplus::Backend>;
template class KeyPair<puresign_plusplus::Backend>;

}  // namespace purify::puresign_core
