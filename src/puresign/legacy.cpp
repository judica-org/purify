// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file puresign/legacy.cpp
 * @brief The legacy Bulletproof backend of PureSign: its proof operations and wire formats.
 *
 * Everything that does not depend on the proof system lives in `core.cpp` and
 * `detail/core_impl.hpp`.
 */

#include "purify/puresign/legacy.hpp"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <limits>
#include <optional>

#include "bulletproof_internal.hpp"
#include "byte_io.hpp"
#include "checked_size.hpp"
#include "detail/core_impl.hpp"
#include "purify/bppp.hpp"

namespace purify::puresign {

using ::purify::detail::append_u32_le;
using ::purify::detail::read_u32_le;

struct Backend::Ops {
    static constexpr std::string_view kMessageProofTag = "PureSign/Proof/Message/V1";
    static constexpr std::string_view kTopicProofTag = "PureSign/Proof/Topic/V1";

    /** Proofs are produced, and cached verification runs, over the packed circuit form. */
    static Result<NativeBulletproofCircuit::PackedWithSlack> instantiate(
        const NativeBulletproofCircuitTemplate& circuit_template, const UInt512& purify_pubkey) {
        return circuit_template.instantiate_packed(purify_pubkey);
    }

    static Result<NonceProof> prove(const NativeBulletproofCircuit::PackedWithSlack& circuit,
                                    const BulletproofAssignmentData& assignment, const Scalar32& prover_seed,
                                    const Nonce& nonce, std::span<const unsigned char> statement_binding,
                                    purify_secp_context* secp_context, CircuitCache* circuit_cache) {
        PURIFY_ASSIGN_OR_RETURN(auto proof,
                                prove_experimental_circuit_assume_valid(circuit, assignment, prover_seed,
                                                                        bppp::base_generator(secp_context),
                                                                        secp_context, statement_binding, {},
                                                                        circuit_cache));
        return NonceProof{nonce, std::move(proof)};
    }

    /** `CircuitLike` is the packed form under a proof cache and the plain form otherwise. */
    template <typename CircuitLike>
    static Result<bool> verify(const CircuitLike& circuit, const NonceProof& nonce_proof,
                               std::span<const unsigned char> statement_binding,
                               purify_secp_context* secp_context, CircuitCache* circuit_cache) {
        return verify_experimental_circuit(circuit, nonce_proof.proof, bppp::base_generator(secp_context),
                                           secp_context, statement_binding, circuit_cache);
    }

    /** The proof's single commitment is the nonce point. */
    static Result<bool> matches_nonce(const NonceProof& nonce_proof, purify_secp_context* secp_context) {
        PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context));
        if (nonce_proof.proof.commitments.size() != 1) {
            return unexpected_error(ErrorCode::SizeMismatch);
        }
        return puresign_core::detail::nonce_matches_point(nonce_proof.nonce, nonce_proof.proof.commitments.front(),
                                                          secp_context);
    }
};

Result<Bytes> NonceProof::serialize(purify_secp_context* secp_context) const {
    PURIFY_ASSIGN_OR_RETURN(auto match, Backend::Ops::matches_nonce(*this, secp_context));
    if (!match) {
        return unexpected_error(ErrorCode::BindingMismatch);
    }
    PURIFY_ASSIGN_OR_RETURN(const auto& proof_bytes, proof.serialize());
    if (proof_bytes.size() > static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max())) {
        return unexpected_error(ErrorCode::UnexpectedSize);
    }
    std::size_t serialized_size = 0;
    if (!(::purify::detail::CheckedSize(37) + proof_bytes.size()).store(serialized_size)) {
        return unexpected_error(ErrorCode::Overflow);
    }

    Bytes out;
    out.reserve(serialized_size);
    out.push_back(static_cast<unsigned char>(2));
    append_u32_le(out, static_cast<std::uint32_t>(proof_bytes.size()));
    out.insert(out.end(), nonce.xonly.begin(), nonce.xonly.end());
    out.insert(out.end(), proof_bytes.begin(), proof_bytes.end());
    return out;
}

Result<NonceProof> NonceProof::deserialize(std::span<const unsigned char> serialized,
                                           purify_secp_context* secp_context) {
    if (serialized.size() < 37) {
        return unexpected_error(ErrorCode::InvalidFixedSize);
    }
    if (serialized[0] != 2) {
        return unexpected_error(ErrorCode::BackendRejectedInput);
    }
    std::optional<std::uint32_t> proof_size = read_u32_le(serialized, 1);
    assert(proof_size.has_value() && "header length check should guarantee a u32 proof size");
    if (*proof_size != serialized.size() - 37) {
        return unexpected_error(ErrorCode::InvalidFixedSize);
    }

    NonceProof out{};
    std::copy_n(serialized.begin() + 5, 32, out.nonce.xonly.begin());
    PURIFY_ASSIGN_OR_RETURN(auto proof_value,
                            ExperimentalBulletproofProof::deserialize(serialized.subspan(37, *proof_size)));
    out.proof = std::move(proof_value);
    PURIFY_ASSIGN_OR_RETURN(auto match, Backend::Ops::matches_nonce(out, secp_context));
    if (!match) {
        return unexpected_error(ErrorCode::BindingMismatch);
    }
    return out;
}

Result<Bytes> ProvenSignature::serialize(purify_secp_context* secp_context) const {
    PURIFY_ASSIGN_OR_RETURN(const auto& nonce_proof_bytes, nonce_proof.serialize(secp_context));
    if (nonce_proof_bytes.size() > static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max())) {
        return unexpected_error(ErrorCode::UnexpectedSize);
    }
    std::size_t serialized_size = 0;
    if (!(::purify::detail::CheckedSize(69) + nonce_proof_bytes.size()).store(serialized_size)) {
        return unexpected_error(ErrorCode::Overflow);
    }

    Bytes out;
    out.reserve(serialized_size);
    out.push_back(static_cast<unsigned char>(1));
    append_u32_le(out, static_cast<std::uint32_t>(nonce_proof_bytes.size()));
    out.insert(out.end(), nonce_proof_bytes.begin(), nonce_proof_bytes.end());
    out.insert(out.end(), signature.bytes.begin(), signature.bytes.end());
    return out;
}

Result<ProvenSignature> ProvenSignature::deserialize(std::span<const unsigned char> serialized,
                                                     purify_secp_context* secp_context) {
    if (serialized.size() < 69) {
        return unexpected_error(ErrorCode::InvalidFixedSize);
    }
    if (serialized[0] != 1) {
        return unexpected_error(ErrorCode::BackendRejectedInput);
    }
    std::optional<std::uint32_t> nonce_proof_size = read_u32_le(serialized, 1);
    assert(nonce_proof_size.has_value() && "header length check should guarantee a u32 nonce proof size");
    const std::size_t payload_size = serialized.size() - 5;
    if (*nonce_proof_size > payload_size || payload_size - *nonce_proof_size != 64) {
        return unexpected_error(ErrorCode::InvalidFixedSize);
    }

    PURIFY_ASSIGN_OR_RETURN(auto nonce_proof_value,
                            NonceProof::deserialize(serialized.subspan(5, *nonce_proof_size), secp_context));
    PURIFY_ASSIGN_OR_RETURN(auto signature_value,
                            Signature::deserialize(serialized.subspan(5 + *nonce_proof_size, 64), secp_context));
    return ProvenSignature{signature_value, nonce_proof_value};
}

}  // namespace purify::puresign

namespace purify::puresign_core {

template struct PublicKey<puresign::Backend>;
template struct MessageProofCache<puresign::Backend>;
template struct TopicProofCache<puresign::Backend>;
template class PreparedNonceWithProof<puresign::Backend>;
template class KeyPair<puresign::Backend>;

}  // namespace purify::puresign_core
