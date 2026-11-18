// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file puresign/core.cpp
 * @brief The parts of PureSign that do not depend on the proof system.
 *
 * Nonce derivation, prepared nonces, plain BIP340 signing and verification, and the wire formats
 * of the value types every backend shares.
 */

#include "purify/puresign/core.hpp"

#include <algorithm>
#include <type_traits>

#include "detail/core_impl.hpp"
#include "purify/secp_bridge.h"

namespace purify::puresign_core {

namespace detail {

namespace {

constexpr std::string_view kMessageNonceTag = "PureSign/Nonce/Message/";
constexpr std::string_view kTopicNonceTag = "PureSign/Nonce/Topic/";
constexpr std::string_view kMessageBindingTag = "PureSign/Binding/Message";
constexpr std::string_view kTopicBindingTag = "PureSign/Binding/Topic";

const TaggedHash& binding_tagged_hash(Scope scope) {
    static const TaggedHash message_hash(kMessageBindingTag);
    static const TaggedHash topic_hash(kTopicBindingTag);
    return scope == Scope::Message ? message_hash : topic_hash;
}

const UInt256& secp256k1_order() {
    static const UInt256 value =
        UInt256::from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    return value;
}

/** PureSign uses a Purify output directly as a nonce, so the two scalar fields must coincide. */
Status validate_puresign_field_alignment() {
    if (prime_p() != secp256k1_order()) {
        return unexpected_error(ErrorCode::InternalMismatch);
    }
    return {};
}

const unsigned char* nullable_data(std::span<const unsigned char> input) {
    return input.empty() ? nullptr : input.data();
}

XOnly32 binding_digest(Scope scope, std::span<const unsigned char> input) {
    return binding_tagged_hash(scope).digest(input);
}

}  // namespace

Bytes nonce_eval_input(Scope scope, std::span<const unsigned char> input) {
    const std::string_view tag = scope == Scope::Message ? kMessageNonceTag : kTopicNonceTag;
    Bytes out;
    best_effort_reserve_add(out, tag.size(), input.size());
    out.insert(out.end(), tag.begin(), tag.end());
    out.insert(out.end(), input.begin(), input.end());
    return out;
}

Bytes serialize_public_key(const UInt512& purify_pubkey, const XOnly32& bip340_pubkey) {
    Bytes out;
    out.reserve(kPublicKeySerializedSize);
    std::array<unsigned char, kPackedPurifyKeySize> packed = purify_pubkey.to_bytes_be();
    out.insert(out.end(), packed.begin(), packed.end());
    out.insert(out.end(), bip340_pubkey.begin(), bip340_pubkey.end());
    return out;
}

Result<PublicKeyParts> deserialize_public_key(std::span<const unsigned char> serialized,
                                              purify_secp_context* secp_context) {
    if (serialized.size() != kPublicKeySerializedSize) {
        return unexpected_error(ErrorCode::InvalidFixedSize);
    }
    PublicKeyParts out{};
    out.purify_pubkey = UInt512::from_bytes_be(serialized.data(), kPackedPurifyKeySize);
    PURIFY_RETURN_IF_ERROR(validate_public_key(out.purify_pubkey));
    std::copy(serialized.begin() + kPackedPurifyKeySize, serialized.end(), out.bip340_pubkey.begin());
    PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context));
    if (purify_bip340_validate_xonly_pubkey(secp_context, out.bip340_pubkey.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput);
    }
    return out;
}

Result<PublicKeyParts> derive_public_key(const SecretKey& secret, purify_secp_context* secp_context) {
    PURIFY_ASSIGN_OR_RETURN(const auto& purify_key, derive_key(secret));
    PURIFY_ASSIGN_OR_RETURN(const auto& bip340_key, derive_bip340_key(secret, secp_context));
    return PublicKeyParts{purify_key.public_key, bip340_key.xonly_pubkey};
}

Status validate_public_key_bundle(const UInt512& purify_pubkey, const XOnly32& bip340_pubkey,
                                  purify_secp_context* secp_context) {
    PURIFY_RETURN_IF_ERROR(validate_public_key(purify_pubkey));
    PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context));
    if (purify_bip340_validate_xonly_pubkey(secp_context, bip340_pubkey.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput);
    }
    return {};
}

Result<bool> verify_bip340_signature(const UInt512& purify_pubkey, const XOnly32& bip340_pubkey,
                                     std::span<const unsigned char> message, const Signature& signature,
                                     purify_secp_context* secp_context) {
    PURIFY_RETURN_IF_ERROR(validate_public_key_bundle(purify_pubkey, bip340_pubkey, secp_context));
    if (purify_bip340_validate_signature(secp_context, signature.bytes.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput);
    }
    return purify_bip340_verify(secp_context, signature.bytes.data(), nullable_data(message), message.size(),
                                bip340_pubkey.data()) != 0;
}

Result<bool> nonce_matches_point(const Nonce& nonce, const std::array<unsigned char, 33>& point,
                                 purify_secp_context* secp_context) {
    XOnly32 xonly{};
    int parity = 0;
    PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context));
    if (purify_bip340_xonly_from_point(secp_context, point.data(), xonly.data(), &parity) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput);
    }
    return xonly == nonce.xonly;
}

DerivedNonceData::DerivedNonceData(DerivedNonceData&& other) noexcept
    : scope(other.scope), scalar(other.scalar), nonce(other.nonce),
      signer_pubkey(other.signer_pubkey), binding_digest(other.binding_digest),
      eval_input(std::move(other.eval_input)) {
    ::purify::detail::secure_erase(other.scalar);
}

DerivedNonceData& DerivedNonceData::operator=(DerivedNonceData&& other) noexcept {
    if (this != &other) {
        ::purify::detail::secure_erase(scalar);
        scope = other.scope;
        scalar = other.scalar;
        nonce = other.nonce;
        signer_pubkey = other.signer_pubkey;
        binding_digest = other.binding_digest;
        eval_input = std::move(other.eval_input);
        ::purify::detail::secure_erase(other.scalar);
    }
    return *this;
}

DerivedNonceData::~DerivedNonceData() {
    ::purify::detail::secure_erase(scalar);
}

Result<DerivedNonceData> derive_nonce_data(const SecretKey& secret, Scope scope,
                                           std::span<const unsigned char> input,
                                           purify_secp_context* secp_context) {
    if (scope == Scope::Topic && input.empty()) {
        return unexpected_error(ErrorCode::EmptyInput);
    }
    PURIFY_RETURN_IF_ERROR(validate_puresign_field_alignment());
    PURIFY_ASSIGN_OR_RETURN(const auto& signer, derive_bip340_key(secret, secp_context));

    DerivedNonceData out{};
    out.scope = scope;
    out.signer_pubkey = signer.xonly_pubkey;
    out.binding_digest = binding_digest(scope, input);
    out.eval_input = nonce_eval_input(scope, input);

    auto nonce_value = eval(secret, out.eval_input);
    if (!nonce_value.has_value()) {
        return unexpected_error(nonce_value.error());
    }
    static_assert(std::is_trivially_destructible_v<FieldElement>);
    if (nonce_value->is_zero()) {
        /* This rejects the unique invalid Schnorr nonce. Since Purify outputs a field element
         * modulo the secp256k1 group order, the failure probability is exactly 1/n, which is
         * negligible for n ~= 2^256.
         */
        ::purify::detail::secure_erase(*nonce_value);
        return unexpected_error(ErrorCode::BackendRejectedInput);
    }
    purify_scalar_get_b32(out.scalar.data(), &::purify::detail::FieldElementAccess::raw(*nonce_value));
    ::purify::detail::secure_erase(*nonce_value);

    PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context));
    if (purify_bip340_nonce_from_scalar(secp_context, out.scalar.data(), out.nonce.xonly.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput);
    }
    return out;
}

PreparedNonce prepared_nonce(const DerivedNonceData& nonce_data) {
    return PreparedNonce::from_parts(nonce_data.scope, nonce_data.scalar, nonce_data.nonce,
                                     nonce_data.signer_pubkey, nonce_data.binding_digest);
}

Result<PreparedNonce> prepare_nonce(const SecretKey& secret, Scope scope, std::span<const unsigned char> input,
                                    purify_secp_context* secp_context) {
    PURIFY_ASSIGN_OR_RETURN(const auto& nonce_data, derive_nonce_data(secret, scope, input, secp_context));
    return prepared_nonce(nonce_data);
}

Result<Signature> sign_with_prepared(const SecretKey& secret, Scope scope, std::span<const unsigned char> message,
                                     PreparedNonce prepared, purify_secp_context* secp_context) {
    PURIFY_ASSIGN_OR_RETURN(const auto& signer, derive_bip340_key(secret, secp_context));
    return scope == Scope::Message ? std::move(prepared).sign_message(signer, message, secp_context)
                                   : std::move(prepared).sign_topic_message(signer, message, secp_context);
}

void derive_secret_prover_seed(const SecretKey& secret, const TaggedHash& proof_hash,
                               std::span<const unsigned char> eval_input, SecretProofSeed& out) {
    ::purify::detail::Secret<std::array<unsigned char, 64>> secret_bytes;
    ::purify::detail::BigUIntCBridge<8>::to_bytes_be(secret_bytes.value.data(), secret.packed().limbs.data());
    std::array digest_segments{
        std::span<const unsigned char>(secret_bytes.value.data(), secret_bytes.value.size()),
        eval_input,
    };
    Scalar32 digest = proof_hash.digest_many(digest_segments);
    out.value = digest;
    ::purify::detail::secure_erase(digest);
}

Result<ProofCacheParts> build_proof_cache_parts(Scope scope, std::span<const unsigned char> input) {
    if (scope == Scope::Topic && input.empty()) {
        return unexpected_error(ErrorCode::EmptyInput);
    }
    ProofCacheParts out{};
    out.eval_input = nonce_eval_input(scope, input);
    PURIFY_ASSIGN_OR_RETURN(auto circuit_template, verifier_circuit_template(out.eval_input));
    PURIFY_ASSIGN_OR_RETURN(auto template_digest, circuit_template.integrity_digest());
    out.circuit_template = std::move(circuit_template);
    out.template_digest = std::move(template_digest);
    return out;
}

Status validate_proof_cache_parts(Scope scope, const Bytes& input, const Bytes& eval_input,
                                  const NativeBulletproofCircuitTemplate& circuit_template,
                                  const Bytes& template_digest) {
    if (scope == Scope::Topic && input.empty()) {
        return unexpected_error(ErrorCode::EmptyInput);
    }
    if (eval_input != nonce_eval_input(scope, input)) {
        return unexpected_error(ErrorCode::BindingMismatch);
    }
    PURIFY_ASSIGN_OR_RETURN(const auto& expected_digest, circuit_template.integrity_digest());
    if (template_digest != expected_digest) {
        return unexpected_error(ErrorCode::BindingMismatch);
    }
    return {};
}

}  // namespace detail

Bytes Nonce::serialize() const {
    return Bytes(xonly.begin(), xonly.end());
}

Result<Nonce> Nonce::deserialize(std::span<const unsigned char> serialized, purify_secp_context* secp_context) {
    if (serialized.size() != kSerializedSize) {
        return unexpected_error(ErrorCode::InvalidFixedSize);
    }
    Nonce out{};
    std::copy(serialized.begin(), serialized.end(), out.xonly.begin());
    PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context));
    if (purify_bip340_validate_xonly_pubkey(secp_context, out.xonly.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput);
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
        return unexpected_error(ErrorCode::InvalidFixedSize);
    }
    Signature out{};
    std::copy(serialized.begin(), serialized.end(), out.bytes.begin());
    PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context));
    if (purify_bip340_validate_signature(secp_context, out.bytes.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput);
    }
    return out;
}

PreparedNonce::PreparedNonce(Scope scope, const Scalar32& scalar, const Nonce& nonce,
                             const XOnly32& signer_pubkey, const XOnly32& binding_digest)
    : scope_(scope), scalar_(scalar), nonce_(nonce),
      signer_pubkey_(signer_pubkey), binding_digest_(binding_digest),
      available_(true) {}

PreparedNonce PreparedNonce::from_parts(Scope scope, const Scalar32& scalar, const Nonce& nonce,
                                        const XOnly32& signer_pubkey, const XOnly32& binding_digest) {
    return PreparedNonce(scope, scalar, nonce, signer_pubkey, binding_digest);
}

PreparedNonce::PreparedNonce(PreparedNonce&& other) noexcept
    : scope_(other.scope_), scalar_(other.scalar_), nonce_(other.nonce_),
      signer_pubkey_(other.signer_pubkey_), binding_digest_(other.binding_digest_),
      available_(other.available_) {
    other.clear();
}

PreparedNonce& PreparedNonce::operator=(PreparedNonce&& other) noexcept {
    if (this != &other) {
        clear();
        scope_ = other.scope_;
        scalar_ = other.scalar_;
        nonce_ = other.nonce_;
        signer_pubkey_ = other.signer_pubkey_;
        binding_digest_ = other.binding_digest_;
        available_ = other.available_;
        other.clear();
    }
    return *this;
}

PreparedNonce::~PreparedNonce() {
    clear();
}

void PreparedNonce::clear() noexcept {
    ::purify::detail::secure_clear_bytes(scalar_.data(), scalar_.size());
    available_ = false;
}

Result<Signature> PreparedNonce::sign(Scope scope, const Bip340Key& signer,
                                      std::span<const unsigned char> message,
                                      purify_secp_context* secp_context) {
    if (!available_) {
        return unexpected_error(ErrorCode::UninitializedState);
    }
    available_ = false;
    ::purify::detail::WipeOnDestruction burn(scalar_);
    if (scope_ != scope) {
        return unexpected_error(ErrorCode::BindingMismatch);
    }
    if (signer_pubkey_ != signer.xonly_pubkey) {
        return unexpected_error(ErrorCode::BindingMismatch);
    }
    // A message-bound nonce signs only its message; a topic-bound nonce signs any one message.
    if (scope == Scope::Message && binding_digest_ != detail::binding_digest(Scope::Message, message)) {
        return unexpected_error(ErrorCode::BindingMismatch);
    }

    PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context));
    Signature out{};
    if (purify_bip340_sign_with_fixed_nonce(secp_context, out.bytes.data(), detail::nullable_data(message),
                                            message.size(), signer.seckey.data(), scalar_.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput);
    }
    if (out.nonce().xonly != nonce_.xonly) {
        return unexpected_error(ErrorCode::InternalMismatch);
    }
    if (purify_bip340_verify(secp_context, out.bytes.data(), detail::nullable_data(message), message.size(),
                             signer.xonly_pubkey.data()) == 0) {
        return unexpected_error(ErrorCode::InternalMismatch);
    }
    return out;
}

Result<Signature> PreparedNonce::sign_message(const Bip340Key& signer, std::span<const unsigned char> message,
                                              purify_secp_context* secp_context) && {
    return sign(Scope::Message, signer, message, secp_context);
}

Result<Signature> PreparedNonce::sign_topic_message(const Bip340Key& signer,
                                                    std::span<const unsigned char> message,
                                                    purify_secp_context* secp_context) && {
    return sign(Scope::Topic, signer, message, secp_context);
}

}  // namespace purify::puresign_core
