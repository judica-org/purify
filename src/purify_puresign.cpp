// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file purify_puresign.cpp
 * @brief Purify-derived BIP340 signing helpers with prepared nonces and wire-format artifacts.
 */

#include "purify/puresign.hpp"

#include <algorithm>
#include <cstring>

#include "purify/curve.hpp"

namespace purify::puresign {
namespace {

constexpr std::string_view kMessageNonceTag = "PureSign/Nonce/Message/";
constexpr std::string_view kTopicNonceTag = "PureSign/Nonce/Topic/";
constexpr std::string_view kMessageBindingTag = "PureSign/Binding/Message";
constexpr std::string_view kTopicBindingTag = "PureSign/Binding/Topic";

const UInt256& secp256k1_order() {
    static const UInt256 value =
        UInt256::from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    return value;
}

Status validate_puresign_field_alignment() {
    if (prime_p() != secp256k1_order()) {
        return unexpected_error(ErrorCode::InternalMismatch, "puresign:field_order_mismatch");
    }
    return {};
}

Bytes copy_bytes(std::span<const unsigned char> input) {
    return Bytes(input.begin(), input.end());
}

const unsigned char* nullable_data(std::span<const unsigned char> input) {
    return input.empty() ? nullptr : input.data();
}

XOnly32 binding_digest(std::string_view tag, std::span<const unsigned char> input) {
    Bytes digest = hmac_sha256(bytes_from_ascii(tag), copy_bytes(input));
    XOnly32 out{};
    assert(digest.size() == out.size() && "hmac_sha256() should return 32 bytes");
    std::copy(digest.begin(), digest.end(), out.begin());
    return out;
}

Bytes tagged_eval_input(std::string_view tag, std::uint8_t counter, std::span<const unsigned char> input) {
    Bytes out;
    out.reserve(tag.size() + 1 + input.size());
    out.insert(out.end(), tag.begin(), tag.end());
    out.push_back(counter);
    out.insert(out.end(), input.begin(), input.end());
    return out;
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

Result<PublicKey> PublicKey::deserialize(std::span<const unsigned char> serialized) {
    if (serialized.size() != kSerializedSize) {
        return unexpected_error(ErrorCode::InvalidFixedSize, "PublicKey::deserialize:size");
    }
    UInt512 purify_pubkey = UInt512::from_bytes_be(serialized.data(), 64);
    Status pubkey_status = validate_public_key(purify_pubkey);
    if (!pubkey_status.has_value()) {
        return unexpected_error(pubkey_status.error(), "PublicKey::deserialize:validate_public_key");
    }

    PublicKey out{};
    out.purify_pubkey = purify_pubkey;
    std::copy(serialized.begin() + 64, serialized.end(), out.bip340_pubkey.begin());
    if (purify_bip340_validate_xonly_pubkey(out.bip340_pubkey.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput, "PublicKey::deserialize:bip340_validate_xonly_pubkey");
    }
    return out;
}

Bytes Nonce::serialize() const {
    return Bytes(xonly.begin(), xonly.end());
}

Result<Nonce> Nonce::deserialize(std::span<const unsigned char> serialized) {
    if (serialized.size() != kSerializedSize) {
        return unexpected_error(ErrorCode::InvalidFixedSize, "Nonce::deserialize:size");
    }
    Nonce out{};
    std::copy(serialized.begin(), serialized.end(), out.xonly.begin());
    if (purify_bip340_validate_xonly_pubkey(out.xonly.data()) == 0) {
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

Result<Signature> Signature::deserialize(std::span<const unsigned char> serialized) {
    if (serialized.size() != kSerializedSize) {
        return unexpected_error(ErrorCode::InvalidFixedSize, "Signature::deserialize:size");
    }
    Signature out{};
    std::copy(serialized.begin(), serialized.end(), out.bytes.begin());
    if (purify_bip340_validate_signature(out.bytes.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput, "Signature::deserialize:bip340_validate_signature");
    }
    return out;
}

PreparedNonce::PreparedNonce(Scope scope, const Scalar32& scalar, const Nonce& nonce,
                             const XOnly32& signer_pubkey, const XOnly32& binding_digest)
    : scope_(scope), scalar_(scalar), nonce_(nonce), signer_pubkey_(signer_pubkey), binding_digest_(binding_digest) {}

PreparedNonce::PreparedNonce(PreparedNonce&& other) noexcept
    : scope_(other.scope_), scalar_(other.scalar_), nonce_(other.nonce_),
      signer_pubkey_(other.signer_pubkey_), binding_digest_(other.binding_digest_) {
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
        other.clear();
    }
    return *this;
}

PreparedNonce::~PreparedNonce() {
    clear();
}

void PreparedNonce::clear() noexcept {
    std::fill(scalar_.begin(), scalar_.end(), 0);
}

Result<PublicKey> derive_public_key(const UInt512& secret) {
    Result<GeneratedKey> purify_key = derive_key(secret);
    if (!purify_key.has_value()) {
        return unexpected_error(purify_key.error(), "derive_public_key:derive_key");
    }
    Result<Bip340Key> bip340_key = derive_bip340_key(secret);
    if (!bip340_key.has_value()) {
        return unexpected_error(bip340_key.error(), "derive_public_key:derive_bip340_key");
    }
    return PublicKey{purify_key->public_key, bip340_key->xonly_pubkey};
}

Result<PreparedNonce> prepare_message_nonce(const UInt512& secret, std::span<const unsigned char> message) {
    Status field_status = validate_puresign_field_alignment();
    if (!field_status.has_value()) {
        return unexpected_error(field_status.error(), "prepare_message_nonce:validate_puresign_field_alignment");
    }

    Result<Bip340Key> signer = derive_bip340_key(secret);
    if (!signer.has_value()) {
        return unexpected_error(signer.error(), "prepare_message_nonce:derive_bip340_key");
    }

    Scalar32 scalar{};
    bool found = false;
    for (std::uint16_t counter = 0; counter <= 0xFF; ++counter) {
        Result<FieldElement> nonce_value = eval(secret, tagged_eval_input(kMessageNonceTag, static_cast<std::uint8_t>(counter), message));
        if (!nonce_value.has_value()) {
            return unexpected_error(nonce_value.error(), "prepare_message_nonce:eval");
        }
        scalar = nonce_value->to_bytes_be();
        if (std::any_of(scalar.begin(), scalar.end(), [](unsigned char byte) { return byte != 0; })) {
            found = true;
            break;
        }
    }
    if (!found) {
        return unexpected_error(ErrorCode::InternalMismatch, "prepare_message_nonce:zero_nonce_exhausted");
    }

    Nonce nonce{};
    if (purify_bip340_nonce_from_scalar(scalar.data(), nonce.xonly.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput, "prepare_message_nonce:bip340_nonce_from_scalar");
    }
    return PreparedNonce(PreparedNonce::Scope::Message, scalar, nonce, signer->xonly_pubkey,
                         binding_digest(kMessageBindingTag, message));
}

Result<PreparedNonce> prepare_topic_nonce(const UInt512& secret, std::span<const unsigned char> topic) {
    if (topic.empty()) {
        return unexpected_error(ErrorCode::EmptyInput, "prepare_topic_nonce:empty_topic");
    }

    Status field_status = validate_puresign_field_alignment();
    if (!field_status.has_value()) {
        return unexpected_error(field_status.error(), "prepare_topic_nonce:validate_puresign_field_alignment");
    }

    Result<Bip340Key> signer = derive_bip340_key(secret);
    if (!signer.has_value()) {
        return unexpected_error(signer.error(), "prepare_topic_nonce:derive_bip340_key");
    }

    Scalar32 scalar{};
    bool found = false;
    for (std::uint16_t counter = 0; counter <= 0xFF; ++counter) {
        Result<FieldElement> nonce_value = eval(secret, tagged_eval_input(kTopicNonceTag, static_cast<std::uint8_t>(counter), topic));
        if (!nonce_value.has_value()) {
            return unexpected_error(nonce_value.error(), "prepare_topic_nonce:eval");
        }
        scalar = nonce_value->to_bytes_be();
        if (std::any_of(scalar.begin(), scalar.end(), [](unsigned char byte) { return byte != 0; })) {
            found = true;
            break;
        }
    }
    if (!found) {
        return unexpected_error(ErrorCode::InternalMismatch, "prepare_topic_nonce:zero_nonce_exhausted");
    }

    Nonce nonce{};
    if (purify_bip340_nonce_from_scalar(scalar.data(), nonce.xonly.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput, "prepare_topic_nonce:bip340_nonce_from_scalar");
    }
    return PreparedNonce(PreparedNonce::Scope::Topic, scalar, nonce, signer->xonly_pubkey,
                         binding_digest(kTopicBindingTag, topic));
}

Result<Signature> sign_message(const UInt512& secret, std::span<const unsigned char> message) {
    Result<PreparedNonce> prepared = prepare_message_nonce(secret, message);
    if (!prepared.has_value()) {
        return unexpected_error(prepared.error(), "sign_message:prepare_message_nonce");
    }
    return sign_message_with_prepared(secret, message, std::move(*prepared));
}

Result<Signature> sign_message_with_prepared(const UInt512& secret, std::span<const unsigned char> message,
                                             PreparedNonce&& prepared) {
    Result<Bip340Key> signer = derive_bip340_key(secret);
    if (!signer.has_value()) {
        return unexpected_error(signer.error(), "sign_message_with_prepared:derive_bip340_key");
    }
    if (prepared.scope_ != PreparedNonce::Scope::Message) {
        return unexpected_error(ErrorCode::BindingMismatch, "sign_message_with_prepared:scope");
    }
    if (prepared.signer_pubkey_ != signer->xonly_pubkey) {
        return unexpected_error(ErrorCode::BindingMismatch, "sign_message_with_prepared:signer_pubkey");
    }
    if (prepared.binding_digest_ != binding_digest(kMessageBindingTag, message)) {
        return unexpected_error(ErrorCode::BindingMismatch, "sign_message_with_prepared:message_binding");
    }

    Signature out{};
    if (purify_bip340_sign_with_fixed_nonce(out.bytes.data(), nullable_data(message), message.size(),
                                            signer->seckey.data(), prepared.scalar_.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput, "sign_message_with_prepared:sign_with_fixed_nonce");
    }
    if (out.nonce().xonly != prepared.nonce_.xonly) {
        return unexpected_error(ErrorCode::InternalMismatch, "sign_message_with_prepared:nonce_mismatch");
    }
    if (purify_bip340_verify(out.bytes.data(), nullable_data(message), message.size(), signer->xonly_pubkey.data()) == 0) {
        return unexpected_error(ErrorCode::InternalMismatch, "sign_message_with_prepared:self_verify");
    }
    return out;
}

Result<Signature> sign_with_topic(const UInt512& secret, std::span<const unsigned char> message,
                                  std::span<const unsigned char> topic) {
    Result<PreparedNonce> prepared = prepare_topic_nonce(secret, topic);
    if (!prepared.has_value()) {
        return unexpected_error(prepared.error(), "sign_with_topic:prepare_topic_nonce");
    }
    return sign_with_prepared_topic(secret, message, std::move(*prepared));
}

Result<Signature> sign_with_prepared_topic(const UInt512& secret, std::span<const unsigned char> message,
                                           PreparedNonce&& prepared) {
    Result<Bip340Key> signer = derive_bip340_key(secret);
    if (!signer.has_value()) {
        return unexpected_error(signer.error(), "sign_with_prepared_topic:derive_bip340_key");
    }
    if (prepared.scope_ != PreparedNonce::Scope::Topic) {
        return unexpected_error(ErrorCode::BindingMismatch, "sign_with_prepared_topic:scope");
    }
    if (prepared.signer_pubkey_ != signer->xonly_pubkey) {
        return unexpected_error(ErrorCode::BindingMismatch, "sign_with_prepared_topic:signer_pubkey");
    }

    Signature out{};
    if (purify_bip340_sign_with_fixed_nonce(out.bytes.data(), nullable_data(message), message.size(),
                                            signer->seckey.data(), prepared.scalar_.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput, "sign_with_prepared_topic:sign_with_fixed_nonce");
    }
    if (out.nonce().xonly != prepared.nonce_.xonly) {
        return unexpected_error(ErrorCode::InternalMismatch, "sign_with_prepared_topic:nonce_mismatch");
    }
    if (purify_bip340_verify(out.bytes.data(), nullable_data(message), message.size(), signer->xonly_pubkey.data()) == 0) {
        return unexpected_error(ErrorCode::InternalMismatch, "sign_with_prepared_topic:self_verify");
    }
    return out;
}

Result<bool> verify_signature(const PublicKey& public_key, std::span<const unsigned char> message,
                              const Signature& signature) {
    Status pubkey_status = validate_public_key(public_key.purify_pubkey);
    if (!pubkey_status.has_value()) {
        return unexpected_error(pubkey_status.error(), "verify_signature:validate_public_key");
    }
    if (purify_bip340_validate_xonly_pubkey(public_key.bip340_pubkey.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput, "verify_signature:bip340_validate_xonly_pubkey");
    }
    if (purify_bip340_validate_signature(signature.bytes.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput, "verify_signature:bip340_validate_signature");
    }
    return purify_bip340_verify(signature.bytes.data(), nullable_data(message), message.size(),
                                public_key.bip340_pubkey.data()) != 0;
}

}  // namespace purify::puresign
