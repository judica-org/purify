// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file purify_c_api.cpp
 * @brief C core implementation for Purify key validation, generation, derivation, and evaluation.
 */

#include "purify.h"

#include <algorithm>
#include <array>
#include <span>
#include <string_view>

#include "purify/curve.hpp"
#include "purify/error.hpp"
#include "purify/secret.hpp"
#include "purify_core.h"
#include "purify_error_bridge.hpp"

namespace purify::capi_detail {

Bytes copy_bytes(const unsigned char* data, std::size_t size) {
    if (size == 0) {
        return {};
    }
    return Bytes(data, data + size);
}

void clear_generated_key(purify_generated_key* out) noexcept {
    if (out == nullptr) {
        return;
    }
    detail::secure_clear_bytes(out->secret_key, sizeof(out->secret_key));
    std::fill(std::begin(out->public_key), std::end(out->public_key), 0);
}

void clear_bip340_key(purify_bip340_key* out) noexcept {
    if (out == nullptr) {
        return;
    }
    detail::secure_clear_bytes(out->secret_key, sizeof(out->secret_key));
    std::fill(std::begin(out->xonly_public_key), std::end(out->xonly_public_key), 0);
}

const UInt256& secp256k1_order() {
    static const UInt256 value =
        UInt256::from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    return value;
}

const UInt256& secp256k1_order_minus_one() {
    static const UInt256 value = [] {
        UInt256 out = secp256k1_order();
        out.sub_assign(UInt256::one());
        return out;
    }();
    return value;
}

Bytes tagged_message(std::string_view prefix, const Bytes& message) {
    Bytes out;
    out.reserve(prefix.size() + message.size());
    out.insert(out.end(), prefix.begin(), prefix.end());
    out.insert(out.end(), message.begin(), message.end());
    return out;
}

Result<UInt512> parse_secret_key(const unsigned char* secret_key) {
    if (secret_key == nullptr) {
        return unexpected_error(ErrorCode::MissingValue, "parse_secret_key:null_secret_key");
    }
    const purify_error_code code = purify_validate_secret_key(secret_key);
    if (code != PURIFY_ERROR_OK) {
        return unexpected_error(core_api_detail::from_core_error_code(code),
                                "parse_secret_key:purify_validate_secret_key");
    }
    UInt512 packed = UInt512::from_bytes_be(secret_key, PURIFY_SECRET_KEY_BYTES);
    return packed;
}

Result<UInt512> parse_public_key(const unsigned char* public_key) {
    if (public_key == nullptr) {
        return unexpected_error(ErrorCode::MissingValue, "parse_public_key:null_public_key");
    }
    const purify_error_code code = purify_validate_public_key(public_key);
    if (code != PURIFY_ERROR_OK) {
        return unexpected_error(core_api_detail::from_core_error_code(code),
                                "parse_public_key:purify_validate_public_key");
    }
    UInt512 packed = UInt512::from_bytes_be(public_key, PURIFY_PUBLIC_KEY_BYTES);
    return packed;
}

void write_uint512(const UInt512& value, unsigned char* out) {
    const std::array<unsigned char, PURIFY_PUBLIC_KEY_BYTES> bytes = value.to_bytes_be();
    std::copy(bytes.begin(), bytes.end(), out);
}

void write_field_element(const FieldElement& value, unsigned char* out) {
    const std::array<unsigned char, PURIFY_FIELD_ELEMENT_BYTES> bytes = value.to_bytes_be();
    std::copy(bytes.begin(), bytes.end(), out);
}

Result<UInt512> derive_public_key_from_secret(const UInt512& secret) {
    PURIFY_ASSIGN_OR_RETURN(const auto& unpacked, unpack_secret(secret), "derive_public_key_from_secret:unpack_secret");
    PURIFY_ASSIGN_OR_RETURN(const auto& p1, curve1().mul_secret_affine(generator1(), unpacked.first),
                            "derive_public_key_from_secret:mul_secret_affine_p1");
    PURIFY_ASSIGN_OR_RETURN(const auto& p2, curve2().mul_secret_affine(generator2(), unpacked.second),
                            "derive_public_key_from_secret:mul_secret_affine_p2");
    return pack_public(p1.x.to_uint256(), p2.x.to_uint256());
}

}  // namespace purify::capi_detail

extern "C" {

purify_error_code purify_generate_key(purify_generated_key* out) {
    purify::Result<purify::UInt512> packed_secret;
    purify::Result<purify::UInt512> public_key;
    purify_error_code status;
    if (out == nullptr) {
        return PURIFY_ERROR_MISSING_VALUE;
    }
    purify::capi_detail::clear_generated_key(out);
    status = purify_core_sample_secret_key(out->secret_key);
    if (status != PURIFY_ERROR_OK) {
        purify::capi_detail::clear_generated_key(out);
        return status;
    }
    packed_secret = purify::capi_detail::parse_secret_key(out->secret_key);
    if (!packed_secret.has_value()) {
        purify::capi_detail::clear_generated_key(out);
        return purify::core_api_detail::to_core_error_code(packed_secret.error().code);
    }
    public_key = purify::capi_detail::derive_public_key_from_secret(*packed_secret);
    if (!public_key.has_value()) {
        purify::capi_detail::clear_generated_key(out);
        return purify::core_api_detail::to_core_error_code(public_key.error().code);
    }
    purify::capi_detail::write_uint512(*public_key, out->public_key);
    return PURIFY_ERROR_OK;
}

purify_error_code purify_generate_key_from_seed(purify_generated_key* out, const unsigned char* seed, size_t seed_len) {
    purify::Result<purify::UInt512> packed_secret;
    purify::Result<purify::UInt512> public_key;
    purify_error_code status;
    if (out == nullptr) {
        return PURIFY_ERROR_MISSING_VALUE;
    }
    purify::capi_detail::clear_generated_key(out);
    status = purify_core_seed_secret_key(out->secret_key, seed, seed_len);
    if (status != PURIFY_ERROR_OK) {
        purify::capi_detail::clear_generated_key(out);
        return status;
    }
    packed_secret = purify::capi_detail::parse_secret_key(out->secret_key);
    if (!packed_secret.has_value()) {
        purify::capi_detail::clear_generated_key(out);
        return purify::core_api_detail::to_core_error_code(packed_secret.error().code);
    }
    public_key = purify::capi_detail::derive_public_key_from_secret(*packed_secret);
    if (!public_key.has_value()) {
        purify::capi_detail::clear_generated_key(out);
        return purify::core_api_detail::to_core_error_code(public_key.error().code);
    }
    purify::capi_detail::write_uint512(*public_key, out->public_key);
    return PURIFY_ERROR_OK;
}

purify_error_code purify_derive_public_key(unsigned char out_public_key[PURIFY_PUBLIC_KEY_BYTES],
                                           const unsigned char secret_key[PURIFY_SECRET_KEY_BYTES]) {
    if (out_public_key == nullptr) {
        return PURIFY_ERROR_MISSING_VALUE;
    }
    std::fill(out_public_key, out_public_key + PURIFY_PUBLIC_KEY_BYTES, 0);

    purify::Result<purify::UInt512> packed_secret = purify::capi_detail::parse_secret_key(secret_key);
    if (!packed_secret.has_value()) {
        return purify::core_api_detail::to_core_error_code(packed_secret.error().code);
    }

    purify::Result<purify::UInt512> public_key = purify::capi_detail::derive_public_key_from_secret(*packed_secret);
    if (!public_key.has_value()) {
        return purify::core_api_detail::to_core_error_code(public_key.error().code);
    }

    purify::capi_detail::write_uint512(*public_key, out_public_key);
    return PURIFY_ERROR_OK;
}

purify_error_code purify_derive_bip340_key(purify_bip340_key* out,
                                           const unsigned char secret_key[PURIFY_SECRET_KEY_BYTES]) {
    if (out == nullptr) {
        return PURIFY_ERROR_MISSING_VALUE;
    }
    purify::capi_detail::clear_bip340_key(out);

    purify::Result<purify::UInt512> packed_secret = purify::capi_detail::parse_secret_key(secret_key);
    if (!packed_secret.has_value()) {
        return purify::core_api_detail::to_core_error_code(packed_secret.error().code);
    }

    static const purify::TaggedHash kBip340KeyGenTag("Purify/BIP340/KeyGen");
    std::array<unsigned char, PURIFY_SECRET_KEY_BYTES> packed_secret_bytes = packed_secret->to_bytes_be();
    purify::Bytes ikm(packed_secret_bytes.begin(), packed_secret_bytes.end());
#if PURIFY_USE_LEGACY_FIELD_HASHES
    std::optional<purify::UInt256> scalar =
        purify::hash_to_int<4>(ikm, purify::capi_detail::secp256k1_order_minus_one(),
                               purify::bytes_from_ascii("Purify/BIP340/KeyGen"));
#else
    std::optional<purify::UInt256> scalar = purify::tagged_hash_to_int<4>(
        std::span<const unsigned char>(ikm.data(), ikm.size()), purify::capi_detail::secp256k1_order_minus_one(),
        kBip340KeyGenTag);
#endif
    purify::detail::secure_clear_bytes(ikm.data(), ikm.size());
    purify::detail::secure_clear_bytes(packed_secret_bytes.data(), packed_secret_bytes.size());
    if (!scalar.has_value()) {
        return PURIFY_ERROR_INTERNAL_MISMATCH;
    }
    scalar->add_small(1);

    const std::array<unsigned char, PURIFY_BIP340_SECRET_KEY_BYTES> scalar_bytes = scalar->to_bytes_be();
    std::copy(scalar_bytes.begin(), scalar_bytes.end(), out->secret_key);
    if (purify_bip340_key_from_seckey(out->secret_key, out->xonly_public_key) == 0) {
        purify::capi_detail::clear_bip340_key(out);
        return PURIFY_ERROR_BACKEND_REJECTED_INPUT;
    }
    return PURIFY_ERROR_OK;
}

purify_error_code purify_eval(unsigned char out_field_element[PURIFY_FIELD_ELEMENT_BYTES],
                              const unsigned char secret_key[PURIFY_SECRET_KEY_BYTES],
                              const unsigned char* message,
                              size_t message_len) {
    if (out_field_element == nullptr) {
        return PURIFY_ERROR_MISSING_VALUE;
    }
    std::fill(out_field_element, out_field_element + PURIFY_FIELD_ELEMENT_BYTES, 0);
    if (message_len != 0 && message == nullptr) {
        return PURIFY_ERROR_MISSING_VALUE;
    }

    purify::Result<purify::UInt512> packed_secret = purify::capi_detail::parse_secret_key(secret_key);
    if (!packed_secret.has_value()) {
        return purify::core_api_detail::to_core_error_code(packed_secret.error().code);
    }

    purify::Result<std::pair<purify::UInt256, purify::UInt256>> unpacked = purify::unpack_secret(*packed_secret);
    if (!unpacked.has_value()) {
        return purify::core_api_detail::to_core_error_code(unpacked.error().code);
    }

    const purify::Bytes message_bytes = purify::capi_detail::copy_bytes(message, message_len);
    purify::Result<purify::JacobianPoint> m1 =
        purify::hash_to_curve(purify::capi_detail::tagged_message("Eval/1/", message_bytes), purify::curve1());
    if (!m1.has_value()) {
        return purify::core_api_detail::to_core_error_code(m1.error().code);
    }
    purify::Result<purify::JacobianPoint> m2 =
        purify::hash_to_curve(purify::capi_detail::tagged_message("Eval/2/", message_bytes), purify::curve2());
    if (!m2.has_value()) {
        return purify::core_api_detail::to_core_error_code(m2.error().code);
    }

    purify::Result<purify::AffinePoint> q1 =
        purify::curve1().mul_secret_affine(*m1, unpacked->first);
    if (!q1.has_value()) {
        return purify::core_api_detail::to_core_error_code(q1.error().code);
    }
    purify::Result<purify::AffinePoint> q2 =
        purify::curve2().mul_secret_affine(*m2, unpacked->second);
    if (!q2.has_value()) {
        return purify::core_api_detail::to_core_error_code(q2.error().code);
    }

    const purify::FieldElement output = purify::combine(q1->x, q2->x);
    purify::capi_detail::write_field_element(output, out_field_element);
    return PURIFY_ERROR_OK;
}

}  // extern "C"
