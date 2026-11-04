// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "purify/puresign/slash_adaptor.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <span>
#include <string_view>

#include "../bridge/bppp_bridge.h"
#include "purify/curve.hpp"
#include "slash_adaptor_internal.hpp"

namespace purify::puresign {
namespace {

constexpr std::size_t kScalarSize = 32;
constexpr std::size_t kPointSize = 33;
constexpr std::size_t kMaxSamplingAttempts = 256;
constexpr std::string_view kAuxiliaryTag = "Char/SlashAdaptor/aux/v1";
constexpr std::string_view kNonceTag = "Char/SlashAdaptor/nonce/v1";
constexpr SecpPoint kBasePoint{
    0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0,
    0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d,
    0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
};

class SecretBytes32 {
public:
  SecretBytes32() = default;
  SecretBytes32(const SecretBytes32 &) = delete;
  SecretBytes32 &operator=(const SecretBytes32 &) = delete;
  ~SecretBytes32() {
    ::purify::detail::secure_clear_bytes(value.data(), value.size());
  }

  CoalitionScalar value{};
};

class SecretScalar {
public:
  SecretScalar() = default;
  SecretScalar(const SecretScalar &) = delete;
  SecretScalar &operator=(const SecretScalar &) = delete;
  ~SecretScalar() {
    ::purify::detail::secure_clear_bytes(&value, sizeof(value));
  }

  purify_scalar value{};
};

std::array<unsigned char, 32> tag_hash(std::string_view tag) {
  std::array<unsigned char, 32> out{};
  purify_sha256(out.data(), reinterpret_cast<const unsigned char *>(tag.data()),
                tag.size());
  return out;
}

const std::array<unsigned char, 32> &auxiliary_tag_hash() {
  static const auto value = tag_hash(kAuxiliaryTag);
  return value;
}

const std::array<unsigned char, 32> &nonce_tag_hash() {
  static const auto value = tag_hash(kNonceTag);
  return value;
}

template <std::size_t N>
bool tagged_hash_into(
    const std::array<unsigned char, 32> &tag,
    const std::array<std::span<const unsigned char>, N> &segments,
    SecretBytes32 &out) {
  std::array<const unsigned char *, N + 2> items{};
  std::array<std::size_t, N + 2> lengths{};
  items[0] = tag.data();
  lengths[0] = tag.size();
  items[1] = tag.data();
  lengths[1] = tag.size();
  for (std::size_t i = 0; i < N; ++i) {
    items[i + 2] = segments[i].data();
    lengths[i + 2] = segments[i].size();
  }
  return purify_sha256_many(out.value.data(), items.data(), lengths.data(),
                            items.size()) != 0;
}

Status require_context(purify_secp_context *secp_context, const char *context) {
  if (secp_context == nullptr) {
    return unexpected_error(ErrorCode::MissingValue, context);
  }
  return {};
}

bool constant_equal(std::span<const unsigned char> lhs,
                    std::span<const unsigned char> rhs) noexcept {
  if (lhs.size() != rhs.size())
    return false;
  volatile unsigned char difference = 0;
  for (std::size_t i = 0; i < lhs.size(); ++i) {
    difference = static_cast<unsigned char>(
        difference | static_cast<unsigned char>(lhs[i] ^ rhs[i]));
  }
  return difference == 0;
}

bool parse_scalar(const CoalitionScalar &bytes, purify_scalar &scalar,
                  bool reject_zero) {
  int overflow = 0;
  purify_scalar_set_b32(&scalar, bytes.data(), &overflow);
  return overflow == 0 && (!reject_zero || purify_scalar_is_zero(&scalar) == 0);
}

SecpPoint negate_point(const SecpPoint &point) {
  SecpPoint out = point;
  out[0] = point[0] == 0x02 ? 0x03 : 0x02;
  return out;
}

SecpPoint even_lift(const std::array<unsigned char, 32> &xonly) {
  SecpPoint out{};
  out[0] = 0x02;
  std::copy(xonly.begin(), xonly.end(), out.begin() + 1);
  return out;
}

std::array<unsigned char, 32> point_xonly(const SecpPoint &point) {
  std::array<unsigned char, 32> out{};
  std::copy(point.begin() + 1, point.end(), out.begin());
  return out;
}

Result<int> validate_point(const SecpPoint &point,
                           purify_secp_context *secp_context,
                           const char *context) {
  std::array<unsigned char, 32> xonly{};
  int parity = 0;
  if (purify_bip340_xonly_from_point(secp_context, point.data(), xonly.data(),
                                     &parity) == 0) {
    return unexpected_error(ErrorCode::BackendRejectedInput, context);
  }
  return parity;
}

Status validate_receipt_encoding(const SlashAdaptorReceipt &receipt,
                                 purify_secp_context *secp_context) {
  auto parity = validate_point(receipt.adapted_nonce, secp_context,
                               "slash_adaptor:adapted_nonce");
  if (!parity.has_value()) {
    return unexpected_error(parity.error(), "slash_adaptor:adapted_nonce");
  }
  SecretScalar response;
  if (!parse_scalar(receipt.pre_response, response.value, false)) {
    return unexpected_error(ErrorCode::RangeViolation,
                            "slash_adaptor:pre_response");
  }
  return {};
}

Status validate_anchor_xonly(const std::array<unsigned char, 32> &anchor_xonly,
                             purify_secp_context *secp_context) {
  if (purify_bip340_validate_xonly_pubkey(secp_context, anchor_xonly.data()) ==
      0) {
    return unexpected_error(ErrorCode::BackendRejectedInput,
                            "slash_adaptor:anchor_xonly");
  }
  return {};
}

Status validate_anchor_key(const Bip340Key &anchor_key,
                           purify_secp_context *secp_context) {
  SecretBytes32 canonical_secret;
  canonical_secret.value = anchor_key.seckey;
  std::array<unsigned char, 32> canonical_xonly{};
  if (purify_bip340_key_from_seckey(secp_context, canonical_secret.value.data(),
                                    canonical_xonly.data()) == 0) {
    return unexpected_error(ErrorCode::RangeViolation,
                            "slash_adaptor:anchor_secret");
  }
  if (!constant_equal(canonical_secret.value, anchor_key.seckey) ||
      canonical_xonly != anchor_key.xonly_pubkey) {
    return unexpected_error(ErrorCode::BindingMismatch,
                            "slash_adaptor:anchor_key");
  }
  return {};
}

Status derive_nonce(const Bip340Key &anchor_key,
                    const EvenCoalitionKey &coalition_key,
                    const SlashMessageDigest &message_digest,
                    const CoalitionScalar &auxiliary_randomness,
                    std::uint32_t counter, SecretBytes32 &out) {
  SecretBytes32 auxiliary_digest;
  std::array auxiliary_segments{
      std::span<const unsigned char>(auxiliary_randomness),
  };
  if (!tagged_hash_into(auxiliary_tag_hash(), auxiliary_segments,
                        auxiliary_digest)) {
    return unexpected_error(ErrorCode::InternalMismatch,
                            "slash_adaptor:nonce_aux_hash");
  }

  SecretBytes32 masked_secret;
  for (std::size_t i = 0; i < masked_secret.value.size(); ++i) {
    masked_secret.value[i] = static_cast<unsigned char>(
        anchor_key.seckey[i] ^ auxiliary_digest.value[i]);
  }
  std::array<unsigned char, 4> counter_bytes{
      static_cast<unsigned char>(counter >> 24),
      static_cast<unsigned char>(counter >> 16),
      static_cast<unsigned char>(counter >> 8),
      static_cast<unsigned char>(counter),
  };
  std::array nonce_segments{
      std::span<const unsigned char>(masked_secret.value),
      std::span<const unsigned char>(anchor_key.xonly_pubkey),
      std::span<const unsigned char>(coalition_key.point()),
      std::span<const unsigned char>(message_digest),
      std::span<const unsigned char>(counter_bytes),
  };
  SecretBytes32 digest;
  if (!tagged_hash_into(nonce_tag_hash(), nonce_segments, digest)) {
    return unexpected_error(ErrorCode::InternalMismatch,
                            "slash_adaptor:nonce_hash");
  }
  SecretScalar scalar;
  purify_scalar_set_b32(&scalar.value, digest.value.data(), nullptr);
  if (purify_scalar_is_zero(&scalar.value) != 0) {
    return unexpected_error(ErrorCode::EquationMismatch,
                            "slash_adaptor:zero_nonce");
  }
  purify_scalar_get_b32(out.value.data(), &scalar.value);
  return {};
}

purify_scalar
challenge_scalar(const SecpPoint &even_nonce,
                 const std::array<unsigned char, 32> &anchor_xonly,
                 const SlashMessageDigest &message_digest) {
  static const TaggedHash kChallengeTag("BIP0340/challenge");
  const auto nonce_xonly = point_xonly(even_nonce);
  std::array segments{
      std::span<const unsigned char>(nonce_xonly),
      std::span<const unsigned char>(anchor_xonly),
      std::span<const unsigned char>(message_digest),
  };
  const auto digest = kChallengeTag.digest_many(segments);
  purify_scalar out{};
  purify_scalar_set_b32(&out, digest.data(), nullptr);
  return out;
}

Result<SecpPoint> scalar_base_point(const CoalitionScalar &scalar,
                                    purify_secp_context *secp_context) {
  SecpPoint out{};
  if (purify_point_scale(secp_context, kBasePoint.data(), scalar.data(),
                         out.data()) == 0) {
    return unexpected_error(ErrorCode::BackendRejectedInput,
                            "slash_adaptor:scalar_base_point");
  }
  return out;
}

Status validate_exposed_scalar(const CoalitionScalar &scalar,
                               const EvenCoalitionKey &coalition_key,
                               purify_secp_context *secp_context) {
  SecretScalar parsed;
  if (!parse_scalar(scalar, parsed.value, true)) {
    return unexpected_error(ErrorCode::RangeViolation,
                            "slash_adaptor:coalition_scalar");
  }
  auto point = scalar_base_point(scalar, secp_context);
  if (!point.has_value()) {
    return unexpected_error(point.error(), "slash_adaptor:coalition_point");
  }
  if (*point != coalition_key.point()) {
    return unexpected_error(ErrorCode::BindingMismatch,
                            "slash_adaptor:coalition_scalar_binding");
  }
  return {};
}

Result<bool> verify_equation(const SlashAdaptorReceipt &receipt,
                             const std::array<unsigned char, 32> &anchor_xonly,
                             const EvenCoalitionKey &coalition_key,
                             const SlashMessageDigest &message_digest,
                             purify_secp_context *secp_context) {
  const SecpPoint negative_coalition = negate_point(coalition_key.point());
  SecpPoint unadapted_nonce{};
  if (purify_point_add(secp_context, receipt.adapted_nonce.data(),
                       negative_coalition.data(),
                       unadapted_nonce.data()) == 0) {
    // A == Q implies K == infinity and s_hat == e*x, directly exposing
    // the anchor signing key whenever the challenge is nonzero.
    return unexpected_error(ErrorCode::RangeViolation,
                            "slash_adaptor:zero_unadapted_nonce");
  }
  const int parity = receipt.adapted_nonce[0] == 0x03 ? 1 : 0;
  const SecpPoint signed_nonce =
      parity == 0 ? unadapted_nonce : negate_point(unadapted_nonce);
  const SecpPoint anchor_point = even_lift(anchor_xonly);

  SecretScalar challenge;
  const SecpPoint even_nonce =
      parity == 0 ? receipt.adapted_nonce : negate_point(receipt.adapted_nonce);
  challenge.value = challenge_scalar(even_nonce, anchor_xonly, message_digest);

  SecpPoint right_hand_side = signed_nonce;
  bool right_hand_side_is_infinity = false;
  if (purify_scalar_is_zero(&challenge.value) == 0) {
    CoalitionScalar challenge_bytes{};
    purify_scalar_get_b32(challenge_bytes.data(), &challenge.value);
    SecpPoint challenge_key{};
    if (purify_point_scale(secp_context, anchor_point.data(),
                           challenge_bytes.data(), challenge_key.data()) == 0) {
      return unexpected_error(ErrorCode::BackendRejectedInput,
                              "slash_adaptor:verify_challenge_key");
    }
    SecpPoint combined{};
    if (purify_point_add(secp_context, right_hand_side.data(),
                         challenge_key.data(), combined.data()) == 0) {
      // Both terms are finite and valid, so failure means their sum is
      // the point at infinity.
      right_hand_side_is_infinity = true;
    } else {
      right_hand_side = combined;
    }
  }

  SecretScalar pre_response;
  if (!parse_scalar(receipt.pre_response, pre_response.value, false)) {
    return unexpected_error(ErrorCode::InternalMismatch,
                            "slash_adaptor:verify_response");
  }
  if (purify_scalar_is_zero(&pre_response.value) != 0) {
    return right_hand_side_is_infinity;
  }
  if (right_hand_side_is_infinity)
    return false;
  auto left_hand_side = scalar_base_point(receipt.pre_response, secp_context);
  if (!left_hand_side.has_value()) {
    return unexpected_error(left_hand_side.error(),
                            "slash_adaptor:verify_response_point");
  }
  return *left_hand_side == right_hand_side;
}

} // namespace

Result<EvenCoalitionKey>
EvenCoalitionKey::parse(const SecpPoint &point,
                        purify_secp_context *secp_context) {
  PURIFY_RETURN_IF_ERROR(
      require_context(secp_context, "EvenCoalitionKey::parse:context"),
      "EvenCoalitionKey::parse:context");
  auto parity =
      validate_point(point, secp_context, "EvenCoalitionKey::parse:point");
  if (!parity.has_value()) {
    return unexpected_error(parity.error(), "EvenCoalitionKey::parse:point");
  }
  if (*parity != 0 || point[0] != 0x02) {
    return unexpected_error(ErrorCode::RangeViolation,
                            "EvenCoalitionKey::parse:parity");
  }
  return EvenCoalitionKey(point, point_xonly(point));
}

SlashAdaptorReceiptBytes SlashAdaptorReceipt::serialize() const noexcept {
  SlashAdaptorReceiptBytes out{};
  std::copy(adapted_nonce.begin(), adapted_nonce.end(), out.begin());
  std::copy(pre_response.begin(), pre_response.end(),
            out.begin() + static_cast<std::ptrdiff_t>(kPointSize));
  return out;
}

Result<SlashAdaptorReceipt>
SlashAdaptorReceipt::deserialize(std::span<const unsigned char> bytes,
                                 purify_secp_context *secp_context) {
  PURIFY_RETURN_IF_ERROR(
      require_context(secp_context, "SlashAdaptorReceipt::deserialize:context"),
      "SlashAdaptorReceipt::deserialize:context");
  if (bytes.size() != kSerializedSize) {
    return unexpected_error(ErrorCode::InvalidFixedSize,
                            "SlashAdaptorReceipt::deserialize:size");
  }
  SlashAdaptorReceipt out{};
  std::copy_n(bytes.begin(), kPointSize, out.adapted_nonce.begin());
  std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(kPointSize),
              kScalarSize, out.pre_response.begin());
  PURIFY_RETURN_IF_ERROR(validate_receipt_encoding(out, secp_context),
                         "SlashAdaptorReceipt::deserialize:encoding");
  return out;
}

Result<SlashAdaptorReceipt> detail::create_slash_adaptor_receipt_with_nonce(
    const Bip340Key &anchor_key, const EvenCoalitionKey &coalition_key,
    const SlashMessageDigest &message_digest,
    const CoalitionScalar &nonce_scalar, purify_secp_context *secp_context) {
  PURIFY_RETURN_IF_ERROR(
      require_context(secp_context, "slash_adaptor:create:context"),
      "slash_adaptor:create:context");
  PURIFY_RETURN_IF_ERROR(validate_anchor_key(anchor_key, secp_context),
                         "slash_adaptor:create:anchor_key");

  SecretScalar nonce;
  if (!parse_scalar(nonce_scalar, nonce.value, true)) {
    return unexpected_error(ErrorCode::RangeViolation,
                            "slash_adaptor:create:nonce");
  }
  auto nonce_point = scalar_base_point(nonce_scalar, secp_context);
  if (!nonce_point.has_value()) {
    return unexpected_error(nonce_point.error(),
                            "slash_adaptor:create:nonce_point");
  }
  SecpPoint adapted_nonce{};
  if (purify_point_add(secp_context, nonce_point->data(),
                       coalition_key.point().data(),
                       adapted_nonce.data()) == 0) {
    // Both inputs were parsed and produced by this backend. Addition can
    // fail here only for K == -Q, which makes the adaptor nonce infinity.
    return unexpected_error(ErrorCode::EquationMismatch,
                            "slash_adaptor:create:infinity");
  }
  auto parity = validate_point(adapted_nonce, secp_context,
                               "slash_adaptor:create:adapted_nonce");
  if (!parity.has_value()) {
    return unexpected_error(parity.error(),
                            "slash_adaptor:create:adapted_nonce");
  }
  const SecpPoint even_nonce =
      *parity == 0 ? adapted_nonce : negate_point(adapted_nonce);

  SecretScalar canonical_nonce;
  canonical_nonce.value = nonce.value;
  if (*parity != 0) {
    purify_scalar_negate(&canonical_nonce.value, &canonical_nonce.value);
  }
  SecretScalar challenge;
  challenge.value =
      challenge_scalar(even_nonce, anchor_key.xonly_pubkey, message_digest);
  SecretScalar anchor_secret;
  if (!parse_scalar(anchor_key.seckey, anchor_secret.value, true)) {
    return unexpected_error(ErrorCode::InternalMismatch,
                            "slash_adaptor:create:canonical_anchor");
  }
  SecretScalar challenge_term;
  purify_scalar_mul(&challenge_term.value, &challenge.value,
                    &anchor_secret.value);
  SecretScalar pre_response;
  purify_scalar_add(&pre_response.value, &canonical_nonce.value,
                    &challenge_term.value);

  SlashAdaptorReceipt out{};
  out.adapted_nonce = adapted_nonce;
  purify_scalar_get_b32(out.pre_response.data(), &pre_response.value);
  auto verified =
      verify_slash_adaptor_receipt(out, anchor_key.xonly_pubkey, coalition_key,
                                   message_digest, secp_context);
  if (!verified.has_value() || !*verified) {
    return unexpected_error(verified.has_value() ? ErrorCode::InternalMismatch
                                                 : verified.error().code,
                            "slash_adaptor:create:self_verify");
  }
  return out;
}

Result<SlashAdaptorReceipt>
create_slash_adaptor_receipt(const Bip340Key &anchor_key,
                             const EvenCoalitionKey &coalition_key,
                             const SlashMessageDigest &message_digest,
                             purify_secp_context *secp_context) {
  PURIFY_RETURN_IF_ERROR(
      require_context(secp_context, "slash_adaptor:create:context"),
      "slash_adaptor:create:context");
  SecretBytes32 auxiliary_randomness;
  PURIFY_RETURN_IF_ERROR(fill_secure_random(auxiliary_randomness.value),
                         "slash_adaptor:create:auxiliary_randomness");
  return detail::create_slash_adaptor_receipt_with_aux_randomness(
      anchor_key, coalition_key, message_digest, auxiliary_randomness.value,
      secp_context);
}

Result<SlashAdaptorReceipt>
detail::create_slash_adaptor_receipt_with_aux_randomness(
    const Bip340Key &anchor_key, const EvenCoalitionKey &coalition_key,
    const SlashMessageDigest &message_digest,
    const CoalitionScalar &auxiliary_randomness,
    purify_secp_context *secp_context) {
  PURIFY_RETURN_IF_ERROR(
      require_context(secp_context, "slash_adaptor:create_aux:context"),
      "slash_adaptor:create_aux:context");
  PURIFY_RETURN_IF_ERROR(validate_anchor_key(anchor_key, secp_context),
                         "slash_adaptor:create_aux:anchor_key");
  for (std::size_t attempt = 0; attempt < kMaxSamplingAttempts; ++attempt) {
    SecretBytes32 nonce;
    auto derived = derive_nonce(anchor_key, coalition_key, message_digest,
                                auxiliary_randomness,
                                static_cast<std::uint32_t>(attempt), nonce);
    if (!derived.has_value()) {
      if (derived.error().code == ErrorCode::EquationMismatch)
        continue;
      return unexpected_error(derived.error(),
                              "slash_adaptor:create_aux:derive_nonce");
    }
    auto result = detail::create_slash_adaptor_receipt_with_nonce(
        anchor_key, coalition_key, message_digest, nonce.value, secp_context);
    if (result.has_value())
      return result;
    if (result.error().code != ErrorCode::EquationMismatch) {
      return unexpected_error(result.error(),
                              "slash_adaptor:create:fixed_nonce");
    }
  }
  return unexpected_error(ErrorCode::HashToCurveExhausted,
                          "slash_adaptor:create_aux:exhausted");
}

Result<bool>
verify_slash_adaptor_receipt(const SlashAdaptorReceipt &receipt,
                             const std::array<unsigned char, 32> &anchor_xonly,
                             const EvenCoalitionKey &coalition_key,
                             const SlashMessageDigest &message_digest,
                             purify_secp_context *secp_context) {
  PURIFY_RETURN_IF_ERROR(
      require_context(secp_context, "slash_adaptor:verify:context"),
      "slash_adaptor:verify:context");
  PURIFY_RETURN_IF_ERROR(validate_anchor_xonly(anchor_xonly, secp_context),
                         "slash_adaptor:verify:anchor");
  PURIFY_RETURN_IF_ERROR(validate_receipt_encoding(receipt, secp_context),
                         "slash_adaptor:verify:receipt");
  return verify_equation(receipt, anchor_xonly, coalition_key, message_digest,
                         secp_context);
}

Result<Bip340Signature> detail::complete_slash_adaptor_receipt_with_scalar(
    const SlashAdaptorReceipt &receipt,
    const std::array<unsigned char, 32> &anchor_xonly,
    const EvenCoalitionKey &coalition_key,
    const SlashMessageDigest &message_digest,
    const CoalitionScalar &coalition_scalar,
    purify_secp_context *secp_context) {
  auto verified = verify_slash_adaptor_receipt(
      receipt, anchor_xonly, coalition_key, message_digest, secp_context);
  if (!verified.has_value()) {
    return unexpected_error(verified.error(), "slash_adaptor:complete:verify");
  }
  if (!*verified) {
    return unexpected_error(ErrorCode::EquationMismatch,
                            "slash_adaptor:complete:equation");
  }
  PURIFY_RETURN_IF_ERROR(
      validate_exposed_scalar(coalition_scalar, coalition_key, secp_context),
      "slash_adaptor:complete:coalition_scalar");

  SecretScalar pre_response;
  SecretScalar exposed;
  SecretScalar completed;
  if (!parse_scalar(receipt.pre_response, pre_response.value, false) ||
      !parse_scalar(coalition_scalar, exposed.value, true)) {
    return unexpected_error(ErrorCode::InternalMismatch,
                            "slash_adaptor:complete:validated_scalars");
  }
  if (receipt.adapted_nonce[0] == 0x03) {
    purify_scalar_negate(&exposed.value, &exposed.value);
  }
  purify_scalar_add(&completed.value, &pre_response.value, &exposed.value);

  Bip340Signature out{};
  std::copy(receipt.adapted_nonce.begin() + 1, receipt.adapted_nonce.end(),
            out.begin());
  purify_scalar_get_b32(out.data() + kScalarSize, &completed.value);
  if (purify_bip340_verify(secp_context, out.data(), message_digest.data(),
                           message_digest.size(), anchor_xonly.data()) == 0) {
    return unexpected_error(ErrorCode::InternalMismatch,
                            "slash_adaptor:complete:final_verify");
  }
  return out;
}

Result<CoalitionScalar>
extract_slash_adaptor_secret(const SlashAdaptorReceipt &receipt,
                             const Bip340Signature &final_signature,
                             const std::array<unsigned char, 32> &anchor_xonly,
                             const EvenCoalitionKey &coalition_key,
                             const SlashMessageDigest &message_digest,
                             purify_secp_context *secp_context) {
  auto verified = verify_slash_adaptor_receipt(
      receipt, anchor_xonly, coalition_key, message_digest, secp_context);
  if (!verified.has_value()) {
    return unexpected_error(verified.error(), "slash_adaptor:extract:receipt");
  }
  if (!*verified) {
    return unexpected_error(ErrorCode::EquationMismatch,
                            "slash_adaptor:extract:equation");
  }
  if (purify_bip340_validate_signature(secp_context, final_signature.data()) ==
      0) {
    return unexpected_error(ErrorCode::RangeViolation,
                            "slash_adaptor:extract:signature_encoding");
  }
  if (purify_bip340_verify(secp_context, final_signature.data(),
                           message_digest.data(), message_digest.size(),
                           anchor_xonly.data()) == 0) {
    return unexpected_error(ErrorCode::EquationMismatch,
                            "slash_adaptor:extract:signature");
  }
  if (!constant_equal(
          std::span<const unsigned char>(final_signature).first(kScalarSize),
          std::span<const unsigned char>(receipt.adapted_nonce).subspan(1))) {
    return unexpected_error(ErrorCode::BindingMismatch,
                            "slash_adaptor:extract:nonce");
  }

  SecretScalar response;
  SecretScalar pre_response;
  SecretScalar difference;
  CoalitionScalar response_bytes{};
  std::copy(final_signature.begin() + static_cast<std::ptrdiff_t>(kScalarSize),
            final_signature.end(), response_bytes.begin());
  if (!parse_scalar(response_bytes, response.value, false) ||
      !parse_scalar(receipt.pre_response, pre_response.value, false)) {
    return unexpected_error(ErrorCode::InternalMismatch,
                            "slash_adaptor:extract:validated_scalars");
  }
  purify_scalar_negate(&pre_response.value, &pre_response.value);
  purify_scalar_add(&difference.value, &response.value, &pre_response.value);
  if (receipt.adapted_nonce[0] == 0x03) {
    purify_scalar_negate(&difference.value, &difference.value);
  }
  CoalitionScalar out{};
  purify_scalar_get_b32(out.data(), &difference.value);
  PURIFY_RETURN_IF_ERROR(
      validate_exposed_scalar(out, coalition_key, secp_context),
      "slash_adaptor:extract:coalition_scalar");
  return out;
}

} // namespace purify::puresign
