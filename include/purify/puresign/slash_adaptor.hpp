// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file purify/puresign/slash_adaptor.hpp
 * @brief Compact BIP340 adaptor receipts for coalition-triggered slashing.
 */

#pragma once

#include <array>
#include <cstddef>
#include <span>

#include "purify/api.hpp"

namespace purify::puresign {

using SlashMessageDigest = std::array<unsigned char, 32>;
using CoalitionScalar = std::array<unsigned char, 32>;
using SecpPoint = std::array<unsigned char, 33>;
using Bip340Signature = std::array<unsigned char, 64>;
using SlashAdaptorReceiptBytes = std::array<unsigned char, 65>;

/**
 * @brief A canonical even-Y coalition point.
 *
 * Requiring the full even compressed point makes an exposed scalar unambiguous:
 * `q`, rather than either representative of the x-only key, must satisfy
 * `q*G == point()`.
 */
class EvenCoalitionKey {
public:
  /** @brief Parses a finite canonical compressed point and requires even Y. */
  [[nodiscard]] static Result<EvenCoalitionKey>
  parse(const SecpPoint &point, purify_secp_context *secp_context);

  [[nodiscard]] const SecpPoint &point() const noexcept { return point_; }
  [[nodiscard]] const std::array<unsigned char, 32> &xonly() const noexcept {
    return xonly_;
  }

private:
  EvenCoalitionKey(const SecpPoint &point,
                   const std::array<unsigned char, 32> &xonly)
      : point_(point), xonly_(xonly) {}

  SecpPoint point_{};
  std::array<unsigned char, 32> xonly_{};
};

/**
 * @brief A 65-byte adaptor pre-signature `(A, s_hat)`.
 *
 * `A` retains its full SEC1 parity. The corresponding BIP340 nonce is the
 * even-Y representative of `A`; its parity selects whether adaptation adds or
 * subtracts the exact coalition scalar.
 */
struct SlashAdaptorReceipt {
  static constexpr std::size_t kSerializedSize = 65;

  SecpPoint adapted_nonce{};
  CoalitionScalar pre_response{};

  [[nodiscard]] SlashAdaptorReceiptBytes serialize() const noexcept;
  [[nodiscard]] static Result<SlashAdaptorReceipt>
  deserialize(std::span<const unsigned char> bytes,
              purify_secp_context *secp_context);
};

/**
 * @brief Creates an adaptor receipt with a hedged statement-bound nonce.
 *
 * The message must be the exact 32-byte Taproot signature digest of the slash
 * transaction authorized by this receipt. This primitive does not carry the
 * unsigned transaction. Bitcoin-only reconstruction therefore requires every
 * transaction and sighash field to be deterministic from on-chain data and
 * protocol constants, or separately made consensus-available.
 * The surrounding protocol record must separately bind the anchor identifier,
 * coalition core digest, and transaction-template version.
 *
 * Nonce derivation mixes fresh operating-system auxiliary randomness with the
 * canonical anchor secret and binds the anchor, coalition point, and message.
 * Repeated auxiliary randomness therefore cannot reuse a nonce across distinct
 * receipt statements.
 */
[[nodiscard]] Result<SlashAdaptorReceipt>
create_slash_adaptor_receipt(const Bip340Key &anchor_key,
                             const EvenCoalitionKey &coalition_key,
                             const SlashMessageDigest &message_digest,
                             purify_secp_context *secp_context);

/** @brief Verifies the exact adaptor equation for one receipt statement. */
[[nodiscard]] Result<bool>
verify_slash_adaptor_receipt(const SlashAdaptorReceipt &receipt,
                             const std::array<unsigned char, 32> &anchor_xonly,
                             const EvenCoalitionKey &coalition_key,
                             const SlashMessageDigest &message_digest,
                             purify_secp_context *secp_context);

/**
 * @brief Extracts the exact coalition scalar from a completed BIP340 signature.
 *
 * The final signature must verify for the exact receipt nonce, anchor, and
 * message. The extracted scalar is accepted only when its full public point
 * equals the registered even coalition point.
 */
[[nodiscard]] Result<CoalitionScalar>
extract_slash_adaptor_secret(const SlashAdaptorReceipt &receipt,
                             const Bip340Signature &final_signature,
                             const std::array<unsigned char, 32> &anchor_xonly,
                             const EvenCoalitionKey &coalition_key,
                             const SlashMessageDigest &message_digest,
                             purify_secp_context *secp_context);

} // namespace purify::puresign
