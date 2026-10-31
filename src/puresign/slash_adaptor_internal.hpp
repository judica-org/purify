// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include "purify/puresign/slash_adaptor.hpp"

namespace purify::puresign::detail {

/** Internal deterministic hedged constructor used by nonce-vector tests. */
[[nodiscard]] Result<SlashAdaptorReceipt>
create_slash_adaptor_receipt_with_aux_randomness(
    const Bip340Key &anchor_key, const EvenCoalitionKey &coalition_key,
    const SlashMessageDigest &message_digest,
    const CoalitionScalar &auxiliary_randomness,
    purify_secp_context *secp_context);

/**
 * Internal deterministic constructor used by fixed-vector tests.
 * Production callers must use create_slash_adaptor_receipt().
 */
[[nodiscard]] Result<SlashAdaptorReceipt>
create_slash_adaptor_receipt_with_nonce(
    const Bip340Key &anchor_key, const EvenCoalitionKey &coalition_key,
    const SlashMessageDigest &message_digest,
    const CoalitionScalar &nonce_scalar, purify_secp_context *secp_context);

/** Internal scalar adapter used until the accountable capability is present. */
[[nodiscard]] Result<Bip340Signature>
complete_slash_adaptor_receipt_with_scalar(
    const SlashAdaptorReceipt &receipt,
    const std::array<unsigned char, 32> &anchor_xonly,
    const EvenCoalitionKey &coalition_key,
    const SlashMessageDigest &message_digest,
    const CoalitionScalar &coalition_scalar, purify_secp_context *secp_context);

} // namespace purify::puresign::detail
