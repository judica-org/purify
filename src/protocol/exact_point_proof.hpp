// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file exact_point_proof.hpp
 * @brief Schnorr proof that a public point is a known multiple of the base generator.
 */

#pragma once

#include <array>
#include <span>

#include "purify/bppp.hpp"

namespace purify::bppp::detail {

/** Schnorr proof of knowledge of `v` with `point = v*G`. */
struct ExactPointProof {
  /** Even-Y x-only Schnorr nonce. */
  std::array<unsigned char, 32> nonce_xonly{};
  /** Schnorr response; canonical and nonzero in a valid proof. */
  ScalarBytes response{};
};

/**
 * Proves that `point` is `value*G`.
 *
 * `context` enters the challenge. The Schnorr nonce is derived from
 * `secret_prover_seed`, `value` and `context`, so one statement always yields
 * one proof.
 */
Result<ExactPointProof> prove_exact_point(
    const PointBytes &point, const FieldElement &value,
    std::span<const unsigned char> context,
    const ScalarBytes &secret_prover_seed, purify_secp_context *secp_context);

/**
 * Checks a proof from `prove_exact_point` for the same point and context.
 *
 * The response must already be a canonical scalar; a non-canonical one is an
 * error here, not a rejection.
 */
Result<bool> verify_exact_point(const PointBytes &point,
                                std::span<const unsigned char> context,
                                const ExactPointProof &proof,
                                purify_secp_context *secp_context);

} // namespace purify::bppp::detail
