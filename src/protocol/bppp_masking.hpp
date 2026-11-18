// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file bppp_masking.hpp
 * @brief The draw-and-retry skeleton and mask arithmetic shared by the masked circuit provers.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <utility>

#include "bppp_circuit_reduction.hpp"
#include "bppp_support.hpp"
#include "purify/bppp.hpp"

namespace purify::bppp {

namespace detail {

/** Masking draws a prover makes before giving up. */
inline constexpr std::uint64_t kMaskingAttempts = 32;

/**
 * Outcome of one masking attempt.
 *
 * A proof ends the search. Without one the prover draws fresh blinding
 * scalars and tries again; `rejection` is the backend's reason for refusing
 * this draw, when it gave one.
 */
template <typename Proof> struct MaskingAttempt {
  std::optional<Proof> proof;
  std::optional<Error> rejection;

  static MaskingAttempt accepted(Proof value) {
    return MaskingAttempt{std::move(value), std::nullopt};
  }
  static MaskingAttempt rejected(Error reason) {
    return MaskingAttempt{std::nullopt, reason};
  }
  static MaskingAttempt redraw() { return MaskingAttempt{}; }
};

/**
 * Runs `attempt(0)`, `attempt(1)`, ... and returns the first proof.
 *
 * An error returned by an attempt ends the search with that error. If every
 * attempt is refused, the first recorded rejection is reported.
 */
template <typename Proof, typename Attempt>
Result<Proof> first_accepted_masking(Attempt &&attempt) {
  std::optional<Error> first_rejection;
  for (std::uint64_t index = 0; index < kMaskingAttempts; ++index) {
    PURIFY_ASSIGN_OR_RETURN(auto outcome, attempt(index));
    if (outcome.proof.has_value()) {
      return std::move(*outcome.proof);
    }
    if (outcome.rejection.has_value() && !first_rejection.has_value()) {
      first_rejection = outcome.rejection;
    }
  }
  if (first_rejection.has_value()) {
    return unexpected_error(*first_rejection);
  }
  return unexpected_error(ErrorCode::BackendRejectedInput);
}

/** Derives `count` secret scalars; the i-th is bound to `(seed, tag, i, attempt)`. */
Result<SecretVector<FieldElement>>
derive_secret_scalars(std::size_t count, std::span<const unsigned char> seed,
                      const TaggedHash &tag, std::uint64_t attempt);

/** Norm-argument inputs committing to the mask vectors under a reduction's public data. */
SecretNormArgInputs
build_mask_inputs(const CircuitNormArgPublicData &public_data,
                  std::span<const FieldElement> mask_n,
                  std::span<const FieldElement> mask_l);

/** The reduced witness plus `challenge` times the mask, entry by entry. */
CircuitNormArgReduction
mask_reduction(const CircuitNormArgReduction &hidden,
               const FieldElement &challenge,
               std::span<const FieldElement> mask_n,
               std::span<const FieldElement> mask_l);

} // namespace detail

} // namespace purify::bppp
