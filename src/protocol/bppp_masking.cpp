// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file bppp_masking.cpp
 * @brief Mask derivation and mask arithmetic shared by the masked circuit provers.
 */

#include "bppp_masking.hpp"

namespace purify::bppp::detail {

Result<SecretVector<FieldElement>>
derive_secret_scalars(std::size_t count, std::span<const unsigned char> seed,
                      const TaggedHash &tag, std::uint64_t attempt) {
  SecretVector<FieldElement> out(count, FieldElement::zero());
  for (std::size_t i = 0; i < out.size(); ++i) {
    PURIFY_RETURN_IF_ERROR(derive_scalar(out[i], seed, tag, i, attempt));
  }
  return out;
}

SecretNormArgInputs
build_mask_inputs(const CircuitNormArgPublicData &public_data,
                  std::span<const FieldElement> mask_n,
                  std::span<const FieldElement> mask_l) {
  SecretNormArgInputs mask_inputs;
  mask_inputs.rho = public_data.rho_bytes;
  mask_inputs.generators = public_data.generators;
  mask_inputs.n_vec = scalar_bytes(mask_n);
  mask_inputs.l_vec = scalar_bytes(mask_l);
  mask_inputs.c_vec = public_data.c_vec_bytes;
  return mask_inputs;
}

CircuitNormArgReduction
mask_reduction(const CircuitNormArgReduction &hidden,
               const FieldElement &challenge,
               std::span<const FieldElement> mask_n,
               std::span<const FieldElement> mask_l) {
  CircuitNormArgReduction masked = hidden;
  for (std::size_t i = 0; i < masked.n_vec.size(); ++i) {
    masked.n_vec[i] = masked.n_vec[i] + challenge * mask_n[i];
  }
  for (std::size_t i = 0; i < masked.l_vec.size(); ++i) {
    masked.l_vec[i] = masked.l_vec[i] + challenge * mask_l[i];
  }
  return masked;
}

} // namespace purify::bppp::detail
