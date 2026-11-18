// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file bppp.cpp
 * @brief Generators, Pedersen commitments and the standalone BPPP norm argument over the C bridge.
 */

#include "purify/bppp.hpp"

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <optional>
#include <span>
#include <type_traits>
#include <utility>
#include <vector>

#include "algebraic_circuit_proof.hpp"
#include "bppp_bridge.h"
#include "bppp_norm_arg.hpp"
#include "bppp_support.hpp"
#include "byte_io.hpp"
#include "purify/secp_bridge.h"

namespace purify::bppp {

// Helpers shared between the translation units of this module live in detail.
using namespace detail;

namespace {

template <typename Inputs>
Result<NormArgProof>
prove_norm_arg_impl(Inputs &&inputs,
                    purify_secp_context *secp_context,
                    ExperimentalCircuitBackend *cache = nullptr) {
  PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context));
  if (inputs.n_vec.empty() || inputs.l_vec.empty() || inputs.c_vec.empty()) {
    return unexpected_error(ErrorCode::EmptyInput);
  }
  if (inputs.l_vec.size() != inputs.c_vec.size()) {
    return unexpected_error(ErrorCode::SizeMismatch);
  }

  const std::vector<PointBytes> *generators = &inputs.generators;
  std::vector<PointBytes> generated_generators;
  if (generators->empty()) {
    PURIFY_ASSIGN_OR_RETURN(
        auto generated,
        create_generators(inputs.n_vec.size() + inputs.l_vec.size(),
                          secp_context));
    generated_generators = std::move(generated);
    generators = &generated_generators;
  }
  std::span<const unsigned char> n_vec = byte_span(inputs.n_vec);
  std::span<const unsigned char> l_vec = byte_span(inputs.l_vec);
  std::span<const unsigned char> c_vec = byte_span(inputs.c_vec);
  ResolvedBpppGeneratorBackend resolved =
      resolve_bppp_generator_backend(cache, *generators, secp_context);
  std::size_t proof_len =
      purify_bppp_required_proof_size(inputs.n_vec.size(), inputs.c_vec.size());
  PointBytes commitment{};
  Bytes proof(proof_len);

  if (proof_len == 0) {
    return unexpected_error(ErrorCode::InvalidDimensions);
  }
  const int ok =
      resolved.backend_resources != nullptr
          ? purify_bppp_prove_norm_arg_with_resources(
                resolved.backend_resources, inputs.rho.data(), n_vec.data(),
                inputs.n_vec.size(), l_vec.data(), inputs.l_vec.size(),
                c_vec.data(), inputs.c_vec.size(), commitment.data(),
                proof.data(), &proof_len)
          : purify_bppp_prove_norm_arg(
                secp_context, inputs.rho.data(), resolved.serialized_bytes.data(),
                resolved.generator_count, n_vec.data(), inputs.n_vec.size(),
                l_vec.data(), inputs.l_vec.size(), c_vec.data(),
                inputs.c_vec.size(), commitment.data(), proof.data(),
                &proof_len);
  if (ok == 0) {
    return unexpected_error(ErrorCode::BackendRejectedInput);
  }
  proof.resize(proof_len);

  std::vector<PointBytes> proof_generators;
  if (!generated_generators.empty()) {
    proof_generators = std::move(generated_generators);
  } else if constexpr (!std::is_const_v<std::remove_reference_t<Inputs>> &&
                       std::is_rvalue_reference_v<Inputs &&>) {
    proof_generators = std::move(inputs.generators);
  } else {
    proof_generators = inputs.generators;
  }

  std::vector<ScalarBytes> proof_c_vec;
  if constexpr (!std::is_const_v<std::remove_reference_t<Inputs>> &&
                std::is_rvalue_reference_v<Inputs &&>) {
    proof_c_vec = std::move(inputs.c_vec);
  } else {
    proof_c_vec = inputs.c_vec;
  }

  return NormArgProof{inputs.rho,
                      std::move(proof_generators),
                      std::move(proof_c_vec),
                      inputs.n_vec.size(),
                      commitment,
                      std::move(proof)};
}

} // namespace

GeneratorBytes base_generator(purify_secp_context *secp_context) {
  GeneratorBytes out{};
  bool ok = secp_context != nullptr
            && purify_bppp_base_generator(secp_context, out.data()) != 0;
  assert(ok && "base_generator() requires a functioning backend");
  (void)ok;
  return out;
}

GeneratorBytes value_generator_h(purify_secp_context *secp_context) {
  GeneratorBytes out{};
  bool ok = secp_context != nullptr
            && purify_bppp_value_generator_h(secp_context, out.data()) != 0;
  assert(ok && "value_generator_h() requires a functioning backend");
  (void)ok;
  return out;
}

Result<std::vector<PointBytes>> create_generators(std::size_t count,
                                                  purify_secp_context *secp_context) {
  std::vector<PointBytes> out(count);
  if (count == 0) {
    return out;
  }
  PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context));
  std::span<unsigned char> serialized = writable_byte_span(out);
  std::size_t serialized_len = serialized.size();
  if (purify_bppp_create_generators(secp_context, count, serialized.data(),
                                   &serialized_len) == 0) {
    return unexpected_error(ErrorCode::BackendRejectedInput);
  }
  if (serialized_len != serialized.size()) {
    return unexpected_error(ErrorCode::UnexpectedSize);
  }
  return out;
}

Result<PointBytes>
commit_norm_arg_with_cache(const NormArgInputs &inputs,
                           purify_secp_context *secp_context,
                           ExperimentalCircuitBackend *cache) {
  PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context));
  if (inputs.n_vec.empty() || inputs.l_vec.empty() || inputs.c_vec.empty()) {
    return unexpected_error(ErrorCode::EmptyInput);
  }
  if (inputs.l_vec.size() != inputs.c_vec.size()) {
    return unexpected_error(ErrorCode::SizeMismatch);
  }

  const std::vector<PointBytes> *generators = &inputs.generators;
  std::vector<PointBytes> generated_generators;
  if (generators->empty()) {
    PURIFY_ASSIGN_OR_RETURN(
        auto generated,
        create_generators(inputs.n_vec.size() + inputs.l_vec.size(),
                          secp_context));
    generated_generators = std::move(generated);
    generators = &generated_generators;
  }

  std::span<const unsigned char> n_vec = byte_span(inputs.n_vec);
  std::span<const unsigned char> l_vec = byte_span(inputs.l_vec);
  std::span<const unsigned char> c_vec = byte_span(inputs.c_vec);
  ResolvedBpppGeneratorBackend resolved =
      resolve_bppp_generator_backend(cache, *generators, secp_context);
  PointBytes commitment{};
  const int ok =
      resolved.backend_resources != nullptr
          ? purify_bppp_commit_norm_arg_with_resources(
                resolved.backend_resources, inputs.rho.data(), n_vec.data(),
                inputs.n_vec.size(), l_vec.data(), inputs.l_vec.size(),
                c_vec.data(), inputs.c_vec.size(), commitment.data())
          : purify_bppp_commit_norm_arg(
                secp_context, inputs.rho.data(), resolved.serialized_bytes.data(),
                resolved.generator_count, n_vec.data(), inputs.n_vec.size(),
                l_vec.data(), inputs.l_vec.size(), c_vec.data(),
                inputs.c_vec.size(), commitment.data());
  if (ok == 0) {
    return unexpected_error(ErrorCode::BackendRejectedInput);
  }
  return commitment;
}

Result<PointBytes> pedersen_commit_char(const ScalarBytes &blind,
                                        const ScalarBytes &value,
                                        purify_secp_context *secp_context) {
  return pedersen_commit_char(blind, value, secp_context,
                              value_generator_h(secp_context),
                              base_generator(secp_context));
}

Result<PointBytes> pedersen_commit_char(const ScalarBytes &blind,
                                        const ScalarBytes &value,
                                        purify_secp_context *secp_context,
                                        const GeneratorBytes &value_gen,
                                        const GeneratorBytes &blind_gen) {
  PointBytes commitment{};
  PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context));
  if (purify_pedersen_commit_char(
          secp_context, blind.data(), value.data(), value_gen.data(), blind_gen.data(),
          commitment.data()) == 0) {
    return unexpected_error(ErrorCode::BackendRejectedInput);
  }
  return commitment;
}

Result<NormArgProof> prove_norm_arg(const NormArgInputs &inputs,
                                    purify_secp_context *secp_context) {
  return prove_norm_arg_impl(inputs, secp_context, nullptr);
}

Result<NormArgProof> prove_norm_arg(NormArgInputs &&inputs,
                                    purify_secp_context *secp_context) {
  return prove_norm_arg_impl(std::move(inputs), secp_context, nullptr);
}

Result<NormArgProof> prove_norm_arg_to_commitment_with_cache(
    const NormArgInputs &inputs, const PointBytes &commitment,
    purify_secp_context *secp_context,
    ExperimentalCircuitBackend *cache) {
  PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context));
  if (inputs.n_vec.empty() || inputs.l_vec.empty() || inputs.c_vec.empty()) {
    return unexpected_error(ErrorCode::EmptyInput);
  }
  if (inputs.l_vec.size() != inputs.c_vec.size()) {
    return unexpected_error(ErrorCode::SizeMismatch);
  }

  const std::vector<PointBytes> *generators = &inputs.generators;
  std::vector<PointBytes> generated_generators;
  if (generators->empty()) {
    PURIFY_ASSIGN_OR_RETURN(
        auto generated,
        create_generators(inputs.n_vec.size() + inputs.l_vec.size(),
                          secp_context));
    generated_generators = std::move(generated);
    generators = &generated_generators;
  }

  std::span<const unsigned char> n_vec = byte_span(inputs.n_vec);
  std::span<const unsigned char> l_vec = byte_span(inputs.l_vec);
  std::span<const unsigned char> c_vec = byte_span(inputs.c_vec);
  ResolvedBpppGeneratorBackend resolved =
      resolve_bppp_generator_backend(cache, *generators, secp_context);
  std::size_t proof_len =
      purify_bppp_required_proof_size(inputs.n_vec.size(), inputs.c_vec.size());
  Bytes proof(proof_len);
  if (proof_len == 0) {
    return unexpected_error(ErrorCode::InvalidDimensions);
  }
  const int ok =
      resolved.backend_resources != nullptr
          ? purify_bppp_prove_norm_arg_to_commitment_with_resources(
                resolved.backend_resources, inputs.rho.data(), n_vec.data(),
                inputs.n_vec.size(), l_vec.data(), inputs.l_vec.size(),
                c_vec.data(), inputs.c_vec.size(), commitment.data(),
                proof.data(), &proof_len)
          : purify_bppp_prove_norm_arg_to_commitment(
                secp_context, inputs.rho.data(),
                resolved.serialized_bytes.data(),
                resolved.generator_count, n_vec.data(), inputs.n_vec.size(),
                l_vec.data(), inputs.l_vec.size(), c_vec.data(),
                inputs.c_vec.size(), commitment.data(), proof.data(),
                &proof_len);
  if (ok == 0) {
    return unexpected_error(ErrorCode::BackendRejectedInput);
  }
  proof.resize(proof_len);

  std::vector<PointBytes> proof_generators;
  if (!generated_generators.empty()) {
    proof_generators = std::move(generated_generators);
  } else {
    proof_generators = inputs.generators;
  }
  return NormArgProof{inputs.rho,   std::move(proof_generators),
                      inputs.c_vec, inputs.n_vec.size(),
                      commitment,   std::move(proof)};
}

struct CircuitNormRoundCallback {
  candidate::CircuitProofTranscriptV4 *transcript = nullptr;
  purify_secp_context *secp_context = nullptr;
  std::vector<candidate::PackedPointPairV4> rounds;
  std::optional<Error> error;
};

int append_circuit_norm_round(void *callback_data,
                              const unsigned char point_pair65[65],
                              size_t round,
                              unsigned char challenge32[32]) {
  auto &callback = *static_cast<CircuitNormRoundCallback *>(callback_data);
  if (round != callback.rounds.size()) {
    return 0;
  }
  candidate::PackedPointPairV4 pair{};
  std::copy_n(point_pair65, pair.size(), pair.begin());
  auto challenge =
      callback.transcript->append_round(pair, callback.secp_context);
  if (!challenge.has_value()) {
    callback.error = challenge.error();
    return 0;
  }
  const ScalarBytes encoded = challenge->scalar.to_bytes_be();
  std::copy(encoded.begin(), encoded.end(), challenge32);
  callback.rounds.push_back(pair);
  return 1;
}

Result<NormArgProof> prove_norm_arg_to_commitment_v4(
    const NormArgInputs &inputs, const PointBytes &commitment,
    candidate::CircuitProofTranscriptV4 &transcript,
    purify_secp_context *secp_context) {
  if (inputs.n_vec.empty() || inputs.l_vec.empty() || inputs.c_vec.empty() ||
      inputs.l_vec.size() != inputs.c_vec.size() ||
      inputs.generators.size() !=
          inputs.n_vec.size() + inputs.l_vec.size()) {
    return unexpected_error(ErrorCode::InvalidDimensions);
  }
  const std::size_t proof_capacity = purify_bppp_required_proof_size(
      inputs.n_vec.size(), inputs.c_vec.size());
  if (proof_capacity == 0) {
    return unexpected_error(ErrorCode::InvalidDimensions);
  }

  Bytes proof(proof_capacity);
  std::size_t proof_len = proof.size();
  CircuitNormRoundCallback callback{&transcript, secp_context, {}, {}};
  const std::span<const unsigned char> generators =
      byte_span(inputs.generators);
  const std::span<const unsigned char> n_vec = byte_span(inputs.n_vec);
  const std::span<const unsigned char> l_vec = byte_span(inputs.l_vec);
  const std::span<const unsigned char> c_vec = byte_span(inputs.c_vec);
  const int ok = purify_bppp_prove_norm_arg_to_commitment_with_callback(
      secp_context, inputs.rho.data(), generators.data(),
      inputs.generators.size(), n_vec.data(), inputs.n_vec.size(),
      l_vec.data(), inputs.l_vec.size(), c_vec.data(), inputs.c_vec.size(),
      commitment.data(), append_circuit_norm_round, &callback, proof.data(),
      &proof_len);
  if (ok == 0) {
    if (callback.error.has_value()) {
      return unexpected_error(*callback.error);
    }
    return unexpected_error(ErrorCode::BackendRejectedInput);
  }
  if (callback.rounds.size() != transcript.shape().round_count()) {
    return unexpected_error(ErrorCode::InternalMismatch);
  }
  proof.resize(proof_len);
  return NormArgProof{inputs.rho, inputs.generators, inputs.c_vec,
                      inputs.n_vec.size(), commitment, std::move(proof)};
}

bool verify_norm_arg_with_cache(const NormArgProof &proof,
                                purify_secp_context *secp_context,
                                ExperimentalCircuitBackend *cache) {
  if (secp_context == nullptr) {
    return false;
  }
  if (proof.n_vec_len == 0 || proof.c_vec.empty()) {
    return false;
  }

  std::span<const unsigned char> c_vec = byte_span(proof.c_vec);
  ResolvedBpppGeneratorBackend resolved =
      resolve_bppp_generator_backend(cache, proof.generators, secp_context);
  const int ok =
      resolved.backend_resources != nullptr
          ? purify_bppp_verify_norm_arg_with_resources(
                resolved.backend_resources, proof.rho.data(), c_vec.data(),
                proof.c_vec.size(), proof.n_vec_len, proof.commitment.data(),
                proof.proof.data(), proof.proof.size())
          : purify_bppp_verify_norm_arg(
                secp_context, proof.rho.data(), resolved.serialized_bytes.data(),
                resolved.generator_count, c_vec.data(), proof.c_vec.size(),
                proof.n_vec_len, proof.commitment.data(), proof.proof.data(),
                proof.proof.size());
  return ok != 0;
}

Result<std::vector<candidate::PackedPointPairV4>>
parse_norm_rounds_v4(const Bytes &proof, std::size_t round_count,
                     ScalarBytes &terminal_n, ScalarBytes &terminal_l) {
  std::size_t expected_size = 0;
  const auto checked_size =
      CheckedSize(round_count) * sizeof(candidate::PackedPointPairV4) +
      2 * sizeof(ScalarBytes);
  if (!checked_size.store(expected_size) ||
      proof.size() != expected_size) {
    return unexpected_error(ErrorCode::InvalidDimensions);
  }
  using ::purify::detail::take_bytes;
  std::vector<candidate::PackedPointPairV4> rounds(round_count);
  std::span<const unsigned char> remaining = proof;
  for (auto &round : rounds) {
    take_bytes(remaining, round);
  }
  take_bytes(remaining, terminal_n);
  take_bytes(remaining, terminal_l);
  return rounds;
}

std::vector<ScalarBytes> scalar_challenges(
    std::span<const candidate::CircuitChallengeV4> challenges) {
  std::vector<ScalarBytes> out;
  out.reserve(challenges.size());
  for (const auto &challenge : challenges) {
    out.push_back(challenge.scalar.to_bytes_be());
  }
  return out;
}

Result<PointBytes> prepare_norm_arg_v4(
    const NormArgProof &norm,
    std::span<const candidate::CircuitChallengeV4> gammas,
    ScalarBytes &terminal_n, ScalarBytes &terminal_l,
    purify_secp_context *secp_context) {
  const std::vector<ScalarBytes> encoded_gammas = scalar_challenges(gammas);
  PointBytes residual{};
  const std::span<const unsigned char> generators =
      byte_span(norm.generators);
  const std::span<const unsigned char> c_vec = byte_span(norm.c_vec);
  if (purify_bppp_prepare_norm_arg_claim_with_challenges(
          secp_context, norm.rho.data(), generators.data(),
          norm.generators.size(), c_vec.data(), norm.c_vec.size(),
          norm.n_vec_len, norm.commitment.data(), norm.proof.data(),
          norm.proof.size(),
          reinterpret_cast<const unsigned char *>(encoded_gammas.data()),
          encoded_gammas.size(), terminal_n.data(), terminal_l.data(),
          residual.data()) == 0) {
    return unexpected_error(ErrorCode::BackendRejectedInput);
  }
  return residual;
}

bool verify_norm_arg_v4(
    const NormArgProof &norm,
    std::span<const candidate::CircuitChallengeV4> gammas,
    purify_secp_context *secp_context) {
  const std::vector<ScalarBytes> encoded_gammas = scalar_challenges(gammas);
  const std::span<const unsigned char> generators =
      byte_span(norm.generators);
  const std::span<const unsigned char> c_vec = byte_span(norm.c_vec);
  return purify_bppp_verify_norm_arg_with_challenges(
             secp_context, norm.rho.data(), generators.data(),
             norm.generators.size(), c_vec.data(), norm.c_vec.size(),
             norm.n_vec_len, norm.commitment.data(), norm.proof.data(),
             norm.proof.size(),
             reinterpret_cast<const unsigned char *>(encoded_gammas.data()),
             encoded_gammas.size()) != 0;
}

Result<PointBytes> commit_norm_arg(const NormArgInputs &inputs,
                                   purify_secp_context *secp_context) {
  return commit_norm_arg_with_cache(inputs, secp_context, nullptr);
}

Result<NormArgProof>
prove_norm_arg_to_commitment(const NormArgInputs &inputs,
                             const PointBytes &commitment,
                             purify_secp_context *secp_context) {
  return prove_norm_arg_to_commitment_with_cache(inputs, commitment, secp_context, nullptr);
}

bool verify_norm_arg(const NormArgProof &proof,
                     purify_secp_context *secp_context) {
  return verify_norm_arg_with_cache(proof, secp_context, nullptr);
}

Result<CommittedPurifyWitness>
commit_output_witness(const Bytes &message, const SecretKey &secret,
                      const ScalarBytes &blind, purify_secp_context *secp_context) {
  return commit_output_witness(message, secret, blind, secp_context,
                               value_generator_h(secp_context),
                               base_generator(secp_context));
}

Result<CommittedPurifyWitness>
commit_output_witness(const Bytes &message, const SecretKey &secret,
                      const ScalarBytes &blind, purify_secp_context *secp_context,
                      const GeneratorBytes &value_gen,
                      const GeneratorBytes &blind_gen) {
  PURIFY_ASSIGN_OR_RETURN(auto witness, prove_assignment_data(message, secret));
  SecretScalarBytes output;
  purify_scalar_get_b32(
      output.value.data(),
      &::purify::detail::FieldElementAccess::raw(witness.output));
  PURIFY_ASSIGN_OR_RETURN(const auto &commitment,
                          pedersen_commit_char(blind, output.value,
                                               secp_context, value_gen,
                                               blind_gen));
  return CommittedPurifyWitness{witness.public_key, witness.output,
                                std::move(witness.assignment), commitment};
}

} // namespace purify::bppp
